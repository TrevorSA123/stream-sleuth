#include "ConsoleMode.h"
#include "ScanCoordinator.h"
#include "StreamWatchService.h"
#include "StreamPreviewer.h"
#include "StreamRemovalService.h"
#include "CsvWriter.h"
#include "JsonWriter.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "FormatUtil.h"
#include "FileTimeUtil.h"

#include <atomic>
#include <cstdio>
#include <io.h>
#include <fcntl.h>

namespace ss {

namespace {

constexpr int kExitSuccess = 0;
constexpr int kExitMatchesFound = 1;
constexpr int kExitInvalidArgs = 2;
constexpr int kExitAccessDenied = 3;
constexpr int kExitWinApiFailure = 4;
constexpr int kExitRemovalFailed = 5;
constexpr int kExitCancelled = 6;
constexpr int kExitInternalError = 10;

std::atomic<bool>* g_ctrlCancelFlag = nullptr;

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        if (g_ctrlCancelFlag != nullptr) g_ctrlCancelFlag->store(true);
        return TRUE;
    }
    return FALSE;
}

void WriteStdOut(const std::wstring& text) {
    std::string utf8 = WideToUtf8(text);
    fwrite(utf8.data(), 1, utf8.size(), stdout);
}

void WriteStdErr(const std::wstring& text) {
    std::string utf8 = WideToUtf8(text);
    fwrite(utf8.data(), 1, utf8.size(), stderr);
}

bool ErrorsLookLikeAccessDenied(const std::vector<std::wstring>& errors) {
    for (const auto& e : errors) {
        if (ContainsIgnoreCase(e, L"access") || ContainsIgnoreCase(e, L"denied") || ContainsIgnoreCase(e, L"privilege")) {
            return true;
        }
    }
    return false;
}

ScanOptions BuildScanOptions(const ParsedCommand& cmd, const std::wstring& path) {
    ScanOptions opts;
    opts.targetPath = path;
    opts.recursive = cmd.recursive.value_or(true);
    opts.includeDirectories = cmd.includeDirectories.value_or(true);
    opts.includeHidden = cmd.includeHidden;
    opts.includeSystem = cmd.includeSystem;
    opts.skipReparsePoints = cmd.skipReparsePoints.value_or(true);

    opts.useFastUsnEnumeration = cmd.fast.value_or(true);
    if (cmd.fast.has_value() && cmd.fast.value() == true) {
        opts.allowRecursiveFallback = false;  // fast explicitly required
    } else {
        opts.allowRecursiveFallback = true;
    }

    opts.incremental = cmd.incremental.value_or(false);
    opts.zoneOnly = false;      // filtering for exit codes/display handled separately in ConsoleMode
    opts.suspiciousOnly = false;
    opts.highRiskOnly = false;

    opts.sizeFilterEnabled = cmd.hasMinSize || cmd.hasMaxSize;
    opts.minStreamSize = cmd.hasMinSize ? cmd.minSize : 0;
    opts.maxStreamSize = cmd.hasMaxSize ? cmd.maxSize : 0;

    return opts;
}

std::vector<StreamRecord> FilterForDisplay(const std::vector<StreamRecord>& streams, const ParsedCommand& cmd) {
    bool anyExclusiveFilter = cmd.zoneOnly || cmd.suspiciousOnly || cmd.highRiskOnly;
    if (!anyExclusiveFilter) return streams;

    std::vector<StreamRecord> out;
    for (const auto& rec : streams) {
        bool included = false;
        bool isZone = EqualsIgnoreCase(rec.streamName, L"Zone.Identifier");
        if (cmd.zoneOnly && isZone) included = true;
        if (cmd.highRiskOnly && rec.classification == StreamClassification::HighRisk) included = true;
        if (cmd.suspiciousOnly &&
            (rec.classification == StreamClassification::Suspicious || rec.classification == StreamClassification::HighRisk)) {
            included = true;
        }
        if (!included && cmd.includeNormal && rec.classification == StreamClassification::Normal) included = true;
        if (included) out.push_back(rec);
    }
    return out;
}

std::vector<StreamRecord> FilterForMatchCount(const std::vector<StreamRecord>& streams, const ParsedCommand& cmd) {
    std::vector<StreamRecord> out;
    for (const auto& rec : streams) {
        if (cmd.highRiskOnly && rec.classification == StreamClassification::HighRisk) {
            out.push_back(rec);
        } else if (cmd.suspiciousOnly &&
                   (rec.classification == StreamClassification::Suspicious || rec.classification == StreamClassification::HighRisk)) {
            out.push_back(rec);
        }
    }
    return out;
}

std::wstring BuildTableText(const std::vector<StreamRecord>& streams, bool verbose) {
    std::wstring out;
    wchar_t header[256];
    swprintf_s(header, L"%-11s %-10s %-9s %-8s %s\n", L"CLASS", L"SIZE", L"ZONE", L"SOURCE", L"HOST : STREAM");
    out += header;
    out += L"---------------------------------------------------------------------------\n";

    for (const auto& rec : streams) {
        std::wstring cls = ClassificationToShortLabel(rec.classification);
        std::wstring size = FormatByteSize(rec.streamSize);
        std::wstring zone = rec.zoneInfo.parsed ? rec.zoneInfo.zoneName : (rec.zoneInfo.isZoneIdentifier ? L"?" : L"-");
        std::wstring source = rec.source;

        wchar_t line[512];
        swprintf_s(line, L"%-11s %-10s %-9s %-8s ", cls.c_str(), size.c_str(), zone.c_str(), source.c_str());
        out += line;
        out += rec.fullStreamPath;
        out += L"\n";
        out += L"    Reason: " + rec.classificationReason + L"\n";
        if (verbose) {
            out += L"    Type guess: " + rec.streamTypeGuess + L"\n";
            for (const auto& d : rec.diagnostics) {
                out += L"    - " + d + L"\n";
            }
        }
    }
    return out;
}

void EmitContent(const ParsedCommand& cmd, const std::wstring& content) {
    if (cmd.hasExport) {
        std::string utf8 = WideToUtf8(content);
        FILE* f = nullptr;
        if (_wfopen_s(&f, cmd.exportFile.c_str(), L"wb") == 0 && f != nullptr) {
            fwrite(utf8.data(), 1, utf8.size(), f);
            fclose(f);
        } else {
            WriteStdErr(L"Could not write to export file: " + cmd.exportFile + L"\n");
        }
    } else {
        WriteStdOut(content);
    }
}

std::wstring WatchEventTypeToString(WatchEventType type) {
    switch (type) {
        case WatchEventType::StreamAdded: return L"StreamAdded";
        case WatchEventType::StreamRemoved: return L"StreamRemoved";
        case WatchEventType::StreamModified: return L"StreamModified";
        case WatchEventType::HostFileCreated: return L"HostFileCreated";
        case WatchEventType::HostFileDeleted: return L"HostFileDeleted";
        case WatchEventType::HostFileRenamed: return L"HostFileRenamed";
        case WatchEventType::ZoneIdentifierAdded: return L"ZoneIdentifierAdded";
        case WatchEventType::ZoneIdentifierRemoved: return L"ZoneIdentifierRemoved";
    }
    return L"Unknown";
}

int RunScan(const ParsedCommand& cmd, std::atomic<bool>& cancelled) {
    ScanOptions opts = BuildScanOptions(cmd, cmd.scanPath);

    if (!PathExistsOnDisk(opts.targetPath)) {
        WriteStdErr(L"Target path does not exist: " + opts.targetPath + L"\n");
        return kExitWinApiFailure;
    }

    ScanResult result = ScanCoordinator::RunSync(opts, cancelled, nullptr, nullptr);

    if (cmd.verbose) {
        for (const auto& w : result.warnings) WriteStdErr(L"Warning: " + w + L"\n");
    }
    for (const auto& e : result.errors) WriteStdErr(L"Error: " + e + L"\n");

    if (cmd.hasPreview) {
        std::wstring host, streamName;
        if (!SplitDisplayStreamPath(cmd.previewStreamFullName, host, streamName)) {
            WriteStdErr(L"Could not parse stream name for preview: " + cmd.previewStreamFullName + L"\n");
            return kExitInvalidArgs;
        }
        PreviewResult preview = StreamPreviewer::Preview(host, streamName, L"$DATA");
        if (!preview.success) {
            WriteStdErr(L"Preview failed: " + preview.error + L"\n");
            return kExitWinApiFailure;
        }
        std::wstring out = L"Preview of " + cmd.previewStreamFullName + L" (" +
                            std::to_wstring(preview.bytesPreviewed) + L" of " + std::to_wstring(preview.totalStreamSize) +
                            L" bytes shown)\n";
        if (!preview.detectedSignature.empty()) out += L"Signature: " + preview.detectedSignature + L"\n";
        out += L"\n";
        out += preview.kind == PreviewContentKind::Text ? preview.textContent : preview.hexDump;
        WriteStdOut(out);
        return kExitSuccess;
    }

    if (cmd.hasRemoveStream) {
        std::wstring host, streamName;
        if (!SplitDisplayStreamPath(cmd.removeStreamFullName, host, streamName)) {
            WriteStdErr(L"Could not parse stream name for removal: " + cmd.removeStreamFullName + L"\n");
            return kExitInvalidArgs;
        }
        RemovalOutcome outcome = StreamRemovalService::RemoveStream(host, streamName, L"$DATA");
        WriteStdOut((outcome.success ? L"Removed: " : L"Failed: ") + cmd.removeStreamFullName + L" - " + outcome.message + L"\n");
        return outcome.success ? kExitSuccess : kExitRemovalFailed;
    }

    if (cmd.removeZoneIdentifier) {
        auto outcomes = StreamRemovalService::BulkRemoveZoneIdentifier(result.streams);
        bool anyFailure = false;
        for (const auto& o : outcomes) {
            WriteStdOut((o.success ? L"Removed: " : L"Failed: ") + o.hostPath + L":Zone.Identifier - " + o.message + L"\n");
            if (!o.success) anyFailure = true;
        }
        if (outcomes.empty()) {
            WriteStdOut(L"No Zone.Identifier streams found in scan results.\n");
        }
        return anyFailure ? kExitRemovalFailed : kExitSuccess;
    }

    std::vector<StreamRecord> display = FilterForDisplay(result.streams, cmd);

    std::wstring content;
    switch (cmd.format) {
        case OutputFormat::Csv:
            content = CsvWriter::BuildCsv(display);
            break;
        case OutputFormat::Json: {
            ScanResult displayResult = result;
            displayResult.streams = display;
            content = JsonWriter::BuildJson(opts, displayResult);
            break;
        }
        case OutputFormat::Table:
        default:
            content = BuildTableText(display, cmd.verbose);
            content += L"\n" + result.summary + L"\n";
            break;
    }
    EmitContent(cmd, content);

    if (result.cancelled) return kExitCancelled;
    if (!result.errors.empty()) {
        return ErrorsLookLikeAccessDenied(result.errors) ? kExitAccessDenied : kExitWinApiFailure;
    }

    if (cmd.suspiciousOnly || cmd.highRiskOnly) {
        auto matches = FilterForMatchCount(result.streams, cmd);
        return matches.empty() ? kExitSuccess : kExitMatchesFound;
    }

    return kExitSuccess;
}

int RunWatch(const ParsedCommand& cmd, std::atomic<bool>& cancelled) {
    ScanOptions opts = BuildScanOptions(cmd, cmd.watchPath);
    if (!PathExistsOnDisk(opts.targetPath)) {
        WriteStdErr(L"Target path does not exist: " + opts.targetPath + L"\n");
        return kExitWinApiFailure;
    }

    WriteStdOut(L"Watching " + opts.targetPath + L" for stream changes. Press Ctrl+C to stop.\n");

    StreamWatchService service;
    bool started = service.Start(
        opts, 2000,
        [&](const WatchEvent& ev) {
            bool isZone = EqualsIgnoreCase(ev.streamName, L"Zone.Identifier") ||
                          ev.type == WatchEventType::ZoneIdentifierAdded || ev.type == WatchEventType::ZoneIdentifierRemoved;
            bool passesFilter = true;
            if (cmd.suspiciousOnly) {
                passesFilter = ev.classification == StreamClassification::Suspicious || ev.classification == StreamClassification::HighRisk;
            }
            if (cmd.highRiskOnly) {
                passesFilter = ev.classification == StreamClassification::HighRisk;
            }
            if (cmd.zoneOnly) {
                passesFilter = isZone;
            }
            if (!passesFilter) return;

            std::wstring line = L"[" + FormatFileTime(ev.timestamp) + L"] " + WatchEventTypeToString(ev.type) +
                                 L" - " + ev.hostPath;
            if (!ev.streamName.empty()) line += L":" + ev.streamName;
            line += L" - " + ev.details + L"\n";
            WriteStdOut(line);
        },
        [&](const std::wstring& warning) {
            WriteStdErr(L"Warning: " + warning + L"\n");
        });

    if (!started) {
        WriteStdErr(L"Could not start watch mode.\n");
        return kExitInternalError;
    }

    while (!cancelled.load()) {
        Sleep(200);
    }

    service.Stop();
    WriteStdOut(L"Watch mode stopped.\n");
    return kExitSuccess;
}

}  // namespace

int ConsoleMode::Run(const ParsedCommand& cmd) {
    SetConsoleOutputCP(CP_UTF8);

    if (cmd.showHelp) {
        WriteStdOut(CommandLineParser::GetHelpText());
        return kExitSuccess;
    }
    if (cmd.showVersion) {
        WriteStdOut(CommandLineParser::GetVersionText());
        return kExitSuccess;
    }
    if (!cmd.valid) {
        WriteStdErr(cmd.errorMessage + L"\n");
        return kExitInvalidArgs;
    }

    std::atomic<bool> cancelled{false};
    g_ctrlCancelFlag = &cancelled;
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    int exitCode = kExitInternalError;
    if (cmd.hasWatch) {
        exitCode = RunWatch(cmd, cancelled);
    } else if (cmd.hasScan) {
        exitCode = RunScan(cmd, cancelled);
    } else {
        WriteStdErr(L"Nothing to do: specify --scan, --watch, --help, or --version.\n");
        exitCode = kExitInvalidArgs;
    }

    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    g_ctrlCancelFlag = nullptr;
    return exitCode;
}

}  // namespace ss
