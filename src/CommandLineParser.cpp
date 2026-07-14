#include "CommandLineParser.h"
#include "FormatUtil.h"
#include "StringUtil.h"

namespace ss {

namespace {

bool NeedsValue(const std::vector<std::wstring>& args, size_t i, ParsedCommand& cmd, const std::wstring& flagName) {
    if (i + 1 >= args.size()) {
        cmd.valid = false;
        cmd.errorMessage = flagName + L" requires a value.";
        return false;
    }
    return true;
}

}  // namespace

ParsedCommand CommandLineParser::Parse(const std::vector<std::wstring>& args) {
    ParsedCommand cmd;

    std::vector<std::wstring> positional;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::wstring& arg = args[i];

        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            cmd.showHelp = true;
        } else if (arg == L"--version") {
            cmd.showVersion = true;
        } else if (arg == L"--no-gui") {
            cmd.noGui = true;
        } else if (arg == L"--gui") {
            cmd.guiExplicit = true;
        } else if (arg == L"--scan") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            cmd.hasScan = true;
            cmd.scanPath = args[++i];
        } else if (arg == L"--watch") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            cmd.hasWatch = true;
            cmd.watchPath = args[++i];
        } else if (arg == L"--recursive") {
            cmd.recursive = true;
        } else if (arg == L"--no-recursive") {
            cmd.recursive = false;
        } else if (arg == L"--fast") {
            cmd.fast = true;
        } else if (arg == L"--no-fast") {
            cmd.fast = false;
        } else if (arg == L"--incremental") {
            cmd.incremental = true;
        } else if (arg == L"--no-incremental") {
            cmd.incremental = false;
        } else if (arg == L"--zone-only") {
            cmd.zoneOnly = true;
        } else if (arg == L"--suspicious-only") {
            cmd.suspiciousOnly = true;
        } else if (arg == L"--high-risk-only") {
            cmd.highRiskOnly = true;
        } else if (arg == L"--include-normal") {
            cmd.includeNormal = true;
        } else if (arg == L"--include-directories") {
            cmd.includeDirectories = true;
        } else if (arg == L"--exclude-directories") {
            cmd.includeDirectories = false;
        } else if (arg == L"--include-hidden") {
            cmd.includeHidden = true;
        } else if (arg == L"--include-system") {
            cmd.includeSystem = true;
        } else if (arg == L"--skip-reparse-points") {
            cmd.skipReparsePoints = true;
        } else if (arg == L"--follow-reparse-points") {
            cmd.skipReparsePoints = false;
        } else if (arg == L"--min-stream-size") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            uint64_t bytes = 0;
            if (!ParseSizeString(args[++i], bytes)) {
                cmd.valid = false;
                cmd.errorMessage = L"Invalid value for --min-stream-size: " + args[i];
                break;
            }
            cmd.hasMinSize = true;
            cmd.minSize = bytes;
        } else if (arg == L"--max-stream-size") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            uint64_t bytes = 0;
            if (!ParseSizeString(args[++i], bytes)) {
                cmd.valid = false;
                cmd.errorMessage = L"Invalid value for --max-stream-size: " + args[i];
                break;
            }
            cmd.hasMaxSize = true;
            cmd.maxSize = bytes;
        } else if (arg == L"--format") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            std::wstring value = ToLower(args[++i]);
            if (value == L"table") cmd.format = OutputFormat::Table;
            else if (value == L"csv") cmd.format = OutputFormat::Csv;
            else if (value == L"json") cmd.format = OutputFormat::Json;
            else {
                cmd.valid = false;
                cmd.errorMessage = L"Invalid --format value (expected table, csv, or json): " + args[i];
                break;
            }
        } else if (arg == L"--preview") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            cmd.hasPreview = true;
            cmd.previewStreamFullName = args[++i];
        } else if (arg == L"--remove-stream") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            cmd.hasRemoveStream = true;
            cmd.removeStreamFullName = args[++i];
        } else if (arg == L"--remove-zone-identifier") {
            cmd.removeZoneIdentifier = true;
        } else if (arg == L"--yes") {
            cmd.yes = true;
        } else if (arg == L"--export") {
            if (!NeedsValue(args, i, cmd, arg)) break;
            cmd.hasExport = true;
            cmd.exportFile = args[++i];
        } else if (arg == L"--verbose") {
            cmd.verbose = true;
        } else if (!arg.empty() && arg[0] == L'-') {
            cmd.valid = false;
            cmd.errorMessage = L"Unrecognized option: " + arg;
            break;
        } else {
            positional.push_back(arg);
        }
    }

    if (cmd.valid && !positional.empty()) {
        cmd.initialPath = positional.front();
    }

    if (cmd.valid && cmd.noGui) {
        if (!cmd.hasScan && !cmd.hasWatch && !cmd.showHelp && !cmd.showVersion) {
            cmd.valid = false;
            cmd.errorMessage = L"--no-gui requires --scan, --watch, --help, or --version.";
        }
    }

    if (cmd.valid && cmd.hasRemoveStream && !cmd.yes && cmd.noGui) {
        cmd.valid = false;
        cmd.errorMessage = L"--remove-stream requires --yes to confirm removal in --no-gui mode.";
    }
    if (cmd.valid && cmd.removeZoneIdentifier && !cmd.yes && cmd.noGui) {
        cmd.valid = false;
        cmd.errorMessage = L"--remove-zone-identifier requires --yes to confirm removal in --no-gui mode.";
    }

    return cmd;
}

std::wstring CommandLineParser::GetHelpText() {
    return
        L"Stream Sleuth - NTFS Alternate Data Stream utility\r\n"
        L"\r\n"
        L"Usage:\r\n"
        L"  StreamSleuth.exe                                   Open the GUI\r\n"
        L"  StreamSleuth.exe <path>                             Open the GUI with a path ready to scan\r\n"
        L"  StreamSleuth.exe --no-gui --scan <path> [options]   Scan without showing any window\r\n"
        L"  StreamSleuth.exe --no-gui --watch <path> [options]  Watch for stream changes\r\n"
        L"\r\n"
        L"General:\r\n"
        L"  --help                       Show this help text\r\n"
        L"  --version                    Show version information\r\n"
        L"  --no-gui                     Run without showing any windows\r\n"
        L"  --gui                        Force the GUI even if a path is supplied\r\n"
        L"  --verbose                    Include extra diagnostics in output\r\n"
        L"\r\n"
        L"Scanning:\r\n"
        L"  --scan <path>                Scan a file, folder, or drive\r\n"
        L"  --watch <path>                Watch a file, folder, or drive for stream changes\r\n"
        L"  --recursive / --no-recursive  Force or disable recursion into subfolders\r\n"
        L"  --fast / --no-fast            Require or disable fast USN-assisted scanning\r\n"
        L"  --incremental / --no-incremental  Use or disable incremental USN-based updates\r\n"
        L"  --skip-reparse-points / --follow-reparse-points  Control reparse point traversal\r\n"
        L"  --include-directories / --exclude-directories    Control directory stream scanning\r\n"
        L"  --include-hidden             Include hidden files\r\n"
        L"  --include-system             Include system files\r\n"
        L"  --min-stream-size <size>     Minimum stream size (e.g. 4KB, 1MB)\r\n"
        L"  --max-stream-size <size>     Maximum stream size\r\n"
        L"\r\n"
        L"Filtering:\r\n"
        L"  --zone-only                  Show only Zone.Identifier streams\r\n"
        L"  --suspicious-only            Show only Suspicious and High Risk streams\r\n"
        L"  --high-risk-only             Show only High Risk streams\r\n"
        L"  --include-normal             Include Normal-classified streams in output\r\n"
        L"\r\n"
        L"Output:\r\n"
        L"  --format table|csv|json      Output format (default table)\r\n"
        L"  --export <file>              Write output to a file instead of stdout\r\n"
        L"\r\n"
        L"Preview and removal:\r\n"
        L"  --preview <stream-full-name>       Preview a stream, e.g. C:\\file.txt:hidden.bin\r\n"
        L"  --remove-stream <stream-full-name> Remove one specific stream (requires --yes)\r\n"
        L"  --remove-zone-identifier           Bulk-remove Zone.Identifier from scan results (requires --yes)\r\n"
        L"  --yes                              Confirm a destructive removal operation\r\n"
        L"\r\n"
        L"Exit codes:\r\n"
        L"  0  success / scan completed / no matches for suspicious-only filters\r\n"
        L"  1  matching streams were found (with --suspicious-only or --high-risk-only)\r\n"
        L"  2  invalid command-line arguments\r\n"
        L"  3  insufficient privileges or access denied\r\n"
        L"  4  Windows API failure\r\n"
        L"  5  stream removal failed\r\n"
        L"  6  scan cancelled\r\n"
        L"  10 internal error\r\n"
        L"\r\n"
        L"StreamSleuth finds and explains NTFS alternate data streams. It is a triage\r\n"
        L"and discovery tool, not a malware scanner. Suspicious/High Risk results are\r\n"
        L"indicators that warrant manual review, not proof of malicious content.\r\n";
}

std::wstring CommandLineParser::GetVersionText() {
    return L"Stream Sleuth 1.0.0\n";
}

}  // namespace ss
