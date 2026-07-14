#include "ScanCoordinator.h"
#include "NtfsUsnFileEnumerator.h"
#include "RecursiveStreamScanner.h"
#include "BaselineStore.h"
#include "UsnStreamChangeTracker.h"
#include "StreamEnumerator.h"
#include "PathUtil.h"
#include "StringUtil.h"

#include <chrono>

namespace ss {

ScanCoordinator::~ScanCoordinator() {
    Cancel();
    Join();
}

void ScanCoordinator::Cancel() {
    cancelled_.store(true);
}

void ScanCoordinator::Join() {
    if (worker_.joinable()) worker_.join();
}

std::vector<StreamRecord> ScanCoordinator::ApplyFilters(const std::vector<StreamRecord>& in, const ScanOptions& options) {
    std::vector<StreamRecord> out;
    out.reserve(in.size());
    for (const auto& rec : in) {
        if (options.zoneOnly && !EqualsIgnoreCase(rec.streamName, L"Zone.Identifier")) continue;
        if (options.highRiskOnly && rec.classification != StreamClassification::HighRisk) continue;
        if (options.suspiciousOnly && !options.highRiskOnly &&
            rec.classification != StreamClassification::Suspicious &&
            rec.classification != StreamClassification::HighRisk) {
            continue;
        }
        out.push_back(rec);
    }
    return out;
}

namespace {

void RunIncremental(const ScanOptions& options, ScanResult& result, const std::atomic<bool>& cancelled,
                     const ScanCoordinator::RecordCallback& onRecord, const ScanCoordinator::ProgressCallback& onProgress) {
    std::wstring volumeRoot = GetVolumeRootPath(options.targetPath);
    VolumeBaseline baseline;
    bool haveBaseline = !volumeRoot.empty() && BaselineStore::Load(volumeRoot, baseline);

    if (!haveBaseline) {
        std::wstring error;
        if (!volumeRoot.empty() && UsnStreamChangeTracker::CreateBaseline(volumeRoot, baseline, error)) {
            BaselineStore::Save(baseline);
        }
        result.warnings.push_back(L"No previous baseline found; performed a full scan and created a new baseline.");
        std::wstring failureReason;
        bool fastOk = options.useFastUsnEnumeration &&
                      NtfsUsnFileEnumerator::Scan(options, result, cancelled, onRecord,
                                                   [&](const NtfsUsnFileEnumerator::Progress& p) {
                                                       if (onProgress) {
                                                           ScanProgressInfo info;
                                                           info.statusText = L"Fast scanning (building baseline)...";
                                                           info.currentPath = p.currentPath;
                                                           info.streamsFound = result.streamsFound;
                                                           info.suspiciousCount = result.suspiciousCount;
                                                           info.highRiskCount = result.highRiskCount;
                                                           onProgress(info);
                                                       }
                                                   }, failureReason);
        if (!fastOk) {
            RecursiveStreamScanner::Scan(options, result, cancelled, onRecord,
                                          [&](const RecursiveStreamScanner::Progress& p) {
                                              if (onProgress) {
                                                  ScanProgressInfo info;
                                                  info.statusText = L"Recursive scanning (building baseline)...";
                                                  info.currentPath = p.currentPath;
                                                  info.filesProcessed = p.filesProcessed;
                                                  info.foldersProcessed = p.foldersProcessed;
                                                  info.streamsFound = result.streamsFound;
                                                  onProgress(info);
                                              }
                                          });
        }
        return;
    }

    UsnUpdateResult update;
    std::wstring error;
    if (!UsnStreamChangeTracker::GetChangesSinceBaseline(baseline, options, update, error)) {
        result.warnings.push_back(L"Incremental update failed (" + error + L"); falling back to full scan.");
        update.fullRescanRequired = true;
    }

    if (update.fullRescanRequired) {
        result.warnings.push_back(L"Full rescan required: " + update.reason);
        std::wstring failureReason;
        bool fastOk = options.useFastUsnEnumeration &&
                      NtfsUsnFileEnumerator::Scan(options, result, cancelled, onRecord, [](const NtfsUsnFileEnumerator::Progress&) {}, failureReason);
        if (!fastOk) {
            RecursiveStreamScanner::Scan(options, result, cancelled, onRecord, [](const RecursiveStreamScanner::Progress&) {});
        }
        VolumeBaseline fresh;
        if (UsnStreamChangeTracker::CreateBaseline(volumeRoot, fresh, error)) {
            BaselineStore::Save(fresh);
        }
        return;
    }

    std::wstring targetLower = ToLower(options.targetPath);
    while (!targetLower.empty() && targetLower.back() == L'\\') targetLower.pop_back();

    for (const auto& path : update.candidatePaths) {
        if (cancelled.load()) { result.cancelled = true; result.partial = true; break; }
        std::wstring pathLower = ToLower(path);
        bool inScope = pathLower == targetLower ||
                        (pathLower.size() > targetLower.size() &&
                         pathLower.compare(0, targetLower.size(), targetLower) == 0 &&
                         pathLower[targetLower.size()] == L'\\');
        if (!inScope) continue;

        std::vector<std::wstring> warnings;
        auto records = StreamEnumerator::EnumerateStreams(path, options, L"NTFS USN-Assisted (Incremental)", warnings, &cancelled);
        for (auto& w : warnings) result.warnings.push_back(w);
        for (auto& rec : records) {
            result.streamsFound++;
            if (rec.classification == StreamClassification::Suspicious) result.suspiciousCount++;
            if (rec.classification == StreamClassification::HighRisk) result.highRiskCount++;
            if (onRecord) onRecord(rec);
            result.streams.push_back(std::move(rec));
        }
        if (IsDirectoryPath(path)) result.foldersProcessed++; else result.filesProcessed++;
    }

    if (update.possibleDeletionsOccurred) {
        result.warnings.push_back(L"Some files were deleted since the last baseline; deleted entries are not reflected automatically. Run a full scan to refresh completely.");
    }

    VolumeBaseline updated = baseline;
    updated.lastProcessedUsn = update.newLastProcessedUsn;
    BaselineStore::Save(updated);

    result.summary = L"Incremental update complete.";
}

}  // namespace

ScanResult ScanCoordinator::RunSync(const ScanOptions& options, const std::atomic<bool>& cancelled,
                                     RecordCallback onRecord, ProgressCallback onProgress) {
    auto startTime = std::chrono::steady_clock::now();
    ScanResult result;

    if (!PathExistsOnDisk(options.targetPath)) {
        result.errors.push_back(L"Target path does not exist: " + options.targetPath);
        return result;
    }

    if (options.incremental) {
        RunIncremental(options, result, cancelled, onRecord, onProgress);
    } else if (options.useFastUsnEnumeration) {
        std::wstring failureReason;
        bool fastOk = NtfsUsnFileEnumerator::Scan(
            options, result, cancelled, onRecord,
            [&](const NtfsUsnFileEnumerator::Progress& p) {
                if (onProgress) {
                    ScanProgressInfo info;
                    info.statusText = L"Fast USN-assisted scan in progress...";
                    info.currentPath = p.currentPath;
                    info.streamsFound = result.streamsFound;
                    info.suspiciousCount = result.suspiciousCount;
                    info.highRiskCount = result.highRiskCount;
                    onProgress(info);
                }
            },
            failureReason);

        if (!fastOk) {
            if (!options.allowRecursiveFallback) {
                result.errors.push_back(L"Fast USN-assisted scan failed and recursive fallback is disabled: " + failureReason);
            } else {
                result.warnings.push_back(L"Fast scan unavailable (" + failureReason + L"); falling back to recursive scan.");
                RecursiveStreamScanner::Scan(
                    options, result, cancelled, onRecord,
                    [&](const RecursiveStreamScanner::Progress& p) {
                        if (onProgress) {
                            ScanProgressInfo info;
                            info.statusText = L"Recursive scan in progress...";
                            info.currentPath = p.currentPath;
                            info.filesProcessed = p.filesProcessed;
                            info.foldersProcessed = p.foldersProcessed;
                            info.streamsFound = result.streamsFound;
                            info.suspiciousCount = result.suspiciousCount;
                            info.highRiskCount = result.highRiskCount;
                            onProgress(info);
                        }
                    });
            }
        }
    } else {
        RecursiveStreamScanner::Scan(
            options, result, cancelled, onRecord,
            [&](const RecursiveStreamScanner::Progress& p) {
                if (onProgress) {
                    ScanProgressInfo info;
                    info.statusText = L"Recursive scan in progress...";
                    info.currentPath = p.currentPath;
                    info.filesProcessed = p.filesProcessed;
                    info.foldersProcessed = p.foldersProcessed;
                    info.streamsFound = result.streamsFound;
                    info.suspiciousCount = result.suspiciousCount;
                    info.highRiskCount = result.highRiskCount;
                    onProgress(info);
                }
            });
    }

    if (cancelled.load()) {
        result.cancelled = true;
        result.partial = true;
    }

    auto endTime = std::chrono::steady_clock::now();
    result.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    wchar_t summaryBuf[256];
    swprintf_s(summaryBuf,
               L"Scanned %llu file(s), %llu folder(s); found %llu stream(s) (%llu suspicious, %llu high risk).",
               static_cast<unsigned long long>(result.filesProcessed),
               static_cast<unsigned long long>(result.foldersProcessed),
               static_cast<unsigned long long>(result.streamsFound),
               static_cast<unsigned long long>(result.suspiciousCount),
               static_cast<unsigned long long>(result.highRiskCount));
    result.summary = summaryBuf;

    return result;
}

bool ScanCoordinator::StartAsync(const ScanOptions& options, RecordCallback onRecord, ProgressCallback onProgress, CompleteCallback onComplete) {
    if (running_.load()) return false;
    cancelled_.store(false);
    running_.store(true);

    if (worker_.joinable()) worker_.join();

    worker_ = std::thread([this, options, onRecord, onProgress, onComplete]() {
        ScanResult result = RunSync(options, cancelled_, onRecord, onProgress);
        running_.store(false);
        if (onComplete) onComplete(result);
    });
    return true;
}

}  // namespace ss
