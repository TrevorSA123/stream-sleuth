// Chooses and drives a scan (fast USN-assisted, recursive fallback, or
// incremental), reporting progress and partial results as it goes.
#pragma once

#include <functional>
#include <atomic>
#include <thread>
#include <string>
#include "StreamTypes.h"

namespace ss {

struct ScanProgressInfo {
    std::wstring statusText;
    std::wstring currentPath;
    uint64_t filesProcessed = 0;
    uint64_t foldersProcessed = 0;
    uint64_t streamsFound = 0;
    uint64_t suspiciousCount = 0;
    uint64_t highRiskCount = 0;
};

class ScanCoordinator {
public:
    using RecordCallback = std::function<void(const StreamRecord&)>;
    using ProgressCallback = std::function<void(const ScanProgressInfo&)>;
    using CompleteCallback = std::function<void(const ScanResult&)>;

    ScanCoordinator() = default;
    ~ScanCoordinator();

    ScanCoordinator(const ScanCoordinator&) = delete;
    ScanCoordinator& operator=(const ScanCoordinator&) = delete;

    // Runs the scan on a new background thread. Returns false if a scan is
    // already running. onComplete is invoked from the worker thread once
    // finished; callers updating UI must marshal back to the UI thread.
    bool StartAsync(const ScanOptions& options, RecordCallback onRecord, ProgressCallback onProgress, CompleteCallback onComplete);

    // Runs the scan on the calling thread and returns the result directly.
    // Used by --no-gui mode.
    static ScanResult RunSync(const ScanOptions& options, const std::atomic<bool>& cancelled, RecordCallback onRecord, ProgressCallback onProgress);

    void Cancel();
    void Join();
    bool IsRunning() const { return running_.load(); }

    // Filters an already-collected set of records for display/export according
    // to options.zoneOnly / suspiciousOnly / highRiskOnly. Size filtering is
    // already applied during collection.
    static std::vector<StreamRecord> ApplyFilters(const std::vector<StreamRecord>& in, const ScanOptions& options);

private:
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> running_{false};
    std::thread worker_;
};

}  // namespace ss
