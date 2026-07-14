// Watches a folder/drive for stream-related changes after an initial
// baseline scan, using USN journal reading where available and polling at a
// modest interval. Not a replacement for a full-fidelity file system monitor:
// it is optimized for detecting alternate-data-stream changes cheaply.
#pragma once

#include <functional>
#include <atomic>
#include <thread>
#include <map>
#include <set>
#include "StreamTypes.h"

namespace ss {

class StreamWatchService {
public:
    using EventCallback = std::function<void(const WatchEvent&)>;
    using WarningCallback = std::function<void(const std::wstring&)>;

    StreamWatchService() = default;
    ~StreamWatchService();

    StreamWatchService(const StreamWatchService&) = delete;
    StreamWatchService& operator=(const StreamWatchService&) = delete;

    // Starts watching in a background thread. Returns false if already running
    // or if the initial baseline scan cannot even begin (bad path).
    bool Start(const ScanOptions& options, unsigned int pollIntervalMs, EventCallback onEvent, WarningCallback onWarning);

    void Stop();
    bool IsRunning() const { return running_.load(); }

private:
    struct KnownStream {
        uint64_t size = 0;
        StreamClassification classification = StreamClassification::Unknown;
    };

    void ThreadProc(ScanOptions options, unsigned int pollIntervalMs, EventCallback onEvent, WarningCallback onWarning);
    void DiffHost(const std::wstring& hostPath, const std::vector<StreamRecord>& newRecords,
                  const EventCallback& onEvent, bool announceHostCreated);
    void RemoveHost(const std::wstring& hostPath, const EventCallback& onEvent);

    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread thread_;

    std::map<std::wstring, KnownStream> knownStreams_;  // key: "host:streamname"
    std::set<std::wstring> knownHosts_;
};

}  // namespace ss
