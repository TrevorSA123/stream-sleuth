#include "StreamWatchService.h"
#include "ScanCoordinator.h"
#include "BaselineStore.h"
#include "UsnStreamChangeTracker.h"
#include "StreamEnumerator.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "FileTimeUtil.h"

namespace ss {

StreamWatchService::~StreamWatchService() {
    Stop();
}

bool StreamWatchService::Start(const ScanOptions& options, unsigned int pollIntervalMs, EventCallback onEvent, WarningCallback onWarning) {
    if (running_.load()) return false;
    if (!PathExistsOnDisk(options.targetPath)) return false;

    stopRequested_.store(false);
    running_.store(true);
    knownStreams_.clear();
    knownHosts_.clear();

    if (thread_.joinable()) thread_.join();
    thread_ = std::thread(&StreamWatchService::ThreadProc, this, options, pollIntervalMs, onEvent, onWarning);
    return true;
}

void StreamWatchService::Stop() {
    stopRequested_.store(true);
    if (thread_.joinable()) thread_.join();
    running_.store(false);
}

void StreamWatchService::DiffHost(const std::wstring& hostPath, const std::vector<StreamRecord>& newRecords,
                                   const EventCallback& onEvent, bool announceHostCreated) {
    bool hostWasKnown = knownHosts_.count(ToLower(hostPath)) > 0;
    if (announceHostCreated && !hostWasKnown && !newRecords.empty() && onEvent) {
        WatchEvent ev;
        ev.type = WatchEventType::HostFileCreated;
        ev.hostPath = hostPath;
        ev.timestamp = NowAsFileTime();
        ev.details = L"New file detected with alternate data streams.";
        onEvent(ev);
    }
    knownHosts_.insert(ToLower(hostPath));

    std::set<std::wstring> newKeys;
    for (const auto& rec : newRecords) {
        std::wstring key = ToLower(rec.fullStreamPath);
        newKeys.insert(key);

        auto it = knownStreams_.find(key);
        bool isZone = EqualsIgnoreCase(rec.streamName, L"Zone.Identifier");
        if (it == knownStreams_.end()) {
            if (onEvent) {
                WatchEvent ev;
                ev.type = isZone ? WatchEventType::ZoneIdentifierAdded : WatchEventType::StreamAdded;
                ev.hostPath = hostPath;
                ev.streamName = rec.streamName;
                ev.classification = rec.classification;
                ev.timestamp = NowAsFileTime();
                ev.details = L"New stream: " + rec.fullStreamPath;
                onEvent(ev);
            }
        } else if (it->second.size != rec.streamSize) {
            if (onEvent) {
                WatchEvent ev;
                ev.type = WatchEventType::StreamModified;
                ev.hostPath = hostPath;
                ev.streamName = rec.streamName;
                ev.classification = rec.classification;
                ev.timestamp = NowAsFileTime();
                ev.details = L"Stream size changed: " + rec.fullStreamPath;
                onEvent(ev);
            }
        }
        knownStreams_[key] = KnownStream{rec.streamSize, rec.classification};
    }

    // Detect removed streams for this host.
    std::wstring hostLowerPrefix = ToLower(hostPath) + L":";
    std::vector<std::wstring> toErase;
    for (const auto& entry : knownStreams_) {
        if (entry.first.compare(0, hostLowerPrefix.size(), hostLowerPrefix) != 0) continue;
        if (newKeys.count(entry.first) > 0) continue;

        bool isZone = entry.first.find(L":zone.identifier") != std::wstring::npos;
        if (onEvent) {
            WatchEvent ev;
            ev.type = isZone ? WatchEventType::ZoneIdentifierRemoved : WatchEventType::StreamRemoved;
            ev.hostPath = hostPath;
            ev.timestamp = NowAsFileTime();
            ev.details = L"Stream removed: " + entry.first;
            onEvent(ev);
        }
        toErase.push_back(entry.first);
    }
    for (const auto& key : toErase) knownStreams_.erase(key);
}

void StreamWatchService::RemoveHost(const std::wstring& hostPath, const EventCallback& onEvent) {
    std::wstring hostLowerPrefix = ToLower(hostPath) + L":";
    std::vector<std::wstring> toErase;
    for (const auto& entry : knownStreams_) {
        if (entry.first.compare(0, hostLowerPrefix.size(), hostLowerPrefix) != 0) continue;
        toErase.push_back(entry.first);
    }
    if (!toErase.empty() && onEvent) {
        WatchEvent ev;
        ev.type = WatchEventType::HostFileDeleted;
        ev.hostPath = hostPath;
        ev.timestamp = NowAsFileTime();
        ev.details = L"Host file deleted; its " + std::to_wstring(toErase.size()) + L" known stream(s) are no longer present.";
        onEvent(ev);
    }
    for (const auto& key : toErase) knownStreams_.erase(key);
    knownHosts_.erase(ToLower(hostPath));
}

void StreamWatchService::ThreadProc(ScanOptions options, unsigned int pollIntervalMs, EventCallback onEvent, WarningCallback onWarning) {
    std::atomic<bool> cancelledFlag{false};

    // Establish the initial baseline snapshot with a full scan.
    ScanResult initial = ScanCoordinator::RunSync(options, cancelledFlag, nullptr, nullptr);
    for (const auto& rec : initial.streams) {
        knownStreams_[ToLower(rec.fullStreamPath)] = KnownStream{rec.streamSize, rec.classification};
        knownHosts_.insert(ToLower(rec.hostPath));
    }
    for (const auto& w : initial.warnings) {
        if (onWarning) onWarning(w);
    }

    std::wstring volumeRoot = GetVolumeRootPath(options.targetPath);
    VolumeBaseline usnBaseline;
    bool usingUsnTracking = false;
    if (!volumeRoot.empty()) {
        std::wstring error;
        usingUsnTracking = UsnStreamChangeTracker::CreateBaseline(volumeRoot, usnBaseline, error);
        if (!usingUsnTracking && onWarning) {
            onWarning(L"USN journal watching unavailable (" + error + L"); falling back to periodic full rescans.");
        }
    }

    if (pollIntervalMs < 250) pollIntervalMs = 250;

    while (!stopRequested_.load()) {
        for (unsigned int waited = 0; waited < pollIntervalMs && !stopRequested_.load(); waited += 100) {
            Sleep(100);
        }
        if (stopRequested_.load()) break;

        if (usingUsnTracking) {
            UsnUpdateResult update;
            std::wstring error;
            if (!UsnStreamChangeTracker::GetChangesSinceBaseline(usnBaseline, options, update, error)) {
                if (onWarning) onWarning(L"Watch update failed: " + error);
                continue;
            }

            if (update.fullRescanRequired) {
                if (onWarning) onWarning(L"USN journal changed (" + update.reason + L"); performing a full rescan to resynchronize watch mode.");
                ScanResult rescan = ScanCoordinator::RunSync(options, cancelledFlag, nullptr, nullptr);

                std::map<std::wstring, KnownStream> newSnapshot;
                std::set<std::wstring> newHosts;
                for (const auto& rec : rescan.streams) {
                    newSnapshot[ToLower(rec.fullStreamPath)] = KnownStream{rec.streamSize, rec.classification};
                    newHosts.insert(ToLower(rec.hostPath));
                }
                knownStreams_.swap(newSnapshot);
                knownHosts_.swap(newHosts);

                std::wstring freshError;
                if (UsnStreamChangeTracker::CreateBaseline(volumeRoot, usnBaseline, freshError)) {
                    // Baseline refreshed.
                } else {
                    usingUsnTracking = false;
                }
                continue;
            }

            std::wstring targetLower = ToLower(options.targetPath);
            while (!targetLower.empty() && targetLower.back() == L'\\') targetLower.pop_back();

            for (const auto& path : update.candidatePaths) {
                if (stopRequested_.load()) break;
                std::wstring pathLower = ToLower(path);
                bool inScope = pathLower == targetLower ||
                                (pathLower.size() > targetLower.size() &&
                                 pathLower.compare(0, targetLower.size(), targetLower) == 0 &&
                                 pathLower[targetLower.size()] == L'\\');
                if (!inScope) continue;

                if (!PathExistsOnDisk(path)) {
                    RemoveHost(path, onEvent);
                    continue;
                }

                std::vector<std::wstring> warnings;
                auto records = StreamEnumerator::EnumerateStreams(path, options, L"NTFS USN-Assisted (Watch)", warnings, nullptr);
                for (auto& w : warnings) {
                    if (onWarning) onWarning(w);
                }
                DiffHost(path, records, onEvent, true);
            }

            if (update.possibleDeletionsOccurred) {
                std::vector<std::wstring> hostsSnapshot(knownHosts_.begin(), knownHosts_.end());
                for (const auto& host : hostsSnapshot) {
                    if (stopRequested_.load()) break;
                    if (!PathExistsOnDisk(host)) {
                        RemoveHost(host, onEvent);
                    }
                }
            }

            usnBaseline.lastProcessedUsn = update.newLastProcessedUsn;
        } else {
            // Fallback: periodic full rescan and diff.
            ScanResult rescan = ScanCoordinator::RunSync(options, cancelledFlag, nullptr, nullptr);

            std::map<std::wstring, std::vector<StreamRecord>> byHost;
            std::set<std::wstring> hostsSeen;
            for (const auto& rec : rescan.streams) {
                byHost[ToLower(rec.hostPath)].push_back(rec);
                hostsSeen.insert(ToLower(rec.hostPath));
            }
            for (const auto& entry : byHost) {
                DiffHost(entry.second.front().hostPath, entry.second, onEvent, true);
            }
            std::vector<std::wstring> previousHosts(knownHosts_.begin(), knownHosts_.end());
            for (const auto& host : previousHosts) {
                if (hostsSeen.count(host) == 0) {
                    RemoveHost(host, onEvent);
                }
            }
        }
    }

    running_.store(false);
}

}  // namespace ss
