// Reads USN journal changes since a baseline to identify candidate
// files/folders that may need rescanning for stream changes, without walking
// the entire volume again. Used for incremental updates and watch mode.
#pragma once

#include <string>
#include <vector>
#include "BaselineStore.h"
#include "StreamTypes.h"

namespace ss {

struct UsnUpdateResult {
    bool fullRescanRequired = false;
    std::wstring reason;

    // Full paths (resolved via OpenFileById where possible) worth rescanning
    // with StreamEnumerator. May include files and directories.
    std::vector<std::wstring> candidatePaths;

    // True if the journal reported any FILE_DELETE reason. The tracker cannot
    // reliably reconstruct the full path of a deleted file from the journal
    // alone, so callers that maintain a known-paths cache (e.g. watch mode)
    // should cross-check existence of previously known paths themselves.
    bool possibleDeletionsOccurred = false;

    long long newLastProcessedUsn = 0;
};

class UsnStreamChangeTracker {
public:
    // Creates a fresh baseline for the volume containing targetPath.
    static bool CreateBaseline(const std::wstring& volumeRoot, VolumeBaseline& outBaseline, std::wstring& error);

    // Reads changes since baseline.lastProcessedUsn. On success, outResult is
    // populated and (unless fullRescanRequired) contains candidate paths to
    // rescan. Returns false only on hard failure (e.g. cannot open volume);
    // journal resets/wraps are reported via fullRescanRequired=true, not failure.
    static bool GetChangesSinceBaseline(
        const VolumeBaseline& baseline,
        const ScanOptions& options,
        UsnUpdateResult& outResult,
        std::wstring& error);
};

}  // namespace ss
