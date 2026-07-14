// Fast candidate file/folder enumeration for NTFS volumes using the USN/MFT
// enumeration APIs (FSCTL_QUERY_USN_JOURNAL, FSCTL_ENUM_USN_DATA). This is NOT
// a raw MFT parser: it uses documented Win32 file system control codes only,
// and stream contents are still discovered via FindFirstStreamW/FindNextStreamW
// on each resulting candidate path. This module only builds the candidate list
// and reconstructs paths quickly.
#pragma once

#include <functional>
#include <atomic>
#include "StreamTypes.h"

namespace ss {

class NtfsUsnFileEnumerator {
public:
    struct Progress {
        uint64_t candidatesScanned = 0;
        uint64_t streamsFound = 0;
        std::wstring currentPath;
    };

    using RecordCallback = std::function<void(const StreamRecord&)>;
    using ProgressCallback = std::function<void(const Progress&)>;

    // Returns true if the volume containing `path` is formatted NTFS.
    static bool IsNtfsVolume(const std::wstring& path);

    // Attempts a fast USN-assisted scan of options.targetPath's subtree.
    // Returns true if the scan ran to completion (or was cancelled) using the
    // fast path. Returns false if fast enumeration could not be used at all,
    // in which case `failureReason` explains why and the caller should fall
    // back to RecursiveStreamScanner (unless fast mode was explicitly required).
    static bool Scan(
        const ScanOptions& options,
        ScanResult& result,
        const std::atomic<bool>& cancelled,
        const RecordCallback& onRecord,
        const ProgressCallback& onProgress,
        std::wstring& failureReason);
};

}  // namespace ss
