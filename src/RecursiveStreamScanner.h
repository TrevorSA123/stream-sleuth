// Fallback scanner that walks a directory tree with FindFirstFileExW and calls
// StreamEnumerator on every candidate file/directory. Always available, unlike
// the USN-assisted fast path, and used when a volume is not NTFS or fast
// enumeration fails.
#pragma once

#include <functional>
#include <atomic>
#include "StreamTypes.h"

namespace ss {

class RecursiveStreamScanner {
public:
    struct Progress {
        uint64_t filesProcessed = 0;
        uint64_t foldersProcessed = 0;
        uint64_t streamsFound = 0;
        std::wstring currentPath;
    };

    using RecordCallback = std::function<void(const StreamRecord&)>;
    using ProgressCallback = std::function<void(const Progress&)>;

    // Walks options.targetPath (a single file or a directory tree) and reports
    // each discovered stream via onRecord as it is found (for partial/live
    // results), and periodic progress via onProgress. Aggregated counters,
    // warnings, and errors are written into `result`. Honors options.recursive,
    // includeDirectories, includeHidden, includeSystem, and skipReparsePoints.
    static void Scan(
        const ScanOptions& options,
        ScanResult& result,
        const std::atomic<bool>& cancelled,
        const RecordCallback& onRecord,
        const ProgressCallback& onProgress);
};

}  // namespace ss
