// Enumerates NTFS alternate data streams for a single file or directory using
// FindFirstStreamW / FindNextStreamW. Never reads full stream contents; only a
// small prefix is sampled for classification purposes.
#pragma once

#include <string>
#include <vector>
#include <atomic>
#include "StreamTypes.h"

namespace ss {

class StreamEnumerator {
public:
    // Enumerates named streams on hostPath (a single file or directory, not a
    // recursive walk). `source` tags the resulting records (e.g. "Recursive" or
    // "NTFS USN-Assisted"). Access errors and missing files are reported via
    // `warnings` rather than thrown. `cancelled`, if non-null, allows the caller
    // to abort a batch of enumerations early (checked between records).
    static std::vector<StreamRecord> EnumerateStreams(
        const std::wstring& hostPath,
        const ScanOptions& options,
        const std::wstring& source,
        std::vector<std::wstring>& warnings,
        const std::atomic<bool>* cancelled = nullptr);

    // Reads up to maxBytes from the start of a named stream. Returns false if
    // the stream could not be opened/read (result is left empty in that case).
    static bool ReadStreamPrefix(
        const std::wstring& hostPath,
        const std::wstring& streamName,
        const std::wstring& streamType,
        size_t maxBytes,
        std::vector<unsigned char>& outData);
};

}  // namespace ss
