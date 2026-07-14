// Safe, read-only preview of a single stream's contents. Never executes or
// loads stream content as code; only reads a bounded prefix for display.
#pragma once

#include <string>
#include <cstdint>

namespace ss {

enum class PreviewContentKind {
    Empty,
    Text,
    Hex
};

struct PreviewResult {
    bool success = false;
    std::wstring error;
    PreviewContentKind kind = PreviewContentKind::Empty;
    std::wstring textContent;
    std::wstring hexDump;
    std::wstring detectedSignature;
    uint64_t totalStreamSize = 0;
    size_t bytesPreviewed = 0;
    bool truncated = false;
};

class StreamPreviewer {
public:
    static constexpr size_t kDefaultPreviewLimit = 64 * 1024;

    static PreviewResult Preview(
        const std::wstring& hostPath,
        const std::wstring& streamName,
        const std::wstring& streamType,
        size_t maxBytes = kDefaultPreviewLimit);
};

}  // namespace ss
