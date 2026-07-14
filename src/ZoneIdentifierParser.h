// Parses Zone.Identifier alternate data streams (mark-of-the-web metadata).
#pragma once

#include <string>
#include "StreamTypes.h"

namespace ss {

class ZoneIdentifierParser {
public:
    static constexpr size_t kMaxReadBytes = 64 * 1024;

    // Reads and parses the Zone.Identifier stream attached to hostPath, if present.
    // Always returns with isZoneIdentifier=true; parsed indicates whether readable
    // structured data was found.
    static ZoneIdentifierInfo ParseFromHostFile(const std::wstring& hostPath);

    // Parses raw INI-like Zone.Identifier text content.
    static ZoneIdentifierInfo ParseText(const std::wstring& text);
};

}  // namespace ss
