// Removes explicitly identified alternate data streams. Never deletes host
// files and never removes the unnamed default data stream. Every attempt is
// reported back individually so callers can show per-item success/failure.
//
// WARNING (surfaced to users in the GUI/CLI): removing streams can change how
// Windows treats downloaded files (e.g. SmartScreen prompts) and may remove
// forensic evidence relevant to an investigation. Removal is always explicit
// and confirmed; StreamSleuth never removes streams automatically.
#pragma once

#include <string>
#include <vector>
#include "StreamTypes.h"

namespace ss {

struct RemovalOutcome {
    bool success = false;
    std::wstring hostPath;
    std::wstring streamName;
    std::wstring message;
};

class StreamRemovalService {
public:
    static RemovalOutcome RemoveStream(const std::wstring& hostPath, const std::wstring& streamName, const std::wstring& streamType);

    static RemovalOutcome RemoveZoneIdentifier(const std::wstring& hostPath);

    // Bulk-removes Zone.Identifier from every record that has one. This is the
    // only bulk removal operation offered; there is intentionally no bulk
    // removal for suspicious/high-risk streams.
    static std::vector<RemovalOutcome> BulkRemoveZoneIdentifier(const std::vector<StreamRecord>& records);
};

}  // namespace ss
