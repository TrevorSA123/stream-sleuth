#include "StreamRemovalService.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "Win32ErrorUtil.h"

namespace ss {

RemovalOutcome StreamRemovalService::RemoveStream(const std::wstring& hostPath, const std::wstring& streamName, const std::wstring& streamType) {
    RemovalOutcome outcome;
    outcome.hostPath = hostPath;
    outcome.streamName = streamName;

    if (streamName.empty()) {
        outcome.message = L"Refused: cannot remove the unnamed default data stream (this would affect file content).";
        return outcome;
    }
    if (!PathExistsOnDisk(hostPath)) {
        outcome.message = L"Host file no longer exists.";
        return outcome;
    }

    std::wstring streamPath = BuildApiStreamPath(hostPath, streamName, streamType);
    std::wstring extended = ToExtendedLengthPath(streamPath);

    if (!DeleteFileW(extended.c_str())) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            outcome.message = L"Stream was already gone.";
            outcome.success = true;
            return outcome;
        }
        outcome.message = L"Failed to remove stream: " + FormatWinError(err);
        return outcome;
    }

    outcome.success = true;
    outcome.message = L"Stream removed.";
    return outcome;
}

RemovalOutcome StreamRemovalService::RemoveZoneIdentifier(const std::wstring& hostPath) {
    return RemoveStream(hostPath, L"Zone.Identifier", L"$DATA");
}

std::vector<RemovalOutcome> StreamRemovalService::BulkRemoveZoneIdentifier(const std::vector<StreamRecord>& records) {
    std::vector<RemovalOutcome> outcomes;
    std::vector<std::wstring> processedHosts;

    for (const auto& rec : records) {
        if (!EqualsIgnoreCase(rec.streamName, L"Zone.Identifier")) continue;

        bool already = false;
        for (const auto& h : processedHosts) {
            if (EqualsIgnoreCase(h, rec.hostPath)) { already = true; break; }
        }
        if (already) continue;
        processedHosts.push_back(rec.hostPath);

        outcomes.push_back(RemoveZoneIdentifier(rec.hostPath));
    }

    return outcomes;
}

}  // namespace ss
