// Persists per-volume USN baseline metadata used for incremental scanning.
// Baselines never store stream contents, only enough metadata to validate and
// resume USN journal reading.
#pragma once

#include <windows.h>
#include <string>

namespace ss {

struct VolumeBaseline {
    std::wstring volumeRoot;    // e.g. "C:\"
    DWORD volumeSerial = 0;
    unsigned long long usnJournalId = 0;
    long long lastProcessedUsn = 0;
    FILETIME createdTime{};
    bool valid = false;
};

class BaselineStore {
public:
    static std::wstring GetBaselineDirectory();

    // Loads the baseline for a volume. Returns false (with outBaseline.valid=false)
    // if no baseline exists or it is corrupt/unreadable.
    static bool Load(const std::wstring& volumeRoot, VolumeBaseline& outBaseline);

    static bool Save(const VolumeBaseline& baseline);

    static bool Delete(const std::wstring& volumeRoot);

private:
    static std::wstring BaselineFilePath(const std::wstring& volumeRoot);
};

}  // namespace ss
