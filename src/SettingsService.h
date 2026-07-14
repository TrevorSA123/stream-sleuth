// User preferences, persisted as a simple INI file at
// %AppData%\StreamSleuth\settings.ini.
#pragma once

#include <string>
#include <cstdint>

namespace ss {

enum class ScanModePreference {
    Auto,
    FastUsnAssisted,
    Recursive
};

struct AppSettings {
    ScanModePreference defaultScanMode = ScanModePreference::Auto;
    bool useFastUsnScan = true;
    bool allowRecursiveFallback = true;
    bool includeDirectories = true;
    bool includeHiddenFiles = true;
    bool includeSystemFiles = false;
    bool skipReparsePoints = true;
    bool parseZoneIdentifier = true;
    bool enableStreamPreview = true;
    uint32_t previewByteLimit = 65536;
    bool showNormalStreams = true;
    bool showSuspiciousFirst = true;
    bool confirmBeforeRemoval = true;
    bool allowBulkZoneRemoval = true;
    uint32_t watchPollIntervalMs = 2000;
    bool persistIncrementalBaseline = true;
    bool alwaysOnTop = false;
};

class SettingsService {
public:
    static std::wstring GetSettingsFilePath();
    static AppSettings Load();
    static bool Save(const AppSettings& settings);
};

}  // namespace ss
