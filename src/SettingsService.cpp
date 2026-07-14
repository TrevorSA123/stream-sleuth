#include "SettingsService.h"
#include "StringUtil.h"

#include <shlobj.h>
#include <fstream>
#include <map>

#pragma comment(lib, "shell32.lib")

namespace ss {

namespace {

std::wstring ScanModeToString(ScanModePreference mode) {
    switch (mode) {
        case ScanModePreference::FastUsnAssisted: return L"Fast";
        case ScanModePreference::Recursive: return L"Recursive";
        case ScanModePreference::Auto: default: return L"Auto";
    }
}

ScanModePreference ScanModeFromString(const std::wstring& s) {
    if (EqualsIgnoreCase(s, L"Fast")) return ScanModePreference::FastUsnAssisted;
    if (EqualsIgnoreCase(s, L"Recursive")) return ScanModePreference::Recursive;
    return ScanModePreference::Auto;
}

bool ParseBool(const std::wstring& s, bool fallback) {
    if (EqualsIgnoreCase(s, L"true") || s == L"1") return true;
    if (EqualsIgnoreCase(s, L"false") || s == L"0") return false;
    return fallback;
}

}  // namespace

std::wstring SettingsService::GetSettingsFilePath() {
    PWSTR path = nullptr;
    std::wstring appData;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path))) {
        appData = path;
    }
    if (path != nullptr) CoTaskMemFree(path);
    if (appData.empty()) return std::wstring();

    std::wstring dir = appData + L"\\StreamSleuth";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\settings.ini";
}

AppSettings SettingsService::Load() {
    AppSettings settings;  // defaults
    std::wstring path = GetSettingsFilePath();
    if (path.empty()) return settings;

    std::wifstream file(path);
    if (!file.is_open()) return settings;

    std::map<std::wstring, std::wstring> values;
    std::wstring line;
    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'[') continue;
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        values[Trim(line.substr(0, eq))] = Trim(line.substr(eq + 1));
    }

    auto get = [&](const wchar_t* key) -> const std::wstring* {
        auto it = values.find(key);
        return it != values.end() ? &it->second : nullptr;
    };

    if (auto v = get(L"DefaultScanMode")) settings.defaultScanMode = ScanModeFromString(*v);
    if (auto v = get(L"UseFastUsnScan")) settings.useFastUsnScan = ParseBool(*v, settings.useFastUsnScan);
    if (auto v = get(L"AllowRecursiveFallback")) settings.allowRecursiveFallback = ParseBool(*v, settings.allowRecursiveFallback);
    if (auto v = get(L"IncludeDirectories")) settings.includeDirectories = ParseBool(*v, settings.includeDirectories);
    if (auto v = get(L"IncludeHiddenFiles")) settings.includeHiddenFiles = ParseBool(*v, settings.includeHiddenFiles);
    if (auto v = get(L"IncludeSystemFiles")) settings.includeSystemFiles = ParseBool(*v, settings.includeSystemFiles);
    if (auto v = get(L"SkipReparsePoints")) settings.skipReparsePoints = ParseBool(*v, settings.skipReparsePoints);
    if (auto v = get(L"ParseZoneIdentifier")) settings.parseZoneIdentifier = ParseBool(*v, settings.parseZoneIdentifier);
    if (auto v = get(L"EnableStreamPreview")) settings.enableStreamPreview = ParseBool(*v, settings.enableStreamPreview);
    if (auto v = get(L"PreviewByteLimit")) {
        try { settings.previewByteLimit = static_cast<uint32_t>(std::stoul(*v)); } catch (...) {}
    }
    if (auto v = get(L"ShowNormalStreams")) settings.showNormalStreams = ParseBool(*v, settings.showNormalStreams);
    if (auto v = get(L"ShowSuspiciousFirst")) settings.showSuspiciousFirst = ParseBool(*v, settings.showSuspiciousFirst);
    if (auto v = get(L"ConfirmBeforeRemoval")) settings.confirmBeforeRemoval = ParseBool(*v, settings.confirmBeforeRemoval);
    if (auto v = get(L"AllowBulkZoneRemoval")) settings.allowBulkZoneRemoval = ParseBool(*v, settings.allowBulkZoneRemoval);
    if (auto v = get(L"WatchPollIntervalMs")) {
        try { settings.watchPollIntervalMs = static_cast<uint32_t>(std::stoul(*v)); } catch (...) {}
    }
    if (auto v = get(L"PersistIncrementalBaseline")) settings.persistIncrementalBaseline = ParseBool(*v, settings.persistIncrementalBaseline);
    if (auto v = get(L"AlwaysOnTop")) settings.alwaysOnTop = ParseBool(*v, settings.alwaysOnTop);

    return settings;
}

bool SettingsService::Save(const AppSettings& settings) {
    std::wstring path = GetSettingsFilePath();
    if (path.empty()) return false;

    std::wofstream file(path, std::ios::trunc);
    if (!file.is_open()) return false;

    file << L"; StreamSleuth settings\n";
    file << L"DefaultScanMode=" << ScanModeToString(settings.defaultScanMode) << L"\n";
    file << L"UseFastUsnScan=" << (settings.useFastUsnScan ? L"true" : L"false") << L"\n";
    file << L"AllowRecursiveFallback=" << (settings.allowRecursiveFallback ? L"true" : L"false") << L"\n";
    file << L"IncludeDirectories=" << (settings.includeDirectories ? L"true" : L"false") << L"\n";
    file << L"IncludeHiddenFiles=" << (settings.includeHiddenFiles ? L"true" : L"false") << L"\n";
    file << L"IncludeSystemFiles=" << (settings.includeSystemFiles ? L"true" : L"false") << L"\n";
    file << L"SkipReparsePoints=" << (settings.skipReparsePoints ? L"true" : L"false") << L"\n";
    file << L"ParseZoneIdentifier=" << (settings.parseZoneIdentifier ? L"true" : L"false") << L"\n";
    file << L"EnableStreamPreview=" << (settings.enableStreamPreview ? L"true" : L"false") << L"\n";
    file << L"PreviewByteLimit=" << settings.previewByteLimit << L"\n";
    file << L"ShowNormalStreams=" << (settings.showNormalStreams ? L"true" : L"false") << L"\n";
    file << L"ShowSuspiciousFirst=" << (settings.showSuspiciousFirst ? L"true" : L"false") << L"\n";
    file << L"ConfirmBeforeRemoval=" << (settings.confirmBeforeRemoval ? L"true" : L"false") << L"\n";
    file << L"AllowBulkZoneRemoval=" << (settings.allowBulkZoneRemoval ? L"true" : L"false") << L"\n";
    file << L"WatchPollIntervalMs=" << settings.watchPollIntervalMs << L"\n";
    file << L"PersistIncrementalBaseline=" << (settings.persistIncrementalBaseline ? L"true" : L"false") << L"\n";
    file << L"AlwaysOnTop=" << (settings.alwaysOnTop ? L"true" : L"false") << L"\n";

    return true;
}

}  // namespace ss
