#include "BaselineStore.h"
#include "StringUtil.h"
#include "PathUtil.h"

#include <shlobj.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "shell32.lib")

namespace ss {

namespace {

std::wstring SanitizeForFilename(const std::wstring& s) {
    std::wstring out;
    for (wchar_t c : s) {
        if (iswalnum(c)) {
            out.push_back(c);
        } else {
            out.push_back(L'_');
        }
    }
    if (out.empty()) out = L"volume";
    return out;
}

}  // namespace

std::wstring BaselineStore::GetBaselineDirectory() {
    PWSTR path = nullptr;
    std::wstring localAppData;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
        localAppData = path;
    }
    if (path != nullptr) CoTaskMemFree(path);
    if (localAppData.empty()) return std::wstring();

    std::wstring appDir = localAppData + L"\\StreamSleuth";
    std::wstring baselinesDir = appDir + L"\\Baselines";
    CreateDirectoryW(appDir.c_str(), nullptr);
    CreateDirectoryW(baselinesDir.c_str(), nullptr);
    return baselinesDir;
}

std::wstring BaselineStore::BaselineFilePath(const std::wstring& volumeRoot) {
    std::wstring dir = GetBaselineDirectory();
    if (dir.empty()) return dir;
    return dir + L"\\" + SanitizeForFilename(volumeRoot) + L".ini";
}

bool BaselineStore::Load(const std::wstring& volumeRoot, VolumeBaseline& outBaseline) {
    outBaseline = VolumeBaseline();
    std::wstring path = BaselineFilePath(volumeRoot);
    if (path.empty()) return false;

    std::wifstream file(path);
    if (!file.is_open()) return false;

    std::wstring line;
    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == L';') continue;
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = Trim(line.substr(0, eq));
        std::wstring value = Trim(line.substr(eq + 1));

        try {
            if (key == L"VolumeRoot") {
                outBaseline.volumeRoot = value;
            } else if (key == L"VolumeSerial") {
                outBaseline.volumeSerial = static_cast<DWORD>(std::stoul(value));
            } else if (key == L"UsnJournalId") {
                outBaseline.usnJournalId = std::stoull(value);
            } else if (key == L"LastProcessedUsn") {
                outBaseline.lastProcessedUsn = std::stoll(value);
            } else if (key == L"CreatedTimeLow") {
                outBaseline.createdTime.dwLowDateTime = static_cast<DWORD>(std::stoul(value));
            } else if (key == L"CreatedTimeHigh") {
                outBaseline.createdTime.dwHighDateTime = static_cast<DWORD>(std::stoul(value));
            }
        } catch (...) {
            return false;  // Corrupt baseline; caller falls back to full scan.
        }
    }

    if (outBaseline.volumeRoot.empty()) return false;

    // Sanity-check against the current volume serial number; if it changed
    // (e.g. reformat) the baseline is no longer valid.
    DWORD currentSerial = 0;
    if (GetVolumeInformationW(volumeRoot.c_str(), nullptr, 0, &currentSerial, nullptr, nullptr, nullptr, 0)) {
        if (currentSerial != outBaseline.volumeSerial) {
            return false;
        }
    }

    outBaseline.valid = true;
    return true;
}

bool BaselineStore::Save(const VolumeBaseline& baseline) {
    std::wstring path = BaselineFilePath(baseline.volumeRoot);
    if (path.empty()) return false;

    std::wofstream file(path, std::ios::trunc);
    if (!file.is_open()) return false;

    file << L"VolumeRoot=" << baseline.volumeRoot << L"\n";
    file << L"VolumeSerial=" << baseline.volumeSerial << L"\n";
    file << L"UsnJournalId=" << baseline.usnJournalId << L"\n";
    file << L"LastProcessedUsn=" << baseline.lastProcessedUsn << L"\n";
    file << L"CreatedTimeLow=" << baseline.createdTime.dwLowDateTime << L"\n";
    file << L"CreatedTimeHigh=" << baseline.createdTime.dwHighDateTime << L"\n";
    return true;
}

bool BaselineStore::Delete(const std::wstring& volumeRoot) {
    std::wstring path = BaselineFilePath(volumeRoot);
    if (path.empty()) return false;
    return DeleteFileW(path.c_str()) != 0;
}

}  // namespace ss
