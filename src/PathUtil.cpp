#include "PathUtil.h"
#include "StringUtil.h"

#include <shlwapi.h>
#include <array>

#pragma comment(lib, "shlwapi.lib")

namespace ss {

namespace {

const std::array<const wchar_t*, 13> kExecutableExtensions = {
    L".exe", L".dll", L".scr", L".com", L".msi", L".sys", L".drv",
    L".cpl", L".ocx", L".bat", L".cmd", L".pif", L".gadget"
};

const std::array<const wchar_t*, 10> kScriptExtensions = {
    L".ps1", L".vbs", L".js", L".jse", L".wsf", L".hta", L".vbe", L".ws", L".psm1", L".msh"
};

}  // namespace

std::wstring ToExtendedLengthPath(const std::wstring& path) {
    if (path.empty()) return path;
    if (StartsWithIgnoreCase(path, L"\\\\?\\")) return path;
    if (StartsWithIgnoreCase(path, L"\\\\")) {
        // UNC path -> \\?\UNC\server\share...
        return L"\\\\?\\UNC\\" + path.substr(2);
    }
    if (path.size() >= 2 && path[1] == L':') {
        return L"\\\\?\\" + path;
    }
    return path;
}

std::wstring ToDisplayPath(const std::wstring& path) {
    if (StartsWithIgnoreCase(path, L"\\\\?\\UNC\\")) {
        return L"\\\\" + path.substr(8);
    }
    if (StartsWithIgnoreCase(path, L"\\\\?\\")) {
        return path.substr(4);
    }
    return path;
}

std::wstring GetFileNamePart(const std::wstring& hostPath) {
    size_t pos = hostPath.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return hostPath;
    return hostPath.substr(pos + 1);
}

std::wstring GetExtensionPart(const std::wstring& hostPath) {
    std::wstring name = GetFileNamePart(hostPath);
    size_t pos = name.find_last_of(L'.');
    if (pos == std::wstring::npos || pos == 0) return std::wstring();
    return name.substr(pos);
}

std::wstring GetParentDirectory(const std::wstring& hostPath) {
    std::wstring trimmed = hostPath;
    while (!trimmed.empty() && (trimmed.back() == L'\\' || trimmed.back() == L'/')) {
        trimmed.pop_back();
    }
    size_t pos = trimmed.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return std::wstring();
    return trimmed.substr(0, pos);
}

std::wstring GetVolumeRootPath(const std::wstring& path) {
    if (path.empty()) return std::wstring();
    wchar_t buffer[MAX_PATH];
    std::wstring display = ToDisplayPath(path);
    if (!GetVolumePathNameW(display.c_str(), buffer, MAX_PATH)) {
        // Fallback: manual detection for "C:\..." form.
        if (display.size() >= 2 && display[1] == L':') {
            return display.substr(0, 2) + L"\\";
        }
        return std::wstring();
    }
    return std::wstring(buffer);
}

bool PathExistsOnDisk(const std::wstring& path) {
    std::wstring extended = ToExtendedLengthPath(path);
    DWORD attrs = GetFileAttributesW(extended.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
}

bool IsDirectoryPath(const std::wstring& path) {
    std::wstring extended = ToExtendedLengthPath(path);
    DWORD attrs = GetFileAttributesW(extended.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool IsReparsePointPath(const std::wstring& path) {
    std::wstring extended = ToExtendedLengthPath(path);
    DWORD attrs = GetFileAttributesW(extended.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool ParseFindStreamName(const std::wstring& rawStreamName, std::wstring& outStreamName, std::wstring& outStreamType) {
    // Expected raw form: ":streamname:$DATA" or "::$DATA" for the unnamed stream.
    if (rawStreamName.empty() || rawStreamName.front() != L':') {
        return false;
    }
    std::wstring rest = rawStreamName.substr(1);  // drop leading colon
    size_t typeColon = rest.find_last_of(L':');
    std::wstring name;
    std::wstring type;
    if (typeColon == std::wstring::npos) {
        name = rest;
        type = L"$DATA";
    } else {
        name = rest.substr(0, typeColon);
        type = rest.substr(typeColon + 1);
    }
    if (name.empty()) {
        return false;  // unnamed default data stream, skip.
    }
    outStreamName = name;
    outStreamType = type.empty() ? L"$DATA" : type;
    return true;
}

std::wstring BuildDisplayStreamPath(const std::wstring& hostPath, const std::wstring& streamName) {
    return hostPath + L":" + streamName;
}

std::wstring BuildApiStreamPath(const std::wstring& hostPath, const std::wstring& streamName, const std::wstring& streamType) {
    std::wstring type = streamType.empty() ? L"$DATA" : streamType;
    return hostPath + L":" + streamName + L":" + type;
}

bool SplitDisplayStreamPath(const std::wstring& fullDisplayPath, std::wstring& outHostPath, std::wstring& outStreamName) {
    if (fullDisplayPath.size() < 3) return false;

    // Skip the drive letter colon (position 1, e.g. "C:") when looking for
    // the host/stream separator; UNC paths have no drive-letter colon at all.
    size_t searchStart = (fullDisplayPath.size() > 1 && fullDisplayPath[1] == L':') ? 2 : 0;
    size_t sep = fullDisplayPath.find_last_of(L':');
    if (sep == std::wstring::npos || sep < searchStart) return false;

    outHostPath = fullDisplayPath.substr(0, sep);
    outStreamName = fullDisplayPath.substr(sep + 1);
    return !outHostPath.empty() && !outStreamName.empty();
}

bool IsLikelyExecutableExtension(const std::wstring& nameOrExtension) {
    for (const wchar_t* ext : kExecutableExtensions) {
        if (EndsWithIgnoreCase(nameOrExtension, ext)) return true;
    }
    return false;
}

bool IsLikelyScriptExtension(const std::wstring& nameOrExtension) {
    for (const wchar_t* ext : kScriptExtensions) {
        if (EndsWithIgnoreCase(nameOrExtension, ext)) return true;
    }
    return false;
}

bool IsUnderSensitiveLocation(const std::wstring& hostPath) {
    static const wchar_t* kMarkers[] = {
        L"\\downloads\\", L"\\temp\\", L"\\tmp\\", L"\\appdata\\local\\temp\\",
        L"\\startup\\", L"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
        L"\\users\\public\\", L"\\programdata\\"
    };
    std::wstring lower = ToLower(hostPath);
    for (const wchar_t* marker : kMarkers) {
        if (lower.find(marker) != std::wstring::npos) return true;
    }
    return false;
}

}  // namespace ss
