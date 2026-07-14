#include "ShellHelpers.h"
#include "Handle.h"

#include <shellapi.h>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")

namespace ss {

bool ShellHelpers::IsProcessElevated() {
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) return false;
    FileHandle token(rawToken);

    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    if (!GetTokenInformation(token.Get(), TokenElevation, &elevation, sizeof(elevation), &size)) {
        return false;
    }
    return elevation.TokenIsElevated != 0;
}

bool ShellHelpers::OpenFileLocation(const std::wstring& path) {
    std::wstring arg = L"/select,\"" + path + L"\"";
    HINSTANCE result = ShellExecuteW(nullptr, L"open", L"explorer.exe", arg.c_str(), nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
}

bool ShellHelpers::RelaunchElevated(HWND ownerWindow, const std::wstring& arguments) {
    wchar_t exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_DEFAULT;
    sei.hwnd = ownerWindow;
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = arguments.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        return false;  // e.g. user declined the UAC prompt.
    }
    return true;
}

}  // namespace ss
