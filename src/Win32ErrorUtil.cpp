#include "Win32ErrorUtil.h"

#include <memory>

namespace ss {

std::wstring FormatWinError(DWORD errorCode) {
    LPWSTR buffer = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring message;
    if (len > 0 && buffer != nullptr) {
        message.assign(buffer, len);
        LocalFree(buffer);
        // Trim trailing CR/LF and whitespace.
        while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
            message.pop_back();
        }
    } else {
        wchar_t fallback[64];
        swprintf_s(fallback, L"Windows error 0x%08lX", errorCode);
        message = fallback;
    }

    wchar_t codeSuffix[32];
    swprintf_s(codeSuffix, L" (error %lu)", errorCode);
    message += codeSuffix;
    return message;
}

std::wstring FormatLastError() {
    return FormatWinError(GetLastError());
}

}  // namespace ss
