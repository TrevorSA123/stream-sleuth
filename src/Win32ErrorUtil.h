// Friendly formatting of Win32 error codes.
#pragma once

#include <windows.h>
#include <string>

namespace ss {

// Returns a human-readable message for a Win32 error code, without a trailing newline.
std::wstring FormatWinError(DWORD errorCode);

// Convenience: formats GetLastError() at the call site.
std::wstring FormatLastError();

}  // namespace ss
