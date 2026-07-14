// Helpers for converting and formatting Win32 FILETIME values.
#pragma once

#include <windows.h>
#include <string>

namespace ss {

std::wstring FormatFileTime(const FILETIME& ft, bool known = true);
std::wstring FormatFileTimeForFilename(const FILETIME& ft);

bool FileTimeToUnsigned64(const FILETIME& ft, unsigned long long& out);

FILETIME NowAsFileTime();

}  // namespace ss
