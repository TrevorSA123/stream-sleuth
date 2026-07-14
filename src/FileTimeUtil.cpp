#include "FileTimeUtil.h"

namespace ss {

std::wstring FormatFileTime(const FILETIME& ft, bool known) {
    if (!known || (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)) {
        return L"(unknown)";
    }
    FILETIME localFt;
    SYSTEMTIME sysTime;
    if (!FileTimeToLocalFileTime(&ft, &localFt) || !FileTimeToSystemTime(&localFt, &sysTime)) {
        return L"(unknown)";
    }
    wchar_t buf[64];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
               sysTime.wYear, sysTime.wMonth, sysTime.wDay,
               sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
    return std::wstring(buf);
}

std::wstring FormatFileTimeForFilename(const FILETIME& ft) {
    SYSTEMTIME sysTime;
    if (!FileTimeToSystemTime(&ft, &sysTime)) {
        return L"unknown";
    }
    wchar_t buf[32];
    swprintf_s(buf, L"%04u%02u%02u_%02u%02u%02u",
               sysTime.wYear, sysTime.wMonth, sysTime.wDay,
               sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
    return std::wstring(buf);
}

bool FileTimeToUnsigned64(const FILETIME& ft, unsigned long long& out) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    out = uli.QuadPart;
    return true;
}

FILETIME NowAsFileTime() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ft;
}

}  // namespace ss
