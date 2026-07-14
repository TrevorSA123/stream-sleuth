#include "DpiUtil.h"

namespace ss {

namespace {

using GetDpiForWindowFn = UINT(WINAPI*)(HWND);

GetDpiForWindowFn ResolveGetDpiForWindow() {
    static GetDpiForWindowFn fn = reinterpret_cast<GetDpiForWindowFn>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow"));
    return fn;
}

}  // namespace

UINT GetHwndDpi(HWND hwnd) {
    GetDpiForWindowFn fn = ResolveGetDpiForWindow();
    if (fn != nullptr && hwnd != nullptr) {
        UINT dpi = fn(hwnd);
        if (dpi > 0) return dpi;
    }

    HDC hdc = GetDC(hwnd);
    int dpi = hdc != nullptr ? GetDeviceCaps(hdc, LOGPIXELSY) : 0;
    if (hdc != nullptr) ReleaseDC(hwnd, hdc);
    return dpi > 0 ? static_cast<UINT>(dpi) : kDefaultDpi;
}

int ScaleForDpi(int value, UINT dpi) {
    return MulDiv(value, static_cast<int>(dpi), static_cast<int>(kDefaultDpi));
}

HFONT CreateUiFont(UINT dpi, bool monospace, int pointSizeAt96) {
    int height = -MulDiv(pointSizeAt96, static_cast<int>(dpi), 72);
    return CreateFontW(height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                        monospace ? (FIXED_PITCH | FF_MODERN) : (VARIABLE_PITCH | FF_SWISS),
                        monospace ? L"Consolas" : L"Segoe UI");
}

}  // namespace ss
