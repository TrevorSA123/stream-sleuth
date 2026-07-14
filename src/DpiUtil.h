// Per-monitor DPI helpers used to scale manually-laid-out Win32 controls and
// fonts. Raw child windows are not auto-scaled by the DPI_AWARENESS_CONTEXT
// manifest setting the way real dialog templates are, so layout code must
// scale pixel metrics itself using these helpers.
#pragma once

#include <windows.h>

namespace ss {

constexpr UINT kDefaultDpi = 96;

// Returns the DPI of the monitor a window is currently on. Falls back to 96
// on systems where GetDpiForWindow is unavailable.
UINT GetHwndDpi(HWND hwnd);

// Scales a pixel value authored at 96 DPI to the given DPI.
int ScaleForDpi(int value, UINT dpi);

// Creates a UI font (Segoe UI, or Consolas for monospace) sized for the given
// DPI. Caller owns the returned font and should DeleteObject it.
HFONT CreateUiFont(UINT dpi, bool monospace = false, int pointSizeAt96 = 9);

}  // namespace ss
