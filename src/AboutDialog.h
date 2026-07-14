// Simple modal About dialog, built manually with CreateWindowEx (no dialog
// resource, no visual designer).
#pragma once

#include <windows.h>

namespace ss {

class AboutDialog {
public:
    static void Show(HWND owner);
};

}  // namespace ss
