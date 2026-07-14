// Advanced scan options dialog (directories/hidden/system/reparse points,
// fast-scan behavior, and size filters), built manually with CreateWindowEx.
#pragma once

#include <windows.h>
#include "StreamTypes.h"

namespace ss {

class ScanOptionsDialog {
public:
    // Shows the dialog modally. Returns true and updates `options` if the
    // user clicked OK; returns false (options unchanged) if cancelled.
    static bool Show(HWND owner, ScanOptions& options);
};

}  // namespace ss
