// Preferences dialog, built manually with CreateWindowEx and standard
// controls (no dialog resource, no visual designer).
#pragma once

#include <windows.h>
#include "SettingsService.h"

namespace ss {

class PreferencesDialog {
public:
    // Shows the dialog modally. Returns true and updates `settings` if the
    // user clicked OK; returns false (settings unchanged) if cancelled.
    static bool Show(HWND owner, AppSettings& settings);
};

}  // namespace ss
