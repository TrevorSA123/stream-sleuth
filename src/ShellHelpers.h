// Shell integration: opening a file's location in Explorer and relaunching
// the current executable elevated via the "runas" verb.
#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace ss {

class ShellHelpers {
public:
    static bool IsProcessElevated();

    // Opens Explorer with the given file selected.
    static bool OpenFileLocation(const std::wstring& path);

    // Relaunches the current executable elevated (UAC prompt), passing the
    // given arguments. Returns true if the relaunch was initiated (a new
    // process was started); does not wait for it to exit.
    static bool RelaunchElevated(HWND ownerWindow, const std::wstring& arguments);
};

}  // namespace ss
