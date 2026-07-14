// Unicode clipboard helper.
#pragma once

#include <windows.h>
#include <string>

namespace ss {

class Clipboard {
public:
    // Copies UTF-16 text to the clipboard. Returns false on failure (e.g.
    // another process holds the clipboard open); does not throw.
    static bool CopyText(HWND owner, const std::wstring& text);
};

}  // namespace ss
