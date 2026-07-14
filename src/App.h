// Top-level application entry: decides between GUI and console mode and runs
// the appropriate message/exit path.
#pragma once

#include <windows.h>
#include <vector>
#include <string>

namespace ss {

class App {
public:
    static int Run(HINSTANCE hInstance, int nCmdShow, const std::vector<std::wstring>& args);
};

}  // namespace ss
