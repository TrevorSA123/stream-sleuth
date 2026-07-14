// Entry point. StreamSleuth is built as a Windows-subsystem (GUI) executable
// but still behaves as a command-line tool: when launched from an existing
// console, we attach to it so --no-gui output is visible there.
#include <windows.h>
#include <shellapi.h>
#include <cstdio>
#include <vector>
#include <string>

#include "App.h"

namespace {

void AttachToParentConsoleIfPresent() {
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        freopen_s(&f, "CONIN$", "r", stdin);
    }
}

}  // namespace

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPWSTR /*lpCmdLine*/, int nCmdShow) {
    AttachToParentConsoleIfPresent();

    int argc = 0;
    LPWSTR* argvRaw = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::wstring> args;
    if (argvRaw != nullptr) {
        for (int i = 1; i < argc; ++i) {
            args.emplace_back(argvRaw[i]);
        }
        LocalFree(argvRaw);
    }

    return ss::App::Run(hInstance, nCmdShow, args);
}
