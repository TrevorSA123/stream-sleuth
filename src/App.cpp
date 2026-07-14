#include "App.h"
#include "CommandLineParser.h"
#include "ConsoleMode.h"
#include "MainWindow.h"

namespace ss {

namespace {

void EnableDpiAwareness() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 != nullptr) {
        using SetCtxFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto setCtx = reinterpret_cast<SetCtxFn>(GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (setCtx != nullptr && setCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
            return;
        }
    }
    // Fall back gracefully on older systems.
    SetProcessDPIAware();
}

}  // namespace

int App::Run(HINSTANCE hInstance, int nCmdShow, const std::vector<std::wstring>& args) {
    ParsedCommand cmd = CommandLineParser::Parse(args);

    if (cmd.noGui) {
        return ConsoleMode::Run(cmd);
    }

    if (!cmd.valid) {
        MessageBoxW(nullptr, cmd.errorMessage.c_str(), L"Stream Sleuth", MB_ICONERROR);
        return 2;
    }
    if (cmd.showHelp) {
        MessageBoxW(nullptr, CommandLineParser::GetHelpText().c_str(), L"Stream Sleuth - Help", MB_ICONINFORMATION);
        return 0;
    }
    if (cmd.showVersion) {
        MessageBoxW(nullptr, CommandLineParser::GetVersionText().c_str(), L"Stream Sleuth", MB_ICONINFORMATION);
        return 0;
    }

    EnableDpiAwareness();

    MainWindow window;
    if (!cmd.initialPath.empty()) {
        window.SetInitialPath(cmd.initialPath);
    }

    if (!window.Create(hInstance, nCmdShow)) {
        MessageBoxW(nullptr, L"Failed to create the main window.", L"Stream Sleuth", MB_ICONERROR);
        return 10;
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

}  // namespace ss
