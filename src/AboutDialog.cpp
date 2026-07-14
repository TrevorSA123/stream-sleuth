#include "AboutDialog.h"
#include "DpiUtil.h"

namespace ss {

namespace {

constexpr wchar_t kClassName[] = L"StreamSleuthAboutDialog";
constexpr int kIdOk = 1001;
constexpr DWORD kStyle = WS_POPUP | WS_CAPTION | WS_SYSMENU;
constexpr DWORD kExStyle = WS_EX_DLGMODALFRAME;

LRESULT CALLBACK AboutWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == kIdOk) {
                DestroyWindow(hwnd);
            }
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

void RegisterAboutClassOnce(HINSTANCE hInstance) {
    static bool registered = false;
    if (registered) return;
    registered = true;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = AboutWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kClassName;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);
}

}  // namespace

void AboutDialog::Show(HWND owner) {
    HINSTANCE hInstance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(owner, GWLP_HINSTANCE));
    RegisterAboutClassOnce(hInstance);

    UINT dpi = GetHwndDpi(owner);
    auto S = [dpi](int v) { return ScaleForDpi(v, dpi); };

    const wchar_t* lines[] = {
        L"Stream Sleuth",
        L"",
        L"Created by Trevor Woollacott",
        L"",
        L"A small native Windows utility for finding and explaining",
        L"NTFS alternate data streams.",
        L"",
        L"Suspicious or high-risk results are indicators that warrant",
        L"manual review, not proof of malware.",
    };
    constexpr int kLineCount = static_cast<int>(sizeof(lines) / sizeof(lines[0]));

    const int lineHeight = S(20);
    const int topMargin = S(16);
    const int buttonGap = S(18);
    const int buttonHeight = S(26);
    const int buttonWidth = S(90);
    const int bottomMargin = S(16);

    int clientWidth = S(400);
    int textY = topMargin + kLineCount * lineHeight;
    int buttonY = textY + buttonGap;
    int clientHeight = buttonY + buttonHeight + bottomMargin;

    RECT rect{0, 0, clientWidth, clientHeight};
    AdjustWindowRectEx(&rect, kStyle, FALSE, kExStyle);
    int windowWidth = rect.right - rect.left;
    int windowHeight = rect.bottom - rect.top;

    RECT ownerRect{};
    GetWindowRect(owner, &ownerRect);
    int x = ownerRect.left + ((ownerRect.right - ownerRect.left) - windowWidth) / 2;
    int y = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - windowHeight) / 2;

    EnableWindow(owner, FALSE);

    HWND dlg = CreateWindowExW(kExStyle, kClassName, L"About Stream Sleuth", kStyle,
                                x, y, windowWidth, windowHeight,
                                owner, nullptr, hInstance, nullptr);

    if (dlg == nullptr) {
        EnableWindow(owner, TRUE);
        return;
    }

    HFONT font = CreateUiFont(dpi);

    int lineY = topMargin;
    for (const wchar_t* line : lines) {
        HWND label = CreateWindowExW(0, L"STATIC", line, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      S(16), lineY, clientWidth - S(32), lineHeight, dlg, nullptr, hInstance, nullptr);
        SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        lineY += lineHeight;
    }

    HWND okButton = CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     (clientWidth - buttonWidth) / 2, buttonY, buttonWidth, buttonHeight,
                                     dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdOk)), hInstance, nullptr);
    SendMessageW(okButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);
    SetFocus(okButton);

    MSG msg;
    while (IsWindow(dlg) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_KEYDOWN && (msg.wParam == VK_ESCAPE || msg.wParam == VK_RETURN)) {
            DestroyWindow(dlg);
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    DeleteObject(font);
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

}  // namespace ss
