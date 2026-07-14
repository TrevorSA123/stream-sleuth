#include "ScanOptionsDialog.h"
#include "FormatUtil.h"
#include "StringUtil.h"
#include "DpiUtil.h"

#include <string>

namespace ss {

namespace {

constexpr wchar_t kClassName[] = L"StreamSleuthScanOptionsDialog";
constexpr int kIdOk = 3001;
constexpr int kIdCancel = 3002;
constexpr int kIdCheckboxBase = 3100;
constexpr int kIdMinSizeEdit = 3200;
constexpr int kIdMaxSizeEdit = 3201;
constexpr DWORD kStyle = WS_POPUP | WS_CAPTION | WS_SYSMENU;
constexpr DWORD kExStyle = WS_EX_DLGMODALFRAME;

struct CheckboxSpec {
    const wchar_t* label;
    bool ScanOptions::* member;
};

const CheckboxSpec kCheckboxes[] = {
    {L"Include directories", &ScanOptions::includeDirectories},
    {L"Include hidden files", &ScanOptions::includeHidden},
    {L"Include system files", &ScanOptions::includeSystem},
    {L"Skip reparse points", &ScanOptions::skipReparsePoints},
    {L"Use fast USN-assisted scan where available", &ScanOptions::useFastUsnEnumeration},
    {L"Allow recursive fallback if fast scan fails", &ScanOptions::allowRecursiveFallback},
    {L"Use incremental update since last baseline", &ScanOptions::incremental},
};
constexpr int kCheckboxCount = static_cast<int>(sizeof(kCheckboxes) / sizeof(kCheckboxes[0]));

struct Context {
    ScanOptions working;
    bool okClicked = false;
    HWND checkboxWindows[kCheckboxCount] = {};
    HWND minSizeEdit = nullptr;
    HWND maxSizeEdit = nullptr;
};

void ApplyToControls(Context* ctx) {
    for (int i = 0; i < kCheckboxCount; ++i) {
        bool value = ctx->working.*(kCheckboxes[i].member);
        SendMessageW(ctx->checkboxWindows[i], BM_SETCHECK, value ? BST_CHECKED : BST_UNCHECKED, 0);
    }
    SetWindowTextW(ctx->minSizeEdit, ctx->working.sizeFilterEnabled ? std::to_wstring(ctx->working.minStreamSize).c_str() : L"");
    SetWindowTextW(ctx->maxSizeEdit, (ctx->working.sizeFilterEnabled && ctx->working.maxStreamSize > 0) ? std::to_wstring(ctx->working.maxStreamSize).c_str() : L"");
}

void ReadFromControls(Context* ctx) {
    for (int i = 0; i < kCheckboxCount; ++i) {
        bool checked = SendMessageW(ctx->checkboxWindows[i], BM_GETCHECK, 0, 0) == BST_CHECKED;
        ctx->working.*(kCheckboxes[i].member) = checked;
    }

    wchar_t buf[64];
    GetWindowTextW(ctx->minSizeEdit, buf, ARRAYSIZE(buf));
    uint64_t minBytes = 0;
    bool hasMin = ParseSizeString(buf, minBytes) && wcslen(buf) > 0;

    GetWindowTextW(ctx->maxSizeEdit, buf, ARRAYSIZE(buf));
    uint64_t maxBytes = 0;
    bool hasMax = ParseSizeString(buf, maxBytes) && wcslen(buf) > 0;

    ctx->working.sizeFilterEnabled = hasMin || hasMax;
    ctx->working.minStreamSize = hasMin ? minBytes : 0;
    ctx->working.maxStreamSize = hasMax ? maxBytes : 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    Context* ctx = reinterpret_cast<Context*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == kIdOk) {
                ReadFromControls(ctx);
                ctx->okClicked = true;
                DestroyWindow(hwnd);
            } else if (LOWORD(wParam) == kIdCancel) {
                DestroyWindow(hwnd);
            }
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

void RegisterClassOnce(HINSTANCE hInstance) {
    static bool registered = false;
    if (registered) return;
    registered = true;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kClassName;
    RegisterClassExW(&wc);
}

}  // namespace

bool ScanOptionsDialog::Show(HWND owner, ScanOptions& options) {
    HINSTANCE hInstance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(owner, GWLP_HINSTANCE));
    RegisterClassOnce(hInstance);

    UINT dpi = GetHwndDpi(owner);
    auto S = [dpi](int v) { return ScaleForDpi(v, dpi); };

    const int clientWidth = S(420);
    const int rowHeight = S(22);
    const int margin = S(14);

    int curY = margin;
    curY += kCheckboxCount * rowHeight;
    curY += S(8);
    curY += S(28);  // min size row
    curY += S(28);  // max size row
    curY += S(12);
    int buttonY = curY;
    int clientHeight = buttonY + S(26) + margin;

    RECT rect{0, 0, clientWidth, clientHeight};
    AdjustWindowRectEx(&rect, kStyle, FALSE, kExStyle);
    int windowWidth = rect.right - rect.left;
    int windowHeight = rect.bottom - rect.top;

    RECT ownerRect{};
    GetWindowRect(owner, &ownerRect);
    int x = ownerRect.left + ((ownerRect.right - ownerRect.left) - windowWidth) / 2;
    int y = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - windowHeight) / 2;

    EnableWindow(owner, FALSE);

    Context ctx;
    ctx.working = options;

    HWND dlg = CreateWindowExW(kExStyle, kClassName, L"Scan Options", kStyle,
                                x, y, windowWidth, windowHeight, owner, nullptr, hInstance, nullptr);
    if (dlg == nullptr) {
        EnableWindow(owner, TRUE);
        return false;
    }
    SetWindowLongPtrW(dlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&ctx));
    HFONT font = CreateUiFont(dpi);

    curY = margin;
    for (int i = 0; i < kCheckboxCount; ++i) {
        ctx.checkboxWindows[i] = CreateWindowExW(0, L"BUTTON", kCheckboxes[i].label,
                                                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP,
                                                  S(14), curY, clientWidth - S(44), S(20), dlg,
                                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCheckboxBase + i)),
                                                  hInstance, nullptr);
        SendMessageW(ctx.checkboxWindows[i], WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        curY += rowHeight;
    }

    curY += S(8);
    HWND minLabel = CreateWindowExW(0, L"STATIC", L"Min stream size (e.g. 4KB):", WS_CHILD | WS_VISIBLE, S(14), curY, S(190), S(20), dlg, nullptr, hInstance, nullptr);
    SendMessageW(minLabel, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    ctx.minSizeEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                       S(210), curY - S(2), S(120), S(22), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdMinSizeEdit)), hInstance, nullptr);
    SendMessageW(ctx.minSizeEdit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    curY += S(28);

    HWND maxLabel = CreateWindowExW(0, L"STATIC", L"Max stream size (e.g. 1MB):", WS_CHILD | WS_VISIBLE, S(14), curY, S(190), S(20), dlg, nullptr, hInstance, nullptr);
    SendMessageW(maxLabel, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    ctx.maxSizeEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                       S(210), curY - S(2), S(120), S(22), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdMaxSizeEdit)), hInstance, nullptr);
    SendMessageW(ctx.maxSizeEdit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    curY += S(28);
    curY += S(12);

    HWND okButton = CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     clientWidth / 2 - S(100), buttonY, S(90), S(26), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdOk)), hInstance, nullptr);
    HWND cancelButton = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                         clientWidth / 2 + S(10), buttonY, S(90), S(26), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCancel)), hInstance, nullptr);
    SendMessageW(okButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    SendMessageW(cancelButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    ApplyToControls(&ctx);

    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    MSG msg;
    while (IsWindow(dlg) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(dlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    DeleteObject(font);
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);

    if (ctx.okClicked) {
        options = ctx.working;
        return true;
    }
    return false;
}

}  // namespace ss
