#include "PreferencesDialog.h"
#include "StringUtil.h"
#include "DpiUtil.h"

#include <vector>
#include <utility>
#include <string>

namespace ss {

namespace {

constexpr wchar_t kClassName[] = L"StreamSleuthPreferencesDialog";
constexpr int kIdOk = 2001;
constexpr int kIdCancel = 2002;
constexpr int kIdScanModeCombo = 2003;
constexpr int kIdPreviewLimitEdit = 2004;
constexpr int kIdPollIntervalEdit = 2005;
constexpr int kIdCheckboxBase = 2100;
constexpr DWORD kStyle = WS_POPUP | WS_CAPTION | WS_SYSMENU;
constexpr DWORD kExStyle = WS_EX_DLGMODALFRAME;

struct CheckboxSpec {
    const wchar_t* label;
    bool AppSettings::* member;
};

const CheckboxSpec kCheckboxes[] = {
    {L"Use fast USN-assisted scan where available", &AppSettings::useFastUsnScan},
    {L"Allow recursive fallback if fast scan fails", &AppSettings::allowRecursiveFallback},
    {L"Include directories in scan results", &AppSettings::includeDirectories},
    {L"Include hidden files", &AppSettings::includeHiddenFiles},
    {L"Include system files", &AppSettings::includeSystemFiles},
    {L"Skip reparse points", &AppSettings::skipReparsePoints},
    {L"Parse Zone.Identifier streams", &AppSettings::parseZoneIdentifier},
    {L"Enable safe stream preview", &AppSettings::enableStreamPreview},
    {L"Show normal streams", &AppSettings::showNormalStreams},
    {L"Show suspicious streams first", &AppSettings::showSuspiciousFirst},
    {L"Confirm before stream removal", &AppSettings::confirmBeforeRemoval},
    {L"Allow bulk Zone.Identifier removal", &AppSettings::allowBulkZoneRemoval},
    {L"Persist scan baseline for incremental update", &AppSettings::persistIncrementalBaseline},
    {L"Always on top", &AppSettings::alwaysOnTop},
};
constexpr int kCheckboxCount = static_cast<int>(sizeof(kCheckboxes) / sizeof(kCheckboxes[0]));

struct PrefsContext {
    AppSettings working;
    bool okClicked = false;
    HWND checkboxWindows[kCheckboxCount] = {};
    HWND scanModeCombo = nullptr;
    HWND previewLimitEdit = nullptr;
    HWND pollIntervalEdit = nullptr;
};

void ApplySettingsToControls(HWND hwnd, PrefsContext* ctx) {
    for (int i = 0; i < kCheckboxCount; ++i) {
        bool value = ctx->working.*(kCheckboxes[i].member);
        SendMessageW(ctx->checkboxWindows[i], BM_SETCHECK, value ? BST_CHECKED : BST_UNCHECKED, 0);
    }
    int comboIndex = ctx->working.defaultScanMode == ScanModePreference::FastUsnAssisted ? 1 :
                      ctx->working.defaultScanMode == ScanModePreference::Recursive ? 2 : 0;
    SendMessageW(ctx->scanModeCombo, CB_SETCURSEL, comboIndex, 0);

    SetWindowTextW(ctx->previewLimitEdit, std::to_wstring(ctx->working.previewByteLimit).c_str());
    SetWindowTextW(ctx->pollIntervalEdit, std::to_wstring(ctx->working.watchPollIntervalMs).c_str());
    (void)hwnd;
}

void ReadControlsIntoSettings(PrefsContext* ctx) {
    for (int i = 0; i < kCheckboxCount; ++i) {
        bool checked = SendMessageW(ctx->checkboxWindows[i], BM_GETCHECK, 0, 0) == BST_CHECKED;
        ctx->working.*(kCheckboxes[i].member) = checked;
    }
    int sel = static_cast<int>(SendMessageW(ctx->scanModeCombo, CB_GETCURSEL, 0, 0));
    ctx->working.defaultScanMode = sel == 1 ? ScanModePreference::FastUsnAssisted :
                                    sel == 2 ? ScanModePreference::Recursive : ScanModePreference::Auto;

    wchar_t buf[32];
    GetWindowTextW(ctx->previewLimitEdit, buf, ARRAYSIZE(buf));
    try { ctx->working.previewByteLimit = static_cast<uint32_t>(std::stoul(buf)); } catch (...) {}

    GetWindowTextW(ctx->pollIntervalEdit, buf, ARRAYSIZE(buf));
    try { ctx->working.watchPollIntervalMs = static_cast<uint32_t>(std::stoul(buf)); } catch (...) {}
}

LRESULT CALLBACK PrefsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    PrefsContext* ctx = reinterpret_cast<PrefsContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == kIdOk) {
                ReadControlsIntoSettings(ctx);
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

void RegisterPrefsClassOnce(HINSTANCE hInstance) {
    static bool registered = false;
    if (registered) return;
    registered = true;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = PrefsWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kClassName;
    RegisterClassExW(&wc);
}

}  // namespace

bool PreferencesDialog::Show(HWND owner, AppSettings& settings) {
    HINSTANCE hInstance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(owner, GWLP_HINSTANCE));
    RegisterPrefsClassOnce(hInstance);

    UINT dpi = GetHwndDpi(owner);
    auto S = [dpi](int v) { return ScaleForDpi(v, dpi); };

    const int clientWidth = S(460);
    const int rowHeight = S(22);
    const int margin = S(12);

    int curY = margin;
    curY += S(30);                       // scan mode combo row
    curY += kCheckboxCount * rowHeight;   // checkboxes
    curY += S(6);
    curY += S(30);                       // preview limit row
    curY += S(40);                       // poll interval row
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

    PrefsContext ctx;
    ctx.working = settings;

    HWND dlg = CreateWindowExW(kExStyle, kClassName, L"Preferences", kStyle,
                                x, y, windowWidth, windowHeight, owner, nullptr, hInstance, nullptr);
    if (dlg == nullptr) {
        EnableWindow(owner, TRUE);
        return false;
    }

    SetWindowLongPtrW(dlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&ctx));
    HFONT font = CreateUiFont(dpi);

    curY = margin;
    HWND label = CreateWindowExW(0, L"STATIC", L"Default scan mode:", WS_CHILD | WS_VISIBLE, S(12), curY, S(150), S(20), dlg, nullptr, hInstance, nullptr);
    SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    ctx.scanModeCombo = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_TABSTOP,
                                         S(170), curY - S(2), S(200), S(200), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdScanModeCombo)),
                                         hInstance, nullptr);
    SendMessageW(ctx.scanModeCombo, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    SendMessageW(ctx.scanModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Auto"));
    SendMessageW(ctx.scanModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Fast USN-Assisted"));
    SendMessageW(ctx.scanModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Recursive"));
    curY += S(30);

    for (int i = 0; i < kCheckboxCount; ++i) {
        ctx.checkboxWindows[i] = CreateWindowExW(0, L"BUTTON", kCheckboxes[i].label,
                                                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP,
                                                  S(12), curY, clientWidth - S(40), S(20), dlg,
                                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCheckboxBase + i)),
                                                  hInstance, nullptr);
        SendMessageW(ctx.checkboxWindows[i], WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        curY += rowHeight;
    }

    curY += S(6);
    HWND previewLabel = CreateWindowExW(0, L"STATIC", L"Preview byte limit:", WS_CHILD | WS_VISIBLE, S(12), curY, S(150), S(20), dlg, nullptr, hInstance, nullptr);
    SendMessageW(previewLabel, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    ctx.previewLimitEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER,
                                            S(170), curY - S(2), S(100), S(22), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdPreviewLimitEdit)),
                                            hInstance, nullptr);
    SendMessageW(ctx.previewLimitEdit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    curY += S(30);

    HWND pollLabel = CreateWindowExW(0, L"STATIC", L"Watch poll interval (ms):", WS_CHILD | WS_VISIBLE, S(12), curY, S(150), S(20), dlg, nullptr, hInstance, nullptr);
    SendMessageW(pollLabel, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    ctx.pollIntervalEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER,
                                            S(170), curY - S(2), S(100), S(22), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdPollIntervalEdit)),
                                            hInstance, nullptr);
    SendMessageW(ctx.pollIntervalEdit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    curY += S(40);

    HWND okButton = CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     clientWidth / 2 - S(100), buttonY, S(90), S(26), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdOk)), hInstance, nullptr);
    HWND cancelButton = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                         clientWidth / 2 + S(10), buttonY, S(90), S(26), dlg, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCancel)), hInstance, nullptr);
    SendMessageW(okButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    SendMessageW(cancelButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    ApplySettingsToControls(dlg, &ctx);

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
        settings = ctx.working;
        return true;
    }
    return false;
}

}  // namespace ss
