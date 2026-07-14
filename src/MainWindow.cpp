#include "MainWindow.h"

#include "AboutDialog.h"
#include "PreferencesDialog.h"
#include "ScanOptionsDialog.h"
#include "CommandLineParser.h"
#include "StreamPreviewer.h"
#include "StreamRemovalService.h"
#include "CsvWriter.h"
#include "JsonWriter.h"
#include "TextReportWriter.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "FormatUtil.h"
#include "FileTimeUtil.h"
#include "Clipboard.h"
#include "ShellHelpers.h"
#include "DpiUtil.h"

#include <shlobj.h>
#include <commdlg.h>
#include <windowsx.h>
#include <thread>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "comctl32.lib")

namespace ss {

namespace {

constexpr wchar_t kWindowClassName[] = L"StreamSleuthMainWindow";
constexpr wchar_t kWindowTitle[] = L"Stream Sleuth";

// --- Menu command IDs -------------------------------------------------------
constexpr int ID_FILE_OPEN_FILE = 100;
constexpr int ID_FILE_OPEN_FOLDER = 101;
constexpr int ID_FILE_OPEN_DRIVE = 102;
constexpr int ID_FILE_EXPORT_CSV = 103;
constexpr int ID_FILE_EXPORT_JSON = 104;
constexpr int ID_FILE_EXPORT_TEXT = 105;
constexpr int ID_FILE_EXIT = 106;

constexpr int ID_SCAN_START = 110;
constexpr int ID_SCAN_CANCEL = 111;
constexpr int ID_SCAN_REFRESH = 112;
constexpr int ID_SCAN_FAST = 113;
constexpr int ID_SCAN_RECURSIVE = 114;
constexpr int ID_SCAN_INCREMENTAL = 115;
constexpr int ID_SCAN_WATCH_START = 116;
constexpr int ID_SCAN_WATCH_STOP = 117;

constexpr int ID_VIEW_ALL = 120;
constexpr int ID_VIEW_ZONE_ONLY = 121;
constexpr int ID_VIEW_SUSPICIOUS = 122;
constexpr int ID_VIEW_HIGH_RISK = 123;
constexpr int ID_VIEW_SHOW_NORMAL = 124;
constexpr int ID_VIEW_SHOW_HIDDEN_SYSTEM_HOSTS = 125;
constexpr int ID_VIEW_GROUP_BY_HOST = 126;
constexpr int ID_VIEW_GROUP_BY_CLASS = 127;

constexpr int ID_ACTION_PREVIEW = 130;
constexpr int ID_ACTION_OPEN_LOCATION = 131;
constexpr int ID_ACTION_COPY_HOST_PATH = 132;
constexpr int ID_ACTION_COPY_STREAM_NAME = 133;
constexpr int ID_ACTION_COPY_FULL_PATH = 134;
constexpr int ID_ACTION_REMOVE_STREAM = 135;
constexpr int ID_ACTION_REMOVE_ZONE_SELECTED = 136;
constexpr int ID_ACTION_BULK_REMOVE_ZONE = 137;
constexpr int ID_ACTION_RUN_AS_ADMIN = 138;

constexpr int ID_OPTIONS_PREFERENCES = 140;
constexpr int ID_OPTIONS_ALWAYS_ON_TOP = 141;

constexpr int ID_HELP_CLI = 150;
constexpr int ID_HELP_ABOUT = 151;

// --- Child control IDs -------------------------------------------------------
constexpr int IDC_EDIT_PATH = 200;
constexpr int IDC_BTN_BROWSE_FILE = 201;
constexpr int IDC_BTN_BROWSE_FOLDER = 202;
constexpr int IDC_BTN_BROWSE_DRIVE = 203;
constexpr int IDC_BTN_START_SCAN = 204;
constexpr int IDC_BTN_CANCEL = 205;
constexpr int IDC_BTN_SCAN_OPTIONS = 206;
constexpr int IDC_COMBO_SCAN_MODE = 207;
constexpr int IDC_COMBO_FILTER = 208;
constexpr int IDC_EDIT_SEARCH = 209;
constexpr int IDC_BTN_WATCH_TOGGLE = 210;
constexpr int IDC_LISTVIEW = 211;
constexpr int IDC_EDIT_DETAILS = 212;
constexpr int IDC_STATUSBAR = 213;
constexpr int IDC_SPLITTER = 214;
constexpr wchar_t kSplitterClassName[] = L"StreamSleuthSplitter";

constexpr UINT_PTR TIMER_ID_DRAIN = 1;
constexpr UINT TIMER_INTERVAL_MS = 200;

constexpr UINT WM_APP_SCAN_COMPLETE = WM_APP + 1;
constexpr UINT WM_APP_WATCH_EVENT = WM_APP + 2;
constexpr UINT WM_APP_WATCH_WARNING = WM_APP + 3;
constexpr UINT WM_APP_PREVIEW_READY = WM_APP + 4;

constexpr int kColumnCount = 11;
const wchar_t* kColumnNames[kColumnCount] = {
    L"Classification", L"Stream Name", L"Stream Size", L"Host Path", L"Host Type",
    L"Host Extension", L"Host Modified", L"Stream Type Guess", L"Zone Info", L"Source", L"Diagnostics"
};
const int kColumnWidths[kColumnCount] = {110, 140, 90, 260, 70, 80, 140, 160, 110, 170, 220};

std::wstring JoinDiagnosticsShort(const std::vector<std::wstring>& diagnostics) {
    std::wstring out;
    for (size_t i = 0; i < diagnostics.size(); ++i) {
        if (i > 0) out += L" | ";
        out += diagnostics[i];
    }
    return out;
}

std::wstring ZoneColumnText(const StreamRecord& rec) {
    if (!rec.zoneInfo.isZoneIdentifier) return L"-";
    if (rec.zoneInfo.parsed) return rec.zoneInfo.zoneName + L" (" + std::to_wstring(rec.zoneInfo.zoneId) + L")";
    return L"Zone.Identifier (unparsed)";
}

std::wstring DriveTypeLabel(UINT type) {
    switch (type) {
        case DRIVE_FIXED: return L"Local disk";
        case DRIVE_REMOVABLE: return L"Removable";
        case DRIVE_REMOTE: return L"Network";
        case DRIVE_CDROM: return L"CD/DVD";
        case DRIVE_RAMDISK: return L"RAM disk";
        default: return L"Unknown";
    }
}

// Small modal drive-picker: a listbox of available drives with OK/Cancel.
// Returns the selected drive root (e.g. "C:\") or an empty string if the
// user cancelled.
class DriveSelectionDialog {
public:
    static std::wstring Show(HWND owner, const std::vector<std::wstring>& drives) {
        HINSTANCE hInstance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(owner, GWLP_HINSTANCE));
        RegisterClassOnce(hInstance);

        UINT dpi = GetHwndDpi(owner);
        auto S = [dpi](int v) { return ScaleForDpi(v, dpi); };

        const int clientWidth = S(280);
        const int listHeight = S(160);
        const int margin = S(12);
        const int clientHeight = margin + S(20) + S(8) + listHeight + S(10) + S(26) + margin;

        constexpr DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
        constexpr DWORD exStyle = WS_EX_DLGMODALFRAME;

        RECT rect{0, 0, clientWidth, clientHeight};
        AdjustWindowRectEx(&rect, style, FALSE, exStyle);
        int windowWidth = rect.right - rect.left;
        int windowHeight = rect.bottom - rect.top;

        RECT ownerRect{};
        GetWindowRect(owner, &ownerRect);
        int x = ownerRect.left + ((ownerRect.right - ownerRect.left) - windowWidth) / 2;
        int y = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - windowHeight) / 2;

        EnableWindow(owner, FALSE);

        Context ctx;
        HWND dlg = CreateWindowExW(exStyle, kClassName, L"Select Drive", style,
                                    x, y, windowWidth, windowHeight, owner, nullptr, hInstance, nullptr);
        if (dlg == nullptr) {
            EnableWindow(owner, TRUE);
            return std::wstring();
        }
        SetWindowLongPtrW(dlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&ctx));
        HFONT font = CreateUiFont(dpi);

        HWND label = CreateWindowExW(0, L"STATIC", L"Choose a drive to scan:", WS_CHILD | WS_VISIBLE,
                                      margin, margin, clientWidth - 2 * margin, S(20), dlg, nullptr, hInstance, nullptr);
        SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

        ctx.listBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS,
                                       margin, margin + S(28), clientWidth - 2 * margin, listHeight, dlg,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdListBox)), hInstance, nullptr);
        SendMessageW(ctx.listBox, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

        for (const auto& d : drives) {
            std::wstring entry = d + L"  (" + DriveTypeLabel(GetDriveTypeW(d.c_str())) + L")";
            SendMessageW(ctx.listBox, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(entry.c_str()));
        }
        if (!drives.empty()) SendMessageW(ctx.listBox, LB_SETCURSEL, 0, 0);

        int buttonY = margin + S(28) + listHeight + S(10);
        HWND okButton = CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                         clientWidth / 2 - S(95), buttonY, S(90), S(26), dlg,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdOk)), hInstance, nullptr);
        HWND cancelButton = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                             clientWidth / 2 + S(5), buttonY, S(90), S(26), dlg,
                                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCancel)), hInstance, nullptr);
        SendMessageW(okButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        SendMessageW(cancelButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

        ShowWindow(dlg, SW_SHOW);
        UpdateWindow(dlg);
        SetFocus(ctx.listBox);

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

        if (ctx.okClicked && ctx.selectedIndex >= 0 && ctx.selectedIndex < static_cast<int>(drives.size())) {
            return drives[ctx.selectedIndex];
        }
        return std::wstring();
    }

private:
    static constexpr wchar_t kClassName[] = L"StreamSleuthDriveDialog";
    static constexpr int kIdListBox = 4001;
    static constexpr int kIdOk = 4002;
    static constexpr int kIdCancel = 4003;

    struct Context {
        HWND listBox = nullptr;
        int selectedIndex = -1;
        bool okClicked = false;
    };

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        Context* ctx = reinterpret_cast<Context*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg) {
            case WM_COMMAND:
                if (LOWORD(wParam) == kIdOk || (LOWORD(wParam) == kIdListBox && HIWORD(wParam) == LBN_DBLCLK)) {
                    if (ctx != nullptr) {
                        ctx->selectedIndex = static_cast<int>(SendMessageW(ctx->listBox, LB_GETCURSEL, 0, 0));
                        ctx->okClicked = ctx->selectedIndex != LB_ERR;
                    }
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

    static void RegisterClassOnce(HINSTANCE hInstance) {
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
};

}  // namespace

MainWindow::MainWindow() = default;

MainWindow::~MainWindow() {
    StopWatch();
    scanCoordinator_.Cancel();
    scanCoordinator_.Join();
}

void MainWindow::SetInitialPath(const std::wstring& path) {
    currentTargetPath_ = path;
    if (editPath_ != nullptr) {
        SetWindowTextW(editPath_, path.c_str());
    }
}

bool MainWindow::Create(HINSTANCE hInstance, int nCmdShow) {
    settings_ = SettingsService::Load();

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = StaticWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kWindowClassName;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    RegisterClassExW(&wc);

    hwnd_ = CreateWindowExW(
        WS_EX_ACCEPTFILES, kWindowClassName, kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1200, 760,
        nullptr, nullptr, hInstance, this);

    if (hwnd_ == nullptr) return false;

    // dpi_ was captured during WM_CREATE (OnCreate); rescale the initial
    // window size for the monitor it was created on.
    if (dpi_ != kDefaultDpi) {
        SetWindowPos(hwnd_, nullptr, 0, 0, ScaleForDpi(1200, dpi_), ScaleForDpi(760, dpi_), SWP_NOMOVE | SWP_NOZORDER);
    }

    if (settings_.alwaysOnTop) {
        SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    }

    ShowWindow(hwnd_, nCmdShow);
    UpdateWindow(hwnd_);

    if (!currentTargetPath_.empty()) {
        SetWindowTextW(editPath_, currentTargetPath_.c_str());
    }

    return true;
}

LRESULT CALLBACK MainWindow::StaticWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        self = reinterpret_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = hwnd;
    } else {
        self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self != nullptr) {
        return self->WndProc(hwnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            OnCreate(hwnd);
            return 0;
        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
        case WM_COMMAND:
            OnCommand(wParam, lParam);
            return 0;
        case WM_NOTIFY:
            OnNotify(lParam);
            return 0;
        case WM_TIMER:
            OnTimer(wParam);
            return 0;
        case WM_DROPFILES:
            OnDropFiles(reinterpret_cast<HDROP>(wParam));
            return 0;
        case WM_DPICHANGED:
            OnDpiChanged(HIWORD(wParam), reinterpret_cast<RECT*>(lParam));
            return 0;
        case WM_APP_SCAN_COMPLETE: {
            std::unique_ptr<ScanResult> result(reinterpret_cast<ScanResult*>(lParam));
            OnScanComplete(result.get());
            return 0;
        }
        case WM_APP_WATCH_EVENT: {
            std::unique_ptr<WatchEvent> ev(reinterpret_cast<WatchEvent*>(lParam));
            OnWatchEvent(ev.get());
            return 0;
        }
        case WM_APP_WATCH_WARNING: {
            std::unique_ptr<std::wstring> warning(reinterpret_cast<std::wstring*>(lParam));
            UpdateStatusBar(L"Watch warning: " + *warning, true);
            return 0;
        }
        case WM_APP_PREVIEW_READY: {
            std::unique_ptr<PreviewResult> preview(reinterpret_cast<PreviewResult*>(lParam));
            std::wstring text;
            if (!preview->success) {
                text = L"Preview unavailable: " + preview->error;
            } else {
                text = L"Bytes shown: " + std::to_wstring(preview->bytesPreviewed) + L" of " +
                       std::to_wstring(preview->totalStreamSize) +
                       (preview->truncated ? L" (truncated)" : L"") + L"\r\n";
                if (!preview->detectedSignature.empty()) text += L"Signature: " + preview->detectedSignature + L"\r\n";
                text += L"\r\n";
                text += preview->kind == PreviewContentKind::Text ? NormalizeToCrlf(preview->textContent) : preview->hexDump;
            }
            SetWindowTextW(editDetails_, text.c_str());
            return 0;
        }
        case WM_CLOSE:
            // Signal any in-progress scan/watch to stop before tearing the
            // window down, so the background threads unwind promptly instead
            // of posting UI messages to a window that no longer exists.
            scanCoordinator_.Cancel();
            watchService_.Stop();
            scanCoordinator_.Join();
            SettingsService::Save(settings_);
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            OnDestroy();
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

void MainWindow::OnCreate(HWND hwnd) {
    hwnd_ = hwnd;
    dpi_ = GetHwndDpi(hwnd_);
    uiFont_ = CreateUiFont(dpi_);
    monoFont_ = CreateUiFont(dpi_, true);

    BuildMenu();
    CreateControls(GetModuleHandleW(nullptr));
    CreateListViewColumns();
    ApplyFontToAllControls();
    DragAcceptFiles(hwnd_, TRUE);
    SetTimer(hwnd_, TIMER_ID_DRAIN, TIMER_INTERVAL_MS, nullptr);
    UpdateStatusBar(L"Ready. Choose a file, folder, or drive to scan.", true);
}

void MainWindow::OnDestroy() {
    KillTimer(hwnd_, TIMER_ID_DRAIN);
    if (uiFont_ != nullptr) { DeleteObject(uiFont_); uiFont_ = nullptr; }
    if (monoFont_ != nullptr) { DeleteObject(monoFont_); monoFont_ = nullptr; }
}

void MainWindow::ApplyFontToAllControls() {
    for (HWND h : {editPath_, btnBrowseFile_, btnBrowseFolder_, btnBrowseDrive_, btnStartScan_, btnCancelScan_,
                    btnScanOptions_, comboScanMode_, comboFilter_, editSearch_, btnWatchToggle_, listView_,
                    statusBar_}) {
        if (h != nullptr) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont_), TRUE);
    }
    if (editDetails_ != nullptr) {
        SendMessageW(editDetails_, WM_SETFONT, reinterpret_cast<WPARAM>(monoFont_), TRUE);
    }
}

void MainWindow::OnDpiChanged(UINT newDpi, const RECT* suggestedRect) {
    dpi_ = newDpi;

    HFONT oldUiFont = uiFont_;
    HFONT oldMonoFont = monoFont_;
    uiFont_ = CreateUiFont(dpi_);
    monoFont_ = CreateUiFont(dpi_, true);
    ApplyFontToAllControls();
    if (oldUiFont != nullptr) DeleteObject(oldUiFont);
    if (oldMonoFont != nullptr) DeleteObject(oldMonoFont);

    if (suggestedRect != nullptr) {
        SetWindowPos(hwnd_, nullptr, suggestedRect->left, suggestedRect->top,
                     suggestedRect->right - suggestedRect->left, suggestedRect->bottom - suggestedRect->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }

    RECT clientRect{};
    GetClientRect(hwnd_, &clientRect);
    OnSize(clientRect.right - clientRect.left, clientRect.bottom - clientRect.top);

    for (int i = 0; i < kColumnCount; ++i) {
        ListView_SetColumnWidth(listView_, i, ScaleForDpi(kColumnWidths[i], dpi_));
    }
}

LRESULT CALLBACK MainWindow::SplitterWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_LBUTTONDOWN:
            SetCapture(hwnd);
            if (self != nullptr) self->splitterDragging_ = true;
            return 0;
        case WM_LBUTTONUP:
            ReleaseCapture();
            if (self != nullptr) self->splitterDragging_ = false;
            return 0;
        case WM_MOUSEMOVE:
            if (self != nullptr && self->splitterDragging_) {
                POINT pt{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
                ClientToScreen(hwnd, &pt);
                ScreenToClient(self->hwnd_, &pt);
                self->OnSplitterDrag(pt.y);
            }
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

void MainWindow::OnSplitterDrag(int clientYInParent) {
    RECT clientRect{};
    GetClientRect(hwnd_, &clientRect);

    RECT statusRect{};
    int statusHeight = 0;
    if (statusBar_ != nullptr) {
        GetWindowRect(statusBar_, &statusRect);
        statusHeight = statusRect.bottom - statusRect.top;
    }

    int margin = ScaleForDpi(6, dpi_);
    int splitterThickness = ScaleForDpi(6, dpi_);
    int bottomReserved = clientRect.bottom - statusHeight - margin;

    int newHeight = bottomReserved - clientYInParent - splitterThickness / 2;
    int minDetails = ScaleForDpi(60, dpi_);
    int maxDetails = bottomReserved - ScaleForDpi(100, dpi_);  // leave room for a minimal list view
    if (maxDetails < minDetails) maxDetails = minDetails;

    if (newHeight < minDetails) newHeight = minDetails;
    if (newHeight > maxDetails) newHeight = maxDetails;

    detailsPanelHeight_ = newHeight;
    OnSize(clientRect.right - clientRect.left, clientRect.bottom - clientRect.top);
}

void MainWindow::BuildMenu() {
    menuBar_ = CreateMenu();

    HMENU fileMenu = CreatePopupMenu();
    AppendMenuW(fileMenu, MF_STRING, ID_FILE_OPEN_FILE, L"Open File...");
    AppendMenuW(fileMenu, MF_STRING, ID_FILE_OPEN_FOLDER, L"Open Folder...");
    AppendMenuW(fileMenu, MF_STRING, ID_FILE_OPEN_DRIVE, L"Open Drive...");
    AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(fileMenu, MF_STRING, ID_FILE_EXPORT_CSV, L"Export CSV...");
    AppendMenuW(fileMenu, MF_STRING, ID_FILE_EXPORT_JSON, L"Export JSON...");
    AppendMenuW(fileMenu, MF_STRING, ID_FILE_EXPORT_TEXT, L"Export Text Report...");
    AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(fileMenu, MF_STRING, ID_FILE_EXIT, L"Exit");
    AppendMenuW(menuBar_, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"File");

    HMENU scanMenu = CreatePopupMenu();
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_START, L"Start Scan");
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_CANCEL, L"Cancel Scan");
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_REFRESH, L"Refresh");
    AppendMenuW(scanMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_FAST, L"Fast USN-Assisted Scan");
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_RECURSIVE, L"Recursive Fallback Scan");
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_INCREMENTAL, L"Incremental Update");
    AppendMenuW(scanMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_WATCH_START, L"Start Watch Mode");
    AppendMenuW(scanMenu, MF_STRING, ID_SCAN_WATCH_STOP, L"Stop Watch Mode");
    AppendMenuW(menuBar_, MF_POPUP, reinterpret_cast<UINT_PTR>(scanMenu), L"Scan");

    HMENU viewMenu = CreatePopupMenu();
    AppendMenuW(viewMenu, MF_STRING, ID_VIEW_ALL, L"All Streams");
    AppendMenuW(viewMenu, MF_STRING, ID_VIEW_ZONE_ONLY, L"Zone.Identifier Only");
    AppendMenuW(viewMenu, MF_STRING, ID_VIEW_SUSPICIOUS, L"Suspicious Only");
    AppendMenuW(viewMenu, MF_STRING, ID_VIEW_HIGH_RISK, L"High Risk Only");
    AppendMenuW(viewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(viewMenu, MF_STRING | MF_CHECKED, ID_VIEW_SHOW_NORMAL, L"Show Normal Streams");
    AppendMenuW(viewMenu, MF_STRING | MF_CHECKED, ID_VIEW_SHOW_HIDDEN_SYSTEM_HOSTS, L"Show Hidden/System Hosts");
    AppendMenuW(viewMenu, MF_STRING, ID_VIEW_GROUP_BY_HOST, L"Group by Host File");
    AppendMenuW(viewMenu, MF_STRING, ID_VIEW_GROUP_BY_CLASS, L"Group by Classification");
    AppendMenuW(menuBar_, MF_POPUP, reinterpret_cast<UINT_PTR>(viewMenu), L"View");

    HMENU actionsMenu = CreatePopupMenu();
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_PREVIEW, L"Preview Stream");
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_OPEN_LOCATION, L"Open Host File Location");
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_COPY_HOST_PATH, L"Copy Host Path");
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_COPY_STREAM_NAME, L"Copy Stream Name");
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_COPY_FULL_PATH, L"Copy Full Stream Path");
    AppendMenuW(actionsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_REMOVE_STREAM, L"Remove Selected Stream...");
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_REMOVE_ZONE_SELECTED, L"Remove Zone.Identifier from Selected...");
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_BULK_REMOVE_ZONE, L"Bulk Remove Zone.Identifier...");
    AppendMenuW(actionsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(actionsMenu, MF_STRING, ID_ACTION_RUN_AS_ADMIN, L"Run as Administrator");
    AppendMenuW(menuBar_, MF_POPUP, reinterpret_cast<UINT_PTR>(actionsMenu), L"Actions");

    HMENU optionsMenu = CreatePopupMenu();
    AppendMenuW(optionsMenu, MF_STRING, ID_OPTIONS_PREFERENCES, L"Preferences...");
    AppendMenuW(optionsMenu, MF_STRING, ID_OPTIONS_ALWAYS_ON_TOP, L"Always On Top");
    AppendMenuW(menuBar_, MF_POPUP, reinterpret_cast<UINT_PTR>(optionsMenu), L"Options");

    HMENU helpMenu = CreatePopupMenu();
    AppendMenuW(helpMenu, MF_STRING, ID_HELP_CLI, L"Command Line Help");
    AppendMenuW(helpMenu, MF_STRING, ID_HELP_ABOUT, L"About");
    AppendMenuW(menuBar_, MF_POPUP, reinterpret_cast<UINT_PTR>(helpMenu), L"Help");

    SetMenu(hwnd_, menuBar_);
}

void MainWindow::CreateControls(HINSTANCE hInstance) {
    editPath_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_EDIT_PATH)), hInstance, nullptr);
    btnBrowseFile_ = CreateWindowExW(0, L"BUTTON", L"File...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                      0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_BROWSE_FILE)), hInstance, nullptr);
    btnBrowseFolder_ = CreateWindowExW(0, L"BUTTON", L"Folder...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                        0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_BROWSE_FOLDER)), hInstance, nullptr);
    btnBrowseDrive_ = CreateWindowExW(0, L"BUTTON", L"Drive...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                       0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_BROWSE_DRIVE)), hInstance, nullptr);
    btnStartScan_ = CreateWindowExW(0, L"BUTTON", L"Start Scan", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_START_SCAN)), hInstance, nullptr);
    btnCancelScan_ = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
                                      0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_CANCEL)), hInstance, nullptr);
    btnScanOptions_ = CreateWindowExW(0, L"BUTTON", L"Options...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                       0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_SCAN_OPTIONS)), hInstance, nullptr);

    comboScanMode_ = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_TABSTOP,
                                      0, 0, 0, 200, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_COMBO_SCAN_MODE)), hInstance, nullptr);
    SendMessageW(comboScanMode_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Auto"));
    SendMessageW(comboScanMode_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Fast USN-Assisted"));
    SendMessageW(comboScanMode_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Recursive"));
    SendMessageW(comboScanMode_, CB_SETCURSEL, 0, 0);

    comboFilter_ = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_TABSTOP,
                                    0, 0, 0, 200, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_COMBO_FILTER)), hInstance, nullptr);
    SendMessageW(comboFilter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"All Streams"));
    SendMessageW(comboFilter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Zone.Identifier Only"));
    SendMessageW(comboFilter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Suspicious Only"));
    SendMessageW(comboFilter_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"High Risk Only"));
    SendMessageW(comboFilter_, CB_SETCURSEL, 0, 0);

    editSearch_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                   0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_EDIT_SEARCH)), hInstance, nullptr);

    btnWatchToggle_ = CreateWindowExW(0, L"BUTTON", L"Start Watch Mode", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                       0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_WATCH_TOGGLE)), hInstance, nullptr);

    listView_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
                                 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LISTVIEW)), hInstance, nullptr);
    ListView_SetExtendedListViewStyle(listView_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    {
        static bool splitterClassRegistered = false;
        if (!splitterClassRegistered) {
            splitterClassRegistered = true;
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = SplitterWndProc;
            wc.hInstance = hInstance;
            wc.hCursor = LoadCursorW(nullptr, IDC_SIZENS);
            wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
            wc.lpszClassName = kSplitterClassName;
            RegisterClassExW(&wc);
        }
    }
    splitter_ = CreateWindowExW(0, kSplitterClassName, L"", WS_CHILD | WS_VISIBLE,
                                 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SPLITTER)), hInstance, nullptr);
    SetWindowLongPtrW(splitter_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

    editDetails_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Select a stream to see details, or use Actions > Preview Stream.",
                                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                    0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_EDIT_DETAILS)), hInstance, nullptr);

    statusBar_ = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                  0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUSBAR)), hInstance, nullptr);
}

void MainWindow::CreateListViewColumns() {
    for (int i = 0; i < kColumnCount; ++i) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = const_cast<LPWSTR>(kColumnNames[i]);
        col.cx = ScaleForDpi(kColumnWidths[i], dpi_);
        col.iSubItem = i;
        ListView_InsertColumn(listView_, i, &col);
    }
}

void MainWindow::OnSize(int width, int height) {
    if (hwnd_ == nullptr) return;

    RECT statusRect{};
    if (statusBar_ != nullptr) {
        SendMessageW(statusBar_, WM_SIZE, 0, 0);
        GetWindowRect(statusBar_, &statusRect);
    }
    int statusHeight = statusRect.bottom - statusRect.top;
    if (statusHeight <= 0) statusHeight = ScaleForDpi(22, dpi_);

    auto S = [this](int v) { return ScaleForDpi(v, dpi_); };

    const int margin = S(6);
    const int rowHeight = S(26);
    const int browseButtonWidth = S(70);
    int y = margin;

    int pathWidth = width - 3 * browseButtonWidth - 5 * margin - S(100);
    if (pathWidth < S(150)) pathWidth = S(150);

    int x = margin;
    MoveWindow(editPath_, x, y, pathWidth, rowHeight - S(4), TRUE);
    x += pathWidth + margin;
    MoveWindow(btnBrowseFile_, x, y - S(2), browseButtonWidth, rowHeight, TRUE); x += browseButtonWidth + margin;
    MoveWindow(btnBrowseFolder_, x, y - S(2), browseButtonWidth, rowHeight, TRUE); x += browseButtonWidth + margin;
    MoveWindow(btnBrowseDrive_, x, y - S(2), browseButtonWidth, rowHeight, TRUE);

    y += rowHeight + margin;
    x = margin;
    MoveWindow(btnStartScan_, x, y, S(100), rowHeight, TRUE); x += S(100) + margin;
    MoveWindow(btnCancelScan_, x, y, S(90), rowHeight, TRUE); x += S(90) + margin;
    MoveWindow(btnScanOptions_, x, y, S(90), rowHeight, TRUE); x += S(90) + margin;
    MoveWindow(comboScanMode_, x, y, S(160), S(200), TRUE); x += S(160) + margin;
    MoveWindow(comboFilter_, x, y, S(160), S(200), TRUE); x += S(160) + margin;

    int searchWidth = width - x - margin - S(140);
    if (searchWidth < S(100)) searchWidth = S(100);
    MoveWindow(editSearch_, x, y, searchWidth, rowHeight - S(4), TRUE);
    x += searchWidth + margin;
    MoveWindow(btnWatchToggle_, x, y - S(2), S(130), rowHeight, TRUE);

    y += rowHeight + margin;

    if (detailsPanelHeight_ <= 0) detailsPanelHeight_ = S(160);

    const int splitterThickness = S(6);
    const int minListHeight = S(100);
    int available = height - y - statusHeight - margin;

    int maxDetails = available - splitterThickness - minListHeight;
    if (maxDetails < S(60)) maxDetails = S(60);
    if (detailsPanelHeight_ > maxDetails) detailsPanelHeight_ = maxDetails;
    if (detailsPanelHeight_ < S(60)) detailsPanelHeight_ = S(60);

    int listHeight = available - splitterThickness - detailsPanelHeight_;
    if (listHeight < minListHeight) listHeight = minListHeight;

    MoveWindow(listView_, margin, y, width - 2 * margin, listHeight, TRUE);
    y += listHeight;
    MoveWindow(splitter_, margin, y, width - 2 * margin, splitterThickness, TRUE);
    y += splitterThickness;
    MoveWindow(editDetails_, margin, y, width - 2 * margin, detailsPanelHeight_, TRUE);
}

// --- Commands ----------------------------------------------------------------

void MainWindow::OnCommand(WPARAM wParam, LPARAM lParam) {
    int id = LOWORD(wParam);
    HWND ctrl = reinterpret_cast<HWND>(lParam);

    if (ctrl == comboFilter_ && HIWORD(wParam) == CBN_SELCHANGE) {
        int sel = static_cast<int>(SendMessageW(comboFilter_, CB_GETCURSEL, 0, 0));
        viewFilter_ = sel == 1 ? ViewFilter::ZoneOnly : sel == 2 ? ViewFilter::SuspiciousOnly : sel == 3 ? ViewFilter::HighRiskOnly : ViewFilter::All;
        ApplyViewFilterAndRender();
        return;
    }
    if (ctrl == editSearch_ && HIWORD(wParam) == EN_CHANGE) {
        wchar_t buf[512];
        GetWindowTextW(editSearch_, buf, ARRAYSIZE(buf));
        searchText_ = buf;
        ApplyViewFilterAndRender();
        return;
    }

    switch (id) {
        case ID_FILE_OPEN_FILE:
        case IDC_BTN_BROWSE_FILE: BrowseForFile(); break;
        case ID_FILE_OPEN_FOLDER:
        case IDC_BTN_BROWSE_FOLDER: BrowseForFolder(); break;
        case ID_FILE_OPEN_DRIVE:
        case IDC_BTN_BROWSE_DRIVE: BrowseForDrive(); break;
        case ID_FILE_EXPORT_CSV: {
            wchar_t fileBuf[MAX_PATH] = L"streamsleuth_export.csv";
            OPENFILENAMEW ofn{};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd_;
            ofn.lpstrFilter = L"CSV files\0*.csv\0All files\0*.*\0";
            ofn.lpstrFile = fileBuf;
            ofn.nMaxFile = ARRAYSIZE(fileBuf);
            ofn.Flags = OFN_OVERWRITEPROMPT;
            ofn.lpstrDefExt = L"csv";
            if (GetSaveFileNameW(&ofn)) {
                std::wstring error;
                if (!CsvWriter::WriteToFile(fileBuf, allRecords_, error)) {
                    MessageBoxW(hwnd_, error.c_str(), kWindowTitle, MB_ICONERROR);
                } else {
                    UpdateStatusBar(L"Exported CSV: " + std::wstring(fileBuf), true);
                }
            }
            break;
        }
        case ID_FILE_EXPORT_JSON: {
            wchar_t fileBuf[MAX_PATH] = L"streamsleuth_export.json";
            OPENFILENAMEW ofn{};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd_;
            ofn.lpstrFilter = L"JSON files\0*.json\0All files\0*.*\0";
            ofn.lpstrFile = fileBuf;
            ofn.nMaxFile = ARRAYSIZE(fileBuf);
            ofn.Flags = OFN_OVERWRITEPROMPT;
            ofn.lpstrDefExt = L"json";
            if (GetSaveFileNameW(&ofn)) {
                ScanResult result;
                result.streams = allRecords_;
                std::wstring error;
                if (!JsonWriter::WriteToFile(fileBuf, lastScanOptions_, result, error)) {
                    MessageBoxW(hwnd_, error.c_str(), kWindowTitle, MB_ICONERROR);
                } else {
                    UpdateStatusBar(L"Exported JSON: " + std::wstring(fileBuf), true);
                }
            }
            break;
        }
        case ID_FILE_EXPORT_TEXT: {
            wchar_t fileBuf[MAX_PATH] = L"streamsleuth_report.txt";
            OPENFILENAMEW ofn{};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd_;
            ofn.lpstrFilter = L"Text files\0*.txt\0All files\0*.*\0";
            ofn.lpstrFile = fileBuf;
            ofn.nMaxFile = ARRAYSIZE(fileBuf);
            ofn.Flags = OFN_OVERWRITEPROMPT;
            ofn.lpstrDefExt = L"txt";
            if (GetSaveFileNameW(&ofn)) {
                ScanResult result;
                result.streams = allRecords_;
                std::wstring error;
                if (!TextReportWriter::WriteToFile(fileBuf, lastScanOptions_, result, scanModeLabel_, error)) {
                    MessageBoxW(hwnd_, error.c_str(), kWindowTitle, MB_ICONERROR);
                } else {
                    UpdateStatusBar(L"Exported text report: " + std::wstring(fileBuf), true);
                }
            }
            break;
        }
        case ID_FILE_EXIT: DestroyWindow(hwnd_); break;

        case ID_SCAN_START:
        case IDC_BTN_START_SCAN: StartScan(); break;
        case ID_SCAN_CANCEL:
        case IDC_BTN_CANCEL: CancelScan(); break;
        case ID_SCAN_REFRESH: RefreshScan(); break;
        case ID_SCAN_FAST: SendMessageW(comboScanMode_, CB_SETCURSEL, 1, 0); break;
        case ID_SCAN_RECURSIVE: SendMessageW(comboScanMode_, CB_SETCURSEL, 2, 0); break;
        case ID_SCAN_INCREMENTAL: {
            lastScanOptions_.incremental = true;
            StartScan();
            lastScanOptions_.incremental = false;
            break;
        }
        case ID_SCAN_WATCH_START:
        case IDC_BTN_WATCH_TOGGLE:
            if (watchRunning_) StopWatch(); else StartWatch();
            break;
        case ID_SCAN_WATCH_STOP: StopWatch(); break;

        case ID_VIEW_ALL: viewFilter_ = ViewFilter::All; SendMessageW(comboFilter_, CB_SETCURSEL, 0, 0); ApplyViewFilterAndRender(); break;
        case ID_VIEW_ZONE_ONLY: viewFilter_ = ViewFilter::ZoneOnly; SendMessageW(comboFilter_, CB_SETCURSEL, 1, 0); ApplyViewFilterAndRender(); break;
        case ID_VIEW_SUSPICIOUS: viewFilter_ = ViewFilter::SuspiciousOnly; SendMessageW(comboFilter_, CB_SETCURSEL, 2, 0); ApplyViewFilterAndRender(); break;
        case ID_VIEW_HIGH_RISK: viewFilter_ = ViewFilter::HighRiskOnly; SendMessageW(comboFilter_, CB_SETCURSEL, 3, 0); ApplyViewFilterAndRender(); break;
        case ID_VIEW_SHOW_NORMAL: {
            showNormal_ = !showNormal_;
            CheckMenuItem(menuBar_, ID_VIEW_SHOW_NORMAL, showNormal_ ? MF_CHECKED : MF_UNCHECKED);
            ApplyViewFilterAndRender();
            break;
        }
        case ID_VIEW_SHOW_HIDDEN_SYSTEM_HOSTS: {
            showHiddenSystemHosts_ = !showHiddenSystemHosts_;
            CheckMenuItem(menuBar_, ID_VIEW_SHOW_HIDDEN_SYSTEM_HOSTS, showHiddenSystemHosts_ ? MF_CHECKED : MF_UNCHECKED);
            ApplyViewFilterAndRender();
            break;
        }
        case ID_VIEW_GROUP_BY_HOST:
            groupMode_ = (groupMode_ == GroupMode::ByHost) ? GroupMode::None : GroupMode::ByHost;
            ApplyViewFilterAndRender();
            break;
        case ID_VIEW_GROUP_BY_CLASS:
            groupMode_ = (groupMode_ == GroupMode::ByClassification) ? GroupMode::None : GroupMode::ByClassification;
            ApplyViewFilterAndRender();
            break;

        case ID_ACTION_PREVIEW: ShowPreviewForSelection(); break;
        case ID_ACTION_OPEN_LOCATION: OpenSelectedHostLocation(); break;
        case ID_ACTION_COPY_HOST_PATH: CopySelectedHostPath(); break;
        case ID_ACTION_COPY_STREAM_NAME: CopySelectedStreamName(); break;
        case ID_ACTION_COPY_FULL_PATH: CopySelectedFullPath(); break;
        case ID_ACTION_REMOVE_STREAM: RemoveSelectedStream(); break;
        case ID_ACTION_REMOVE_ZONE_SELECTED: RemoveZoneFromSelected(); break;
        case ID_ACTION_BULK_REMOVE_ZONE: BulkRemoveZone(); break;
        case ID_ACTION_RUN_AS_ADMIN: RunAsAdministrator(); break;

        case ID_OPTIONS_PREFERENCES: ShowPreferences(); break;
        case ID_OPTIONS_ALWAYS_ON_TOP: {
            settings_.alwaysOnTop = !settings_.alwaysOnTop;
            CheckMenuItem(menuBar_, ID_OPTIONS_ALWAYS_ON_TOP, settings_.alwaysOnTop ? MF_CHECKED : MF_UNCHECKED);
            SetWindowPos(hwnd_, settings_.alwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            break;
        }

        case ID_HELP_CLI: ShowCommandLineHelp(); break;
        case ID_HELP_ABOUT: AboutDialog::Show(hwnd_); break;

        case IDC_BTN_SCAN_OPTIONS: {
            if (ScanOptionsDialog::Show(hwnd_, lastScanOptions_)) {
                UpdateStatusBar(L"Scan options updated.", true);
            }
            break;
        }
        default: break;
    }
}

void MainWindow::OnTimer(UINT_PTR id) {
    if (id != TIMER_ID_DRAIN) return;
    DrainPendingRecords();
}

void MainWindow::DrainPendingRecords() {
    std::vector<StreamRecord> batch;
    ScanProgressInfo progress;
    bool progressDirty;
    {
        std::lock_guard<std::mutex> lock(recordsMutex_);
        batch.swap(pendingRecords_);
        progress = latestProgress_;
        progressDirty = progressDirty_;
        progressDirty_ = false;
    }

    if (!batch.empty()) {
        size_t firstNewIndex = allRecords_.size();
        for (auto& rec : batch) allRecords_.push_back(std::move(rec));

        if (groupMode_ == GroupMode::None) {
            // Fast path: append just the new rows instead of rebuilding the
            // whole ListView, so large in-progress scans don't repeatedly
            // redraw an ever-growing list and stall the UI thread.
            AppendNewRecordsToListView(firstNewIndex);
        } else {
            // Group membership can change as records arrive; recompute fully.
            ApplyViewFilterAndRender();
        }
    }

    if (progressDirty) {
        wchar_t buf[512];
        swprintf_s(buf, L"%s | Files: %llu Folders: %llu Streams: %llu Suspicious: %llu HighRisk: %llu | %s",
                   progress.statusText.c_str(),
                   static_cast<unsigned long long>(progress.filesProcessed),
                   static_cast<unsigned long long>(progress.foldersProcessed),
                   static_cast<unsigned long long>(progress.streamsFound),
                   static_cast<unsigned long long>(progress.suspiciousCount),
                   static_cast<unsigned long long>(progress.highRiskCount),
                   progress.currentPath.c_str());
        UpdateStatusBar(buf, true);
    }
}

void MainWindow::OnNotify(LPARAM lParam) {
    NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
    if (hdr->hwndFrom != listView_) return;

    if (hdr->code == LVN_ITEMCHANGED) {
        ShowDetailsForSelection();
    } else if (hdr->code == LVN_COLUMNCLICK) {
        NMLISTVIEW* nmlv = reinterpret_cast<NMLISTVIEW*>(lParam);
        int col = nmlv->iSubItem;
        std::stable_sort(displayedOrder_.begin(), displayedOrder_.end(), [&](int a, int b) {
            const StreamRecord& ra = allRecords_[a];
            const StreamRecord& rb = allRecords_[b];
            switch (col) {
                case 0: return static_cast<int>(ra.classification) > static_cast<int>(rb.classification);
                case 1: return ra.streamName < rb.streamName;
                case 2: return ra.streamSize < rb.streamSize;
                case 3: return ra.hostPath < rb.hostPath;
                case 6: return CompareFileTime(&ra.hostModifiedTime, &rb.hostModifiedTime) < 0;
                case 9: return ra.source < rb.source;
                default: return a < b;
            }
        });
        RenderListView();
    } else if (hdr->code == NM_DBLCLK) {
        ShowPreviewForSelection();
    }
}

void MainWindow::OnDropFiles(HDROP hDrop) {
    wchar_t buf[MAX_PATH];
    if (DragQueryFileW(hDrop, 0, buf, ARRAYSIZE(buf)) > 0) {
        SetWindowTextW(editPath_, buf);
        currentTargetPath_ = buf;
    }
    DragFinish(hDrop);
}

// --- Browsing ------------------------------------------------------------

void MainWindow::BrowseForFile() {
    wchar_t fileBuf[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"All files\0*.*\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = ARRAYSIZE(fileBuf);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(editPath_, fileBuf);
        currentTargetPath_ = fileBuf;
    }
}

void MainWindow::BrowseForFolder() {
    BROWSEINFOW bi{};
    bi.hwndOwner = hwnd_;
    bi.lpszTitle = L"Select a folder to scan";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST idl = SHBrowseForFolderW(&bi);
    if (idl != nullptr) {
        wchar_t path[MAX_PATH];
        if (SHGetPathFromIDListW(idl, path)) {
            SetWindowTextW(editPath_, path);
            currentTargetPath_ = path;
        }
        CoTaskMemFree(idl);
    }
}

void MainWindow::BrowseForDrive() {
    wchar_t drives[256];
    DWORD len = GetLogicalDriveStringsW(ARRAYSIZE(drives), drives);
    if (len == 0) return;

    std::vector<std::wstring> driveList;
    wchar_t* p = drives;
    while (*p != L'\0') {
        driveList.push_back(p);
        p += wcslen(p) + 1;
    }
    if (driveList.empty()) return;

    std::wstring selected = DriveSelectionDialog::Show(hwnd_, driveList);
    if (!selected.empty()) {
        SetWindowTextW(editPath_, selected.c_str());
        currentTargetPath_ = selected;
    }
}

// --- Scanning --------------------------------------------------------------

void MainWindow::StartScan() {
    if (scanRunning_) return;

    wchar_t buf[4096];
    GetWindowTextW(editPath_, buf, ARRAYSIZE(buf));
    std::wstring path = buf;
    if (path.empty()) {
        MessageBoxW(hwnd_, L"Choose a file, folder, or drive first.", kWindowTitle, MB_ICONWARNING);
        return;
    }
    if (!PathExistsOnDisk(path)) {
        MessageBoxW(hwnd_, L"That path does not exist.", kWindowTitle, MB_ICONERROR);
        return;
    }

    allRecords_.clear();
    displayedOrder_.clear();
    RenderListView();

    int modeSel = static_cast<int>(SendMessageW(comboScanMode_, CB_GETCURSEL, 0, 0));
    ScanOptions opts = lastScanOptions_;
    opts.targetPath = path;
    opts.useFastUsnEnumeration = (modeSel != 2);
    opts.allowRecursiveFallback = (modeSel != 1);
    scanModeLabel_ = modeSel == 1 ? L"Fast USN-Assisted" : modeSel == 2 ? L"Recursive" : L"Auto";
    lastScanOptions_ = opts;
    currentTargetPath_ = path;

    SetControlsEnabledForScanState(true);
    scanRunning_ = true;
    scanStartTick_ = GetTickCount64();
    UpdateStatusBar(L"Scanning " + path + L"...", true);

    HWND hwnd = hwnd_;
    scanCoordinator_.StartAsync(
        opts,
        [this](const StreamRecord& rec) {
            std::lock_guard<std::mutex> lock(recordsMutex_);
            pendingRecords_.push_back(rec);
        },
        [this](const ScanProgressInfo& progress) {
            std::lock_guard<std::mutex> lock(recordsMutex_);
            latestProgress_ = progress;
            progressDirty_ = true;
        },
        [hwnd](const ScanResult& result) {
            ScanResult* copy = new ScanResult(result);
            PostMessageW(hwnd, WM_APP_SCAN_COMPLETE, 0, reinterpret_cast<LPARAM>(copy));
        });
}

void MainWindow::CancelScan() {
    scanCoordinator_.Cancel();
    UpdateStatusBar(L"Cancelling...", true);
}

void MainWindow::RefreshScan() {
    StartScan();
}

void MainWindow::OnScanComplete(ScanResult* result) {
    DrainPendingRecords();
    scanRunning_ = false;
    SetControlsEnabledForScanState(false);

    std::wstring status = result->summary;
    if (result->cancelled) status = L"Scan cancelled. " + status;
    if (result->partial) status += L" (partial results)";
    if (result->elevationRecommended) status += L" - consider Run as Administrator for full access.";
    if (!result->warnings.empty()) status += L" | " + std::to_wstring(result->warnings.size()) + L" warning(s)";
    if (!result->errors.empty()) status += L" | " + std::to_wstring(result->errors.size()) + L" error(s)";
    UpdateStatusBar(status, true);

    if (!result->errors.empty()) {
        std::wstring msg = L"Scan finished with errors:\r\n";
        for (const auto& e : result->errors) msg += L"- " + e + L"\r\n";
        MessageBoxW(hwnd_, msg.c_str(), kWindowTitle, MB_ICONWARNING);
    }
}

// --- Watch mode --------------------------------------------------------------

void MainWindow::StartWatch() {
    wchar_t buf[4096];
    GetWindowTextW(editPath_, buf, ARRAYSIZE(buf));
    std::wstring path = buf;
    if (path.empty() || !PathExistsOnDisk(path)) {
        MessageBoxW(hwnd_, L"Choose a valid file, folder, or drive first.", kWindowTitle, MB_ICONWARNING);
        return;
    }

    ScanOptions opts = lastScanOptions_;
    opts.targetPath = path;
    opts.recursive = true;

    HWND hwnd = hwnd_;
    bool started = watchService_.Start(
        opts, settings_.watchPollIntervalMs,
        [hwnd](const WatchEvent& ev) {
            WatchEvent* copy = new WatchEvent(ev);
            PostMessageW(hwnd, WM_APP_WATCH_EVENT, 0, reinterpret_cast<LPARAM>(copy));
        },
        [hwnd](const std::wstring& warning) {
            std::wstring* copy = new std::wstring(warning);
            PostMessageW(hwnd, WM_APP_WATCH_WARNING, 0, reinterpret_cast<LPARAM>(copy));
        });

    if (!started) {
        MessageBoxW(hwnd_, L"Could not start watch mode.", kWindowTitle, MB_ICONERROR);
        return;
    }
    watchRunning_ = true;
    SetWindowTextW(btnWatchToggle_, L"Stop Watch Mode");
    UpdateStatusBar(L"Watching " + path + L" for stream changes...", true);
}

void MainWindow::StopWatch() {
    if (!watchRunning_) return;
    watchService_.Stop();
    watchRunning_ = false;
    if (btnWatchToggle_ != nullptr) SetWindowTextW(btnWatchToggle_, L"Start Watch Mode");
    UpdateStatusBar(L"Watch mode stopped.", true);
}

void MainWindow::OnWatchEvent(WatchEvent* ev) {
    std::wstring typeText;
    switch (ev->type) {
        case WatchEventType::StreamAdded: typeText = L"Stream added"; break;
        case WatchEventType::StreamRemoved: typeText = L"Stream removed"; break;
        case WatchEventType::StreamModified: typeText = L"Stream modified"; break;
        case WatchEventType::HostFileCreated: typeText = L"Host file created"; break;
        case WatchEventType::HostFileDeleted: typeText = L"Host file deleted"; break;
        case WatchEventType::HostFileRenamed: typeText = L"Host file renamed"; break;
        case WatchEventType::ZoneIdentifierAdded: typeText = L"Zone.Identifier added"; break;
        case WatchEventType::ZoneIdentifierRemoved: typeText = L"Zone.Identifier removed"; break;
    }
    UpdateStatusBar(L"[Watch] " + typeText + L": " + ev->hostPath + (ev->streamName.empty() ? L"" : L":" + ev->streamName), true);

    // A rescan on the next manual "Refresh" will pick up the change in the
    // grid; watch events are also useful surfaced via the status bar/details.
}

// --- Rendering ---------------------------------------------------------------

bool MainWindow::PassesFilter(const StreamRecord& rec) const {
    if (!showNormal_ && rec.classification == StreamClassification::Normal) return false;
    if (!showHiddenSystemHosts_ && (rec.hostAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) return false;

    bool isZone = EqualsIgnoreCase(rec.streamName, L"Zone.Identifier");
    switch (viewFilter_) {
        case ViewFilter::ZoneOnly: if (!isZone) return false; break;
        case ViewFilter::SuspiciousOnly:
            if (rec.classification != StreamClassification::Suspicious && rec.classification != StreamClassification::HighRisk) return false;
            break;
        case ViewFilter::HighRiskOnly: if (rec.classification != StreamClassification::HighRisk) return false; break;
        case ViewFilter::All: default: break;
    }

    if (!searchText_.empty() &&
        !ContainsIgnoreCase(rec.hostPath, searchText_) &&
        !ContainsIgnoreCase(rec.streamName, searchText_)) {
        return false;
    }

    return true;
}

std::vector<int> MainWindow::GetFilteredIndices() const {
    std::vector<int> indices;
    for (int i = 0; i < static_cast<int>(allRecords_.size()); ++i) {
        if (PassesFilter(allRecords_[i])) indices.push_back(i);
    }
    return indices;
}

void MainWindow::ApplyViewFilterAndRender() {
    displayedOrder_ = GetFilteredIndices();
    RenderListView();
}

void MainWindow::RenderListView() {
    SendMessageW(listView_, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(listView_);

    bool grouping = groupMode_ != GroupMode::None;
    ListView_EnableGroupView(listView_, grouping ? TRUE : FALSE);

    if (grouping) {
        ListView_RemoveAllGroups(listView_);
        std::vector<std::wstring> groupKeys;
        for (int idx : displayedOrder_) {
            const StreamRecord& rec = allRecords_[idx];
            std::wstring key = groupMode_ == GroupMode::ByHost ? rec.hostPath : ClassificationToString(rec.classification);
            if (std::find(groupKeys.begin(), groupKeys.end(), key) == groupKeys.end()) {
                groupKeys.push_back(key);
            }
        }
        for (size_t g = 0; g < groupKeys.size(); ++g) {
            LVGROUP group{};
            group.cbSize = sizeof(group);
            group.mask = LVGF_HEADER | LVGF_GROUPID;
            group.pszHeader = const_cast<LPWSTR>(groupKeys[g].c_str());
            group.iGroupId = static_cast<int>(g);
            ListView_InsertGroup(listView_, static_cast<int>(g), &group);
        }

        int itemIndex = 0;
        for (int idx : displayedOrder_) {
            const StreamRecord& rec = allRecords_[idx];
            std::wstring key = groupMode_ == GroupMode::ByHost ? rec.hostPath : ClassificationToString(rec.classification);
            int groupId = static_cast<int>(std::find(groupKeys.begin(), groupKeys.end(), key) - groupKeys.begin());

            LVITEMW item{};
            item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_GROUPID;
            item.iItem = itemIndex;
            item.iSubItem = 0;
            std::wstring cls = ClassificationToShortLabel(rec.classification);
            item.pszText = const_cast<LPWSTR>(cls.c_str());
            item.lParam = static_cast<LPARAM>(idx);
            item.iGroupId = groupId;
            ListView_InsertItem(listView_, &item);

            SetListViewRowText(itemIndex, rec);
            itemIndex++;
        }
    } else {
        int itemIndex = 0;
        for (int idx : displayedOrder_) {
            const StreamRecord& rec = allRecords_[idx];

            LVITEMW item{};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = itemIndex;
            item.iSubItem = 0;
            std::wstring cls = ClassificationToShortLabel(rec.classification);
            item.pszText = const_cast<LPWSTR>(cls.c_str());
            item.lParam = static_cast<LPARAM>(idx);
            ListView_InsertItem(listView_, &item);

            SetListViewRowText(itemIndex, rec);
            itemIndex++;
        }
    }

    SendMessageW(listView_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(listView_, nullptr, TRUE);
}

void MainWindow::SetListViewRowText(int itemIndex, const StreamRecord& rec) {
    ListView_SetItemText(listView_, itemIndex, 1, const_cast<LPWSTR>(rec.streamName.c_str()));
    std::wstring size = FormatByteSize(rec.streamSize);
    ListView_SetItemText(listView_, itemIndex, 2, const_cast<LPWSTR>(size.c_str()));
    ListView_SetItemText(listView_, itemIndex, 3, const_cast<LPWSTR>(rec.hostPath.c_str()));
    std::wstring hostType = rec.hostIsDirectory ? L"Directory" : L"File";
    ListView_SetItemText(listView_, itemIndex, 4, const_cast<LPWSTR>(hostType.c_str()));
    ListView_SetItemText(listView_, itemIndex, 5, const_cast<LPWSTR>(rec.hostExtension.c_str()));
    std::wstring modified = FormatFileTime(rec.hostModifiedTime, rec.hostModifiedTimeKnown);
    ListView_SetItemText(listView_, itemIndex, 6, const_cast<LPWSTR>(modified.c_str()));
    ListView_SetItemText(listView_, itemIndex, 7, const_cast<LPWSTR>(rec.streamTypeGuess.c_str()));
    std::wstring zone = ZoneColumnText(rec);
    ListView_SetItemText(listView_, itemIndex, 8, const_cast<LPWSTR>(zone.c_str()));
    ListView_SetItemText(listView_, itemIndex, 9, const_cast<LPWSTR>(rec.source.c_str()));
    std::wstring diag = JoinDiagnosticsShort(rec.diagnostics);
    ListView_SetItemText(listView_, itemIndex, 10, const_cast<LPWSTR>(diag.c_str()));
}

// Appends only the newly-arrived records (allRecords_[firstNewIndex..end)) to
// the ListView, instead of rebuilding the whole list. This keeps the UI
// responsive during large scans, where DrainPendingRecords() would otherwise
// rebuild the entire (growing) list on every timer tick. Not used when
// grouping is active, since group membership can require a full recompute.
void MainWindow::AppendNewRecordsToListView(size_t firstNewIndex) {
    SendMessageW(listView_, WM_SETREDRAW, FALSE, 0);

    for (size_t i = firstNewIndex; i < allRecords_.size(); ++i) {
        const StreamRecord& rec = allRecords_[i];
        if (!PassesFilter(rec)) continue;

        int itemIndex = ListView_GetItemCount(listView_);
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = itemIndex;
        item.iSubItem = 0;
        std::wstring cls = ClassificationToShortLabel(rec.classification);
        item.pszText = const_cast<LPWSTR>(cls.c_str());
        item.lParam = static_cast<LPARAM>(i);
        ListView_InsertItem(listView_, &item);

        SetListViewRowText(itemIndex, rec);
        displayedOrder_.push_back(static_cast<int>(i));
    }

    SendMessageW(listView_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(listView_, nullptr, TRUE);
}

// --- Selection-based actions ---------------------------------------------

int MainWindow::GetSelectedRecordIndex() const {
    int sel = ListView_GetNextItem(listView_, -1, LVNI_SELECTED);
    if (sel < 0) return -1;
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = sel;
    ListView_GetItem(listView_, &item);
    return static_cast<int>(item.lParam);
}

void MainWindow::ShowDetailsForSelection() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0 || idx >= static_cast<int>(allRecords_.size())) return;
    const StreamRecord& rec = allRecords_[idx];

    std::wstringstream ss_;
    ss_ << L"Host:           " << rec.hostPath << (rec.hostIsDirectory ? L" [directory]" : L"") << L"\r\n";
    ss_ << L"Stream:         " << rec.streamName << L" (" << rec.streamType << L")\r\n";
    ss_ << L"Size:           " << FormatByteSize(rec.streamSize) << L" (" << rec.streamSize << L" bytes)\r\n";
    ss_ << L"Classification: " << ClassificationToString(rec.classification) << L"\r\n";
    ss_ << L"Reason:         " << rec.classificationReason << L"\r\n";
    ss_ << L"Type guess:     " << rec.streamTypeGuess << L"\r\n";
    ss_ << L"Source:         " << rec.source << L"\r\n";
    if (rec.zoneInfo.isZoneIdentifier) {
        ss_ << L"Zone:           " << (rec.zoneInfo.parsed ? rec.zoneInfo.zoneName : L"(unparsed)") << L"\r\n";
        if (!rec.zoneInfo.hostUrl.empty()) ss_ << L"Host URL:       " << rec.zoneInfo.hostUrl << L"\r\n";
        if (!rec.zoneInfo.referrerUrl.empty()) ss_ << L"Referrer URL:   " << rec.zoneInfo.referrerUrl << L"\r\n";
    }
    if (!rec.diagnostics.empty()) {
        ss_ << L"Diagnostics:\r\n";
        for (const auto& d : rec.diagnostics) ss_ << L"  - " << d << L"\r\n";
    }
    ss_ << L"\r\nUse Actions > Preview Stream for content preview.";

    SetWindowTextW(editDetails_, ss_.str().c_str());
}

void MainWindow::ShowPreviewForSelection() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0 || idx >= static_cast<int>(allRecords_.size())) {
        MessageBoxW(hwnd_, L"Select a stream first.", kWindowTitle, MB_ICONINFORMATION);
        return;
    }
    if (!settings_.enableStreamPreview) {
        MessageBoxW(hwnd_, L"Stream preview is disabled in Preferences.", kWindowTitle, MB_ICONINFORMATION);
        return;
    }

    StreamRecord rec = allRecords_[idx];
    HWND hwnd = hwnd_;
    size_t limit = settings_.previewByteLimit;

    std::thread([hwnd, rec, limit]() {
        PreviewResult result = StreamPreviewer::Preview(rec.hostPath, rec.streamName, rec.streamType, limit);
        PreviewResult* copy = new PreviewResult(result);
        PostMessageW(hwnd, WM_APP_PREVIEW_READY, 0, reinterpret_cast<LPARAM>(copy));
    }).detach();

    SetWindowTextW(editDetails_, L"Loading preview...");
}

void MainWindow::RemoveSelectedStream() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0 || idx >= static_cast<int>(allRecords_.size())) {
        MessageBoxW(hwnd_, L"Select a stream first.", kWindowTitle, MB_ICONINFORMATION);
        return;
    }
    StreamRecord rec = allRecords_[idx];

    if (settings_.confirmBeforeRemoval) {
        std::wstring msg = L"Remove this stream?\r\n\r\n" + rec.fullStreamPath +
                            L"\r\n\r\nWARNING: Removing streams can change how Windows treats downloaded "
                            L"files and may remove forensic evidence. This cannot be undone.";
        if (MessageBoxW(hwnd_, msg.c_str(), L"Confirm Stream Removal", MB_ICONWARNING | MB_YESNO) != IDYES) {
            return;
        }
    }

    RemovalOutcome outcome = StreamRemovalService::RemoveStream(rec.hostPath, rec.streamName, rec.streamType);
    MessageBoxW(hwnd_, outcome.message.c_str(), outcome.success ? L"Removed" : L"Removal Failed",
                outcome.success ? MB_ICONINFORMATION : MB_ICONERROR);
    if (outcome.success) {
        allRecords_.erase(allRecords_.begin() + idx);
        ApplyViewFilterAndRender();
    }
}

void MainWindow::RemoveZoneFromSelected() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0 || idx >= static_cast<int>(allRecords_.size())) {
        MessageBoxW(hwnd_, L"Select a stream first.", kWindowTitle, MB_ICONINFORMATION);
        return;
    }
    StreamRecord rec = allRecords_[idx];

    if (settings_.confirmBeforeRemoval) {
        std::wstring msg = L"Remove Zone.Identifier from this file?\r\n\r\n" + rec.hostPath +
                            L"\r\n\r\nWARNING: This changes how Windows treats this downloaded file "
                            L"(e.g. SmartScreen prompts) and may remove forensic evidence.";
        if (MessageBoxW(hwnd_, msg.c_str(), L"Confirm Removal", MB_ICONWARNING | MB_YESNO) != IDYES) {
            return;
        }
    }

    RemovalOutcome outcome = StreamRemovalService::RemoveZoneIdentifier(rec.hostPath);
    MessageBoxW(hwnd_, outcome.message.c_str(), outcome.success ? L"Removed" : L"Removal Failed",
                outcome.success ? MB_ICONINFORMATION : MB_ICONERROR);
    if (outcome.success) {
        allRecords_.erase(std::remove_if(allRecords_.begin(), allRecords_.end(), [&](const StreamRecord& r) {
            return EqualsIgnoreCase(r.hostPath, rec.hostPath) && EqualsIgnoreCase(r.streamName, L"Zone.Identifier");
        }), allRecords_.end());
        ApplyViewFilterAndRender();
    }
}

void MainWindow::BulkRemoveZone() {
    if (!settings_.allowBulkZoneRemoval) {
        MessageBoxW(hwnd_, L"Bulk Zone.Identifier removal is disabled in Preferences.", kWindowTitle, MB_ICONINFORMATION);
        return;
    }

    size_t count = 0;
    for (const auto& rec : allRecords_) {
        if (EqualsIgnoreCase(rec.streamName, L"Zone.Identifier")) count++;
    }
    if (count == 0) {
        MessageBoxW(hwnd_, L"No Zone.Identifier streams in the current results.", kWindowTitle, MB_ICONINFORMATION);
        return;
    }

    std::wstring msg = L"Remove Zone.Identifier from " + std::to_wstring(count) + L" file(s) in the current results?\r\n\r\n"
                        L"WARNING: This changes how Windows treats these downloaded files and may remove "
                        L"forensic evidence. This cannot be undone.";
    if (MessageBoxW(hwnd_, msg.c_str(), L"Confirm Bulk Removal", MB_ICONWARNING | MB_YESNO) != IDYES) {
        return;
    }

    auto outcomes = StreamRemovalService::BulkRemoveZoneIdentifier(allRecords_);
    size_t succeeded = 0;
    for (const auto& o : outcomes) if (o.success) succeeded++;

    allRecords_.erase(std::remove_if(allRecords_.begin(), allRecords_.end(), [](const StreamRecord& r) {
        return EqualsIgnoreCase(r.streamName, L"Zone.Identifier");
    }), allRecords_.end());
    ApplyViewFilterAndRender();

    std::wstring resultMsg = L"Removed Zone.Identifier from " + std::to_wstring(succeeded) + L" of " +
                              std::to_wstring(outcomes.size()) + L" file(s).";
    MessageBoxW(hwnd_, resultMsg.c_str(), L"Bulk Removal Complete", MB_ICONINFORMATION);
}

void MainWindow::OpenSelectedHostLocation() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0) return;
    ShellHelpers::OpenFileLocation(allRecords_[idx].hostPath);
}

void MainWindow::CopySelectedHostPath() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0) return;
    Clipboard::CopyText(hwnd_, allRecords_[idx].hostPath);
}

void MainWindow::CopySelectedStreamName() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0) return;
    Clipboard::CopyText(hwnd_, allRecords_[idx].streamName);
}

void MainWindow::CopySelectedFullPath() {
    int idx = GetSelectedRecordIndex();
    if (idx < 0) return;
    Clipboard::CopyText(hwnd_, allRecords_[idx].fullStreamPath);
}

void MainWindow::ShowCommandLineHelp() {
    SetWindowTextW(editDetails_, CommandLineParser::GetHelpText().c_str());
}

void MainWindow::RunAsAdministrator() {
    if (ShellHelpers::IsProcessElevated()) {
        MessageBoxW(hwnd_, L"Stream Sleuth is already running elevated.", kWindowTitle, MB_ICONINFORMATION);
        return;
    }

    std::wstring msg = L"Whole-drive fast scans and some protected paths may require administrator "
                        L"privileges. Relaunch Stream Sleuth elevated with the current target path?";
    if (MessageBoxW(hwnd_, msg.c_str(), L"Run as Administrator", MB_ICONQUESTION | MB_YESNO) != IDYES) {
        return;
    }

    wchar_t buf[4096];
    GetWindowTextW(editPath_, buf, ARRAYSIZE(buf));
    std::wstring args;
    if (wcslen(buf) > 0) {
        args = L"\"" + std::wstring(buf) + L"\"";
    }
    if (!ShellHelpers::RelaunchElevated(hwnd_, args)) {
        MessageBoxW(hwnd_, L"Could not relaunch elevated (the request may have been declined).", kWindowTitle, MB_ICONWARNING);
    }
}

void MainWindow::ShowPreferences() {
    AppSettings before = settings_;
    if (PreferencesDialog::Show(hwnd_, settings_)) {
        SettingsService::Save(settings_);
        if (before.alwaysOnTop != settings_.alwaysOnTop) {
            SetWindowPos(hwnd_, settings_.alwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        }
        UpdateStatusBar(L"Preferences updated.", true);
    }
}

// --- Status/state helpers -----------------------------------------------

void MainWindow::UpdateStatusBar(const std::wstring& status, bool force) {
    (void)force;
    if (statusBar_ != nullptr) {
        SendMessageW(statusBar_, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(status.c_str()));
    }
}

void MainWindow::SetControlsEnabledForScanState(bool scanning) {
    EnableWindow(btnStartScan_, !scanning);
    EnableWindow(btnCancelScan_, scanning);
    EnableWindow(btnBrowseFile_, !scanning);
    EnableWindow(btnBrowseFolder_, !scanning);
    EnableWindow(btnBrowseDrive_, !scanning);
}

}  // namespace ss
