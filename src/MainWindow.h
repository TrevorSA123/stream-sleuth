// Main application window: menus, toolbar-style controls, results ListView,
// details panel, and status bar, all built manually with CreateWindowEx.
#pragma once

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>

#include "StreamTypes.h"
#include "ScanCoordinator.h"
#include "StreamWatchService.h"
#include "SettingsService.h"

namespace ss {

enum class ViewFilter {
    All,
    ZoneOnly,
    SuspiciousOnly,
    HighRiskOnly
};

enum class GroupMode {
    None,
    ByHost,
    ByClassification
};

class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    bool Create(HINSTANCE hInstance, int nCmdShow);

    // Prepares (but does not start) a scan for the given path, e.g. from the
    // command line or a drag-and-drop / Open dialog action.
    void SetInitialPath(const std::wstring& path);

    HWND GetHwnd() const { return hwnd_; }

private:
    static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void OnCreate(HWND hwnd);
    void OnSize(int width, int height);
    void OnDestroy();
    void OnCommand(WPARAM wParam, LPARAM lParam);
    void OnTimer(UINT_PTR id);
    void OnNotify(LPARAM lParam);
    void OnDropFiles(HDROP hDrop);
    void OnDpiChanged(UINT newDpi, const RECT* suggestedRect);

    void BuildMenu();
    void CreateControls(HINSTANCE hInstance);
    void CreateListViewColumns();
    void ApplyFontToAllControls();

    void BrowseForFile();
    void BrowseForFolder();
    void BrowseForDrive();

    void StartScan();
    void CancelScan();
    void RefreshScan();
    void OnScanComplete(ScanResult* result);
    void DrainPendingRecords();

    void StartWatch();
    void StopWatch();
    void OnWatchEvent(WatchEvent* ev);

    void ApplyViewFilterAndRender();
    void RenderListView();
    std::vector<int> GetFilteredIndices() const;
    bool PassesFilter(const StreamRecord& rec) const;
    void SetListViewRowText(int itemIndex, const StreamRecord& rec);
    void AppendNewRecordsToListView(size_t firstNewIndex);

    int GetSelectedRecordIndex() const;
    void ShowPreviewForSelection();
    void ShowDetailsForSelection();
    void RemoveSelectedStream();
    void RemoveZoneFromSelected();
    void BulkRemoveZone();
    void OpenSelectedHostLocation();
    void CopySelectedHostPath();
    void CopySelectedStreamName();
    void CopySelectedFullPath();
    void ShowCommandLineHelp();
    void RunAsAdministrator();
    void ShowPreferences();

    void UpdateStatusBar(const std::wstring& status, bool force = false);
    void SetControlsEnabledForScanState(bool scanning);

    static LRESULT CALLBACK SplitterWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnSplitterDrag(int clientYInParent);

    HWND hwnd_ = nullptr;
    HWND editPath_ = nullptr;
    HWND btnBrowseFile_ = nullptr;
    HWND btnBrowseFolder_ = nullptr;
    HWND btnBrowseDrive_ = nullptr;
    HWND btnStartScan_ = nullptr;
    HWND btnCancelScan_ = nullptr;
    HWND btnScanOptions_ = nullptr;
    HWND comboScanMode_ = nullptr;
    HWND comboFilter_ = nullptr;
    HWND editSearch_ = nullptr;
    HWND btnWatchToggle_ = nullptr;
    HWND listView_ = nullptr;
    HWND splitter_ = nullptr;
    HWND editDetails_ = nullptr;
    HWND statusBar_ = nullptr;

    // Height of the details panel in current pixels; 0 means "not yet
    // initialized", in which case OnSize picks a DPI-scaled default. Updated
    // live while the user drags the splitter between the list and details.
    int detailsPanelHeight_ = 0;
    bool splitterDragging_ = false;

    HMENU menuBar_ = nullptr;

    UINT dpi_ = 96;
    HFONT uiFont_ = nullptr;
    HFONT monoFont_ = nullptr;

    AppSettings settings_;
    ScanOptions lastScanOptions_;
    std::wstring scanModeLabel_;

    ScanCoordinator scanCoordinator_;
    bool scanRunning_ = false;

    std::mutex recordsMutex_;
    std::vector<StreamRecord> pendingRecords_;
    ScanProgressInfo latestProgress_;
    bool progressDirty_ = false;

    std::vector<StreamRecord> allRecords_;
    std::vector<int> displayedOrder_;  // indices into allRecords_ currently shown, in display order
    ViewFilter viewFilter_ = ViewFilter::All;
    GroupMode groupMode_ = GroupMode::None;
    bool showNormal_ = true;
    bool showHiddenSystemHosts_ = true;
    std::wstring searchText_;

    StreamWatchService watchService_;
    bool watchRunning_ = false;

    ULONGLONG scanStartTick_ = 0;
    std::wstring currentTargetPath_;
};

}  // namespace ss
