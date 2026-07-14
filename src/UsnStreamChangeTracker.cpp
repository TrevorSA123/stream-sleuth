#include "UsnStreamChangeTracker.h"
#include "PathUtil.h"
#include "Win32ErrorUtil.h"
#include "Handle.h"

#include <winioctl.h>
#include <unordered_set>

namespace ss {

namespace {

struct UsnRecordHeader {
    DWORD RecordLength;
    WORD MajorVersion;
    WORD MinorVersion;
};

std::wstring DeviceSpecForVolume(const std::wstring& volumeRoot) {
    std::wstring driveSpec = volumeRoot;
    while (!driveSpec.empty() && (driveSpec.back() == L'\\' || driveSpec.back() == L'/')) {
        driveSpec.pop_back();
    }
    return L"\\\\.\\" + driveSpec;
}

// Resolves a file reference number to its current full path. Only works while
// the file still exists; deleted files cannot be resolved this way.
std::wstring ResolvePathByFileReference(HANDLE volumeHandle, DWORDLONG frn) {
    FILE_ID_DESCRIPTOR fid{};
    fid.dwSize = sizeof(FILE_ID_DESCRIPTOR);
    fid.Type = FileIdType;
    fid.FileId.QuadPart = static_cast<LONGLONG>(frn);

    FileHandle fileHandle(OpenFileById(volumeHandle, &fid, FILE_READ_ATTRIBUTES,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, FILE_FLAG_BACKUP_SEMANTICS));
    if (!fileHandle.IsValid()) return std::wstring();

    wchar_t buffer[4096];
    DWORD len = GetFinalPathNameByHandleW(fileHandle.Get(), buffer, ARRAYSIZE(buffer), FILE_NAME_NORMALIZED);
    if (len == 0 || len >= ARRAYSIZE(buffer)) return std::wstring();
    return ToDisplayPath(std::wstring(buffer, len));
}

}  // namespace

bool UsnStreamChangeTracker::CreateBaseline(const std::wstring& volumeRoot, VolumeBaseline& outBaseline, std::wstring& error) {
    outBaseline = VolumeBaseline();
    std::wstring devicePath = DeviceSpecForVolume(volumeRoot);

    FileHandle volumeHandle(CreateFileW(devicePath.c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING, 0, nullptr));
    if (!volumeHandle.IsValid()) {
        error = L"Could not open volume " + devicePath + L" to establish a baseline: " + FormatLastError();
        return false;
    }

    USN_JOURNAL_DATA_V0 journalData{};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(volumeHandle.Get(), FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                          &journalData, sizeof(journalData), &bytesReturned, nullptr)) {
        error = L"USN journal is not available on " + volumeRoot + L": " + FormatLastError();
        return false;
    }

    DWORD serial = 0;
    GetVolumeInformationW(volumeRoot.c_str(), nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);

    outBaseline.volumeRoot = volumeRoot;
    outBaseline.volumeSerial = serial;
    outBaseline.usnJournalId = journalData.UsnJournalID;
    outBaseline.lastProcessedUsn = journalData.NextUsn;
    GetSystemTimeAsFileTime(&outBaseline.createdTime);
    outBaseline.valid = true;
    return true;
}

bool UsnStreamChangeTracker::GetChangesSinceBaseline(
    const VolumeBaseline& baseline,
    const ScanOptions& options,
    UsnUpdateResult& outResult,
    std::wstring& error) {
    (void)options;
    outResult = UsnUpdateResult();
    std::wstring devicePath = DeviceSpecForVolume(baseline.volumeRoot);

    FileHandle volumeHandle(CreateFileW(devicePath.c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING, 0, nullptr));
    if (!volumeHandle.IsValid()) {
        error = L"Could not open volume " + devicePath + L" to read journal changes: " + FormatLastError();
        return false;
    }

    USN_JOURNAL_DATA_V0 journalData{};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(volumeHandle.Get(), FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                          &journalData, sizeof(journalData), &bytesReturned, nullptr)) {
        outResult.fullRescanRequired = true;
        outResult.reason = L"USN journal is no longer available on " + baseline.volumeRoot + L"; a full rescan is required.";
        return true;
    }

    if (journalData.UsnJournalID != baseline.usnJournalId) {
        outResult.fullRescanRequired = true;
        outResult.reason = L"USN journal was reset or recreated since the baseline was taken; a full rescan is required.";
        return true;
    }

    if (baseline.lastProcessedUsn < journalData.FirstUsn) {
        outResult.fullRescanRequired = true;
        outResult.reason = L"USN journal has wrapped or been truncated past the last processed position; a full rescan is required.";
        return true;
    }

    if (baseline.lastProcessedUsn >= journalData.NextUsn) {
        // Nothing new since baseline.
        outResult.newLastProcessedUsn = baseline.lastProcessedUsn;
        return true;
    }

    READ_USN_JOURNAL_DATA_V0 readData{};
    readData.StartUsn = baseline.lastProcessedUsn;
    readData.ReasonMask = 0xFFFFFFFF;
    readData.ReturnOnlyOnClose = FALSE;
    readData.Timeout = 0;
    readData.BytesToWaitFor = 0;
    readData.UsnJournalID = baseline.usnJournalId;

    std::vector<unsigned char> buffer(1 << 16);
    std::unordered_set<DWORDLONG> seenFrns;
    long long lastUsn = baseline.lastProcessedUsn;

    for (;;) {
        BOOL ok = DeviceIoControl(volumeHandle.Get(), FSCTL_READ_USN_JOURNAL,
                                   &readData, sizeof(readData), buffer.data(), static_cast<DWORD>(buffer.size()),
                                   &bytesReturned, nullptr);
        if (!ok) {
            DWORD err = GetLastError();
            error = L"Reading USN journal changes failed: " + FormatWinError(err);
            outResult.fullRescanRequired = true;
            outResult.reason = L"USN journal read failed; falling back to full rescan.";
            return true;
        }
        if (bytesReturned <= sizeof(USN)) break;

        USN nextUsn = *reinterpret_cast<USN*>(buffer.data());
        BYTE* recordPtr = buffer.data() + sizeof(USN);
        BYTE* bufferEnd = buffer.data() + bytesReturned;

        if (recordPtr >= bufferEnd) {
            lastUsn = nextUsn;
            break;
        }

        while (recordPtr < bufferEnd) {
            UsnRecordHeader* header = reinterpret_cast<UsnRecordHeader*>(recordPtr);
            if (header->RecordLength == 0) break;

            if (header->MajorVersion == 2) {
                USN_RECORD_V2* rec = reinterpret_cast<USN_RECORD_V2*>(recordPtr);

                if (rec->Reason & USN_REASON_FILE_DELETE) {
                    outResult.possibleDeletionsOccurred = true;
                }

                bool relevant = (rec->Reason & (USN_REASON_FILE_CREATE | USN_REASON_DATA_EXTEND |
                                                 USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_TRUNCATION |
                                                 USN_REASON_NAMED_DATA_EXTEND | USN_REASON_NAMED_DATA_OVERWRITE |
                                                 USN_REASON_NAMED_DATA_TRUNCATION | USN_REASON_RENAME_NEW_NAME |
                                                 USN_REASON_RENAME_OLD_NAME | USN_REASON_EA_CHANGE |
                                                 USN_REASON_SECURITY_CHANGE | USN_REASON_BASIC_INFO_CHANGE |
                                                 USN_REASON_REPARSE_POINT_CHANGE)) != 0;

                if (relevant && seenFrns.insert(rec->FileReferenceNumber).second) {
                    std::wstring path = ResolvePathByFileReference(volumeHandle.Get(), rec->FileReferenceNumber);
                    if (!path.empty()) {
                        outResult.candidatePaths.push_back(path);
                    }
                }

                lastUsn = rec->Usn;
            }

            recordPtr += header->RecordLength;
        }
    }

    outResult.newLastProcessedUsn = (lastUsn > baseline.lastProcessedUsn) ? lastUsn : baseline.lastProcessedUsn;
    return true;
}

}  // namespace ss
