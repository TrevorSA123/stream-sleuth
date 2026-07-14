#include "NtfsUsnFileEnumerator.h"
#include "StreamEnumerator.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "Win32ErrorUtil.h"
#include "Handle.h"

#include <winioctl.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>

namespace ss {

namespace {

// 64-bit NTFS file reference numbers are the norm; we keep a 128-bit key
// shape so a best-effort V3 (128-bit file id) record can also be stored,
// without requiring a raw MFT parser.
struct FileRefKey {
    uint64_t low = 0;
    uint64_t high = 0;

    bool operator==(const FileRefKey& other) const {
        return low == other.low && high == other.high;
    }
};

struct FileRefKeyHash {
    size_t operator()(const FileRefKey& k) const {
        return std::hash<uint64_t>()(k.low) ^ (std::hash<uint64_t>()(k.high) << 1);
    }
};

struct FsNode {
    FileRefKey parent;
    std::wstring name;
    DWORD attributes = 0;
    bool isDirectory = false;
};

bool IsDotOrDotDot(const std::wstring& name) {
    return name == L"." || name == L"..";
}

// Common prefix shared by USN_RECORD_V2 and USN_RECORD_V3, used to read the
// record length/version before interpreting the rest of the structure.
struct UsnRecordHeader {
    DWORD RecordLength;
    WORD MajorVersion;
    WORD MinorVersion;
};

}  // namespace

bool NtfsUsnFileEnumerator::IsNtfsVolume(const std::wstring& path) {
    std::wstring root = GetVolumeRootPath(path);
    if (root.empty()) return false;

    wchar_t fsName[MAX_PATH + 1] = {0};
    if (!GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, fsName, MAX_PATH)) {
        return false;
    }
    return EqualsIgnoreCase(fsName, L"NTFS");
}

bool NtfsUsnFileEnumerator::Scan(
    const ScanOptions& options,
    ScanResult& result,
    const std::atomic<bool>& cancelled,
    const RecordCallback& onRecord,
    const ProgressCallback& onProgress,
    std::wstring& failureReason) {
    std::wstring volumeRoot = GetVolumeRootPath(options.targetPath);
    if (volumeRoot.empty()) {
        failureReason = L"Could not determine the volume for the target path.";
        return false;
    }

    if (!IsNtfsVolume(volumeRoot)) {
        failureReason = L"Target volume is not formatted NTFS; fast USN-assisted scanning is unavailable.";
        return false;
    }

    // Volume path form for DeviceIoControl: "\\.\C:" (no trailing backslash).
    std::wstring driveSpec = volumeRoot;
    while (!driveSpec.empty() && (driveSpec.back() == L'\\' || driveSpec.back() == L'/')) {
        driveSpec.pop_back();
    }
    std::wstring devicePath = L"\\\\.\\" + driveSpec;

    FileHandle volumeHandle(CreateFileW(devicePath.c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING, 0, nullptr));
    if (!volumeHandle.IsValid()) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            result.elevationRecommended = true;
            failureReason = L"Opening the volume for a fast whole-drive scan requires administrator privileges.";
        } else {
            failureReason = L"Could not open volume " + devicePath + L" for fast scanning: " + FormatWinError(err);
        }
        return false;
    }

    // Validate/query the USN journal. Not fatal if unavailable: FSCTL_ENUM_USN_DATA
    // can still walk the MFT even when the change journal itself is not active.
    USN_JOURNAL_DATA_V0 journalData{};
    DWORD bytesReturned = 0;
    BOOL journalOk = DeviceIoControl(volumeHandle.Get(), FSCTL_QUERY_USN_JOURNAL,
                                      nullptr, 0, &journalData, sizeof(journalData), &bytesReturned, nullptr);
    if (!journalOk) {
        result.warnings.push_back(L"USN journal is not active on " + volumeRoot +
                                   L"; fast scan will still use MFT enumeration but incremental updates will be unavailable.");
    }

    // Determine the volume root's own file reference number, used as the
    // terminal point when walking parent chains back to the top.
    std::wstring rootForHandle = volumeRoot;
    FileHandle rootDirHandle(CreateFileW(ToExtendedLengthPath(rootForHandle).c_str(), GENERIC_READ,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                          nullptr, OPEN_EXISTING,
                                          FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    FileRefKey rootKey;
    if (rootDirHandle.IsValid()) {
        BY_HANDLE_FILE_INFORMATION info{};
        if (GetFileInformationByHandle(rootDirHandle.Get(), &info)) {
            rootKey.low = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
            rootKey.high = 0;
        }
    }

    std::unordered_map<FileRefKey, FsNode, FileRefKeyHash> nodes;
    nodes.reserve(1 << 16);

    std::vector<unsigned char> buffer(1 << 16);
    MFT_ENUM_DATA_V0 med{};
    med.StartFileReferenceNumber = 0;
    med.LowUsn = 0;
    med.HighUsn = MAXLONGLONG;

    for (;;) {
        if (cancelled.load()) {
            result.cancelled = true;
            result.partial = true;
            break;
        }

        BOOL ok = DeviceIoControl(volumeHandle.Get(), FSCTL_ENUM_USN_DATA,
                                   &med, sizeof(med), buffer.data(), static_cast<DWORD>(buffer.size()),
                                   &bytesReturned, nullptr);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF) {
                break;  // Enumeration complete.
            }
            if (nodes.empty()) {
                failureReason = L"MFT enumeration failed: " + FormatWinError(err);
                return false;
            }
            result.warnings.push_back(L"MFT enumeration ended early: " + FormatWinError(err));
            break;
        }
        if (bytesReturned <= sizeof(DWORDLONG)) break;

        DWORDLONG nextStart = *reinterpret_cast<DWORDLONG*>(buffer.data());
        BYTE* recordPtr = buffer.data() + sizeof(DWORDLONG);
        BYTE* bufferEnd = buffer.data() + bytesReturned;

        while (recordPtr < bufferEnd) {
            UsnRecordHeader* header = reinterpret_cast<UsnRecordHeader*>(recordPtr);
            if (header->RecordLength == 0) break;

            if (header->MajorVersion == 2) {
                USN_RECORD_V2* rec = reinterpret_cast<USN_RECORD_V2*>(recordPtr);
                FileRefKey key{rec->FileReferenceNumber, 0};
                FileRefKey parentKey{rec->ParentFileReferenceNumber, 0};

                FsNode node;
                node.parent = parentKey;
                node.attributes = rec->FileAttributes;
                node.isDirectory = (rec->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                node.name.assign(reinterpret_cast<wchar_t*>(recordPtr + rec->FileNameOffset),
                                  rec->FileNameLength / sizeof(wchar_t));

                if (!IsDotOrDotDot(node.name)) {
                    nodes[key] = std::move(node);
                }
            }
            // V3 (128-bit file ids, primarily ReFS) is intentionally not
            // decoded in this version; such records are skipped safely.

            recordPtr += header->RecordLength;
        }

        med.StartFileReferenceNumber = nextStart;
    }

    if (nodes.empty() && !result.cancelled) {
        failureReason = L"MFT enumeration returned no usable records.";
        return false;
    }

    // Path reconstruction with caching to avoid repeated parent-chain walks.
    std::unordered_map<FileRefKey, std::wstring, FileRefKeyHash> pathCache;
    pathCache[rootKey] = volumeRoot;

    auto reconstructPath = [&](const FileRefKey& leaf) -> std::wstring {
        auto cached = pathCache.find(leaf);
        if (cached != pathCache.end()) return cached->second;

        std::vector<FileRefKey> chain;
        std::unordered_set<FileRefKey, FileRefKeyHash> visited;
        FileRefKey current = leaf;
        bool resolved = false;

        while (true) {
            auto cacheHit = pathCache.find(current);
            if (cacheHit != pathCache.end()) {
                resolved = true;
                break;
            }
            if (visited.count(current) > 0) {
                break;  // Cycle detected in corrupt metadata; stop walking.
            }
            visited.insert(current);
            chain.push_back(current);

            auto nodeIt = nodes.find(current);
            if (nodeIt == nodes.end()) {
                break;  // Parent unknown (e.g. outside enumerated set).
            }
            current = nodeIt->second.parent;
            if (chain.size() > 4096) break;  // Sanity guard against corrupt chains.
        }

        std::wstring basePath = resolved ? pathCache[current] : std::wstring();
        if (!resolved) {
            return std::wstring();  // Unresolvable; caller should skip.
        }

        // chain is leaf-first; walk it in reverse (root-most first) appending names.
        std::wstring path = basePath;
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
            auto nodeIt = nodes.find(*it);
            if (nodeIt == nodes.end()) continue;
            if (!path.empty() && path.back() != L'\\') path += L'\\';
            path += nodeIt->second.name;
            pathCache[*it] = path;
        }
        return path;
    };

    std::wstring targetNormalized = ToLower(options.targetPath);
    while (!targetNormalized.empty() && targetNormalized.back() == L'\\') targetNormalized.pop_back();

    uint64_t candidatesScanned = 0;
    DWORD lastProgressTick = GetTickCount();

    for (const auto& entry : nodes) {
        if (cancelled.load()) {
            result.cancelled = true;
            result.partial = true;
            break;
        }

        const FsNode& node = entry.second;
        if ((node.attributes & FILE_ATTRIBUTE_HIDDEN) && !options.includeHidden) continue;
        if ((node.attributes & FILE_ATTRIBUTE_SYSTEM) && !options.includeSystem) continue;
        if (node.isDirectory && !options.includeDirectories) continue;

        std::wstring fullPath = reconstructPath(entry.first);
        if (fullPath.empty()) continue;

        std::wstring fullPathLower = ToLower(fullPath);
        bool inScope = (fullPathLower == targetNormalized) ||
                        (fullPathLower.size() > targetNormalized.size() &&
                         fullPathLower.compare(0, targetNormalized.size(), targetNormalized) == 0 &&
                         fullPathLower[targetNormalized.size()] == L'\\');
        if (!inScope) continue;

        candidatesScanned++;

        std::vector<std::wstring> warnings;
        std::vector<StreamRecord> records = StreamEnumerator::EnumerateStreams(
            fullPath, options, L"NTFS USN-Assisted", warnings, &cancelled);
        for (auto& w : warnings) result.warnings.push_back(w);
        for (auto& rec : records) {
            result.streamsFound++;
            if (rec.classification == StreamClassification::Suspicious) result.suspiciousCount++;
            if (rec.classification == StreamClassification::HighRisk) result.highRiskCount++;
            if (onRecord) onRecord(rec);
            result.streams.push_back(std::move(rec));
        }

        if (node.isDirectory) result.foldersProcessed++; else result.filesProcessed++;

        DWORD now = GetTickCount();
        if (onProgress && (now - lastProgressTick) > 150) {
            Progress p;
            p.candidatesScanned = candidatesScanned;
            p.streamsFound = result.streamsFound;
            p.currentPath = fullPath;
            onProgress(p);
            lastProgressTick = now;
        }
    }

    return true;
}

}  // namespace ss
