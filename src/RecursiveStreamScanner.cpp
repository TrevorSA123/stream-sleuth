#include "RecursiveStreamScanner.h"
#include "StreamEnumerator.h"
#include "PathUtil.h"
#include "Win32ErrorUtil.h"

#include <deque>

namespace ss {

namespace {

bool ShouldSkipByAttributes(DWORD attrs, const ScanOptions& options) {
    if ((attrs & FILE_ATTRIBUTE_HIDDEN) && !options.includeHidden) return true;
    if ((attrs & FILE_ATTRIBUTE_SYSTEM) && !options.includeSystem) return true;
    return false;
}

void ProcessOne(const std::wstring& path, bool isDirectory, const ScanOptions& options,
                 ScanResult& result, const RecursiveStreamScanner::RecordCallback& onRecord) {
    std::vector<std::wstring> warnings;
    std::vector<StreamRecord> records = StreamEnumerator::EnumerateStreams(path, options, L"Recursive", warnings, nullptr);
    for (auto& w : warnings) result.warnings.push_back(w);
    for (auto& rec : records) {
        result.streamsFound++;
        if (rec.classification == StreamClassification::Suspicious) result.suspiciousCount++;
        if (rec.classification == StreamClassification::HighRisk) result.highRiskCount++;
        if (onRecord) onRecord(rec);
        result.streams.push_back(std::move(rec));
    }
    if (isDirectory) {
        result.foldersProcessed++;
    } else {
        result.filesProcessed++;
    }
}

}  // namespace

void RecursiveStreamScanner::Scan(
    const ScanOptions& options,
    ScanResult& result,
    const std::atomic<bool>& cancelled,
    const RecordCallback& onRecord,
    const ProgressCallback& onProgress) {
    std::wstring target = options.targetPath;
    if (!PathExistsOnDisk(target)) {
        result.errors.push_back(L"Target path does not exist: " + target);
        return;
    }

    if (!IsDirectoryPath(target)) {
        ProcessOne(target, false, options, result, onRecord);
        return;
    }

    std::deque<std::wstring> pending;
    pending.push_back(target);

    DWORD lastProgressTick = GetTickCount();

    while (!pending.empty()) {
        if (cancelled.load()) {
            result.cancelled = true;
            result.partial = true;
            break;
        }

        std::wstring dir = pending.front();
        pending.pop_front();

        std::wstring searchPattern = dir;
        if (!searchPattern.empty() && searchPattern.back() != L'\\') searchPattern += L'\\';
        searchPattern += L"*";

        WIN32_FIND_DATAW findData{};
        std::wstring extendedPattern = ToExtendedLengthPath(searchPattern);
        HANDLE hFind = FindFirstFileExW(extendedPattern.c_str(), FindExInfoBasic, &findData,
                                         FindExSearchNameMatch, nullptr, 0);
        if (hFind == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                result.warnings.push_back(L"Access denied listing folder: " + dir);
                result.elevationRecommended = true;
            } else if (err != ERROR_FILE_NOT_FOUND) {
                result.warnings.push_back(L"Could not list folder " + dir + L": " + FormatWinError(err));
            }
            continue;
        }

        // Process the directory itself for streams (once, when first encountered).
        if (options.includeDirectories) {
            ProcessOne(dir, true, options, result, onRecord);
        } else {
            result.foldersProcessed++;
        }

        do {
            if (cancelled.load()) break;

            std::wstring name = findData.cFileName;
            if (name == L"." || name == L"..") continue;

            std::wstring fullPath = dir;
            if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
            fullPath += name;

            bool isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            bool isReparse = (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

            if (ShouldSkipByAttributes(findData.dwFileAttributes, options)) continue;

            if (isDir) {
                if (isReparse) {
                    result.warnings.push_back(L"Reparse point skipped: " + fullPath);
                    if (options.skipReparsePoints) continue;
                }
                if (options.recursive) {
                    pending.push_back(fullPath);
                }
                // Directory streams themselves are enumerated when this directory is popped.
            } else {
                ProcessOne(fullPath, false, options, result, onRecord);
            }

            DWORD now = GetTickCount();
            if (onProgress && (now - lastProgressTick) > 150) {
                Progress p;
                p.filesProcessed = result.filesProcessed;
                p.foldersProcessed = result.foldersProcessed;
                p.streamsFound = result.streamsFound;
                p.currentPath = fullPath;
                onProgress(p);
                lastProgressTick = now;
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    if (onProgress) {
        Progress p;
        p.filesProcessed = result.filesProcessed;
        p.foldersProcessed = result.foldersProcessed;
        p.streamsFound = result.streamsFound;
        p.currentPath = target;
        onProgress(p);
    }
}

}  // namespace ss
