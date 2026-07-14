#include "StreamEnumerator.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "Win32ErrorUtil.h"
#include "Handle.h"
#include "StreamClassifier.h"
#include "ZoneIdentifierParser.h"

namespace ss {

namespace {

void FillHostInfo(StreamRecord& record, const std::wstring& hostPath) {
    record.hostPath = hostPath;
    record.hostName = GetFileNamePart(hostPath);
    record.hostExtension = GetExtensionPart(hostPath);

    WIN32_FILE_ATTRIBUTE_DATA attrData{};
    std::wstring extended = ToExtendedLengthPath(hostPath);
    if (GetFileAttributesExW(extended.c_str(), GetFileExInfoStandard, &attrData)) {
        record.hostIsDirectory = (attrData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        record.hostAttributes = attrData.dwFileAttributes;
        if (!record.hostIsDirectory) {
            ULARGE_INTEGER size;
            size.LowPart = attrData.nFileSizeLow;
            size.HighPart = attrData.nFileSizeHigh;
            record.hostSize = size.QuadPart;
            record.hostSizeKnown = true;
        }
        record.hostCreatedTime = attrData.ftCreationTime;
        record.hostCreatedTimeKnown = true;
        record.hostModifiedTime = attrData.ftLastWriteTime;
        record.hostModifiedTimeKnown = true;
    }
}

}  // namespace

bool StreamEnumerator::ReadStreamPrefix(
    const std::wstring& hostPath,
    const std::wstring& streamName,
    const std::wstring& streamType,
    size_t maxBytes,
    std::vector<unsigned char>& outData) {
    outData.clear();
    std::wstring streamPath = BuildApiStreamPath(hostPath, streamName, streamType);
    std::wstring extended = ToExtendedLengthPath(streamPath);

    FileHandle handle(CreateFileW(extended.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!handle.IsValid()) return false;

    outData.resize(maxBytes);
    DWORD bytesRead = 0;
    if (!ReadFile(handle.Get(), outData.data(), static_cast<DWORD>(maxBytes), &bytesRead, nullptr)) {
        outData.clear();
        return false;
    }
    outData.resize(bytesRead);
    return true;
}

std::vector<StreamRecord> StreamEnumerator::EnumerateStreams(
    const std::wstring& hostPath,
    const ScanOptions& options,
    const std::wstring& source,
    std::vector<std::wstring>& warnings,
    const std::atomic<bool>* cancelled) {
    std::vector<StreamRecord> results;

    std::wstring extended = ToExtendedLengthPath(hostPath);

    WIN32_FIND_STREAM_DATA streamData{};
    FindHandle findHandle(FindFirstStreamW(extended.c_str(), FindStreamInfoStandard, &streamData, 0));
    if (!findHandle.IsValid()) {
        DWORD err = GetLastError();
        if (err == ERROR_HANDLE_EOF) {
            return results;  // No streams at all (not even data) - unusual but not an error.
        }
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            warnings.push_back(L"Path disappeared during scan: " + hostPath);
        } else if (err == ERROR_ACCESS_DENIED) {
            warnings.push_back(L"Access denied enumerating streams: " + hostPath);
        } else if (err != ERROR_CALL_NOT_IMPLEMENTED) {
            warnings.push_back(L"Could not enumerate streams for " + hostPath + L": " + FormatWinError(err));
        }
        return results;
    }

    bool hostInfoLoaded = false;
    StreamRecord hostTemplate;

    do {
        if (cancelled != nullptr && cancelled->load()) break;

        std::wstring name;
        std::wstring type;
        if (!ParseFindStreamName(streamData.cStreamName, name, type)) {
            continue;  // unnamed default stream, or unparseable entry.
        }

        if (!hostInfoLoaded) {
            FillHostInfo(hostTemplate, hostPath);
            hostInfoLoaded = true;
        }

        StreamRecord record = hostTemplate;
        record.streamName = name;
        record.streamType = type;
        record.streamSize = static_cast<uint64_t>(streamData.StreamSize.QuadPart);
        record.fullStreamPath = BuildDisplayStreamPath(hostPath, name);
        record.source = source;

        if (options.sizeFilterEnabled) {
            if (record.streamSize < options.minStreamSize) continue;
            if (options.maxStreamSize > 0 && record.streamSize > options.maxStreamSize) continue;
        }

        bool isZone = EqualsIgnoreCase(name, L"Zone.Identifier");
        if (isZone) {
            record.zoneInfo = ZoneIdentifierParser::ParseFromHostFile(hostPath);
        }

        std::vector<unsigned char> sample;
        if (!record.hostIsDirectory && !isZone) {
            ReadStreamPrefix(hostPath, name, type, StreamClassifier::kSignatureSampleSize, sample);
        }

        StreamClassifier::Classify(record, sample.empty() ? nullptr : sample.data(), sample.size());

        results.push_back(std::move(record));
    } while (FindNextStreamW(findHandle.Get(), &streamData));

    DWORD finalErr = GetLastError();
    if (finalErr != ERROR_HANDLE_EOF && finalErr != ERROR_SUCCESS && !results.empty()) {
        // Non-fatal: we already collected some streams; note the truncation.
        warnings.push_back(L"Stream enumeration ended early for " + hostPath + L": " + FormatWinError(finalErr));
    }

    return results;
}

}  // namespace ss
