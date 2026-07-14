// Core data model shared across scanning, classification, export, and UI code.
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace ss {

enum class StreamClassification {
    Normal,
    Interesting,
    Suspicious,
    HighRisk,
    Unknown
};

struct ZoneIdentifierInfo {
    bool isZoneIdentifier = false;
    bool parsed = false;
    int zoneId = -1;
    std::wstring zoneName;
    std::wstring referrerUrl;
    std::wstring hostUrl;
    std::vector<std::wstring> rawLines;
    std::vector<std::wstring> diagnostics;
};

struct StreamRecord {
    std::wstring hostPath;
    std::wstring hostName;
    std::wstring hostExtension;
    bool hostIsDirectory = false;
    uint64_t hostSize = 0;
    bool hostSizeKnown = false;
    FILETIME hostCreatedTime{};
    bool hostCreatedTimeKnown = false;
    FILETIME hostModifiedTime{};
    bool hostModifiedTimeKnown = false;
    uint32_t hostAttributes = 0;

    std::wstring streamName;
    std::wstring streamType;
    uint64_t streamSize = 0;
    std::wstring fullStreamPath;

    StreamClassification classification = StreamClassification::Unknown;
    std::wstring classificationReason;
    std::wstring streamTypeGuess;

    ZoneIdentifierInfo zoneInfo;

    std::wstring source;  // "Recursive" or "NTFS USN-Assisted"
    std::vector<std::wstring> diagnostics;
};

struct ScanOptions {
    std::wstring targetPath;
    bool recursive = true;
    bool includeDirectories = true;
    bool includeHidden = true;
    bool includeSystem = false;
    bool skipReparsePoints = true;
    bool useFastUsnEnumeration = true;
    bool allowRecursiveFallback = true;
    bool incremental = false;
    bool zoneOnly = false;
    bool suspiciousOnly = false;
    bool highRiskOnly = false;
    uint64_t minStreamSize = 0;
    uint64_t maxStreamSize = 0;
    bool sizeFilterEnabled = false;
};

struct ScanResult {
    std::vector<StreamRecord> streams;
    std::vector<std::wstring> warnings;
    std::vector<std::wstring> errors;
    uint64_t filesProcessed = 0;
    uint64_t foldersProcessed = 0;
    uint64_t streamsFound = 0;
    uint64_t suspiciousCount = 0;
    uint64_t highRiskCount = 0;
    bool cancelled = false;
    bool partial = false;
    bool elevationRecommended = false;
    std::chrono::milliseconds scanDuration{0};
    std::wstring summary;
};

enum class WatchEventType {
    StreamAdded,
    StreamRemoved,
    StreamModified,
    HostFileCreated,
    HostFileDeleted,
    HostFileRenamed,
    ZoneIdentifierAdded,
    ZoneIdentifierRemoved
};

struct WatchEvent {
    WatchEventType type;
    std::wstring hostPath;
    std::wstring streamName;
    StreamClassification classification = StreamClassification::Unknown;
    std::wstring details;
    FILETIME timestamp{};
};

}  // namespace ss
