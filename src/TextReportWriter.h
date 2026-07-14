// Exports a human-readable plain text scan report.
#pragma once

#include <string>
#include "StreamTypes.h"

namespace ss {

class TextReportWriter {
public:
    static std::wstring BuildReport(const ScanOptions& options, const ScanResult& result, const std::wstring& scanMode);
    static bool WriteToFile(const std::wstring& filePath, const ScanOptions& options, const ScanResult& result, const std::wstring& scanMode, std::wstring& error);
};

}  // namespace ss
