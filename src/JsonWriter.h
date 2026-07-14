// Exports scan results as structured JSON (summary + records array).
#pragma once

#include <string>
#include "StreamTypes.h"

namespace ss {

class JsonWriter {
public:
    static std::wstring BuildJson(const ScanOptions& options, const ScanResult& result);
    static bool WriteToFile(const std::wstring& filePath, const ScanOptions& options, const ScanResult& result, std::wstring& error);
};

}  // namespace ss
