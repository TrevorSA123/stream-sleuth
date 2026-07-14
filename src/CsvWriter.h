// Exports scan results as CSV.
#pragma once

#include <string>
#include <vector>
#include "StreamTypes.h"

namespace ss {

class CsvWriter {
public:
    static std::wstring BuildCsv(const std::vector<StreamRecord>& records);
    static bool WriteToFile(const std::wstring& filePath, const std::vector<StreamRecord>& records, std::wstring& error);
};

}  // namespace ss
