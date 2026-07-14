#include "CsvWriter.h"
#include "FormatUtil.h"
#include "StringUtil.h"

#include <fstream>

namespace ss {

namespace {

std::wstring CsvEscape(const std::wstring& field) {
    bool needsQuoting = field.find_first_of(L",\"\r\n") != std::wstring::npos;
    if (!needsQuoting) return field;
    std::wstring out = L"\"";
    for (wchar_t c : field) {
        if (c == L'"') out += L"\"\"";
        else out += c;
    }
    out += L"\"";
    return out;
}

std::wstring JoinDiagnostics(const std::vector<std::wstring>& diagnostics) {
    std::wstring out;
    for (size_t i = 0; i < diagnostics.size(); ++i) {
        if (i > 0) out += L" | ";
        out += diagnostics[i];
    }
    return out;
}

}  // namespace

std::wstring CsvWriter::BuildCsv(const std::vector<StreamRecord>& records) {
    std::wstring out;
    out += L"Classification,ClassificationReason,HostPath,HostType,HostExtension,StreamName,StreamType,StreamSize,ZoneId,ZoneName,ReferrerUrl,HostUrl,Source,Diagnostics\r\n";

    for (const auto& rec : records) {
        std::vector<std::wstring> fields;
        fields.push_back(ClassificationToString(rec.classification));
        fields.push_back(rec.classificationReason);
        fields.push_back(rec.hostPath);
        fields.push_back(rec.hostIsDirectory ? L"Directory" : L"File");
        fields.push_back(rec.hostExtension);
        fields.push_back(rec.streamName);
        fields.push_back(rec.streamType);
        fields.push_back(std::to_wstring(rec.streamSize));
        fields.push_back(rec.zoneInfo.parsed ? std::to_wstring(rec.zoneInfo.zoneId) : L"");
        fields.push_back(rec.zoneInfo.parsed ? rec.zoneInfo.zoneName : L"");
        fields.push_back(rec.zoneInfo.referrerUrl);
        fields.push_back(rec.zoneInfo.hostUrl);
        fields.push_back(rec.source);
        fields.push_back(JoinDiagnostics(rec.diagnostics));

        for (size_t i = 0; i < fields.size(); ++i) {
            if (i > 0) out += L",";
            out += CsvEscape(fields[i]);
        }
        out += L"\r\n";
    }
    return out;
}

bool CsvWriter::WriteToFile(const std::wstring& filePath, const std::vector<StreamRecord>& records, std::wstring& error) {
    std::wstring csv = BuildCsv(records);
    std::string utf8 = WideToUtf8(csv);

    std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        error = L"Could not open file for writing: " + filePath;
        return false;
    }
    const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
    file.write(reinterpret_cast<const char*>(bom), sizeof(bom));
    file.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    if (!file.good()) {
        error = L"Failed while writing CSV file: " + filePath;
        return false;
    }
    return true;
}

}  // namespace ss
