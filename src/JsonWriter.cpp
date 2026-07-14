#include "JsonWriter.h"
#include "FormatUtil.h"
#include "FileTimeUtil.h"
#include "StringUtil.h"

#include <fstream>
#include <sstream>

namespace ss {

namespace {

std::wstring JsonEscape(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 8);
    for (wchar_t c : s) {
        switch (c) {
            case L'"': out += L"\\\""; break;
            case L'\\': out += L"\\\\"; break;
            case L'\n': out += L"\\n"; break;
            case L'\r': out += L"\\r"; break;
            case L'\t': out += L"\\t"; break;
            default:
                if (c < 0x20) {
                    wchar_t buf[8];
                    swprintf_s(buf, L"\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::wstring JsonString(const std::wstring& s) {
    return L"\"" + JsonEscape(s) + L"\"";
}

std::wstring JsonBool(bool b) {
    return b ? L"true" : L"false";
}

std::wstring JsonNumber(unsigned long long v) {
    return std::to_wstring(v);
}

}  // namespace

std::wstring JsonWriter::BuildJson(const ScanOptions& options, const ScanResult& result) {
    std::wstringstream ss_;

    ss_ << L"{\n";
    ss_ << L"  \"scanSummary\": {\n";
    ss_ << L"    \"targetPath\": " << JsonString(options.targetPath) << L",\n";
    ss_ << L"    \"filesProcessed\": " << JsonNumber(result.filesProcessed) << L",\n";
    ss_ << L"    \"foldersProcessed\": " << JsonNumber(result.foldersProcessed) << L",\n";
    ss_ << L"    \"streamsFound\": " << JsonNumber(result.streamsFound) << L",\n";
    ss_ << L"    \"suspiciousCount\": " << JsonNumber(result.suspiciousCount) << L",\n";
    ss_ << L"    \"highRiskCount\": " << JsonNumber(result.highRiskCount) << L",\n";
    ss_ << L"    \"cancelled\": " << JsonBool(result.cancelled) << L",\n";
    ss_ << L"    \"partial\": " << JsonBool(result.partial) << L",\n";
    ss_ << L"    \"elevationRecommended\": " << JsonBool(result.elevationRecommended) << L",\n";
    ss_ << L"    \"scanDurationMs\": " << JsonNumber(static_cast<unsigned long long>(result.scanDuration.count())) << L",\n";
    ss_ << L"    \"summary\": " << JsonString(result.summary) << L",\n";

    ss_ << L"    \"warnings\": [";
    for (size_t i = 0; i < result.warnings.size(); ++i) {
        if (i > 0) ss_ << L",";
        ss_ << L"\n      " << JsonString(result.warnings[i]);
    }
    ss_ << (result.warnings.empty() ? L"]" : L"\n    ]") << L",\n";

    ss_ << L"    \"errors\": [";
    for (size_t i = 0; i < result.errors.size(); ++i) {
        if (i > 0) ss_ << L",";
        ss_ << L"\n      " << JsonString(result.errors[i]);
    }
    ss_ << (result.errors.empty() ? L"]" : L"\n    ]") << L"\n";

    ss_ << L"  },\n";
    ss_ << L"  \"streams\": [";

    for (size_t i = 0; i < result.streams.size(); ++i) {
        const StreamRecord& rec = result.streams[i];
        if (i > 0) ss_ << L",";
        ss_ << L"\n    {\n";
        ss_ << L"      \"hostPath\": " << JsonString(rec.hostPath) << L",\n";
        ss_ << L"      \"hostName\": " << JsonString(rec.hostName) << L",\n";
        ss_ << L"      \"hostExtension\": " << JsonString(rec.hostExtension) << L",\n";
        ss_ << L"      \"hostIsDirectory\": " << JsonBool(rec.hostIsDirectory) << L",\n";
        ss_ << L"      \"hostSize\": " << JsonNumber(rec.hostSize) << L",\n";
        ss_ << L"      \"hostModified\": " << JsonString(FormatFileTime(rec.hostModifiedTime, rec.hostModifiedTimeKnown)) << L",\n";
        ss_ << L"      \"streamName\": " << JsonString(rec.streamName) << L",\n";
        ss_ << L"      \"streamType\": " << JsonString(rec.streamType) << L",\n";
        ss_ << L"      \"streamSize\": " << JsonNumber(rec.streamSize) << L",\n";
        ss_ << L"      \"fullStreamPath\": " << JsonString(rec.fullStreamPath) << L",\n";
        ss_ << L"      \"classification\": " << JsonString(ClassificationToString(rec.classification)) << L",\n";
        ss_ << L"      \"classificationReason\": " << JsonString(rec.classificationReason) << L",\n";
        ss_ << L"      \"streamTypeGuess\": " << JsonString(rec.streamTypeGuess) << L",\n";
        ss_ << L"      \"source\": " << JsonString(rec.source) << L",\n";

        ss_ << L"      \"zoneInfo\": {\n";
        ss_ << L"        \"isZoneIdentifier\": " << JsonBool(rec.zoneInfo.isZoneIdentifier) << L",\n";
        ss_ << L"        \"parsed\": " << JsonBool(rec.zoneInfo.parsed) << L",\n";
        ss_ << L"        \"zoneId\": " << rec.zoneInfo.zoneId << L",\n";
        ss_ << L"        \"zoneName\": " << JsonString(rec.zoneInfo.zoneName) << L",\n";
        ss_ << L"        \"referrerUrl\": " << JsonString(rec.zoneInfo.referrerUrl) << L",\n";
        ss_ << L"        \"hostUrl\": " << JsonString(rec.zoneInfo.hostUrl) << L"\n";
        ss_ << L"      },\n";

        ss_ << L"      \"diagnostics\": [";
        for (size_t d = 0; d < rec.diagnostics.size(); ++d) {
            if (d > 0) ss_ << L",";
            ss_ << L"\n        " << JsonString(rec.diagnostics[d]);
        }
        ss_ << (rec.diagnostics.empty() ? L"]" : L"\n      ]") << L"\n";
        ss_ << L"    }";
    }
    ss_ << (result.streams.empty() ? L"]\n" : L"\n  ]\n");
    ss_ << L"}\n";

    return ss_.str();
}

bool JsonWriter::WriteToFile(const std::wstring& filePath, const ScanOptions& options, const ScanResult& result, std::wstring& error) {
    std::wstring json = BuildJson(options, result);
    std::string utf8 = WideToUtf8(json);

    std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        error = L"Could not open file for writing: " + filePath;
        return false;
    }
    file.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    if (!file.good()) {
        error = L"Failed while writing JSON file: " + filePath;
        return false;
    }
    return true;
}

}  // namespace ss
