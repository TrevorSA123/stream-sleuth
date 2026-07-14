#include "TextReportWriter.h"
#include "FormatUtil.h"
#include "FileTimeUtil.h"
#include "StringUtil.h"

#include <fstream>
#include <sstream>

namespace ss {

std::wstring TextReportWriter::BuildReport(const ScanOptions& options, const ScanResult& result, const std::wstring& scanMode) {
    std::wstringstream out;

    out << L"StreamSleuth Scan Report\n";
    out << L"========================\n\n";
    out << L"Scan target:    " << options.targetPath << L"\n";
    out << L"Scan time:      " << FormatFileTime(NowAsFileTime()) << L"\n";
    out << L"Scan mode:      " << scanMode << L"\n";
    out << L"Scan duration:  " << FormatDuration(result.scanDuration) << L"\n";
    out << L"Partial result: " << (result.partial ? L"Yes" : L"No") << L"\n";
    out << L"Cancelled:      " << (result.cancelled ? L"Yes" : L"No") << L"\n\n";

    out << L"Files processed:    " << FormatCount(result.filesProcessed) << L"\n";
    out << L"Folders processed:  " << FormatCount(result.foldersProcessed) << L"\n";
    out << L"Streams found:      " << FormatCount(result.streamsFound) << L"\n";
    out << L"Suspicious count:   " << FormatCount(result.suspiciousCount) << L"\n";
    out << L"High risk count:    " << FormatCount(result.highRiskCount) << L"\n\n";

    out << L"IMPORTANT: Suspicious and High Risk classifications are indicators that\n";
    out << L"warrant manual review. They are not proof of malware. StreamSleuth is a\n";
    out << L"discovery and triage tool, not a malware scanner.\n\n";

    if (!result.warnings.empty()) {
        out << L"Warnings (" << result.warnings.size() << L"):\n";
        for (const auto& w : result.warnings) out << L"  - " << w << L"\n";
        out << L"\n";
    }

    if (!result.errors.empty()) {
        out << L"Errors (" << result.errors.size() << L"):\n";
        for (const auto& e : result.errors) out << L"  - " << e << L"\n";
        out << L"\n";
    }

    out << L"Detailed stream list (" << result.streams.size() << L" entries)\n";
    out << L"----------------------------------------\n";
    for (const auto& rec : result.streams) {
        out << L"\n";
        out << L"Host:           " << rec.hostPath << (rec.hostIsDirectory ? L" [directory]" : L"") << L"\n";
        out << L"Stream:         " << rec.streamName << L" (" << rec.streamType << L")\n";
        out << L"Full path:      " << rec.fullStreamPath << L"\n";
        out << L"Size:           " << FormatByteSize(rec.streamSize) << L" (" << rec.streamSize << L" bytes)\n";
        out << L"Classification: " << ClassificationToString(rec.classification) << L"\n";
        out << L"Reason:         " << rec.classificationReason << L"\n";
        out << L"Type guess:     " << rec.streamTypeGuess << L"\n";
        out << L"Source:         " << rec.source << L"\n";
        if (rec.zoneInfo.parsed) {
            out << L"Zone:           " << rec.zoneInfo.zoneName << L" (ZoneId=" << rec.zoneInfo.zoneId << L")\n";
            if (!rec.zoneInfo.hostUrl.empty()) out << L"Host URL:       " << rec.zoneInfo.hostUrl << L"\n";
            if (!rec.zoneInfo.referrerUrl.empty()) out << L"Referrer URL:   " << rec.zoneInfo.referrerUrl << L"\n";
        }
        if (!rec.diagnostics.empty()) {
            out << L"Diagnostics:\n";
            for (const auto& d : rec.diagnostics) out << L"  - " << d << L"\n";
        }
    }

    return out.str();
}

bool TextReportWriter::WriteToFile(const std::wstring& filePath, const ScanOptions& options, const ScanResult& result, const std::wstring& scanMode, std::wstring& error) {
    std::wstring text = BuildReport(options, result, scanMode);
    std::string utf8 = WideToUtf8(text);

    std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        error = L"Could not open file for writing: " + filePath;
        return false;
    }
    const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
    file.write(reinterpret_cast<const char*>(bom), sizeof(bom));
    file.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    if (!file.good()) {
        error = L"Failed while writing text report: " + filePath;
        return false;
    }
    return true;
}

}  // namespace ss
