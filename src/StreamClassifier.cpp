#include "StreamClassifier.h"
#include "PathUtil.h"
#include "StringUtil.h"

#include <cwctype>
#include <algorithm>

namespace ss {

namespace {

bool ContainsAny(const std::wstring& haystackLower, std::initializer_list<const wchar_t*> needles) {
    for (const wchar_t* n : needles) {
        if (haystackLower.find(n) != std::wstring::npos) return true;
    }
    return false;
}

}  // namespace

bool StreamClassifier::HasPeHeader(const unsigned char* data, size_t len) {
    return len >= 2 && data[0] == 'M' && data[1] == 'Z';
}

bool StreamClassifier::ContainsScriptMarkers(const unsigned char* data, size_t len) {
    if (data == nullptr || len == 0) return false;
    std::string narrow(reinterpret_cast<const char*>(data), len);
    std::wstring text = ToLower(Utf8ToWide(narrow));
    return ContainsAny(text, {
        L"powershell", L"invoke-expression", L"iex(", L"frombase64string",
        L"<script", L"wscript.shell", L"cmd.exe /c", L"downloadstring",
        L"-encodedcommand", L"eval(", L"activexobject"
    });
}

bool StreamClassifier::LooksRandomName(const std::wstring& name) {
    if (name.size() < 10) return false;
    size_t letters = 0, digits = 0, vowels = 0;
    for (wchar_t c : name) {
        if (iswalpha(c)) {
            letters++;
            wchar_t lower = static_cast<wchar_t>(towlower(c));
            if (lower == L'a' || lower == L'e' || lower == L'i' || lower == L'o' || lower == L'u') vowels++;
        } else if (iswdigit(c)) {
            digits++;
        }
    }
    if (letters < name.size() / 2) return false;  // too many non-letters, likely a normal-ish token
    // Very few vowels relative to letters suggests a random/hashed token.
    double vowelRatio = letters > 0 ? static_cast<double>(vowels) / static_cast<double>(letters) : 1.0;
    bool hasDigitsMixedWithLetters = digits > 0 && letters > 0;
    return vowelRatio < 0.15 && (name.size() >= 16 || hasDigitsMixedWithLetters);
}

std::wstring StreamClassifier::GuessStreamType(const StreamRecord& record, const unsigned char* sampleData, size_t sampleLen) {
    if (EqualsIgnoreCase(record.streamName, L"Zone.Identifier")) {
        return L"Zone.Identifier metadata";
    }
    if (sampleData != nullptr && sampleLen >= 2 && HasPeHeader(sampleData, sampleLen)) {
        return L"Possible PE executable (MZ header)";
    }
    if (sampleData != nullptr && sampleLen >= 4) {
        if (sampleData[0] == 0x50 && sampleData[1] == 0x4B) return L"ZIP / Office document container";
        if (sampleData[0] == 0x25 && sampleData[1] == 0x50 && sampleData[2] == 0x44 && sampleData[3] == 0x46) return L"PDF document";
        if (sampleData[0] == 0x89 && sampleData[1] == 0x50 && sampleData[2] == 0x4E && sampleData[3] == 0x47) return L"PNG image";
        if (sampleData[0] == 0xFF && sampleData[1] == 0xD8) return L"JPEG image";
        if (sampleData[0] == 'G' && sampleData[1] == 'I' && sampleData[2] == 'F') return L"GIF image";
    }
    if (IsLikelyExecutableExtension(record.streamName)) return L"Executable-looking stream name";
    if (IsLikelyScriptExtension(record.streamName)) return L"Script-looking stream name";
    if (sampleData != nullptr && LooksLikeText(sampleData, sampleLen)) {
        if (ContainsScriptMarkers(sampleData, sampleLen)) return L"Script-like text content";
        return L"Text content";
    }
    if (sampleData != nullptr && sampleLen > 0) return L"Binary content";
    return L"Unknown";
}

void StreamClassifier::Classify(StreamRecord& record, const unsigned char* sampleData, size_t sampleLen) {
    record.diagnostics.clear();
    record.streamTypeGuess = GuessStreamType(record, sampleData, sampleLen);

    const bool isZone = EqualsIgnoreCase(record.streamName, L"Zone.Identifier");
    const bool execExt = IsLikelyExecutableExtension(record.hostExtension) || IsLikelyExecutableExtension(record.hostName);
    const bool scriptExt = IsLikelyScriptExtension(record.hostExtension) || IsLikelyScriptExtension(record.hostName);
    const bool streamNameExecLike = IsLikelyExecutableExtension(record.streamName);
    const bool streamNameScriptLike = IsLikelyScriptExtension(record.streamName);
    const bool sensitiveLocation = IsUnderSensitiveLocation(record.hostPath);
    const bool hasPe = sampleData != nullptr && HasPeHeader(sampleData, sampleLen);
    const bool hasScriptMarkers = ContainsScriptMarkers(sampleData, sampleLen);
    const bool randomName = LooksRandomName(record.streamName);

    // --- Zone.Identifier handling -------------------------------------------------
    if (isZone) {
        if (execExt || scriptExt) {
            record.classification = StreamClassification::Interesting;
            record.classificationReason =
                L"Zone.Identifier marks this file as downloaded from the Internet, and the host file "
                L"is executable or script-capable. This is common for legitimately downloaded installers "
                L"and tools, but worth a quick look if you don't recognize the file. Review recommended.";
        } else {
            record.classification = StreamClassification::Normal;
            record.classificationReason =
                L"Zone.Identifier marks this file as downloaded from the Internet (mark-of-the-web). "
                L"This is normal and expected for files saved by a browser or email client.";
        }
        if (record.zoneInfo.parsed) {
            record.diagnostics.push_back(L"Zone: " + record.zoneInfo.zoneName + L" (ZoneId=" + std::to_wstring(record.zoneInfo.zoneId) + L")");
            if (!record.zoneInfo.hostUrl.empty()) record.diagnostics.push_back(L"HostUrl: " + record.zoneInfo.hostUrl);
            if (!record.zoneInfo.referrerUrl.empty()) record.diagnostics.push_back(L"ReferrerUrl: " + record.zoneInfo.referrerUrl);
            if (record.zoneInfo.zoneId == 4) {
                record.classification = StreamClassification::Suspicious;
                record.classificationReason =
                    L"Zone.Identifier marks this file as coming from the Restricted Sites zone. "
                    L"Review recommended.";
            }
        }
        return;
    }

    // --- Non-zone streams: start from a baseline and escalate ---------------------
    StreamClassification level = StreamClassification::Interesting;
    std::vector<std::wstring> reasons;

    if (record.hostIsDirectory) {
        reasons.push_back(L"Alternate data stream is attached to a folder rather than a file, which is unusual.");
    }

    if (record.streamSize > kSuspiciousSizeThreshold) {
        level = StreamClassification::Suspicious;
        reasons.push_back(L"Stream size exceeds 1 MB, which is large for a hidden alternate data stream.");
    } else if (record.streamSize > kInterestingSizeThreshold) {
        if (level < StreamClassification::Suspicious) level = StreamClassification::Interesting;
        reasons.push_back(L"Stream size exceeds 64 KB, larger than typical metadata streams.");
    }

    if (streamNameExecLike || streamNameScriptLike) {
        level = StreamClassification::Suspicious;
        reasons.push_back(L"Stream name has an executable or script-like extension (" + record.streamName + L").");
    }

    if (randomName) {
        level = (level < StreamClassification::Suspicious) ? StreamClassification::Suspicious : level;
        reasons.push_back(L"Stream name looks randomly generated rather than a descriptive, human-chosen name.");
    }

    if (hasScriptMarkers) {
        level = StreamClassification::Suspicious;
        reasons.push_back(L"Stream content contains script-like or encoded-command text markers (e.g. PowerShell/JavaScript patterns).");
    }

    if (sensitiveLocation && (streamNameExecLike || streamNameScriptLike || hasScriptMarkers || hasPe)) {
        level = StreamClassification::HighRisk;
        reasons.push_back(L"Host file is located under a Downloads, Temp, Startup, or similar user-writable/execution-relevant folder.");
    } else if (sensitiveLocation) {
        if (level < StreamClassification::Interesting) level = StreamClassification::Interesting;
        reasons.push_back(L"Host file is located under a Downloads, Temp, Startup, or similar folder.");
    }

    if (hasPe) {
        level = StreamClassification::HighRisk;
        reasons.push_back(L"Stream content begins with an MZ/PE executable header. High risk indicator: review recommended.");
    }

    if (!execExt && !scriptExt && (streamNameExecLike || hasPe)) {
        // Misleading host: e.g. a .txt or .jpg host hiding an executable stream.
        level = StreamClassification::HighRisk;
        reasons.push_back(L"Host file type does not suggest executable content, but the hidden stream looks executable. This mismatch is a high risk indicator.");
    }

    if (reasons.empty()) {
        reasons.push_back(L"Named alternate data stream present with no strong risk indicators; presence alone can still be worth noting.");
    }

    record.classification = level;
    std::wstring reasonText;
    for (size_t i = 0; i < reasons.size(); ++i) {
        if (i > 0) reasonText += L" ";
        reasonText += reasons[i];
    }
    if (level == StreamClassification::Suspicious) {
        reasonText += L" This is an indicator requiring review, not proof of malware.";
    } else if (level == StreamClassification::HighRisk) {
        reasonText += L" This is a high risk indicator requiring review, not proof of malware.";
    }
    record.classificationReason = reasonText;
}

}  // namespace ss
