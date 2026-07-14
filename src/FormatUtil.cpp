#include "FormatUtil.h"
#include "StringUtil.h"

#include <cwctype>

namespace ss {

std::wstring FormatDuration(std::chrono::milliseconds ms) {
    long long totalMs = ms.count();
    long long totalSec = totalMs / 1000;
    long long hours = totalSec / 3600;
    long long minutes = (totalSec % 3600) / 60;
    long long seconds = totalSec % 60;
    wchar_t buf[64];
    if (hours > 0) {
        swprintf_s(buf, L"%lldh %lldm %llds", hours, minutes, seconds);
    } else if (minutes > 0) {
        swprintf_s(buf, L"%lldm %llds", minutes, seconds);
    } else {
        swprintf_s(buf, L"%lld.%03llds", seconds, totalMs % 1000);
    }
    return std::wstring(buf);
}

std::wstring FormatCount(uint64_t count) {
    std::wstring digits = std::to_wstring(count);
    std::wstring out;
    int sinceGroup = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (sinceGroup == 3) {
            out.push_back(L',');
            sinceGroup = 0;
        }
        out.push_back(*it);
        sinceGroup++;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::wstring ClassificationToString(StreamClassification c) {
    switch (c) {
        case StreamClassification::Normal: return L"Normal";
        case StreamClassification::Interesting: return L"Interesting";
        case StreamClassification::Suspicious: return L"Suspicious";
        case StreamClassification::HighRisk: return L"High Risk Indicator";
        case StreamClassification::Unknown: default: return L"Unknown";
    }
}

std::wstring ClassificationToShortLabel(StreamClassification c) {
    switch (c) {
        case StreamClassification::Normal: return L"Normal";
        case StreamClassification::Interesting: return L"Interesting";
        case StreamClassification::Suspicious: return L"Suspicious";
        case StreamClassification::HighRisk: return L"High Risk";
        case StreamClassification::Unknown: default: return L"Unknown";
    }
}

StreamClassification ClassificationFromString(const std::wstring& s) {
    std::wstring lower = ToLower(s);
    if (lower == L"normal") return StreamClassification::Normal;
    if (lower == L"interesting") return StreamClassification::Interesting;
    if (lower == L"suspicious") return StreamClassification::Suspicious;
    if (lower == L"highrisk" || lower == L"high risk" || lower == L"high risk indicator") return StreamClassification::HighRisk;
    return StreamClassification::Unknown;
}

std::wstring ZoneIdToName(int zoneId) {
    switch (zoneId) {
        case 0: return L"Local Machine";
        case 1: return L"Local Intranet";
        case 2: return L"Trusted Sites";
        case 3: return L"Internet";
        case 4: return L"Restricted Sites";
        default: return L"Unknown Zone";
    }
}

bool ParseSizeString(const std::wstring& text, uint64_t& outBytes) {
    std::wstring trimmed = Trim(text);
    if (trimmed.empty()) return false;

    size_t i = 0;
    while (i < trimmed.size() && (iswdigit(trimmed[i]) || trimmed[i] == L'.')) {
        i++;
    }
    if (i == 0) return false;

    double value = 0.0;
    try {
        value = std::stod(trimmed.substr(0, i));
    } catch (...) {
        return false;
    }

    std::wstring suffix = ToLower(Trim(trimmed.substr(i)));
    uint64_t multiplier = 1;
    if (suffix.empty() || suffix == L"b") {
        multiplier = 1;
    } else if (suffix == L"kb" || suffix == L"k") {
        multiplier = 1024ULL;
    } else if (suffix == L"mb" || suffix == L"m") {
        multiplier = 1024ULL * 1024ULL;
    } else if (suffix == L"gb" || suffix == L"g") {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
    } else {
        return false;
    }

    outBytes = static_cast<uint64_t>(value * static_cast<double>(multiplier));
    return true;
}

}  // namespace ss
