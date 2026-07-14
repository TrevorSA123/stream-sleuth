#include "StringUtil.h"

#include <algorithm>
#include <cwctype>
#include <cstdio>

namespace ss {

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring result(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), result.data(), needed);
    return result;
}

std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), result.data(), needed, nullptr, nullptr);
    return result;
}

std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return out;
}

std::wstring Trim(const std::wstring& s) {
    size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return std::wstring();
    size_t end = s.find_last_not_of(L" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool EndsWithIgnoreCase(const std::wstring& s, const std::wstring& suffix) {
    if (suffix.size() > s.size()) return false;
    return ToLower(s.substr(s.size() - suffix.size())) == ToLower(suffix);
}

bool StartsWithIgnoreCase(const std::wstring& s, const std::wstring& prefix) {
    if (prefix.size() > s.size()) return false;
    return ToLower(s.substr(0, prefix.size())) == ToLower(prefix);
}

bool ContainsIgnoreCase(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    return ToLower(haystack).find(ToLower(needle)) != std::wstring::npos;
}

bool EqualsIgnoreCase(const std::wstring& a, const std::wstring& b) {
    return ToLower(a) == ToLower(b);
}

std::vector<std::wstring> SplitLines(const std::wstring& text) {
    std::vector<std::wstring> lines;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t next = text.find_first_of(L"\r\n", pos);
        if (next == std::wstring::npos) {
            lines.push_back(text.substr(pos));
            break;
        }
        lines.push_back(text.substr(pos, next - pos));
        // Skip \r\n or \n or \r combos.
        if (text[next] == L'\r' && next + 1 < text.size() && text[next + 1] == L'\n') {
            pos = next + 2;
        } else {
            pos = next + 1;
        }
    }
    return lines;
}

std::vector<std::wstring> Split(const std::wstring& text, wchar_t delimiter) {
    std::vector<std::wstring> parts;
    size_t start = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == delimiter) {
            parts.push_back(text.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}

bool LooksLikeText(const unsigned char* data, size_t length) {
    if (length == 0) return true;
    size_t sampleLen = std::min<size_t>(length, 4096);
    size_t printable = 0;
    size_t control = 0;
    for (size_t i = 0; i < sampleLen; ++i) {
        unsigned char c = data[i];
        if (c == 0) {
            return false;  // NUL bytes strongly suggest binary content.
        }
        if (c == L'\t' || c == L'\r' || c == L'\n') {
            printable++;
        } else if (c >= 0x20 && c < 0x7F) {
            printable++;
        } else if (c >= 0x80) {
            // Could be UTF-8/16 text; don't penalize heavily.
        } else {
            control++;
        }
    }
    double ratio = static_cast<double>(printable) / static_cast<double>(sampleLen);
    return ratio > 0.85 && control < sampleLen / 10;
}

std::wstring NormalizeToCrlf(const std::wstring& text) {
    std::wstring out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == L'\n' && (i == 0 || text[i - 1] != L'\r')) {
            out += L"\r\n";
        } else {
            out += text[i];
        }
    }
    return out;
}

std::wstring FormatByteSize(unsigned long long bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double value = static_cast<double>(bytes);
    int unitIndex = 0;
    while (value >= 1024.0 && unitIndex < 4) {
        value /= 1024.0;
        unitIndex++;
    }
    wchar_t buf[64];
    if (unitIndex == 0) {
        swprintf_s(buf, L"%llu %s", bytes, units[unitIndex]);
    } else {
        swprintf_s(buf, L"%.1f %s", value, units[unitIndex]);
    }
    return std::wstring(buf);
}

}  // namespace ss
