#include "ZoneIdentifierParser.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "Handle.h"

#include <vector>

namespace ss {

ZoneIdentifierInfo ZoneIdentifierParser::ParseFromHostFile(const std::wstring& hostPath) {
    ZoneIdentifierInfo info;
    info.isZoneIdentifier = true;

    std::wstring streamPath = BuildApiStreamPath(hostPath, L"Zone.Identifier", L"$DATA");
    std::wstring extended = ToExtendedLengthPath(streamPath);

    FileHandle handle(CreateFileW(extended.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!handle.IsValid()) {
        info.diagnostics.push_back(L"Could not open Zone.Identifier stream for reading.");
        return info;
    }

    std::vector<char> buffer(kMaxReadBytes);
    DWORD bytesRead = 0;
    if (!ReadFile(handle.Get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)) {
        info.diagnostics.push_back(L"Failed to read Zone.Identifier stream contents.");
        return info;
    }

    std::string narrow(buffer.data(), bytesRead);
    std::wstring text = Utf8ToWide(narrow);
    if (text.empty() && bytesRead > 0) {
        // Fall back to naive ANSI widen if UTF-8 conversion produced nothing useful.
        text.assign(narrow.begin(), narrow.end());
    }

    ZoneIdentifierInfo parsed = ParseText(text);
    parsed.isZoneIdentifier = true;
    return parsed;
}

ZoneIdentifierInfo ZoneIdentifierParser::ParseText(const std::wstring& text) {
    ZoneIdentifierInfo info;
    info.isZoneIdentifier = true;

    std::vector<std::wstring> lines = SplitLines(text);
    bool inZoneTransferSection = false;
    bool sawZoneId = false;

    for (const std::wstring& rawLine : lines) {
        std::wstring line = Trim(rawLine);
        if (line.empty()) continue;
        info.rawLines.push_back(line);

        if (line.front() == L'[' && line.back() == L']') {
            inZoneTransferSection = EqualsIgnoreCase(line, L"[ZoneTransfer]");
            continue;
        }
        if (!inZoneTransferSection) continue;

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = Trim(line.substr(0, eq));
        std::wstring value = Trim(line.substr(eq + 1));

        if (EqualsIgnoreCase(key, L"ZoneId")) {
            try {
                info.zoneId = std::stoi(value);
                sawZoneId = true;
            } catch (...) {
                info.diagnostics.push_back(L"ZoneId value could not be parsed as a number.");
            }
        } else if (EqualsIgnoreCase(key, L"ReferrerUrl")) {
            info.referrerUrl = value;
        } else if (EqualsIgnoreCase(key, L"HostUrl")) {
            info.hostUrl = value;
        }
    }

    if (sawZoneId) {
        info.parsed = true;
        switch (info.zoneId) {
            case 0: info.zoneName = L"Local Machine"; break;
            case 1: info.zoneName = L"Local Intranet"; break;
            case 2: info.zoneName = L"Trusted Sites"; break;
            case 3: info.zoneName = L"Internet"; break;
            case 4: info.zoneName = L"Restricted Sites"; break;
            default: info.zoneName = L"Unknown Zone"; break;
        }
    } else {
        info.diagnostics.push_back(L"Zone.Identifier stream did not contain a recognizable ZoneId entry.");
    }

    return info;
}

}  // namespace ss
