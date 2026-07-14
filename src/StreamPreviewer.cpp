#include "StreamPreviewer.h"
#include "PathUtil.h"
#include "StringUtil.h"
#include "Win32ErrorUtil.h"
#include "Handle.h"

#include <vector>
#include <cstdio>

namespace ss {

namespace {

std::wstring DetectSignature(const std::vector<unsigned char>& data) {
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') return L"Possible PE executable (MZ header)";
    if (data.size() >= 4 && data[0] == 0x50 && data[1] == 0x4B && (data[2] == 0x03 || data[2] == 0x05 || data[2] == 0x07)) {
        return L"ZIP / Office document container";
    }
    if (data.size() >= 4 && data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) return L"PDF document";
    if (data.size() >= 8 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') return L"PNG image";
    if (data.size() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return L"JPEG image";
    if (data.size() >= 3 && data[0] == 'G' && data[1] == 'I' && data[2] == 'F') return L"GIF image";
    return std::wstring();
}

std::wstring BuildHexDump(const std::vector<unsigned char>& data) {
    std::wstring out;
    wchar_t lineBuf[128];
    for (size_t offset = 0; offset < data.size(); offset += 16) {
        size_t lineLen = std::min<size_t>(16, data.size() - offset);
        std::wstring hexPart;
        std::wstring asciiPart;
        for (size_t i = 0; i < 16; ++i) {
            if (i < lineLen) {
                wchar_t byteBuf[4];
                swprintf_s(byteBuf, L"%02X ", data[offset + i]);
                hexPart += byteBuf;
                unsigned char c = data[offset + i];
                asciiPart += (c >= 0x20 && c < 0x7F) ? static_cast<wchar_t>(c) : L'.';
            } else {
                hexPart += L"   ";
            }
            if (i == 7) hexPart += L" ";
        }
        swprintf_s(lineBuf, L"%08zX  ", offset);
        out += lineBuf;
        out += hexPart;
        out += L" ";
        out += asciiPart;
        out += L"\r\n";
    }
    return out;
}

}  // namespace

PreviewResult StreamPreviewer::Preview(
    const std::wstring& hostPath,
    const std::wstring& streamName,
    const std::wstring& streamType,
    size_t maxBytes) {
    PreviewResult result;

    std::wstring streamPath = BuildApiStreamPath(hostPath, streamName, streamType);
    std::wstring extended = ToExtendedLengthPath(streamPath);

    FileHandle handle(CreateFileW(extended.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!handle.IsValid()) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            result.error = L"Stream no longer exists (it may have been removed since the scan).";
        } else if (err == ERROR_ACCESS_DENIED) {
            result.error = L"Access denied opening stream for preview.";
        } else {
            result.error = L"Could not open stream for preview: " + FormatWinError(err);
        }
        return result;
    }

    LARGE_INTEGER size{};
    if (GetFileSizeEx(handle.Get(), &size)) {
        result.totalStreamSize = static_cast<uint64_t>(size.QuadPart);
    }

    std::vector<unsigned char> data(maxBytes);
    DWORD bytesRead = 0;
    if (!ReadFile(handle.Get(), data.data(), static_cast<DWORD>(maxBytes), &bytesRead, nullptr)) {
        result.error = L"Failed to read stream contents: " + FormatLastError();
        return result;
    }
    data.resize(bytesRead);

    result.bytesPreviewed = bytesRead;
    result.truncated = result.totalStreamSize > bytesRead;
    result.detectedSignature = DetectSignature(data);

    if (data.empty()) {
        result.kind = PreviewContentKind::Empty;
    } else if (LooksLikeText(data.data(), data.size())) {
        result.kind = PreviewContentKind::Text;
        std::string narrow(reinterpret_cast<const char*>(data.data()), data.size());
        result.textContent = Utf8ToWide(narrow);
        if (result.textContent.empty()) {
            result.textContent.assign(narrow.begin(), narrow.end());
        }
    } else {
        result.kind = PreviewContentKind::Hex;
        result.hexDump = BuildHexDump(data);
    }

    result.success = true;
    return result;
}

}  // namespace ss
