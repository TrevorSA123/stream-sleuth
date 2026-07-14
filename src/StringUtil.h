// Small string helper functions used throughout StreamSleuth.
#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace ss {

std::wstring Utf8ToWide(const std::string& utf8);
std::string WideToUtf8(const std::wstring& wide);

std::wstring ToLower(const std::wstring& s);
std::wstring Trim(const std::wstring& s);

bool EndsWithIgnoreCase(const std::wstring& s, const std::wstring& suffix);
bool StartsWithIgnoreCase(const std::wstring& s, const std::wstring& prefix);
bool ContainsIgnoreCase(const std::wstring& haystack, const std::wstring& needle);
bool EqualsIgnoreCase(const std::wstring& a, const std::wstring& b);

std::vector<std::wstring> SplitLines(const std::wstring& text);
std::vector<std::wstring> Split(const std::wstring& text, wchar_t delimiter);

// Returns true if the buffer looks like printable/text content (heuristic).
bool LooksLikeText(const unsigned char* data, size_t length);

// Normalizes line endings to \r\n. Raw Win32 EDIT controls only render \r\n
// as a line break, so any text with bare \n (Unix-style file content, etc.)
// needs this before being handed to SetWindowTextW on a multiline EDIT.
std::wstring NormalizeToCrlf(const std::wstring& text);

std::wstring FormatByteSize(unsigned long long bytes);

}  // namespace ss
