// Path parsing and manipulation helpers, including careful handling of NTFS
// alternate data stream path syntax (host:stream:type) versus drive-letter colons.
#pragma once

#include <windows.h>
#include <string>

namespace ss {

// Applies the \\?\ long path prefix where useful/safe. Leaves UNC and already
// prefixed paths alone. Does not prefix paths shorter than MAX_PATH unless
// they are already absolute, since the prefix disables some path processing.
std::wstring ToExtendedLengthPath(const std::wstring& path);

// Strips a \\?\ or \\?\UNC\ prefix for display purposes.
std::wstring ToDisplayPath(const std::wstring& path);

std::wstring GetFileNamePart(const std::wstring& hostPath);
std::wstring GetExtensionPart(const std::wstring& hostPath);
std::wstring GetParentDirectory(const std::wstring& hostPath);

// Returns the volume root for a path, e.g. "C:\" for "C:\Users\foo" or a UNC
// or volume-GUID prefix. Returns empty string if it cannot be determined.
std::wstring GetVolumeRootPath(const std::wstring& path);

bool PathExistsOnDisk(const std::wstring& path);
bool IsDirectoryPath(const std::wstring& path);
bool IsReparsePointPath(const std::wstring& path);

// Parses a raw name returned by FindFirstStreamW/FindNextStreamW, which looks
// like ":streamname:$DATA". Splits into stream name and stream type. Returns
// false if the entry is the unnamed default data stream (::$DATA) or cannot
// be parsed.
bool ParseFindStreamName(const std::wstring& rawStreamName, std::wstring& outStreamName, std::wstring& outStreamType);

// Builds a full stream path for DISPLAY purposes only: "host:streamname".
// Does not include the :$DATA suffix.
std::wstring BuildDisplayStreamPath(const std::wstring& hostPath, const std::wstring& streamName);

// Builds a stream path suitable for Win32 file APIs (CreateFileW, DeleteFileW):
// "host:streamname:$DATA" (or the supplied stream type). This is the ONLY
// place stream paths should be assembled for actual I/O, to avoid ambiguous
// colon parsing elsewhere in the code base.
std::wstring BuildApiStreamPath(const std::wstring& hostPath, const std::wstring& streamName, const std::wstring& streamType);

// Splits a display-form full stream path ("C:\Temp\file.txt:hidden.bin") back
// into host path and stream name, being careful not to mistake the drive
// letter's colon for the host/stream separator. Returns false if no stream
// separator colon is found beyond the drive letter.
bool SplitDisplayStreamPath(const std::wstring& fullDisplayPath, std::wstring& outHostPath, std::wstring& outStreamName);

bool IsLikelyExecutableExtension(const std::wstring& nameOrExtension);
bool IsLikelyScriptExtension(const std::wstring& nameOrExtension);

// Heuristic: does the path fall under a location commonly associated with
// downloads, temp files, startup, or user-writable execution surfaces?
bool IsUnderSensitiveLocation(const std::wstring& hostPath);

}  // namespace ss
