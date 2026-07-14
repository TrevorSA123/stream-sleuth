// Small formatting helpers for numbers, durations, and classification labels.
#pragma once

#include <string>
#include <chrono>
#include <cstdint>
#include "StreamTypes.h"

namespace ss {

std::wstring FormatDuration(std::chrono::milliseconds ms);
std::wstring FormatCount(uint64_t count);

std::wstring ClassificationToString(StreamClassification c);
std::wstring ClassificationToShortLabel(StreamClassification c);
StreamClassification ClassificationFromString(const std::wstring& s);

std::wstring ZoneIdToName(int zoneId);

// Parses a human size string like "64KB", "1MB", "2048" into bytes.
// Returns true on success.
bool ParseSizeString(const std::wstring& text, uint64_t& outBytes);

}  // namespace ss
