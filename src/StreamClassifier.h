// Rule-based, explainable classification of alternate data streams.
//
// StreamSleuth never claims to detect malware. Classifications describe how
// unusual or noteworthy a stream is and always come with a plain-language
// reason. "Suspicious" and "High Risk Indicator" mean "review recommended",
// not "confirmed malicious".
#pragma once

#include "StreamTypes.h"

namespace ss {

class StreamClassifier {
public:
    static constexpr uint64_t kInterestingSizeThreshold = 64ULL * 1024ULL;   // 64 KB
    static constexpr uint64_t kSuspiciousSizeThreshold = 1024ULL * 1024ULL;  // 1 MB
    static constexpr size_t kSignatureSampleSize = 4096;

    // Classifies the record in place, filling classification, classificationReason,
    // and streamTypeGuess. sampleData/sampleLen is an optional small prefix of the
    // stream's bytes (up to kSignatureSampleSize) used for content hints; pass
    // nullptr/0 if content could not be safely sampled.
    static void Classify(StreamRecord& record, const unsigned char* sampleData, size_t sampleLen);

private:
    static std::wstring GuessStreamType(const StreamRecord& record, const unsigned char* sampleData, size_t sampleLen);
    static bool LooksRandomName(const std::wstring& name);
    static bool ContainsScriptMarkers(const unsigned char* data, size_t len);
    static bool HasPeHeader(const unsigned char* data, size_t len);
};

}  // namespace ss
