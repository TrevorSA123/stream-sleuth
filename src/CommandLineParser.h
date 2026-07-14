// Parses StreamSleuth's command line into a structured command. Also used by
// App.cpp to decide whether to show the GUI.
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace ss {

enum class OutputFormat { Table, Csv, Json };

struct ParsedCommand {
    bool showHelp = false;
    bool showVersion = false;
    bool noGui = false;
    bool guiExplicit = false;

    std::wstring initialPath;  // positional path argument for GUI mode

    bool hasScan = false;
    std::wstring scanPath;

    bool hasWatch = false;
    std::wstring watchPath;

    std::optional<bool> recursive;
    std::optional<bool> fast;
    std::optional<bool> incremental;
    std::optional<bool> skipReparsePoints;
    std::optional<bool> includeDirectories;

    bool zoneOnly = false;
    bool suspiciousOnly = false;
    bool highRiskOnly = false;
    bool includeNormal = false;
    bool includeHidden = false;
    bool includeSystem = false;

    bool hasMinSize = false;
    uint64_t minSize = 0;
    bool hasMaxSize = false;
    uint64_t maxSize = 0;

    OutputFormat format = OutputFormat::Table;

    bool hasPreview = false;
    std::wstring previewStreamFullName;

    bool hasRemoveStream = false;
    std::wstring removeStreamFullName;

    bool removeZoneIdentifier = false;
    bool yes = false;

    bool hasExport = false;
    std::wstring exportFile;

    bool verbose = false;

    bool valid = true;
    std::wstring errorMessage;
};

class CommandLineParser {
public:
    static ParsedCommand Parse(const std::vector<std::wstring>& args);
    static std::wstring GetHelpText();
    static std::wstring GetVersionText();
};

}  // namespace ss
