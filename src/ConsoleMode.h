// Executes scans, watch mode, preview, and removal without any GUI, writing
// results to stdout and errors to stderr with meaningful process exit codes.
#pragma once

#include "CommandLineParser.h"

namespace ss {

class ConsoleMode {
public:
    // Runs the parsed command and returns the process exit code.
    static int Run(const ParsedCommand& cmd);
};

}  // namespace ss
