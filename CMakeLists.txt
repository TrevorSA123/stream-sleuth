cmake_minimum_required(VERSION 3.20)
project(StreamSleuth LANGUAGES CXX RC)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT MSVC)
    message(FATAL_ERROR "StreamSleuth is designed to be built with MSVC.")
endif()

set(STREAMSLEUTH_SOURCES
    src/main.cpp
    src/App.cpp
    src/CommandLineParser.cpp
    src/ConsoleMode.cpp
    src/MainWindow.cpp
    src/AboutDialog.cpp
    src/PreferencesDialog.cpp
    src/ScanOptionsDialog.cpp
    src/StreamEnumerator.cpp
    src/RecursiveStreamScanner.cpp
    src/NtfsUsnFileEnumerator.cpp
    src/UsnStreamChangeTracker.cpp
    src/StreamWatchService.cpp
    src/StreamClassifier.cpp
    src/ZoneIdentifierParser.cpp
    src/StreamPreviewer.cpp
    src/StreamRemovalService.cpp
    src/ScanCoordinator.cpp
    src/PathUtil.cpp
    src/DpiUtil.cpp
    src/FileTimeUtil.cpp
    src/FormatUtil.cpp
    src/CsvWriter.cpp
    src/JsonWriter.cpp
    src/TextReportWriter.cpp
    src/SettingsService.cpp
    src/BaselineStore.cpp
    src/Clipboard.cpp
    src/ShellHelpers.cpp
    src/StringUtil.cpp
    src/Win32ErrorUtil.cpp
)

set(STREAMSLEUTH_HEADERS
    src/App.h
    src/CommandLineParser.h
    src/ConsoleMode.h
    src/MainWindow.h
    src/AboutDialog.h
    src/PreferencesDialog.h
    src/ScanOptionsDialog.h
    src/StreamEnumerator.h
    src/RecursiveStreamScanner.h
    src/NtfsUsnFileEnumerator.h
    src/UsnStreamChangeTracker.h
    src/StreamWatchService.h
    src/StreamClassifier.h
    src/ZoneIdentifierParser.h
    src/StreamPreviewer.h
    src/StreamRemovalService.h
    src/ScanCoordinator.h
    src/PathUtil.h
    src/DpiUtil.h
    src/FileTimeUtil.h
    src/FormatUtil.h
    src/CsvWriter.h
    src/JsonWriter.h
    src/TextReportWriter.h
    src/SettingsService.h
    src/BaselineStore.h
    src/Clipboard.h
    src/ShellHelpers.h
    src/StringUtil.h
    src/Win32ErrorUtil.h
    src/StreamTypes.h
    src/Handle.h
)

add_executable(StreamSleuth WIN32
    ${STREAMSLEUTH_SOURCES}
    ${STREAMSLEUTH_HEADERS}
    resources/StreamSleuth.rc
)

target_include_directories(StreamSleuth PRIVATE src)

target_compile_definitions(StreamSleuth PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
)

if(MSVC)
    target_compile_options(StreamSleuth PRIVATE /W4 /permissive- /utf-8)
endif()

target_link_libraries(StreamSleuth PRIVATE
    user32
    gdi32
    comctl32
    comdlg32
    shell32
    shlwapi
    advapi32
    ole32
    kernel32
)

set_target_properties(StreamSleuth PROPERTIES
    OUTPUT_NAME "StreamSleuth"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    # The application manifest (DPI awareness, asInvoker execution level) is
    # embedded manually via resources/StreamSleuth.rc, so disable the linker's
    # automatic manifest generation to avoid a duplicate MANIFEST resource.
    LINK_FLAGS "/MANIFEST:NO"
)

source_group("Source Files" FILES ${STREAMSLEUTH_SOURCES})
source_group("Header Files" FILES ${STREAMSLEUTH_HEADERS})
