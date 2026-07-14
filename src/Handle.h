// RAII wrappers for native Windows handles used throughout StreamSleuth.
#pragma once

#include <windows.h>
#include <utility>

namespace ss {

// Wraps a HANDLE from CreateFileW / CreateFile2, closed with CloseHandle.
// Treats both nullptr and INVALID_HANDLE_VALUE as "no handle".
class FileHandle {
public:
    FileHandle() noexcept : handle_(INVALID_HANDLE_VALUE) {}
    explicit FileHandle(HANDLE h) noexcept : handle_(h) {}

    ~FileHandle() { Close(); }

    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    FileHandle(FileHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    FileHandle& operator=(FileHandle&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    bool IsValid() const noexcept {
        return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr;
    }

    HANDLE Get() const noexcept { return handle_; }

    void Reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        Close();
        handle_ = h;
    }

    HANDLE Release() noexcept {
        HANDLE h = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return h;
    }

    void Close() noexcept {
        if (IsValid()) {
            CloseHandle(handle_);
        }
        handle_ = INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
};

// Wraps a search handle from FindFirstFileW / FindFirstStreamW, closed with FindClose.
class FindHandle {
public:
    FindHandle() noexcept : handle_(INVALID_HANDLE_VALUE) {}
    explicit FindHandle(HANDLE h) noexcept : handle_(h) {}

    ~FindHandle() { Close(); }

    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;

    FindHandle(FindHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    FindHandle& operator=(FindHandle&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    bool IsValid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }
    HANDLE Get() const noexcept { return handle_; }

    void Reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        Close();
        handle_ = h;
    }

    void Close() noexcept {
        if (IsValid()) {
            FindClose(handle_);
        }
        handle_ = INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
};

// Wraps an HKEY, closed with RegCloseKey.
class RegKeyHandle {
public:
    RegKeyHandle() noexcept : key_(nullptr) {}
    explicit RegKeyHandle(HKEY k) noexcept : key_(k) {}

    ~RegKeyHandle() { Close(); }

    RegKeyHandle(const RegKeyHandle&) = delete;
    RegKeyHandle& operator=(const RegKeyHandle&) = delete;

    RegKeyHandle(RegKeyHandle&& other) noexcept : key_(other.key_) {
        other.key_ = nullptr;
    }

    RegKeyHandle& operator=(RegKeyHandle&& other) noexcept {
        if (this != &other) {
            Close();
            key_ = other.key_;
            other.key_ = nullptr;
        }
        return *this;
    }

    bool IsValid() const noexcept { return key_ != nullptr; }
    HKEY Get() const noexcept { return key_; }
    HKEY* AddressOf() noexcept { return &key_; }

    void Close() noexcept {
        if (key_ != nullptr) {
            RegCloseKey(key_);
        }
        key_ = nullptr;
    }

private:
    HKEY key_;
};

// Generic RAII wrapper for a critical section.
class CriticalSectionLock {
public:
    explicit CriticalSectionLock(CRITICAL_SECTION& cs) noexcept : cs_(cs) {
        EnterCriticalSection(&cs_);
    }
    ~CriticalSectionLock() { LeaveCriticalSection(&cs_); }

    CriticalSectionLock(const CriticalSectionLock&) = delete;
    CriticalSectionLock& operator=(const CriticalSectionLock&) = delete;

private:
    CRITICAL_SECTION& cs_;
};

// RAII wrapper that closes a handle allocated with LocalAlloc via LocalFree.
class LocalMemHandle {
public:
    LocalMemHandle() noexcept : ptr_(nullptr) {}
    explicit LocalMemHandle(HLOCAL p) noexcept : ptr_(p) {}
    ~LocalMemHandle() { Close(); }

    LocalMemHandle(const LocalMemHandle&) = delete;
    LocalMemHandle& operator=(const LocalMemHandle&) = delete;

    HLOCAL Get() const noexcept { return ptr_; }

    void Close() noexcept {
        if (ptr_ != nullptr) {
            LocalFree(ptr_);
        }
        ptr_ = nullptr;
    }

private:
    HLOCAL ptr_;
};

}  // namespace ss
