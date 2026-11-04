#pragma once

#include <string>
#include <mutex>
#include <shared_mutex>
#include <system_error>
#include <thread>
#include <chrono>
#include <memory>
#include "merklechain/hash.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace mc::cas {

/**
 * @brief OS-level dual-layer inter-process and inter-thread maintenance barrier.
 *
 * Provides reader-writer synchronization for CAS operations:
 * - Shared (reader) access: For version publishers, submission acceptances,
 *   version reconstructions, and CAS reads.
 * - Exclusive (writer) access: For garbage collection sweeping, reference count
 *   reconciliation, and startup crash recovery.
 *
 * Guarantees:
 * 1. OS-Level Crash Release: On Windows (LockFileEx) and POSIX (flock), file locks
 *    are held by the kernel handle table and automatically released if a process
 *    crashes or terminates (e.g. std::_Exit), preventing hung or stale locks.
 * 2. In-Process Thread Coordination: In-process threads share OS locks via
 *    reference counting protected by a local shared_mutex, avoiding redundant OS calls.
 */
class InterprocessCasBarrier {
public:
    explicit InterprocessCasBarrier(fs::path lock_file_path)
        : lock_file_path_(std::move(lock_file_path)) {}

    ~InterprocessCasBarrier() {
        close_file();
    }

    InterprocessCasBarrier(const InterprocessCasBarrier&) = delete;
    InterprocessCasBarrier& operator=(const InterprocessCasBarrier&) = delete;
    InterprocessCasBarrier(InterprocessCasBarrier&&) = delete;
    InterprocessCasBarrier& operator=(InterprocessCasBarrier&&) = delete;

    void lock_shared() {
        in_proc_mutex_.lock_shared();
        std::lock_guard<std::mutex> lk(os_mutex_);
        if (++in_proc_shared_readers_ == 1) {
            acquire_os_lock(false);
        }
    }

    void unlock_shared() {
        {
            std::lock_guard<std::mutex> lk(os_mutex_);
            if (--in_proc_shared_readers_ == 0) {
                release_os_lock();
            }
        }
        in_proc_mutex_.unlock_shared();
    }

    void lock_exclusive() {
        in_proc_mutex_.lock();
        std::lock_guard<std::mutex> lk(os_mutex_);
        acquire_os_lock(true);
        os_exclusive_held_ = true;
    }

    void unlock_exclusive() {
        {
            std::lock_guard<std::mutex> lk(os_mutex_);
            if (os_exclusive_held_) {
                release_os_lock();
                os_exclusive_held_ = false;
            }
        }
        in_proc_mutex_.unlock();
    }

    const fs::path& lock_file_path() const noexcept { return lock_file_path_; }

private:
    fs::path lock_file_path_;
#ifdef _WIN32
    HANDLE file_handle_{INVALID_HANDLE_VALUE};
#else
    int fd_{-1};
#endif
    mutable std::shared_mutex in_proc_mutex_;
    mutable std::mutex os_mutex_;
    int in_proc_shared_readers_{0};
    bool os_exclusive_held_{false};
    bool os_lock_acquired_{false};

    bool ensure_file_open() {
#ifdef _WIN32
        if (file_handle_ != INVALID_HANDLE_VALUE) return true;
        std::error_code ec;
        fs::create_directories(lock_file_path_.parent_path(), ec);
        file_handle_ = ::CreateFileW(
            lock_file_path_.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        return file_handle_ != INVALID_HANDLE_VALUE;
#else
        if (fd_ >= 0) return true;
        std::error_code ec;
        fs::create_directories(lock_file_path_.parent_path(), ec);
        fd_ = ::open(lock_file_path_.c_str(), O_CREAT | O_RDWR, 0666);
        return fd_ >= 0;
#endif
    }

    void close_file() {
        std::lock_guard<std::mutex> lk(os_mutex_);
        if (os_lock_acquired_) {
            release_os_lock_unlocked();
        }
#ifdef _WIN32
        if (file_handle_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file_handle_);
            file_handle_ = INVALID_HANDLE_VALUE;
        }
#else
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
#endif
    }

    void acquire_os_lock(bool exclusive) {
        if (!ensure_file_open()) return;
#ifdef _WIN32
        OVERLAPPED ov{};
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        const DWORD flags = exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0;
        if (::LockFileEx(file_handle_, flags, 0, 1, 0, &ov)) {
            os_lock_acquired_ = true;
        }
#else
        const int op = exclusive ? LOCK_EX : LOCK_SH;
        if (::flock(fd_, op) == 0) {
            os_lock_acquired_ = true;
        }
#endif
    }

    void release_os_lock() {
        release_os_lock_unlocked();
    }

    void release_os_lock_unlocked() {
        if (!os_lock_acquired_) return;
#ifdef _WIN32
        if (file_handle_ != INVALID_HANDLE_VALUE) {
            OVERLAPPED ov{};
            ov.Offset = 0;
            ov.OffsetHigh = 0;
            ::UnlockFileEx(file_handle_, 0, 1, 0, &ov);
        }
#else
        if (fd_ >= 0) {
            ::flock(fd_, LOCK_UN);
        }
#endif
        os_lock_acquired_ = false;
    }
};

class CasSharedBarrierGuard {
public:
    explicit CasSharedBarrierGuard(InterprocessCasBarrier& barrier) : barrier_(barrier) {
        barrier_.lock_shared();
    }
    ~CasSharedBarrierGuard() {
        barrier_.unlock_shared();
    }
    CasSharedBarrierGuard(const CasSharedBarrierGuard&) = delete;
    CasSharedBarrierGuard& operator=(const CasSharedBarrierGuard&) = delete;
private:
    InterprocessCasBarrier& barrier_;
};

class CasExclusiveBarrierGuard {
public:
    explicit CasExclusiveBarrierGuard(InterprocessCasBarrier& barrier) : barrier_(barrier) {
        barrier_.lock_exclusive();
    }
    ~CasExclusiveBarrierGuard() {
        barrier_.unlock_exclusive();
    }
    CasExclusiveBarrierGuard(const CasExclusiveBarrierGuard&) = delete;
    CasExclusiveBarrierGuard& operator=(const CasExclusiveBarrierGuard&) = delete;
private:
    InterprocessCasBarrier& barrier_;
};

} // namespace mc::cas

