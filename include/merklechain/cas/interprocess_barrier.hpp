#pragma once

#include <string>
#include <mutex>
#include <shared_mutex>
#include <system_error>
#include <thread>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <stdexcept>
#include <sstream>
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
#include <errno.h>
#include <cstring>
#endif

namespace mc::cas {

/**
 * @brief Explicit outcome of an OS-level file lock acquisition attempt.
 */
enum class BarrierLockStatus {
    Acquired,              ///< Lock successfully acquired and verified
    Contended,             ///< Lock currently held by another thread or process (timeout/try_lock)
    OperatingSystemError   ///< OS-level failure (e.g. access denied, invalid handle, directory missing)
};

/**
 * @brief Exception thrown when an interprocess lock acquisition fails.
 */
class InterprocessLockException : public std::runtime_error {
public:
    explicit InterprocessLockException(const std::string& msg, BarrierLockStatus status = BarrierLockStatus::OperatingSystemError)
        : std::runtime_error(msg), status_(status) {}

    BarrierLockStatus status() const noexcept { return status_; }

private:
    BarrierLockStatus status_;
};

/**
 * @brief Test fault-injection points for verifying barrier failure paths.
 */
enum class BarrierFaultPoint {
    None,
    FailEnsureFileOpen,
    FailLockShared,
    FailLockExclusive,
    FailUnlock
};

inline BarrierFaultPoint& barrier_fault_point_ref() noexcept {
    static BarrierFaultPoint fp = BarrierFaultPoint::None;
    return fp;
}

inline void set_barrier_fault_point_for_testing(BarrierFaultPoint fp) noexcept {
    barrier_fault_point_ref() = fp;
}

inline BarrierFaultPoint get_barrier_fault_point_for_testing() noexcept {
    return barrier_fault_point_ref();
}

/**
 * @brief OS-level dual-layer inter-process and inter-thread maintenance barrier.
 *
 * Provides fail-closed reader-writer synchronization for CAS operations:
 * - Shared (reader) access: For version publishers, submission acceptances,
 *   version reconstructions, and CAS reads.
 * - Exclusive (writer) access: For garbage collection sweeping, reference count
 *   reconciliation, and startup crash recovery.
 *
 * Guarantees:
 * 1. Fail-Closed Safety: If the underlying OS lock cannot be acquired, execution
 *    NEVER enters the protected section. Local in-process locks are released,
 *    counters are restored, and a typed InterprocessLockException is propagated.
 * 2. OS-Level Crash Release: On Windows (LockFileEx) and POSIX (flock), file locks
 *    are held by the kernel handle table and automatically released if a process
 *    crashes or terminates (e.g. std::_Exit), preventing hung or stale locks.
 * 3. In-Process Thread Coordination: In-process threads share OS locks via
 *    reference counting protected by a local shared_mutex, avoiding redundant OS calls.
 */
class InterprocessCasBarrier {
public:
    explicit InterprocessCasBarrier(fs::path lock_file_path)
        : lock_file_path_(std::move(lock_file_path)) {}

    ~InterprocessCasBarrier() {
        close_file();
        shared_depth_map().erase(this);
    }

    InterprocessCasBarrier(const InterprocessCasBarrier&) = delete;
    InterprocessCasBarrier& operator=(const InterprocessCasBarrier&) = delete;
    InterprocessCasBarrier(InterprocessCasBarrier&&) = delete;
    InterprocessCasBarrier& operator=(InterprocessCasBarrier&&) = delete;

    /**
     * @brief Acquires a shared lock. Fails closed and throws InterprocessLockException
     *        if the OS lock cannot be acquired.
     */
    void lock_shared() {
        auto& depth = shared_depth_map()[this];
        if (depth > 0) {
            ++depth;
            return;
        }

        in_proc_mutex_.lock_shared();
        try {
            std::lock_guard<std::mutex> lk(os_mutex_);
            if (++in_proc_shared_readers_ == 1) {
                const auto st = acquire_os_lock(false, std::chrono::milliseconds(-1));
                if (st != BarrierLockStatus::Acquired) {
                    --in_proc_shared_readers_;
                    std::string err_msg = "InterprocessCasBarrier: failed to acquire shared OS file lock on '" +
                                          lock_file_path_.string() + "': " + last_os_error_message();
                    throw InterprocessLockException(err_msg, st);
                }
            }
        } catch (...) {
            in_proc_mutex_.unlock_shared();
            throw;
        }
        depth = 1;
    }

    /**
     * @brief Attempts to acquire a shared lock with an optional timeout.
     */
    BarrierLockStatus try_lock_shared(std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) {
        auto& depth = shared_depth_map()[this];
        if (depth > 0) {
            ++depth;
            return BarrierLockStatus::Acquired;
        }

        if (!in_proc_mutex_.try_lock_shared()) {
            return BarrierLockStatus::Contended;
        }

        try {
            std::lock_guard<std::mutex> lk(os_mutex_);
            if (++in_proc_shared_readers_ == 1) {
                const auto st = acquire_os_lock(false, timeout);
                if (st != BarrierLockStatus::Acquired) {
                    --in_proc_shared_readers_;
                    in_proc_mutex_.unlock_shared();
                    return st;
                }
            }
        } catch (...) {
            in_proc_mutex_.unlock_shared();
            throw;
        }

        depth = 1;
        return BarrierLockStatus::Acquired;
    }

    void unlock_shared() noexcept {
        auto& map = shared_depth_map();
        auto it = map.find(this);
        if (it == map.end() || it->second <= 0) {
            return;
        }
        if (it->second > 1) {
            --(it->second);
            return;
        }
        it->second = 0;
        {
            std::lock_guard<std::mutex> lk(os_mutex_);
            if (--in_proc_shared_readers_ == 0) {
                release_os_lock_unlocked();
            }
        }
        in_proc_mutex_.unlock_shared();
    }

    /**
     * @brief Acquires an exclusive lock. Fails closed and throws InterprocessLockException
     *        if the OS lock cannot be acquired.
     */
    void lock_exclusive() {
        in_proc_mutex_.lock();
        try {
            std::lock_guard<std::mutex> lk(os_mutex_);
            const auto st = acquire_os_lock(true, std::chrono::milliseconds(-1));
            if (st != BarrierLockStatus::Acquired) {
                std::string err_msg = "InterprocessCasBarrier: failed to acquire exclusive OS file lock on '" +
                                      lock_file_path_.string() + "': " + last_os_error_message();
                throw InterprocessLockException(err_msg, st);
            }
            os_exclusive_held_ = true;
        } catch (...) {
            in_proc_mutex_.unlock();
            throw;
        }
    }

    /**
     * @brief Attempts to acquire an exclusive lock with an optional timeout.
     */
    BarrierLockStatus try_lock_exclusive(std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) {
        if (!in_proc_mutex_.try_lock()) {
            return BarrierLockStatus::Contended;
        }

        try {
            std::lock_guard<std::mutex> lk(os_mutex_);
            const auto st = acquire_os_lock(true, timeout);
            if (st != BarrierLockStatus::Acquired) {
                in_proc_mutex_.unlock();
                return st;
            }
            os_exclusive_held_ = true;
            return BarrierLockStatus::Acquired;
        } catch (...) {
            in_proc_mutex_.unlock();
            throw;
        }
    }

    void unlock_exclusive() noexcept {
        {
            std::lock_guard<std::mutex> lk(os_mutex_);
            if (os_exclusive_held_) {
                release_os_lock_unlocked();
                os_exclusive_held_ = false;
            }
        }
        in_proc_mutex_.unlock();
    }

    const fs::path& lock_file_path() const noexcept { return lock_file_path_; }

    bool is_os_lock_acquired() const noexcept {
        std::lock_guard<std::mutex> lk(os_mutex_);
        return os_lock_acquired_;
    }

private:
    static std::unordered_map<const InterprocessCasBarrier*, int>& shared_depth_map() {
        static thread_local std::unordered_map<const InterprocessCasBarrier*, int> map;
        return map;
    }

    fs::path lock_file_path_;
#ifdef _WIN32
    HANDLE file_handle_{INVALID_HANDLE_VALUE};
    DWORD last_os_error_{0};
#else
    int fd_{-1};
    int last_os_error_{0};
#endif
    mutable std::shared_mutex in_proc_mutex_;
    mutable std::mutex os_mutex_;
    int in_proc_shared_readers_{0};
    bool os_exclusive_held_{false};
    bool os_lock_acquired_{false};

    std::string last_os_error_message() const {
#ifdef _WIN32
        if (last_os_error_ == 0) return "no OS error recorded";
        char buf[256];
        DWORD len = ::FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, last_os_error_, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf, sizeof(buf), NULL);
        if (len > 0) {
            while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' || buf[len - 1] == ' ')) {
                buf[--len] = '\0';
            }
            return std::string(buf) + " (code " + std::to_string(last_os_error_) + ")";
        }
        return "Windows error code " + std::to_string(last_os_error_);
#else
        if (last_os_error_ == 0) return "no OS error recorded";
        return std::string(std::strerror(last_os_error_)) + " (errno " + std::to_string(last_os_error_) + ")";
#endif
    }

    bool ensure_file_open() {
        if (get_barrier_fault_point_for_testing() == BarrierFaultPoint::FailEnsureFileOpen) {
#ifdef _WIN32
            last_os_error_ = ERROR_ACCESS_DENIED;
#else
            last_os_error_ = EACCES;
#endif
            return false;
        }

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
        if (file_handle_ == INVALID_HANDLE_VALUE) {
            last_os_error_ = ::GetLastError();
            return false;
        }
        last_os_error_ = 0;
        return true;
#else
        if (fd_ >= 0) return true;
        std::error_code ec;
        fs::create_directories(lock_file_path_.parent_path(), ec);
        fd_ = ::open(lock_file_path_.c_str(), O_CREAT | O_RDWR, 0666);
        if (fd_ < 0) {
            last_os_error_ = errno;
            return false;
        }
        last_os_error_ = 0;
        return true;
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

    BarrierLockStatus acquire_os_lock(bool exclusive, std::chrono::milliseconds timeout) {
        if (!ensure_file_open()) {
            return BarrierLockStatus::OperatingSystemError;
        }

        const auto fp = get_barrier_fault_point_for_testing();
        if (fp == BarrierFaultPoint::FailLockShared && !exclusive) {
#ifdef _WIN32
            last_os_error_ = ERROR_LOCK_FAILED;
#else
            last_os_error_ = EIO;
#endif
            return BarrierLockStatus::OperatingSystemError;
        }
        if (fp == BarrierFaultPoint::FailLockExclusive && exclusive) {
#ifdef _WIN32
            last_os_error_ = ERROR_LOCK_FAILED;
#else
            last_os_error_ = EIO;
#endif
            return BarrierLockStatus::OperatingSystemError;
        }

#ifdef _WIN32
        OVERLAPPED ov{};
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        const DWORD base_flags = exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0;

        if (timeout < std::chrono::milliseconds(0)) {
            // Indefinite blocking wait
            if (::LockFileEx(file_handle_, base_flags, 0, 1, 0, &ov)) {
                os_lock_acquired_ = true;
                last_os_error_ = 0;
                return BarrierLockStatus::Acquired;
            }
            last_os_error_ = ::GetLastError();
            return BarrierLockStatus::OperatingSystemError;
        }

        // Timed or immediate non-blocking wait
        const auto start = std::chrono::steady_clock::now();
        do {
            if (::LockFileEx(file_handle_, base_flags | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)) {
                os_lock_acquired_ = true;
                last_os_error_ = 0;
                return BarrierLockStatus::Acquired;
            }

            const DWORD err = ::GetLastError();
            if (err != ERROR_LOCK_VIOLATION && err != ERROR_IO_PENDING) {
                last_os_error_ = err;
                return BarrierLockStatus::OperatingSystemError;
            }

            if (timeout == std::chrono::milliseconds(0)) {
                last_os_error_ = err;
                return BarrierLockStatus::Contended;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        } while (std::chrono::steady_clock::now() - start < timeout);

        last_os_error_ = ERROR_LOCK_VIOLATION;
        return BarrierLockStatus::Contended;
#else
        const int base_op = exclusive ? LOCK_EX : LOCK_SH;

        if (timeout < std::chrono::milliseconds(0)) {
            // Indefinite blocking wait
            if (::flock(fd_, base_op) == 0) {
                os_lock_acquired_ = true;
                last_os_error_ = 0;
                return BarrierLockStatus::Acquired;
            }
            last_os_error_ = errno;
            return BarrierLockStatus::OperatingSystemError;
        }

        // Timed or immediate non-blocking wait
        const auto start = std::chrono::steady_clock::now();
        do {
            if (::flock(fd_, base_op | LOCK_NB) == 0) {
                os_lock_acquired_ = true;
                last_os_error_ = 0;
                return BarrierLockStatus::Acquired;
            }

            const int err = errno;
            if (err != EWOULDBLOCK && err != EAGAIN) {
                last_os_error_ = err;
                return BarrierLockStatus::OperatingSystemError;
            }

            if (timeout == std::chrono::milliseconds(0)) {
                last_os_error_ = err;
                return BarrierLockStatus::Contended;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        } while (std::chrono::steady_clock::now() - start < timeout);

        last_os_error_ = EWOULDBLOCK;
        return BarrierLockStatus::Contended;
#endif
    }

    void release_os_lock_unlocked() noexcept {
        if (!os_lock_acquired_) return;

        if (get_barrier_fault_point_for_testing() == BarrierFaultPoint::FailUnlock) {
            // Simulated unlock failure
            return;
        }

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

/**
 * @brief RAII scoped guard for InterprocessCasBarrier shared locks.
 *        Guarantees exception safety: fails closed if lock cannot be acquired.
 */
class CasSharedBarrierGuard {
public:
    explicit CasSharedBarrierGuard(InterprocessCasBarrier& barrier) : barrier_(barrier) {
        barrier_.lock_shared();
        locked_ = true;
    }

    ~CasSharedBarrierGuard() noexcept {
        if (locked_) {
            barrier_.unlock_shared();
        }
    }

    CasSharedBarrierGuard(const CasSharedBarrierGuard&) = delete;
    CasSharedBarrierGuard& operator=(const CasSharedBarrierGuard&) = delete;

private:
    InterprocessCasBarrier& barrier_;
    bool locked_{false};
};

/**
 * @brief RAII scoped guard for InterprocessCasBarrier exclusive locks.
 *        Guarantees exception safety: fails closed if lock cannot be acquired.
 */
class CasExclusiveBarrierGuard {
public:
    explicit CasExclusiveBarrierGuard(InterprocessCasBarrier& barrier) : barrier_(barrier) {
        barrier_.lock_exclusive();
        locked_ = true;
    }

    ~CasExclusiveBarrierGuard() noexcept {
        if (locked_) {
            barrier_.unlock_exclusive();
        }
    }

    CasExclusiveBarrierGuard(const CasExclusiveBarrierGuard&) = delete;
    CasExclusiveBarrierGuard& operator=(const CasExclusiveBarrierGuard&) = delete;

private:
    InterprocessCasBarrier& barrier_;
    bool locked_{false};
};

} // namespace mc::cas
