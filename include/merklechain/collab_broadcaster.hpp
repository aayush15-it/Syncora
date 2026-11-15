#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <deque>
#include <cstdint>
#include "merklechain/collab_store.hpp"

namespace mc {

class EventBroadcaster {
public:
    explicit EventBroadcaster(std::chrono::milliseconds ping_interval = std::chrono::milliseconds(15000));
    ~EventBroadcaster();

    EventBroadcaster(const EventBroadcaster&) = delete;
    EventBroadcaster& operator=(const EventBroadcaster&) = delete;

    void start();
    void stop();

    // Sockets are stored as uintptr_t (SOCKET under Winsock)
    void add_client(std::uintptr_t client_socket);
    void broadcast(const CollabEvent& event);
    void broadcast_raw(const std::string& raw_frame);

    std::size_t client_count() const;
    bool is_running() const { return running_.load(); }

private:
    void io_thread_loop();
    bool send_to_socket(std::uintptr_t s, const char* data, std::size_t len);

    std::chrono::milliseconds ping_interval_;
    std::atomic<bool> running_{false};
    std::thread io_thread_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::uintptr_t> clients_;
    std::deque<std::string> pending_frames_;
    std::chrono::steady_clock::time_point last_ping_time_;
};

} // namespace mc

