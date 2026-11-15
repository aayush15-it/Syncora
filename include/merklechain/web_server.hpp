#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>

namespace mc {

class EventBroadcaster;

class WebServer {
public:
    struct ServerState;

    explicit WebServer(std::uint16_t port = 47831, std::size_t num_workers = 4);
    ~WebServer();

    WebServer(const WebServer&) = delete;
    WebServer& operator=(const WebServer&) = delete;

    void start();
    void stop();
    void wait();

    std::uint16_t port() const { return port_; }
    std::shared_ptr<EventBroadcaster> broadcaster() const { return broadcaster_; }
    bool is_running() const { return running_.load(); }

private:
    void accept_loop();
    void worker_loop();

    std::uint16_t port_;
    std::size_t num_workers_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};

    std::uintptr_t listener_socket_{static_cast<std::uintptr_t>(~0ULL)};
    std::thread accept_thread_;
    std::vector<std::thread> workers_;

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<std::uintptr_t> socket_queue_;

    std::shared_ptr<EventBroadcaster> broadcaster_;
    std::unique_ptr<ServerState> state_;
};

// Runs the multi-threaded HTTP dashboard service bound only to IPv4 loopback.
void run_web_server(std::uint16_t port = 47831);

} // namespace mc
