#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "merklechain/collab_broadcaster.hpp"
#include <algorithm>
#include <iostream>

namespace mc {

EventBroadcaster::EventBroadcaster(std::chrono::milliseconds ping_interval)
    : ping_interval_(ping_interval),
      last_ping_time_(std::chrono::steady_clock::now()) {
}

EventBroadcaster::~EventBroadcaster() {
    stop();
}

void EventBroadcaster::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_.load()) return;
    running_.store(true);
    last_ping_time_ = std::chrono::steady_clock::now();
    io_thread_ = std::thread(&EventBroadcaster::io_thread_loop, this);
}

void EventBroadcaster::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        cv_.notify_all();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto s : clients_) {
        SOCKET sock = static_cast<SOCKET>(s);
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
    }
    clients_.clear();
    pending_frames_.clear();
}

void EventBroadcaster::add_client(std::uintptr_t client_socket) {
    if (client_socket == static_cast<std::uintptr_t>(INVALID_SOCKET)) return;

    SOCKET sock = static_cast<SOCKET>(client_socket);
    // Set 2-second send timeout to prevent blocked sends from stalling the I/O thread
    DWORD timeout_ms = 2000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    std::lock_guard<std::mutex> lock(mutex_);
    clients_.push_back(client_socket);
    cv_.notify_all();
}

void EventBroadcaster::broadcast(const CollabEvent& event) {
    std::string frame;
    if (!event.id.empty()) {
        frame += "id: " + event.id + "\n";
    }
    frame += "event: " + event.event_type + "\n";
    frame += "data: " + event.payload_json + "\n\n";

    broadcast_raw(frame);
}

void EventBroadcaster::broadcast_raw(const std::string& raw_frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_.load()) return;

    // Enforce maximum buffer bounds: if pending queue exceeds 512 frames, drop oldest
    if (pending_frames_.size() > 512) {
        pending_frames_.pop_front();
    }
    pending_frames_.push_back(raw_frame);
    cv_.notify_all();
}

std::size_t EventBroadcaster::client_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return clients_.size();
}

bool EventBroadcaster::send_to_socket(std::uintptr_t s, const char* data, std::size_t len) {
    SOCKET sock = static_cast<SOCKET>(s);
    if (sock == INVALID_SOCKET) return false;

    std::size_t sent = 0;
    while (sent < len) {
        int count = send(sock, data + sent, static_cast<int>(len - sent), 0);
        if (count == SOCKET_ERROR || count == 0) {
            return false;
        }
        sent += static_cast<std::size_t>(count);
    }
    return true;
}

void EventBroadcaster::io_thread_loop() {
    while (running_.load()) {
        std::deque<std::string> frames_to_send;
        std::vector<std::uintptr_t> current_clients;

        {
            std::unique_lock<std::mutex> lock(mutex_);
            auto now = std::chrono::steady_clock::now();
            auto time_since_ping = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_ping_time_);
            auto wait_time = (time_since_ping >= ping_interval_)
                                 ? std::chrono::milliseconds(0)
                                 : (ping_interval_ - time_since_ping);

            cv_.wait_for(lock, wait_time, [this]() {
                return !running_.load() || !pending_frames_.empty();
            });

            if (!running_.load()) break;

            now = std::chrono::steady_clock::now();
            if (now - last_ping_time_ >= ping_interval_) {
                pending_frames_.push_back(": ping\n\n");
                last_ping_time_ = now;
            }

            frames_to_send.swap(pending_frames_);
            current_clients = clients_;
        }

        if (frames_to_send.empty() || current_clients.empty()) {
            continue;
        }

        std::vector<std::uintptr_t> failed_clients;

        for (const auto& frame : frames_to_send) {
            for (auto client : current_clients) {
                // If this client already failed in an earlier frame in this batch, skip
                if (std::find(failed_clients.begin(), failed_clients.end(), client) != failed_clients.end()) {
                    continue;
                }

                if (!send_to_socket(client, frame.data(), frame.size())) {
                    failed_clients.push_back(client);
                }
            }
        }

        if (!failed_clients.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto failed : failed_clients) {
                auto it = std::find(clients_.begin(), clients_.end(), failed);
                if (it != clients_.end()) {
                    clients_.erase(it);
                }
                SOCKET sock = static_cast<SOCKET>(failed);
                if (sock != INVALID_SOCKET) {
                    closesocket(sock);
                }
            }
        }
    }
}

} // namespace mc

