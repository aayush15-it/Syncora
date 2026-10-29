#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "merklechain/peer/peer_auth.hpp"
#include "merklechain/peer/peer_protocol.hpp"

#include <chrono>
#include <cstdint>
#include <deque>

namespace mc::peer {

class WinsockRuntime {
public:
    WinsockRuntime();
    ~WinsockRuntime();
    WinsockRuntime(const WinsockRuntime&) = delete;
    WinsockRuntime& operator=(const WinsockRuntime&) = delete;
    WinsockRuntime(WinsockRuntime&& other) noexcept;
    WinsockRuntime& operator=(WinsockRuntime&& other) noexcept;

private:
    bool active_{false};
};

// One authenticated TLS stream. The context must outlive this connection.
// All socket and TLS operations use finite configured deadlines.
class PeerConnection {
public:
    ~PeerConnection();
    PeerConnection(const PeerConnection&) = delete;
    PeerConnection& operator=(const PeerConnection&) = delete;
    PeerConnection(PeerConnection&& other) noexcept;
    PeerConnection& operator=(PeerConnection&& other) noexcept;

    static PeerConnection connect(const PeerConfig& config, PeerTlsContext& tls);
    void send_frame(const Frame& frame);
    Frame receive_frame();
    void close() noexcept;
    bool is_open() const noexcept { return socket_ != INVALID_SOCKET && ssl_ != nullptr; }

#ifdef MERKLECHAIN_TESTING
    void send_partial_frame_for_testing(const Frame& frame, std::size_t bytes);
    void send_raw_for_testing(const std::uint8_t* data, std::size_t size);
#endif

private:
    friend class PeerListener;
    explicit PeerConnection(const PeerConfig& config);
    PeerConnection(const PeerConfig& config, SOCKET accepted, PeerTlsContext& tls);
    void initialize_tls(PeerTlsContext& tls, bool as_client);
    void handshake(bool as_client, const std::string& peer_pin, std::uint32_t timeout_seconds);
    void write_all(const std::uint8_t* data, std::size_t size,
                   std::chrono::steady_clock::time_point deadline);
    Frame read_frame(std::chrono::steady_clock::time_point deadline);

    WinsockRuntime winsock_;
    SOCKET socket_{INVALID_SOCKET};
    SSL* ssl_{};
    std::uint32_t io_timeout_seconds_{30};
    FrameDecoder decoder_;
    std::deque<Frame> ready_frames_;
};

// A deliberately single-accept listener: callers decide when to accept the
// next peer. This avoids an implicit, unbounded worker/thread pool.
class PeerListener {
public:
    explicit PeerListener(const PeerConfig& config);
    ~PeerListener();
    PeerListener(const PeerListener&) = delete;
    PeerListener& operator=(const PeerListener&) = delete;

    PeerConnection accept_authenticated(PeerTlsContext& tls);
    void close() noexcept;
    std::uint16_t local_port() const;

private:
    WinsockRuntime winsock_;
    SOCKET socket_{INVALID_SOCKET};
    PeerConfig config_;
};

} // namespace mc::peer
