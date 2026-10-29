#include "merklechain/peer/peer_transport.hpp"

#include <openssl/err.h>

#include <array>
#include <climits>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace mc::peer {
namespace {
using Clock = std::chrono::steady_clock;

std::string winsock_error(const char* action) {
    return std::string(action) + " failed (Winsock error " +
           std::to_string(WSAGetLastError()) + ")";
}

std::string tls_error(const char* action, int ssl_error) {
    if (ssl_error == SSL_ERROR_ZERO_RETURN)
        return std::string(action) + ": peer closed the TLS stream";
    const auto code = ERR_get_error();
    if (code == 0)
        return std::string(action) + " failed (TLS error " +
               std::to_string(ssl_error) + ")";
    std::array<char, 256> buffer{};
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return std::string(action) + ": " + buffer.data();
}

void set_nonblocking(SOCKET socket) {
    u_long enabled = 1;
    if (ioctlsocket(socket, FIONBIO, &enabled) == SOCKET_ERROR)
        throw std::runtime_error(winsock_error("setting nonblocking socket mode"));
}

void wait_socket(SOCKET socket, bool write, Clock::time_point deadline,
                 const char* action) {
    for (;;) {
        const auto now = Clock::now();
        if (now >= deadline) throw std::runtime_error(std::string(action) + " timed out");
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        timeval timeout{};
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(remaining);
        timeout.tv_sec = static_cast<long>(seconds.count());
        timeout.tv_usec = static_cast<long>((remaining - seconds).count());
        fd_set read_set;
        fd_set write_set;
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);
        if (write) FD_SET(socket, &write_set);
        else FD_SET(socket, &read_set);
        const int ready = select(0, write ? nullptr : &read_set,
                                 write ? &write_set : nullptr, nullptr, &timeout);
        if (ready > 0) return;
        if (ready == 0) throw std::runtime_error(std::string(action) + " timed out");
        const int error = WSAGetLastError();
        if (error != WSAEINTR)
            throw std::runtime_error(std::string(action) + " select failed (Winsock error " +
                                     std::to_string(error) + ")");
    }
}

Clock::time_point make_deadline(std::uint32_t seconds) {
    return Clock::now() + std::chrono::seconds(seconds);
}

void finish_connect(SOCKET socket, const sockaddr_in& address,
                    Clock::time_point deadline) {
    const int status = ::connect(socket, reinterpret_cast<const sockaddr*>(&address),
                                 static_cast<int>(sizeof(address)));
    if (status == 0) return;
    const int error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEINVAL)
        throw std::runtime_error("peer TCP connect failed (Winsock error " +
                                 std::to_string(error) + ")");
    wait_socket(socket, true, deadline, "peer TCP connect");
    int socket_error = 0;
    int length = static_cast<int>(sizeof(socket_error));
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&socket_error), &length) == SOCKET_ERROR)
        throw std::runtime_error(winsock_error("checking peer TCP connect"));
    if (socket_error != 0)
        throw std::runtime_error("peer TCP connect failed (Winsock error " +
                                 std::to_string(socket_error) + ")");
}

} // namespace

WinsockRuntime::WinsockRuntime() {
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0)
        throw std::runtime_error("Winsock 2.2 initialization failed (error " +
                                 std::to_string(result) + ")");
    if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2) {
        WSACleanup();
        throw std::runtime_error("Winsock 2.2 is unavailable");
    }
    active_ = true;
}

WinsockRuntime::~WinsockRuntime() { if (active_) WSACleanup(); }

WinsockRuntime::WinsockRuntime(WinsockRuntime&& other) noexcept
    : active_(std::exchange(other.active_, false)) {}

WinsockRuntime& WinsockRuntime::operator=(WinsockRuntime&& other) noexcept {
    if (this != &other) {
        if (active_) WSACleanup();
        active_ = std::exchange(other.active_, false);
    }
    return *this;
}

PeerConnection::PeerConnection(const PeerConfig& config)
    : io_timeout_seconds_(config.io_timeout_seconds) {}

PeerConnection::PeerConnection(const PeerConfig& config, SOCKET accepted,
                               PeerTlsContext& tls)
    : io_timeout_seconds_(config.io_timeout_seconds) {
    try {
        socket_ = accepted;
        set_nonblocking(socket_);
        initialize_tls(tls, false);
        handshake(false, config.expected_peer_sha256, config.handshake_timeout_seconds);
    } catch (...) {
        if (ssl_) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        // The caller retains ownership of accepted until construction succeeds.
        socket_ = INVALID_SOCKET;
        throw;
    }
}

PeerConnection::~PeerConnection() { close(); }

PeerConnection::PeerConnection(PeerConnection&& other) noexcept
    : winsock_(std::move(other.winsock_)),
      socket_(std::exchange(other.socket_, INVALID_SOCKET)),
      ssl_(std::exchange(other.ssl_, nullptr)),
      io_timeout_seconds_(other.io_timeout_seconds_),
      decoder_(std::move(other.decoder_)),
      ready_frames_(std::move(other.ready_frames_)) {}

PeerConnection& PeerConnection::operator=(PeerConnection&& other) noexcept {
    if (this != &other) {
        close();
        winsock_ = std::move(other.winsock_);
        socket_ = std::exchange(other.socket_, INVALID_SOCKET);
        ssl_ = std::exchange(other.ssl_, nullptr);
        io_timeout_seconds_ = other.io_timeout_seconds_;
        decoder_ = std::move(other.decoder_);
        ready_frames_ = std::move(other.ready_frames_);
    }
    return *this;
}

void PeerConnection::initialize_tls(PeerTlsContext& tls, bool as_client) {
    if (socket_ == INVALID_SOCKET) throw std::runtime_error("peer TCP socket is not open");
    if (static_cast<std::uint64_t>(socket_) > static_cast<std::uint64_t>(INT_MAX))
        throw std::runtime_error("Winsock socket handle cannot be represented by OpenSSL on this platform");
    ssl_ = SSL_new(tls.get());
    if (!ssl_) throw std::runtime_error(tls_error("creating TLS connection", SSL_ERROR_SSL));
    if (SSL_set_fd(ssl_, static_cast<int>(socket_)) != 1)
        throw std::runtime_error(tls_error("attaching TLS to Winsock socket", SSL_ERROR_SSL));
    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    (void)as_client;
}

void PeerConnection::handshake(bool as_client, const std::string& peer_pin,
                               std::uint32_t timeout_seconds) {
    if (!ssl_) throw std::runtime_error("TLS connection is not initialized");
    const auto deadline = make_deadline(timeout_seconds);
    for (;;) {
        const int result = as_client ? SSL_connect(ssl_) : SSL_accept(ssl_);
        if (result == 1) break;
        const int error = SSL_get_error(ssl_, result);
        if (error == SSL_ERROR_WANT_READ) wait_socket(socket_, false, deadline, "TLS handshake");
        else if (error == SSL_ERROR_WANT_WRITE) wait_socket(socket_, true, deadline, "TLS handshake");
        else throw std::runtime_error(tls_error("TLS handshake", error));
    }
    verify_authenticated_peer(ssl_, peer_pin);
}

PeerConnection PeerConnection::connect(const PeerConfig& config, PeerTlsContext& tls) {
    if (config.role != Role::Client) throw std::runtime_error("peer connect requires client configuration");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config.port);
    if (InetPtonA(AF_INET, config.host_address.c_str(), &address.sin_addr) != 1)
        throw std::runtime_error("peer host_address must be a numeric IPv4 address");

    const auto deadline = make_deadline(config.handshake_timeout_seconds);
    for (;;) {
        PeerConnection connection(config);
        connection.socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connection.socket_ == INVALID_SOCKET)
            throw std::runtime_error(winsock_error("creating peer TCP socket"));
        try {
            set_nonblocking(connection.socket_);
            finish_connect(connection.socket_, address, deadline);
            connection.initialize_tls(tls, true);
            connection.handshake(true, config.expected_peer_sha256, config.handshake_timeout_seconds);
            return connection;
        } catch (const std::exception& e) {
            connection.close();
            const std::string err = e.what();
            if (Clock::now() < deadline &&
                (err.find("10061") != std::string::npos || err.find("10054") != std::string::npos)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
                continue;
            }
            throw;
        }
    }
}

void PeerConnection::write_all(const std::uint8_t* data, std::size_t size,
                               Clock::time_point deadline) {
    std::size_t sent = 0;
    while (sent < size) {
        std::size_t written = 0;
        const int result = SSL_write_ex(ssl_, data + sent, size - sent, &written);
        if (result == 1) {
            if (written == 0) throw std::runtime_error("TLS write made no progress");
            sent += written;
            continue;
        }
        const int error = SSL_get_error(ssl_, result);
        if (error == SSL_ERROR_WANT_READ) wait_socket(socket_, false, deadline, "TLS write");
        else if (error == SSL_ERROR_WANT_WRITE) wait_socket(socket_, true, deadline, "TLS write");
        else throw std::runtime_error(tls_error("TLS write", error));
    }
}

void PeerConnection::send_frame(const Frame& frame) {
    if (!is_open()) throw std::runtime_error("peer TLS connection is closed");
    const auto wire = encode_frame(frame);
    write_all(wire.data(), wire.size(), make_deadline(io_timeout_seconds_));
}

Frame PeerConnection::read_frame(Clock::time_point deadline) {
    std::array<std::uint8_t, 16384> buffer{};
    for (;;) {
        std::size_t received = 0;
        const int result = SSL_read_ex(ssl_, buffer.data(), buffer.size(), &received);
        if (result == 1) {
            if (received == 0) throw std::runtime_error("TLS read made no progress");
            auto frames = decoder_.feed(buffer.data(), received);
            for (auto& frame : frames) ready_frames_.push_back(std::move(frame));
            if (!ready_frames_.empty()) {
                Frame next = std::move(ready_frames_.front());
                ready_frames_.pop_front();
                return next;
            }
            continue;
        }
        const int error = SSL_get_error(ssl_, result);
        if (error == SSL_ERROR_WANT_READ) wait_socket(socket_, false, deadline, "TLS frame read");
        else if (error == SSL_ERROR_WANT_WRITE) wait_socket(socket_, true, deadline, "TLS frame read");
        else if (error == SSL_ERROR_ZERO_RETURN) {
            decoder_.finish();
            throw std::runtime_error("peer disconnected before sending a complete frame");
        } else throw std::runtime_error(tls_error("TLS frame read", error));
    }
}

Frame PeerConnection::receive_frame() {
    if (!is_open()) throw std::runtime_error("peer TLS connection is closed");
    if (!ready_frames_.empty()) {
        Frame next = std::move(ready_frames_.front());
        ready_frames_.pop_front();
        return next;
    }
    return read_frame(make_deadline(io_timeout_seconds_));
}

#ifdef MERKLECHAIN_TESTING
void PeerConnection::send_partial_frame_for_testing(const Frame& frame, std::size_t bytes) {
    const auto wire = encode_frame(frame);
    if (bytes > wire.size()) throw std::runtime_error("test partial-frame length exceeds frame size");
    write_all(wire.data(), bytes, make_deadline(io_timeout_seconds_));
}

void PeerConnection::send_raw_for_testing(const std::uint8_t* data, std::size_t size) {
    if (size > kMaximumFramePayload + kFrameHeaderSize)
        throw std::runtime_error("test raw frame exceeds protocol limit");
    write_all(data, size, make_deadline(io_timeout_seconds_));
}
#endif

void PeerConnection::close() noexcept {
    if (ssl_) {
        // Best-effort bidirectional close_notify with a short hard bound, so
        // normal teardown is orderly without allowing destruction to hang.
        if (socket_ != INVALID_SOCKET && SSL_is_init_finished(ssl_) == 1) {
            const auto deadline = Clock::now() + std::chrono::milliseconds(250);
            for (unsigned int attempt = 0; attempt < 3; ++attempt) {
                const int result = SSL_shutdown(ssl_);
                if (result == 1) break;
                try {
                    if (result == 0) wait_socket(socket_, false, deadline, "TLS shutdown");
                    else {
                        const int error = SSL_get_error(ssl_, result);
                        if (error == SSL_ERROR_WANT_READ) wait_socket(socket_, false, deadline, "TLS shutdown");
                        else if (error == SSL_ERROR_WANT_WRITE) wait_socket(socket_, true, deadline, "TLS shutdown");
                        else break;
                    }
                } catch (...) { break; }
            }
        }
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (socket_ != INVALID_SOCKET) {
        (void)shutdown(socket_, SD_BOTH);
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    decoder_.reset();
    ready_frames_.clear();
}

PeerListener::PeerListener(const PeerConfig& config) : config_(config) {
    if (config.role != Role::Host) throw std::runtime_error("peer listener requires host configuration");
    in_addr bind_address{};
    if (InetPtonA(AF_INET, config.bind_address.c_str(), &bind_address) != 1)
        throw std::runtime_error("peer bind_address must be a numeric IPv4 address");
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) throw std::runtime_error(winsock_error("creating peer listener socket"));
    try {
        BOOL exclusive = TRUE;
        if (setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == SOCKET_ERROR)
            throw std::runtime_error(winsock_error("protecting peer listener port"));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr = bind_address;
        address.sin_port = htons(config.port);
        if (bind(socket_, reinterpret_cast<const sockaddr*>(&address),
                 static_cast<int>(sizeof(address))) == SOCKET_ERROR)
            throw std::runtime_error(winsock_error("binding peer listener"));
        if (listen(socket_, 1) == SOCKET_ERROR)
            throw std::runtime_error(winsock_error("starting peer listener"));
        set_nonblocking(socket_);
    } catch (...) {
        close();
        throw;
    }
}

PeerListener::~PeerListener() { close(); }

PeerConnection PeerListener::accept_authenticated(PeerTlsContext& tls) {
    if (socket_ == INVALID_SOCKET) throw std::runtime_error("peer listener is closed");
    wait_socket(socket_, false, make_deadline(config_.handshake_timeout_seconds), "peer accept");
    SOCKET accepted = accept(socket_, nullptr, nullptr);
    if (accepted == INVALID_SOCKET) throw std::runtime_error(winsock_error("accepting peer connection"));
    try {
        return PeerConnection(config_, accepted, tls);
    } catch (...) {
        closesocket(accepted);
        throw;
    }
}

void PeerListener::close() noexcept {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
}

std::uint16_t PeerListener::local_port() const {
    if (socket_ == INVALID_SOCKET) throw std::runtime_error("peer listener is closed");
    sockaddr_in address{};
    int length = static_cast<int>(sizeof(address));
    if (getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &length) == SOCKET_ERROR)
        throw std::runtime_error(winsock_error("reading peer listener port"));
    return ntohs(address.sin_port);
}

} // namespace mc::peer
