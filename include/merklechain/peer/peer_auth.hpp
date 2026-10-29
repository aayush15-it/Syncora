#pragma once

#include "merklechain/peer/peer_config.hpp"

#include <openssl/ssl.h>
#include <string>

namespace mc::peer {

class PeerTlsContext {
public:
    PeerTlsContext(const PeerConfig& config, Role local_role);
    ~PeerTlsContext();
    PeerTlsContext(const PeerTlsContext&) = delete;
    PeerTlsContext& operator=(const PeerTlsContext&) = delete;
    SSL_CTX* get() const noexcept { return context_; }

private:
    SSL_CTX* context_{};
};

// Requires both successful TLS chain validation and an exact configured
// SHA-256 fingerprint pin for the remote leaf certificate.
std::string peer_certificate_fingerprint(SSL* connection);
void verify_authenticated_peer(SSL* connection, const std::string& expected_sha256);

} // namespace mc::peer
