#include "merklechain/peer/peer_auth.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <array>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace mc::peer {
namespace {
std::string openssl_error(const char* action) {
    const auto code = ERR_get_error();
    if (code == 0) return std::string(action) + " failed";
    std::array<char, 256> buffer{};
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return std::string(action) + ": " + buffer.data();
}
std::string lower_ascii(std::string value) {
    for (auto& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}
}

PeerTlsContext::PeerTlsContext(const PeerConfig& config, Role local_role) {
    if (config.role != local_role) throw std::runtime_error("peer TLS role does not match its configuration");
    const auto method = local_role == Role::Host ? TLS_server_method() : TLS_client_method();
    context_ = SSL_CTX_new(method);
    if (!context_) throw std::runtime_error(openssl_error("TLS context creation"));
    try {
        if (SSL_CTX_set_min_proto_version(context_, TLS1_2_VERSION) != 1)
            throw std::runtime_error(openssl_error("setting minimum TLS version"));
        SSL_CTX_set_options(context_, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
        if (SSL_CTX_load_verify_locations(context_, config.ca_file.string().c_str(), nullptr) != 1)
            throw std::runtime_error(openssl_error("loading peer trust anchors"));
        if (SSL_CTX_use_certificate_chain_file(context_, config.certificate_file.string().c_str()) != 1)
            throw std::runtime_error(openssl_error("loading local certificate chain"));
        if (SSL_CTX_use_PrivateKey_file(context_, config.private_key_file.string().c_str(), SSL_FILETYPE_PEM) != 1)
            throw std::runtime_error(openssl_error("loading local private key"));
        if (SSL_CTX_check_private_key(context_) != 1)
            throw std::runtime_error(openssl_error("checking certificate/private-key match"));
        int verify_flags = SSL_VERIFY_PEER;
        if (local_role == Role::Host) verify_flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(context_, verify_flags, nullptr);
        SSL_CTX_set_verify_depth(context_, 4);
    } catch (...) {
        SSL_CTX_free(context_);
        context_ = nullptr;
        throw;
    }
}

PeerTlsContext::~PeerTlsContext() { if (context_) SSL_CTX_free(context_); }

std::string peer_certificate_fingerprint(SSL* connection) {
    if (!connection) throw std::runtime_error("TLS connection is missing");
    X509* certificate = SSL_get1_peer_certificate(connection);
    if (!certificate) throw std::runtime_error("peer did not present a certificate");
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    const int ok = X509_digest(certificate, EVP_sha256(), digest.data(), &length);
    X509_free(certificate);
    if (ok != 1 || length != 32) throw std::runtime_error(openssl_error("computing peer certificate fingerprint"));
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < length; ++i) result << std::setw(2) << static_cast<unsigned>(digest[i]);
    return result.str();
}

void verify_authenticated_peer(SSL* connection, const std::string& expected_sha256) {
    if (!connection || SSL_is_init_finished(connection) != 1)
        throw std::runtime_error("peer TLS handshake is incomplete");
    if (SSL_get_verify_result(connection) != X509_V_OK)
        throw std::runtime_error("peer certificate chain validation failed");
    if (expected_sha256.size() != 64) throw std::runtime_error("peer certificate pin must be a SHA-256 fingerprint");
    const auto actual = peer_certificate_fingerprint(connection);
    const auto expected = lower_ascii(expected_sha256);
    if (CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) != 0)
        throw std::runtime_error("peer certificate fingerprint does not match the configured identity");
}

} // namespace mc::peer
