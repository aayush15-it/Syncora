#include "merklechain/peer/peer_transport.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <array>
#include <exception>
#include <iostream>
#include <fstream>
#include <memory>
#include <thread>
#include <vector>

namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

Key make_key() {
    KeyContext context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0)
        throw std::runtime_error("test RSA key setup failed");
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(context.get(), &raw) <= 0) throw std::runtime_error("test RSA key generation failed");
    return Key(raw, EVP_PKEY_free);
}

void add_extension(X509* certificate, X509* issuer, int nid, const char* value) {
    X509V3_CTX context{};
    X509V3_set_ctx(&context, issuer ? issuer : certificate, certificate, nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid,
                                                    const_cast<char*>(value));
    if (!extension || X509_add_ext(certificate, extension, -1) != 1) {
        if (extension) X509_EXTENSION_free(extension);
        throw std::runtime_error("test certificate extension generation failed");
    }
    X509_EXTENSION_free(extension);
}

Certificate make_certificate(EVP_PKEY* subject_key, const char* common_name,
                             X509* issuer, EVP_PKEY* issuer_key, long serial,
                             bool is_ca) {
    Certificate certificate(X509_new(), X509_free);
    if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400) ||
        X509_set_pubkey(certificate.get(), subject_key) != 1)
        throw std::runtime_error("test certificate initialization failed");
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    if (!subject || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) != 1)
        throw std::runtime_error("test certificate subject setup failed");
    if (issuer) {
        if (X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer)) != 1)
            throw std::runtime_error("test certificate issuer setup failed");
    } else if (X509_set_issuer_name(certificate.get(), subject) != 1) {
        throw std::runtime_error("test CA self-issuer setup failed");
    }
    add_extension(certificate.get(), issuer, NID_basic_constraints,
                  is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_extension(certificate.get(), issuer, NID_key_usage,
                  is_ca ? "critical,keyCertSign,cRLSign,digitalSignature" :
                          "critical,digitalSignature,keyEncipherment");
    if (!is_ca) add_extension(certificate.get(), issuer, NID_ext_key_usage, "serverAuth,clientAuth");
    if (X509_sign(certificate.get(), issuer_key ? issuer_key : subject_key, EVP_sha256()) <= 0)
        throw std::runtime_error("test certificate signing failed");
    return certificate;
}

void write_identity(const mc::fs::path& key_path, const mc::fs::path& cert_path,
                    EVP_PKEY* key, X509* certificate) {
    std::unique_ptr<FILE, decltype(&fclose)> key_file(_wfopen(key_path.c_str(), L"wb"), fclose);
    std::unique_ptr<FILE, decltype(&fclose)> cert_file(_wfopen(cert_path.c_str(), L"wb"), fclose);
    if (!key_file || !cert_file || PEM_write_PrivateKey(key_file.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
        PEM_write_X509(cert_file.get(), certificate) != 1)
        throw std::runtime_error("test certificate fixture write failed");
}

std::string fingerprint(X509* certificate) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (X509_digest(certificate, EVP_sha256(), digest.data(), &length) != 1 || length != 32)
        throw std::runtime_error("test certificate fingerprint failed");
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned int index = 0; index < length; ++index) {
        result.push_back(hex[digest[index] >> 4U]);
        result.push_back(hex[digest[index] & 0x0fU]);
    }
    return result;
}

bool connect_loopback_with_deadline(SOCKET socket_handle, std::uint16_t port,
                                   int& error, std::string& operation) {
    u_long nonblocking = 1;
    if (ioctlsocket(socket_handle, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        operation = "ioctlsocket(FIONBIO)";
        error = WSAGetLastError();
        return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    (void)InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr);
    if (::connect(socket_handle, reinterpret_cast<const sockaddr*>(&address),
                  static_cast<int>(sizeof(address))) == 0) {
        error = 0;
        operation = "connect";
        return true;
    }
    error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEINVAL) {
        operation = "connect";
        return false;
    }
    fd_set write_set;
    fd_set except_set;
    FD_ZERO(&write_set);
    FD_ZERO(&except_set);
    FD_SET(socket_handle, &write_set);
    FD_SET(socket_handle, &except_set);
    timeval timeout{2, 0};
    const int selected = select(0, nullptr, &write_set, &except_set, &timeout);
    if (selected <= 0) {
        error = selected == 0 ? WSAETIMEDOUT : WSAGetLastError();
        operation = selected == 0 ? "select(connect readiness timeout)" : "select(connect readiness)";
        return false;
    }
    const bool exceptional = FD_ISSET(socket_handle, &except_set) != 0;
    int socket_error = 0;
    int length = static_cast<int>(sizeof(socket_error));
    if (getsockopt(socket_handle, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&socket_error), &length) == SOCKET_ERROR) {
        operation = "getsockopt(SO_ERROR)";
        error = WSAGetLastError();
        return false;
    }
    error = socket_error;
    operation = exceptional ? "select(connect exception)/getsockopt(SO_ERROR)" :
                               "select(connect writable)/getsockopt(SO_ERROR)";
    return socket_error == 0;
}

const char* winsock_error_name(int error) {
    switch (error) {
        case WSAEACCES: return "WSAEACCES";
        case WSAETIMEDOUT: return "WSAETIMEDOUT";
        case WSAEHOSTUNREACH: return "WSAEHOSTUNREACH";
        case WSAENETUNREACH: return "WSAENETUNREACH";
        case WSAECONNREFUSED: return "WSAECONNREFUSED";
        default: return "Winsock error";
    }
}

struct IdentityFiles {
    Key key{nullptr, EVP_PKEY_free};
    Certificate certificate{nullptr, X509_free};
    mc::fs::path key_path;
    mc::fs::path cert_path;
};

IdentityFiles make_ca(const mc::fs::path& directory, const std::string& label) {
    mc::fs::create_directories(directory);
    IdentityFiles files;
    files.key = make_key();
    files.certificate = make_certificate(files.key.get(), label.c_str(), nullptr, nullptr, 1, true);
    files.key_path = directory / (label + "-key.pem");
    files.cert_path = directory / (label + "-cert.pem");
    write_identity(files.key_path, files.cert_path, files.key.get(), files.certificate.get());
    return files;
}

IdentityFiles make_leaf(const mc::fs::path& directory, const std::string& label,
                        X509* ca, EVP_PKEY* ca_key, long serial) {
    IdentityFiles files;
    files.key = make_key();
    files.certificate = make_certificate(files.key.get(), label.c_str(), ca, ca_key, serial, false);
    files.key_path = directory / (label + "-key.pem");
    files.cert_path = directory / (label + "-cert.pem");
    write_identity(files.key_path, files.cert_path, files.key.get(), files.certificate.get());
    return files;
}

} // namespace

void run_peer_transport_tests(const mc::fs::path& fixture_root,
                              void (*check)(bool, const char*),
                              void (*skip)(const char*)) {
    using namespace mc::peer;
    const auto directory = fixture_root / "peer-transport";
    mc::fs::create_directories(directory);
    auto ca = make_ca(directory, "trusted-ca");
    auto rogue_ca = make_ca(directory, "untrusted-ca");
    auto host_identity = make_leaf(directory, "host", ca.certificate.get(), ca.key.get(), 2);
    auto client_identity = make_leaf(directory, "client", ca.certificate.get(), ca.key.get(), 3);
    auto rogue_identity = make_leaf(directory, "rogue-client", rogue_ca.certificate.get(), rogue_ca.key.get(), 4);

    PeerConfig host;
    host.role = Role::Host;
    host.identity = "host";
    host.sync_root = directory;
    host.bind_address = "127.0.0.1";
    host.port = 0;
    host.certificate_file = host_identity.cert_path;
    host.private_key_file = host_identity.key_path;
    host.ca_file = ca.cert_path;
    host.expected_peer_sha256 = fingerprint(client_identity.certificate.get());
    host.handshake_timeout_seconds = 3;
    host.io_timeout_seconds = 3;

    PeerConfig client;
    client.role = Role::Client;
    client.identity = "client";
    client.sync_root = directory;
    client.host_address = "127.0.0.1";
    client.certificate_file = client_identity.cert_path;
    client.private_key_file = client_identity.key_path;
    client.ca_file = ca.cert_path;
    client.expected_peer_sha256 = fingerprint(host_identity.certificate.get());
    client.handshake_timeout_seconds = 3;
    client.io_timeout_seconds = 3;

    std::unique_ptr<PeerTlsContext> host_tls;
    std::unique_ptr<PeerTlsContext> client_tls;
    bool contexts_valid = false;
    try {
        host_tls = std::make_unique<PeerTlsContext>(host, Role::Host);
        client_tls = std::make_unique<PeerTlsContext>(client, Role::Client);
        contexts_valid = true;
    } catch (...) {}
    check(contexts_valid, "OpenSSL loads generated CA-signed host/client certificates and matching private keys");
    PeerConfig mismatched_key = client;
    mismatched_key.private_key_file = host_identity.key_path;
    bool mismatch_rejected = false;
    try { PeerTlsContext invalid(mismatched_key, Role::Client); }
    catch (...) { mismatch_rejected = true; }
    check(mismatch_rejected, "OpenSSL rejects a local certificate paired with the wrong private key");

    // Some managed execution sandboxes prohibit loopback sockets. Detect that
    // explicitly so a policy restriction is reported as skipped coverage,
    // never as a successful TLS test or an application defect. Credential
    // loading above still runs offline in that environment.
    {
        PeerListener probe(host);
        WinsockRuntime runtime;
        const SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int error = socket_handle == INVALID_SOCKET ? WSAGetLastError() : 0;
        std::string operation = socket_handle == INVALID_SOCKET ? "socket" : "connect";
        const bool connected = socket_handle != INVALID_SOCKET &&
            connect_loopback_with_deadline(socket_handle, probe.local_port(), error, operation);
        if (socket_handle != INVALID_SOCKET) closesocket(socket_handle);
        if (!connected) {
            if (error == WSAEACCES || error == WSAETIMEDOUT ||
                error == WSAEHOSTUNREACH || error == WSAENETUNREACH) {
                const auto detail = std::string("peer TLS loopback cases skipped: ") + operation +
                    " to 127.0.0.1:" + std::to_string(probe.local_port()) + " failed with " +
                    winsock_error_name(error) + " (" + std::to_string(error) + ")";
                skip(detail.c_str());
                return;
            }
            check(false, "peer TLS loopback TCP preflight succeeds");
            return;
        }
    }

    {
        PeerListener listener(host);
        client.port = listener.local_port();
        std::exception_ptr server_error;
        std::string received;
        std::string client_error;
        std::thread server([&] {
            try {
                auto connection = listener.accept_authenticated(*host_tls);
                received = connection.receive_frame().payload;
                connection.send_frame(Frame{kProtocolVersion, MessageType::SyncResult, "authenticated"});
            } catch (...) { server_error = std::current_exception(); }
        });
        bool client_ok = false;
        try {
            auto connection = PeerConnection::connect(client, *client_tls);
            connection.send_frame(Frame{kProtocolVersion, MessageType::Hello, "hello"});
            client_ok = connection.receive_frame().payload == "authenticated";
        } catch (const std::exception& error) { client_error = error.what(); }
        server.join();
        if (!client_ok) std::cerr << "peer TLS loopback client diagnostic: " << client_error << "\n";
        if (server_error) {
            try { std::rethrow_exception(server_error); }
            catch (const std::exception& error) { std::cerr << "peer TLS loopback server diagnostic: " << error.what() << "\n"; }
        }
        check(client_ok && !server_error && received == "hello",
              "loopback TLS 1.2+ authenticates both pinned peers and exchanges framed data");
    }

    {
        PeerListener listener(host);
        client.port = listener.local_port();
        PeerConfig wrong_pin = client;
        wrong_pin.expected_peer_sha256.assign(64, '0');
        bool server_authenticated = false;
        std::string client_error;
        std::thread server([&] { try { auto connection = listener.accept_authenticated(*host_tls); server_authenticated = true; } catch (...) {} });
        bool rejected = false;
        try { (void)PeerConnection::connect(wrong_pin, *client_tls); }
        catch (const std::exception& error) { rejected = true; client_error = error.what(); }
        server.join();
        check(rejected && server_authenticated && client_error.find("fingerprint") != std::string::npos,
              "loopback TLS rejects a peer whose certificate pin is wrong");
    }

    {
        PeerListener listener(host);
        client.port = listener.local_port();
        PeerConfig untrusted_client = client;
        untrusted_client.certificate_file = rogue_identity.cert_path;
        untrusted_client.private_key_file = rogue_identity.key_path;
        PeerTlsContext rogue_tls(untrusted_client, Role::Client);
        std::string server_error;
        std::thread server([&] { try { (void)listener.accept_authenticated(*host_tls); }
                                  catch (const std::exception& error) { server_error = error.what(); } });
        bool rejected = false;
        try {
            auto connection = PeerConnection::connect(untrusted_client, rogue_tls);
            (void)connection.receive_frame();
        }
        catch (...) { rejected = true; }
        server.join();
        check(rejected && server_error.find("TLS handshake") != std::string::npos,
              "loopback mutual TLS rejects a certificate signed by an untrusted CA");
    }

    {
        PeerListener listener(host);
        client.port = listener.local_port();
        std::string server_error;
        std::thread server([&] {
            try { (void)listener.accept_authenticated(*host_tls); }
            catch (const std::exception& error) { server_error = error.what(); }
        });
        WinsockRuntime runtime;
        SOCKET raw = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int connect_error = raw == INVALID_SOCKET ? WSAGetLastError() : 0;
        std::string connect_operation = raw == INVALID_SOCKET ? "socket" : "connect";
        const bool connected = raw != INVALID_SOCKET &&
            connect_loopback_with_deadline(raw, client.port, connect_error, connect_operation);
        server.join();
        if (raw != INVALID_SOCKET) closesocket(raw);
        const bool handshake_timed_out = server_error.find("TLS handshake timed out") != std::string::npos;
        if (!connected && (connect_error == WSAEACCES || connect_error == WSAETIMEDOUT ||
                           connect_error == WSAEHOSTUNREACH || connect_error == WSAENETUNREACH))
            skip("peer TLS handshake-timeout case unavailable: OS denied the raw loopback TCP connection");
        else
            check(connected && handshake_timed_out,
                  "loopback TLS handshake times out when a TCP peer sends no TLS records");
    }

    {
        PeerListener listener(host);
        client.port = listener.local_port();
        bool malformed_rejected = false;
        bool connected = false;
        std::thread server([&] {
            try { auto connection = listener.accept_authenticated(*host_tls); (void)connection.receive_frame(); }
            catch (...) { malformed_rejected = true; }
        });
        {
            try {
                auto connection = PeerConnection::connect(client, *client_tls);
                connected = true;
                auto wire = encode_frame(Frame{kProtocolVersion, MessageType::Hello, "bad"});
                wire[0] = static_cast<std::uint8_t>('X');
                connection.send_raw_for_testing(wire.data(), wire.size());
            } catch (...) {}
        }
        server.join();
        check(connected && malformed_rejected, "loopback TLS transport rejects a malformed frame header");
    }

    {
        PeerListener listener(host);
        client.port = listener.local_port();
        bool truncated_rejected = false;
        bool connected = false;
        std::thread server([&] {
            try { auto connection = listener.accept_authenticated(*host_tls); (void)connection.receive_frame(); }
            catch (...) { truncated_rejected = true; }
        });
        {
            try {
                auto connection = PeerConnection::connect(client, *client_tls);
                connected = true;
                connection.send_partial_frame_for_testing(Frame{kProtocolVersion, MessageType::FileData, "partial"}, 7);
            } catch (...) {}
        }
        server.join();
        check(connected && truncated_rejected, "loopback TLS transport rejects disconnect during a framed message");
    }
}
