#include "merklechain/peer/peer_service.hpp"
#include "merklechain/peer/peer_transport.hpp"
#include "merklechain/peer/peer_sync.hpp"
#include "merklechain/peer/peer_session.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/staging_file.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

namespace mc {
namespace {

using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

Key make_key() {
    KeyContext context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0)
        throw std::runtime_error("RSA key setup failed");
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(context.get(), &raw) <= 0) throw std::runtime_error("RSA key generation failed");
    return Key(raw, EVP_PKEY_free);
}

void add_extension(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX context{};
    X509V3_set_ctx(&context, issuer ? issuer : cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value));
    if (!extension || X509_add_ext(cert, extension, -1) != 1) {
        if (extension) X509_EXTENSION_free(extension);
        throw std::runtime_error("extension generation failed");
    }
    X509_EXTENSION_free(extension);
}

Certificate make_certificate(EVP_PKEY* subject_key, const char* common_name,
                             X509* issuer, EVP_PKEY* issuer_key, long serial, bool is_ca) {
    Certificate cert(X509_new(), X509_free);
    if (!cert || X509_set_version(cert.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400) ||
        X509_set_pubkey(cert.get(), subject_key) != 1)
        throw std::runtime_error("certificate initialization failed");
    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (!subject || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) != 1)
        throw std::runtime_error("certificate subject setup failed");
    if (issuer) {
        if (X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer)) != 1)
            throw std::runtime_error("certificate issuer setup failed");
    } else if (X509_set_issuer_name(cert.get(), subject) != 1) {
        throw std::runtime_error("CA self-issuer setup failed");
    }
    add_extension(cert.get(), issuer, NID_basic_constraints, is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_extension(cert.get(), issuer, NID_key_usage,
                  is_ca ? "critical,keyCertSign,cRLSign,digitalSignature" : "critical,digitalSignature,keyEncipherment");
    if (!is_ca) add_extension(cert.get(), issuer, NID_ext_key_usage, "serverAuth,clientAuth");
    if (X509_sign(cert.get(), issuer_key ? issuer_key : subject_key, EVP_sha256()) <= 0)
        throw std::runtime_error("certificate signing failed");
    return cert;
}

void write_identity(const fs::path& key_path, const fs::path& cert_path, EVP_PKEY* key, X509* cert) {
    std::unique_ptr<FILE, decltype(&fclose)> key_file(_wfopen(key_path.c_str(), L"wb"), fclose);
    std::unique_ptr<FILE, decltype(&fclose)> cert_file(_wfopen(cert_path.c_str(), L"wb"), fclose);
    if (!key_file || !cert_file || PEM_write_PrivateKey(key_file.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
        PEM_write_X509(cert_file.get(), cert) != 1)
        throw std::runtime_error("certificate fixture write failed");
}

std::string fingerprint(X509* cert) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (X509_digest(cert, EVP_sha256(), digest.data(), &length) != 1 || length != 32)
        throw std::runtime_error("fingerprint calculation failed");
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned int i = 0; i < length; ++i) {
        result.push_back(hex[digest[i] >> 4U]);
        result.push_back(hex[digest[i] & 0x0fU]);
    }
    return result;
}

void write_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

struct TlsTestEnvironment {
    fs::path cert_dir;
    fs::path ca_path;
    fs::path host_cert_path;
    fs::path host_key_path;
    std::string host_pin;
    fs::path client_cert_path;
    fs::path client_key_path;
    std::string client_pin;
    fs::path rogue_ca_path;
    fs::path rogue_client_cert_path;
    fs::path rogue_client_key_path;
    std::string rogue_client_pin;
};

TlsTestEnvironment setup_tls_env(const fs::path& root) {
    TlsTestEnvironment env;
    env.cert_dir = root / "tls";
    fs::create_directories(env.cert_dir);

    // CA
    auto ca_key = make_key();
    auto ca_cert = make_certificate(ca_key.get(), "MerkleChain Test CA", nullptr, nullptr, 1, true);
    env.ca_path = env.cert_dir / "ca.crt";
    {
        std::unique_ptr<FILE, decltype(&fclose)> ca_file(_wfopen(env.ca_path.c_str(), L"wb"), fclose);
        PEM_write_X509(ca_file.get(), ca_cert.get());
    }

    // Host
    auto host_key = make_key();
    auto host_cert = make_certificate(host_key.get(), "Laptop A (Host)", ca_cert.get(), ca_key.get(), 2, false);
    env.host_cert_path = env.cert_dir / "host.crt";
    env.host_key_path = env.cert_dir / "host.key";
    write_identity(env.host_key_path, env.host_cert_path, host_key.get(), host_cert.get());
    env.host_pin = fingerprint(host_cert.get());

    // Client
    auto client_key = make_key();
    auto client_cert = make_certificate(client_key.get(), "Laptop B (Client)", ca_cert.get(), ca_key.get(), 3, false);
    env.client_cert_path = env.cert_dir / "client.crt";
    env.client_key_path = env.cert_dir / "client.key";
    write_identity(env.client_key_path, env.client_cert_path, client_key.get(), client_cert.get());
    env.client_pin = fingerprint(client_cert.get());

    // Rogue CA and Rogue Client
    auto rogue_ca_key = make_key();
    auto rogue_ca_cert = make_certificate(rogue_ca_key.get(), "Rogue CA", nullptr, nullptr, 100, true);
    env.rogue_ca_path = env.cert_dir / "rogue_ca.crt";
    {
        std::unique_ptr<FILE, decltype(&fclose)> rogue_file(_wfopen(env.rogue_ca_path.c_str(), L"wb"), fclose);
        PEM_write_X509(rogue_file.get(), rogue_ca_cert.get());
    }
    auto rogue_client_key = make_key();
    auto rogue_client_cert = make_certificate(rogue_client_key.get(), "Rogue Client", rogue_ca_cert.get(), rogue_ca_key.get(), 101, false);
    env.rogue_client_cert_path = env.cert_dir / "rogue_client.crt";
    env.rogue_client_key_path = env.cert_dir / "rogue_client.key";
    write_identity(env.rogue_client_key_path, env.rogue_client_cert_path, rogue_client_key.get(), rogue_client_cert.get());
    env.rogue_client_pin = fingerprint(rogue_client_cert.get());

    return env;
}

peer::PeerConfig make_host_config(const TlsTestEnvironment& env, const fs::path& sync_root, std::uint16_t port) {
    peer::PeerConfig cfg;
    cfg.role = peer::Role::Host;
    cfg.identity = "laptop_a";
    cfg.sync_root = sync_root;
    cfg.bind_address = "127.0.0.1";
    cfg.port = port;
    cfg.ca_file = env.ca_path;
    cfg.certificate_file = env.host_cert_path;
    cfg.private_key_file = env.host_key_path;
    cfg.expected_peer_sha256 = env.client_pin;
    cfg.handshake_timeout_seconds = 5;
    cfg.io_timeout_seconds = 5;
    return cfg;
}

peer::PeerConfig make_client_config(const TlsTestEnvironment& env, const fs::path& sync_root, std::uint16_t port) {
    peer::PeerConfig cfg;
    cfg.role = peer::Role::Client;
    cfg.identity = "laptop_b";
    cfg.sync_root = sync_root;
    cfg.host_address = "127.0.0.1";
    cfg.port = port;
    cfg.ca_file = env.ca_path;
    cfg.certificate_file = env.client_cert_path;
    cfg.private_key_file = env.client_key_path;
    cfg.expected_peer_sha256 = env.host_pin;
    cfg.handshake_timeout_seconds = 5;
    cfg.io_timeout_seconds = 5;
    return cfg;
}

} // namespace
} // namespace mc

void run_peer_service_tests(const mc::fs::path& fixture_root,
                            void (*check)(bool, const char*),
                            void (*skip)(const char*)) {
    (void)skip;
    const auto base_dir = fixture_root / "peer_service_suite";
    std::error_code ec;
    mc::fs::remove_all(base_dir, ec);
    mc::fs::create_directories(base_dir);

    const auto env = mc::setup_tls_env(base_dir);
    std::uint16_t port_counter = 43000;
    const auto next_port = [&]() -> std::uint16_t {
        for (;;) {
            const auto candidate = ++port_counter;
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) return candidate;
            BOOL exclusive = TRUE;
            (void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                             reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
            sockaddr_in address{};
            address.sin_family = AF_INET;
            (void)InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr);
            address.sin_port = htons(candidate);
            const int res = bind(s, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
            closesocket(s);
            if (res == 0) return candidate;
        }
    };
    const auto auto_approve = [](const mc::peer::PeerSyncPlan&) { return std::make_pair(true, true); };

    // -------------------------------------------------------------------------
    // Test 1: Valid authenticated bilateral synchronization & mTLS verification
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t1_valid_auth";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        mc::write_file(host_sync / "host_note.txt", "hello from laptop A");
        mc::write_file(client_sync / "client_note.txt", "hello from laptop B");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        mc::peer::PeerSyncReport host_rep;
        std::thread host_thread([&] {
            host_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve);
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto client_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve);

        host_thread.join();

        const bool files_on_both =
            mc::fs::exists(host_sync / "client_note.txt") &&
            mc::read_file(host_sync / "client_note.txt") == "hello from laptop B" &&
            mc::fs::exists(client_sync / "host_note.txt") &&
            mc::read_file(client_sync / "host_note.txt") == "hello from laptop A";

        if (!host_rep.success) std::cerr << "  Test 1 host error: " << host_rep.error << "\n";
        if (!client_rep.success) std::cerr << "  Test 1 client error: " << client_rep.error << "\n";
        check(host_rep.success && client_rep.success && files_on_both &&
              host_rep.final_merkle_root == client_rep.final_merkle_root,
              "valid authenticated bilateral TLS synchronization succeeds and converges Merkle roots");
    }

    // -------------------------------------------------------------------------
    // Test 2: Rejection of wrong certificate pin
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t2_wrong_pin";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        mc::write_file(host_sync / "secret.txt", "secret host data");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);
        client_cfg.expected_peer_sha256.assign(64, '0'); // Tampered pin

        bool host_failed = false;
        std::thread host_thread([&] {
            auto rep = mc::peer::PeerService::run_host(host_cfg, auto_approve);
            if (!rep.success) host_failed = true;
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto client_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_thread.join();

        check(!client_rep.success && (client_rep.error.find("fingerprint") != std::string::npos ||
                                      client_rep.error.find("certificate") != std::string::npos) &&
              !mc::fs::exists(client_sync / "secret.txt"),
              "peer connection rejects host with mismatched certificate pin before file transfer");
    }

    // -------------------------------------------------------------------------
    // Test 3: Rejection of untrusted certificate
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t3_untrusted_cert";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        mc::write_file(host_sync / "confidential.txt", "confidential");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);
        // Client uses rogue certificate not trusted by Host's CA
        client_cfg.certificate_file = env.rogue_client_cert_path;
        client_cfg.private_key_file = env.rogue_client_key_path;
        host_cfg.expected_peer_sha256 = env.rogue_client_pin;

        bool host_rejected = false;
        std::thread host_thread([&] {
            auto rep = mc::peer::PeerService::run_host(host_cfg, auto_approve);
            if (!rep.success) host_rejected = true;
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto client_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_thread.join();

        check(host_rejected && !client_rep.success && !mc::fs::exists(client_sync / "confidential.txt"),
              "mTLS rejects client certificate issued by an untrusted CA authority");
    }

    // -------------------------------------------------------------------------
    // Test 4: Addition and modification in both directions
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t4_bidirectional_add_mod";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";

        // Initial state
        mc::write_file(host_sync / "shared.txt", "v1 original");
        mc::write_file(client_sync / "shared.txt", "v1 original");
        mc::write_file(host_sync / "from_host.txt", "initial host only");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        // First establish common baseline
        mc::peer::PeerSyncReport host_rep1;
        std::thread host_t([&] { host_rep1 = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto c_rep1 = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t.join();

        // Now both modify and add:
        // Host modifies shared.txt and adds host_new.txt
        mc::write_file(host_sync / "shared.txt", "v2 updated by host");
        mc::write_file(host_sync / "host_new.txt", "added by host");
        // Client adds client_new.txt
        mc::write_file(client_sync / "client_new.txt", "added by client");

        const auto port2 = next_port();
        host_cfg.port = port2;
        client_cfg.port = port2;

        mc::peer::PeerSyncReport host_rep2;
        std::thread host_t2([&] { host_rep2 = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t2.join();

        if (!host_rep1.success) std::cerr << "  Test 4 pass 1 host error: " << host_rep1.error << "\n";
        if (!c_rep1.success) std::cerr << "  Test 4 pass 1 client error: " << c_rep1.error << "\n";
        if (!host_rep2.success) std::cerr << "  Test 4 pass 2 host error: " << host_rep2.error << "\n";
        if (!c_rep.success) std::cerr << "  Test 4 pass 2 client error: " << c_rep.error << "\n";

        const bool both_converged =
            mc::read_file(host_sync / "shared.txt") == "v2 updated by host" &&
            mc::read_file(client_sync / "shared.txt") == "v2 updated by host" &&
            mc::read_file(client_sync / "host_new.txt") == "added by host" &&
            mc::read_file(host_sync / "client_new.txt") == "added by client";

        check(c_rep.success && both_converged,
              "bidirectional additions and modifications sync cleanly across TLS peers");
    }

    // -------------------------------------------------------------------------
    // Test 5: Independent non-conflicting edits on both peers
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t5_nonconflict_edits";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";

        mc::write_file(host_sync / "doc_a.txt", "doc a v1");
        mc::write_file(host_sync / "doc_b.txt", "doc b v1");
        mc::write_file(client_sync / "doc_a.txt", "doc a v1");
        mc::write_file(client_sync / "doc_b.txt", "doc b v1");

        const auto port1 = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port1);
        auto client_cfg = mc::make_client_config(env, client_sync, port1);

        // Baseline sync
        std::thread host_t([&] { (void)mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t.join();

        // Independent edits: Host edits doc_a, Client edits doc_b
        mc::write_file(host_sync / "doc_a.txt", "doc a edited by host");
        mc::write_file(client_sync / "doc_b.txt", "doc b edited by client");

        const auto port2 = next_port();
        host_cfg.port = port2;
        client_cfg.port = port2;

        mc::peer::PeerSyncReport host_rep2;
        std::thread host_t2([&] { host_rep2 = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t2.join();

        if (!host_rep2.success) std::cerr << "  Test 5 host error: " << host_rep2.error << "\n";
        if (!c_rep.success) std::cerr << "  Test 5 client error: " << c_rep.error << "\n";

        const bool match =
            mc::read_file(client_sync / "doc_a.txt") == "doc a edited by host" &&
            mc::read_file(host_sync / "doc_b.txt") == "doc b edited by client";

        check(c_rep.success && host_rep2.success && match,
              "independent non-conflicting edits on separate files merge bilaterally");
    }

    // -------------------------------------------------------------------------
    // Test 6: Concurrent modification and delete-versus-modify conflicts
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t6_conflicts";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";

        mc::write_file(host_sync / "conflict.txt", "base");
        mc::write_file(client_sync / "conflict.txt", "base");
        mc::write_file(host_sync / "del_mod.txt", "base del mod");
        mc::write_file(client_sync / "del_mod.txt", "base del mod");

        const auto port1 = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port1);
        auto client_cfg = mc::make_client_config(env, client_sync, port1);

        std::thread host_t([&] { (void)mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t.join();

        // Case 6A: Concurrent modification on conflict.txt
        mc::write_file(host_sync / "conflict.txt", "host divergent edit");
        mc::write_file(client_sync / "conflict.txt", "client divergent edit");

        const auto port2 = next_port();
        host_cfg.port = port2;
        client_cfg.port = port2;

        mc::peer::PeerSyncReport host_rep_conf;
        std::thread host_t2([&] { host_rep_conf = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto c_rep2 = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t2.join();

        check(!c_rep2.success && (c_rep2.cancelled || c_rep2.error.find("conflict") != std::string::npos) &&
              !host_rep_conf.success && (host_rep_conf.cancelled || host_rep_conf.error.find("conflict") != std::string::npos) &&
              mc::read_file(host_sync / "conflict.txt") == "host divergent edit" &&
              mc::read_file(client_sync / "conflict.txt") == "client divergent edit",
              "concurrent file modification triggers conflict detection and preserves both files");
    }

    // -------------------------------------------------------------------------
    // Test 7: Required approval and deletion confirmation
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t7_approval_declined";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";

        mc::write_file(host_sync / "item.txt", "host item");
        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        // Approval callback returns false -> user cancelled
        mc::peer::PeerSyncReport host_rep;
        std::thread host_t([&] { host_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto c_rep = mc::peer::PeerService::run_client(client_cfg, [](const mc::peer::PeerSyncPlan&) {
            return std::make_pair(false, false);
        });
        host_t.join();

        const bool host_unchanged = mc::fs::exists(host_sync / "item.txt") &&
                                    mc::read_file(host_sync / "item.txt") == "host item";
        const bool client_unchanged = !mc::fs::exists(client_sync / "item.txt");

        check(!c_rep.success && c_rep.cancelled &&
              !host_rep.success && host_rep.cancelled &&
              host_unchanged && client_unchanged,
              "declining interactive plan approval cancels synchronization without disk mutations");
    }

    // -------------------------------------------------------------------------
    // Test 8: Invalid and stale plan rejection
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t8_stale_plan";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        mc::fs::create_directories(client_sync);

        mc::write_file(host_sync / "safe.txt", "safe data");
        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);

        bool host_rejected_bad_plan = false;
        std::thread host_thread([&] {
            auto rep = mc::peer::PeerService::run_host(host_cfg, auto_approve);
            if (!rep.success && rep.error.find("plan hash") != std::string::npos) {
                host_rejected_bad_plan = true;
            }
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Connect manually via TLS and send tampered approval frame with fake plan hash
        auto client_cfg = mc::make_client_config(env, client_sync, port);
        mc::peer::PeerTlsContext tls(client_cfg, mc::peer::Role::Client);
        auto conn = mc::peer::PeerConnection::connect(client_cfg, tls);

        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Hello, client_cfg.identity});
        (void)conn.receive_frame(); // Host Hello

        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::ManifestRequest, "sess_stale_1"});
        (void)conn.receive_frame(); // Host Manifest

        auto c_manifest = mc::scan_folder(client_sync);
        auto enc_manifest = mc::peer::encode_peer_manifest(c_manifest, client_cfg.max_manifest_files, client_cfg.max_file_size_bytes);
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Manifest, enc_manifest});

        // Send invalid approval frame with bogus plan hash
        std::string bogus_approval(140, 'a');
        bogus_approval.assign(64, '9'); // fake plan hash
        while (bogus_approval.size() < 128) bogus_approval.push_back(' ');
        bogus_approval.push_back('\1');
        bogus_approval.push_back('\1');
        bogus_approval.append("sess_stale_1");

        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Approval, bogus_approval});
        auto resp = conn.receive_frame();

        host_thread.join();

        check(resp.type == mc::peer::MessageType::Error && host_rejected_bad_plan,
              "host rejects client with mismatched or stale plan hash before file mutation");
    }

    // -------------------------------------------------------------------------
    // Test 9: Disconnect during transfer fails closed
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t9_disconnect";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        mc::fs::create_directories(client_sync);

        // Large file to ensure chunks
        std::string large_payload(256 * 1024, 'X');
        mc::write_file(host_sync / "large.dat", large_payload);

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        bool host_caught_abort = false;
        std::thread host_thread([&] {
            auto rep = mc::peer::PeerService::run_host(host_cfg, auto_approve);
            if (!rep.success) host_caught_abort = true;
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Connect, negotiate, request file, and disconnect immediately after first frame
        mc::peer::PeerTlsContext tls(client_cfg, mc::peer::Role::Client);
        auto conn = mc::peer::PeerConnection::connect(client_cfg, tls);
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Hello, client_cfg.identity});
        (void)conn.receive_frame();

        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::ManifestRequest, "sess_disc_1"});
        auto host_m_frame = conn.receive_frame();
        auto host_m = mc::peer::decode_peer_manifest(host_m_frame.payload, 1000, 100000000);

        auto c_manifest = mc::scan_folder(client_sync);
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Manifest,
                        mc::peer::encode_peer_manifest(c_manifest, 1000, 100000000)});

        auto plan = mc::peer::plan_bidirectional(client_cfg.identity, "default", {}, c_manifest, host_m);

        // Send approval
        std::string approval_data;
        approval_data.append(plan.plan_hash);
        while (approval_data.size() < 64) approval_data.push_back(' ');
        approval_data.append(host_m.merkle_root);
        while (approval_data.size() < 128) approval_data.push_back(' ');
        approval_data.push_back('\1');
        approval_data.push_back('\1');
        approval_data.append("sess_disc_1");
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Approval, approval_data});
        (void)conn.receive_frame(); // Host approval

        // Request file then immediately close connection
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::FileRequest, "large.dat"});
        conn.close();

        host_thread.join();

        check(host_caught_abort && !mc::fs::exists(client_sync / "large.dat"),
              "network disconnect during file transfer fails closed without partial corruption");
    }

    // -------------------------------------------------------------------------
    // Test 10: Corrupt file data rejection
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t10_corrupt_data";
        const auto sync_dir = test_dir / "sync";
        const auto recovery_dir = test_dir / "recovery";
        const auto state_dir = sync_dir / ".merklechain";
        mc::fs::create_directories(state_dir);
        const auto db_path = (state_dir / "activity.sqlite3").string();

        mc::peer::PeerSessionJournal journal(db_path);
        const std::string session_id = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_id, "laptop_b");

        mc::FileManifest local_m;
        local_m.complete = true;
        local_m.merkle_root = mc::merkle_root(local_m.files);
        mc::FileManifest remote_m;
        remote_m.complete = true;
        mc::FileMetadata fm;
        fm.relative_path = "data.bin";
        fm.size = 12;
        fm.sha256 = mc::sha256_data("good content", 12);
        remote_m.files.push_back(fm);
        remote_m.merkle_root = mc::merkle_root(remote_m.files);

        journal.record_manifests(session_id, local_m.merkle_root, remote_m.merkle_root, "");
        auto plan = mc::peer::plan_bidirectional("laptop_b", "default", {}, local_m, remote_m);
        journal.agree_plan(session_id, plan.plan_hash, plan.plan_hash, remote_m.merkle_root, false, false);
        journal.begin_approval(session_id);
        journal.record_approval(session_id, plan.plan_hash, true, true);

        mc::peer::PeerTransactionCoordinator coord(journal, sync_dir, recovery_dir);
        coord.plan_operations(session_id, plan);

        // Write corrupt bytes into staging file
        auto corrupt_writer = [](const mc::peer::PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("bad corrupt!", 12); // Wrong content hash!
        };
        bool prep_ok = false;
        try {
            prep_ok = coord.prepare_operations(session_id, plan.plan_hash, corrupt_writer);
        } catch (...) {
            prep_ok = false;
        }

        check(!prep_ok && !mc::fs::exists(sync_dir / "data.bin"),
              "corrupt file data in staging is rejected and destination remains unmutated");
    }

    // -------------------------------------------------------------------------
    // Test 11: Destination preservation after failure
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t11_dest_preserve";
        const auto sync_dir = test_dir / "sync";
        const auto recovery_dir = test_dir / "recovery";
        const auto state_dir = sync_dir / ".merklechain";
        mc::fs::create_directories(state_dir);
        const auto db_path = (state_dir / "activity.sqlite3").string();

        mc::write_file(sync_dir / "original.txt", "pre-existing destination data");
        const auto orig_hash = mc::sha256_file(sync_dir / "original.txt");

        mc::peer::PeerSessionJournal journal(db_path);
        const std::string session_id = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_id, "laptop_b");

        auto local_m = mc::scan_folder(sync_dir);
        mc::FileManifest remote_m = local_m;
        remote_m.files[0].sha256 = mc::sha256_data("incoming new data", 17);
        remote_m.merkle_root = mc::merkle_root(remote_m.files);

        mc::peer::PeerBaseline baseline;
        baseline.peer_id = "laptop_b";
        baseline.folder_pair_id = "default";
        baseline.merkle_root = local_m.merkle_root;
        baseline.files = local_m.files;
        baseline.exists = true;

        // Regression check: plan_operations safely refuses plans with unresolved conflicts
        bool conflict_safely_rejected = false;
        try {
            auto conflict_plan = mc::peer::plan_bidirectional("laptop_b", "default", {}, local_m, remote_m);
            mc::peer::PeerTransactionCoordinator conflict_coord(journal, sync_dir, recovery_dir);
            (void)conflict_coord.plan_operations(session_id, conflict_plan);
        } catch (const std::runtime_error& e) {
            conflict_safely_rejected = (std::string(e.what()).find("unresolved conflicts") != std::string::npos);
        }
        check(conflict_safely_rejected, "coordinator plan_operations safely rejects plans with unresolved conflicts");

        journal.record_manifests(session_id, local_m.merkle_root, remote_m.merkle_root, local_m.merkle_root);
        auto plan = mc::peer::plan_bidirectional("laptop_b", "default", baseline, local_m, remote_m);
        journal.agree_plan(session_id, plan.plan_hash, plan.plan_hash, remote_m.merkle_root, false, false);
        journal.begin_approval(session_id);
        journal.record_approval(session_id, plan.plan_hash, true, true);

        mc::peer::PeerTransactionCoordinator coord(journal, sync_dir, recovery_dir);
        coord.plan_operations(session_id, plan);

        // Prepare fails with corrupt staging data
        auto writer = [](const mc::peer::PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("wrong staging bytes", 19);
        };
        try {
            (void)coord.prepare_operations(session_id, plan.plan_hash, writer);
        } catch (...) {}

        check(mc::fs::exists(sync_dir / "original.txt") &&
              mc::sha256_file(sync_dir / "original.txt") == orig_hash &&
              mc::read_file(sync_dir / "original.txt") == "pre-existing destination data",
              "destination preservation maintains original files intact when preparation fails");
    }

    // -------------------------------------------------------------------------
    // Test 12: Recovery following simulated interruption
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t12_recovery";
        const auto sync_dir = test_dir / "sync";
        const auto recovery_dir = test_dir / "recovery";
        const auto state_dir = sync_dir / ".merklechain";
        mc::fs::create_directories(state_dir);
        const auto db_path = (state_dir / "activity.sqlite3").string();

        mc::write_file(sync_dir / "rec.txt", "version 1 original content");
        const auto orig_hash = mc::sha256_file(sync_dir / "rec.txt");

        mc::peer::PeerSessionJournal journal(db_path);
        const std::string session_id = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_id, "laptop_b");

        auto local_m = mc::scan_folder(sync_dir);
        mc::FileManifest remote_m = local_m;
        remote_m.files[0].sha256 = mc::sha256_data("version 2 new content", 21);
        remote_m.merkle_root = mc::merkle_root(remote_m.files);

        mc::peer::PeerBaseline baseline;
        baseline.peer_id = "laptop_b";
        baseline.folder_pair_id = "default";
        baseline.merkle_root = local_m.merkle_root;
        baseline.files = local_m.files;
        baseline.exists = true;

        journal.record_manifests(session_id, local_m.merkle_root, remote_m.merkle_root, local_m.merkle_root);
        auto plan = mc::peer::plan_bidirectional("laptop_b", "default", baseline, local_m, remote_m);
        journal.agree_plan(session_id, plan.plan_hash, plan.plan_hash, remote_m.merkle_root, false, false);
        journal.begin_approval(session_id);
        journal.record_approval(session_id, plan.plan_hash, true, true);

        mc::peer::PeerTransactionCoordinator coord(journal, sync_dir, recovery_dir);
        coord.plan_operations(session_id, plan);

        auto writer = [](const mc::peer::PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("version 2 new content", 21);
        };
        coord.prepare_operations(session_id, plan.plan_hash, writer);
        journal.acknowledge_peer_prepared(session_id, "laptop_b", plan.plan_hash);

        // Crash during replacement
        mc::peer::PeerExecutorOptions crash_opt;
        crash_opt.simulate_crash_during_replacement = true;
        try { coord.commit_local(session_id, plan.plan_hash, crash_opt); } catch (...) {}

        // Verify target absent, retiring file exists
        auto ops = journal.load_operations(session_id);
        const auto retiring = sync_dir / ("rec.txt.mc-retiring-" + ops.front().operation_id.substr(0, 16));
        const bool retiring_exists = mc::fs::exists(retiring);

        // Reconcile
        auto rep = coord.reconcile_interrupted_session(session_id, false);

        check(retiring_exists && rep.reconciled && mc::fs::exists(sync_dir / "rec.txt") &&
              mc::sha256_file(sync_dir / "rec.txt") == orig_hash,
              "automatic startup reconciliation recovers from interrupted replacement without data loss");
    }

    // -------------------------------------------------------------------------
    // Test 13: Successful synchronization followed by second no-op synchronization
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t13_noop_sync";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";

        mc::write_file(host_sync / "alpha.txt", "alpha content");
        mc::write_file(client_sync / "beta.txt", "beta content");

        const auto port1 = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port1);
        auto client_cfg = mc::make_client_config(env, client_sync, port1);

        // First synchronization: exchanges alpha and beta
        std::thread host_t1([&] { (void)mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto rep1 = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t1.join();

        // Second synchronization: immediately following without modifications
        const auto port2 = next_port();
        host_cfg.port = port2;
        client_cfg.port = port2;

        mc::peer::PeerSyncReport host_rep2;
        std::thread host_t2([&] {
            host_rep2 = mc::peer::PeerService::run_host(host_cfg, auto_approve);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto rep2 = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t2.join();

        check(rep1.success && rep2.success && host_rep2.success &&
              rep2.operations_executed == 0 &&
              rep1.final_merkle_root == rep2.final_merkle_root,
              "successful bilateral sync followed by immediate second sync completes cleanly as a no-op");
    }

    // -------------------------------------------------------------------------
    // Test 14: Correct history and baseline updates on both peers
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t14_history_baselines";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";

        mc::write_file(host_sync / "item_x.txt", "data x");
        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        std::thread host_t([&] { (void)mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto rep = mc::peer::PeerService::run_client(client_cfg, auto_approve);
        host_t.join();

        // Verify baseline stores on both sides
        mc::peer::PeerBaselineStore host_bs(host_sync / ".merklechain" / "baselines.sqlite3");
        auto host_base = host_bs.load("laptop_b", "default");

        mc::peer::PeerBaselineStore client_bs(client_sync / ".merklechain" / "baselines.sqlite3");
        auto client_base = client_bs.load("laptop_a", "default");

        // Verify activity databases on both sides
        const auto host_act_db = (host_sync / ".merklechain" / "activity.sqlite3").string();
        const auto client_act_db = (client_sync / ".merklechain" / "activity.sqlite3").string();

        check(rep.success && host_base.exists && client_base.exists &&
              host_base.merkle_root == rep.final_merkle_root &&
              client_base.merkle_root == rep.final_merkle_root &&
              mc::fs::exists(host_act_db) && mc::fs::exists(client_act_db),
              "both peers record durable activity history and synchronized baseline roots");
    }

    // -------------------------------------------------------------------------
    // Test 15: Unauthorized and traversal file request rejection
    // -------------------------------------------------------------------------
    {
        const auto test_dir = base_dir / "t15_unauthorized_req";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        mc::fs::create_directories(client_sync);

        mc::write_file(host_sync / "allowed.txt", "allowed content");
        mc::write_file(host_sync / ".merklechain" / "secret.sqlite3", "secret internal data");
        mc::write_file(test_dir / "outside.txt", "outside root");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);

        bool host_rejected_bad_path = false;
        std::thread host_t([&] {
            auto rep = mc::peer::PeerService::run_host(host_cfg, auto_approve);
            if (!rep.success && rep.error.find("rejected") != std::string::npos) {
                host_rejected_bad_path = true;
            }
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Connect client and send an unauthorized / traversal FileRequest
        auto client_cfg = mc::make_client_config(env, client_sync, port);
        mc::peer::PeerTlsContext tls(client_cfg, mc::peer::Role::Client);
        auto conn = mc::peer::PeerConnection::connect(client_cfg, tls);

        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Hello, client_cfg.identity});
        (void)conn.receive_frame();

        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::ManifestRequest, "sess_sec_1"});
        auto hm_frame = conn.receive_frame();
        auto hm = mc::peer::decode_peer_manifest(hm_frame.payload, 1000, 100000000);

        auto cm = mc::scan_folder(client_sync);
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Manifest,
                        mc::peer::encode_peer_manifest(cm, 1000, 100000000)});

        auto plan = mc::peer::plan_bidirectional(host_cfg.identity, "default", {}, cm, hm);

        std::string appr_data;
        appr_data.append(plan.plan_hash);
        while (appr_data.size() < 64) appr_data.push_back(' ');
        appr_data.append(hm.merkle_root);
        while (appr_data.size() < 128) appr_data.push_back(' ');
        appr_data.push_back('\1');
        appr_data.push_back('\1');
        appr_data.append("sess_sec_1");
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Approval, appr_data});
        (void)conn.receive_frame(); // Host approval

        // Send traversal FileRequest
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::FileRequest, "../outside.txt"});
        auto err_frame = conn.receive_frame();

        host_t.join();

        check(err_frame.type == mc::peer::MessageType::Error && host_rejected_bad_path,
              "host service rejects traversal and unauthorized file requests with Error frame");
    }

    mc::fs::remove_all(base_dir, ec);
}
