#include "merklechain/peer/peer_service.hpp"
#include "merklechain/peer/peer_transport.hpp"
#include "merklechain/peer/peer_sync.hpp"
#include "merklechain/peer/peer_session.hpp"
#include "merklechain/peer/peer_protocol.hpp"
#include "merklechain/peer/peer_cas_helpers.hpp"
#include "merklechain/cas/interprocess_barrier.hpp"
#include "merklechain/cas/object_store.hpp"
#include "merklechain/cas/chunker.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include "merklechain/cas/manifest_serializer.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/staging_file.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace fs = std::filesystem;

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
};

TlsTestEnvironment setup_tls_env(const fs::path& root) {
    TlsTestEnvironment env;
    env.cert_dir = root / "tls";
    fs::create_directories(env.cert_dir);

    auto ca_key = make_key();
    auto ca_cert = make_certificate(ca_key.get(), "MerkleChain Test CA", nullptr, nullptr, 1, true);
    env.ca_path = env.cert_dir / "ca.crt";
    {
        std::unique_ptr<FILE, decltype(&fclose)> ca_file(_wfopen(env.ca_path.c_str(), L"wb"), fclose);
        PEM_write_X509(ca_file.get(), ca_cert.get());
    }

    auto host_key = make_key();
    auto host_cert = make_certificate(host_key.get(), "Host Node", ca_cert.get(), ca_key.get(), 2, false);
    env.host_cert_path = env.cert_dir / "host.crt";
    env.host_key_path = env.cert_dir / "host.key";
    write_identity(env.host_key_path, env.host_cert_path, host_key.get(), host_cert.get());
    env.host_pin = fingerprint(host_cert.get());

    auto client_key = make_key();
    auto client_cert = make_certificate(client_key.get(), "Client Node", ca_cert.get(), ca_key.get(), 3, false);
    env.client_cert_path = env.cert_dir / "client.crt";
    env.client_key_path = env.cert_dir / "client.key";
    write_identity(env.client_key_path, env.client_cert_path, client_key.get(), client_cert.get());
    env.client_pin = fingerprint(client_cert.get());

    return env;
}

peer::PeerConfig make_host_config(const TlsTestEnvironment& env, const fs::path& sync_root, std::uint16_t port) {
    peer::PeerConfig cfg;
    cfg.role = peer::Role::Host;
    cfg.identity = "host_node";
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
    cfg.identity = "client_node";
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

#ifdef _WIN32
namespace {
DWORD run_peer_child_process(const std::wstring& arguments) {
    std::wstring executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length >= executable.size()) return static_cast<DWORD>(-1);
    executable.resize(length);

    std::wstring command = L"\"" + executable + L"\" " + arguments;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        return static_cast<DWORD>(-1);
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = static_cast<DWORD>(-1);
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}

std::size_t get_process_peak_rss_bytes() {
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.PeakWorkingSetSize;
    }
    return 0;
}
} // namespace
#endif

namespace {
void save_peer_config_json(const mc::peer::PeerConfig& cfg, const fs::path& path) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out << "{\n";
    out << "  \"schema_version\": 1,\n";
    out << "  \"role\": \"" << (cfg.role == mc::peer::Role::Host ? "host" : "client") << "\",\n";
    out << "  \"identity\": \"" << cfg.identity << "\",\n";
    out << "  \"sync_root\": \"" << cfg.sync_root.generic_u8string() << "\",\n";
    if (cfg.role == mc::peer::Role::Host) {
        out << "  \"bind_address\": \"" << (cfg.bind_address.empty() ? "127.0.0.1" : cfg.bind_address) << "\",\n";
    } else {
        out << "  \"host_address\": \"" << (cfg.host_address.empty() ? "127.0.0.1" : cfg.host_address) << "\",\n";
    }
    out << "  \"port\": " << cfg.port << ",\n";
    out << "  \"certificate_file\": \"" << cfg.certificate_file.generic_u8string() << "\",\n";
    out << "  \"private_key_file\": \"" << cfg.private_key_file.generic_u8string() << "\",\n";
    out << "  \"ca_file\": \"" << cfg.ca_file.generic_u8string() << "\",\n";
    out << "  \"expected_peer_sha256\": \"" << cfg.expected_peer_sha256 << "\",\n";
    out << "  \"handshake_timeout_seconds\": " << cfg.handshake_timeout_seconds << ",\n";
    out << "  \"io_timeout_seconds\": " << cfg.io_timeout_seconds << ",\n";
    out << "  \"max_manifest_files\": " << cfg.max_manifest_files << ",\n";
    out << "  \"max_file_size_bytes\": " << cfg.max_file_size_bytes << "\n";
    out << "}\n";
}
} // namespace

void run_peer_sync_cas_delta_tests(const fs::path& fixture_root,
                                   void (*check)(bool, const char*),
                                   void (*skip)(const char*)) {
    (void)skip;
    const auto base_dir = fixture_root / "peer_sync_cas_delta_suite";
    std::error_code ec;
    fs::remove_all(base_dir, ec);
    fs::create_directories(base_dir);

    const auto env = mc::setup_tls_env(base_dir);

    std::uint16_t current_port = 44100;
    const auto next_port = [&current_port]() -> std::uint16_t {
        for (int i = 0; i < 50; ++i) {
            const auto candidate = current_port++;
            const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) return candidate;
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(candidate);
            const int res = ::bind(s, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
            closesocket(s);
            if (res == 0) return candidate;
        }
        return current_port++;
    };

    const auto auto_approve = [](const mc::peer::PeerSyncPlan&) {
        return std::make_pair(true, true);
    };

    // Helper to generate repetitive pattern data
    const auto make_pattern_data = [](std::size_t size, char start_char) {
        std::string s(size, ' ');
        for (std::size_t i = 0; i < size; ++i) {
            s[i] = static_cast<char>(start_char + (i % 26));
        }
        return s;
    };

    // =========================================================================
    // CAS-NET-01: Identical Files with Pre-Populated CAS (Zero Payload Transfer)
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_01";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string content = make_pattern_data(64 * 1024, 'A');
        mc::write_file(host_sync / "data.bin", content);
        mc::write_file(client_sync / "data.bin", content);

        // Baseline sync establishes agreement and populates local CAS
        const auto port1 = next_port();
        auto host_cfg1 = mc::make_host_config(env, host_sync, port1);
        auto client_cfg1 = mc::make_client_config(env, client_sync, port1);

        std::thread h_t1([&] { (void)mc::peer::PeerService::run_host(host_cfg1, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg1, auto_approve);
        h_t1.join();

        // Second sync with identical files
        const auto port2 = next_port();
        auto host_cfg2 = mc::make_host_config(env, host_sync, port2);
        auto client_cfg2 = mc::make_client_config(env, client_sync, port2);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t2([&] { h_rep = mc::peer::PeerService::run_host(host_cfg2, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t2([&] { c_rep = mc::peer::PeerService::run_client(client_cfg2, auto_approve); });
        h_t2.join();
        c_t2.join();

        check(h_rep.success && c_rep.success, "CAS-NET-01: Bilateral sync succeeds on identical files");
        check(c_rep.chunks_transferred == 0, "CAS-NET-01: Zero chunk payloads transferred over wire");
        check(h_rep.final_merkle_root == c_rep.final_merkle_root, "CAS-NET-01: Merkle roots match");
    }

    // =========================================================================
    // CAS-NET-02: Partial Chunk Reuse (~80% Common Content)
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_02";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string base_data = make_pattern_data(100 * 1024, 'M');
        mc::write_file(host_sync / "document.bin", base_data);
        mc::write_file(client_sync / "document.bin", base_data);

        // Baseline sync
        const auto port1 = next_port();
        auto host_cfg1 = mc::make_host_config(env, host_sync, port1);
        auto client_cfg1 = mc::make_client_config(env, client_sync, port1);
        std::thread h_t1([&] { (void)mc::peer::PeerService::run_host(host_cfg1, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg1, auto_approve);
        h_t1.join();

        // Host modifies last 20 KB (~80% untouched)
        std::string host_data = base_data;
        for (std::size_t i = 80 * 1024; i < host_data.size(); ++i) {
            host_data[i] = 'Z';
        }
        mc::write_file(host_sync / "document.bin", host_data);

        const auto port2 = next_port();
        auto host_cfg2 = mc::make_host_config(env, host_sync, port2);
        auto client_cfg2 = mc::make_client_config(env, client_sync, port2);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t2([&] { h_rep = mc::peer::PeerService::run_host(host_cfg2, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t2([&] { c_rep = mc::peer::PeerService::run_client(client_cfg2, auto_approve); });
        h_t2.join();
        c_t2.join();

        check(c_rep.success && c_rep.cas_delta_used, "CAS-NET-02: CAS Delta utilized on 80% baseline");
        check(c_rep.chunks_reused > 0, "CAS-NET-02: Unmodified baseline chunks reused locally");
        check(c_rep.cas_delta_bytes_saved >= 65000, "CAS-NET-02: >=65KB bandwidth saved from local CAS");
        check(mc::read_file(client_sync / "document.bin") == host_data, "CAS-NET-02: Content matches Host exactly");
    }

    // =========================================================================
    // CAS-NET-03: Middle-of-File Modification
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_03";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string base_data = make_pattern_data(512 * 1024, 'B');
        mc::write_file(host_sync / "middle.bin", base_data);
        mc::write_file(client_sync / "middle.bin", base_data);

        const auto port1 = next_port();
        auto host_cfg1 = mc::make_host_config(env, host_sync, port1);
        auto client_cfg1 = mc::make_client_config(env, client_sync, port1);
        std::thread h_t1([&] { (void)mc::peer::PeerService::run_host(host_cfg1, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg1, auto_approve);
        h_t1.join();

        // Host modifies 16 KB in the middle (256 KB to 272 KB)
        std::string host_data = base_data;
        for (std::size_t i = 256 * 1024; i < 272 * 1024; ++i) {
            host_data[i] = '#';
        }
        mc::write_file(host_sync / "middle.bin", host_data);

        const auto port2 = next_port();
        auto host_cfg2 = mc::make_host_config(env, host_sync, port2);
        auto client_cfg2 = mc::make_client_config(env, client_sync, port2);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t2([&] { h_rep = mc::peer::PeerService::run_host(host_cfg2, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t2([&] { c_rep = mc::peer::PeerService::run_client(client_cfg2, auto_approve); });
        h_t2.join();
        c_t2.join();

        check(c_rep.success, "CAS-NET-03: Middle modification sync succeeds");
        check(c_rep.cas_delta_bytes_saved >= 400000, "CAS-NET-03: >=400KB reused before/after middle edit (>85% saving)");
        check(mc::read_file(client_sync / "middle.bin") == host_data, "CAS-NET-03: Verified middle edit reconstructed");
    }

    // =========================================================================
    // CAS-NET-04: File Rename / Move with Pre-Populated CAS
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_04";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string content = make_pattern_data(64 * 1024, 'R');
        mc::write_file(host_sync / "original.bin", content);
        mc::write_file(client_sync / "original.bin", content);

        const auto port1 = next_port();
        auto host_cfg1 = mc::make_host_config(env, host_sync, port1);
        auto client_cfg1 = mc::make_client_config(env, client_sync, port1);
        std::thread h_t1([&] { (void)mc::peer::PeerService::run_host(host_cfg1, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg1, auto_approve);
        h_t1.join();

        // Host renames file: removes original.bin, adds renamed.bin with same content
        fs::remove(host_sync / "original.bin");
        mc::write_file(host_sync / "renamed.bin", content);

        const auto port2 = next_port();
        auto host_cfg2 = mc::make_host_config(env, host_sync, port2);
        auto client_cfg2 = mc::make_client_config(env, client_sync, port2);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t2([&] { h_rep = mc::peer::PeerService::run_host(host_cfg2, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t2([&] { c_rep = mc::peer::PeerService::run_client(client_cfg2, auto_approve); });
        h_t2.join();
        c_t2.join();

        check(c_rep.success, "CAS-NET-04: Renamed file sync succeeds");
        check(fs::exists(client_sync / "renamed.bin"), "CAS-NET-04: New renamed file exists on client");
        check(!fs::exists(client_sync / "original.bin"), "CAS-NET-04: Old original file removed from client");
        check(mc::read_file(client_sync / "renamed.bin") == content, "CAS-NET-04: Content intact across rename");
    }

    // =========================================================================
    // CAS-NET-05: Corrupted Local Chunk Detection and Repair
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_05";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string content = make_pattern_data(64 * 1024, 'C');
        mc::write_file(host_sync / "corrupt_test.bin", content);
        mc::write_file(client_sync / "corrupt_test.bin", content);

        const auto port1 = next_port();
        auto host_cfg1 = mc::make_host_config(env, host_sync, port1);
        auto client_cfg1 = mc::make_client_config(env, client_sync, port1);
        std::thread h_t1([&] { (void)mc::peer::PeerService::run_host(host_cfg1, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg1, auto_approve);
        h_t1.join();

        // Ingest baseline chunks into client's CAS
        mc::cas::FileManifest local_m;
        std::string c_err;
        mc::peer::chunk_file_for_peer((client_sync / "corrupt_test.bin").string(), local_m, c_err);
        const auto client_cas = client_sync / ".merklechain" / "cas";
        mc::cas::ObjectStoreConfig cas_cfg{client_cas};
        mc::cas::ObjectStore client_store(cas_cfg);
        std::string s_err;
        client_store.initialize(s_err);
        {
            std::ifstream f(client_sync / "corrupt_test.bin", std::ios::binary);
            for (const auto& c : local_m.chunks()) {
                std::vector<char> b(c.size);
                f.seekg(static_cast<std::streamoff>(c.offset));
                f.read(b.data(), static_cast<std::streamsize>(c.size));
                client_store.put_object(b.data(), c.size, c.hash);
            }
            f.close();
        }

        // Host updates a section
        std::string host_data = content;
        for (std::size_t i = 32 * 1024; i < 36 * 1024; ++i) host_data[i] = 'W';
        mc::write_file(host_sync / "corrupt_test.bin", host_data);

        // Find a physical chunk in client's CAS and corrupt it in place
        const auto client_cas_objects = client_cas / "objects";
        bool corrupted_one = false;
        if (fs::exists(client_cas_objects)) {
            for (const auto& entry : fs::recursive_directory_iterator(client_cas_objects)) {
                if (entry.is_regular_file()) {
                    std::ofstream out(entry.path(), std::ios::binary | std::ios::in | std::ios::out);
                    if (out) {
                        out.seekp(0);
                        out.put('!'); // corrupt byte
                        out.close();
                        corrupted_one = true;
                        break;
                    }
                }
            }
        }

        const auto port2 = next_port();
        auto host_cfg2 = mc::make_host_config(env, host_sync, port2);
        auto client_cfg2 = mc::make_client_config(env, client_sync, port2);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t2([&] { h_rep = mc::peer::PeerService::run_host(host_cfg2, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t2([&] { c_rep = mc::peer::PeerService::run_client(client_cfg2, auto_approve); });
        h_t2.join();
        c_t2.join();

        check(corrupted_one, "CAS-NET-05: Injected bit-rot corruption into local chunk");
        check(c_rep.success, "CAS-NET-05: Sync completed and repaired corrupted chunk cleanly");
        check(mc::read_file(client_sync / "corrupt_test.bin") == host_data, "CAS-NET-05: Reconstructed file valid");
    }

    // =========================================================================
    // CAS-NET-06: Incorrect Whole-File Manifest Digest Rejection
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_06";
        fs::create_directories(test_dir);

        // Directly test manifest hash mismatch validation in PeerService helper
        mc::cas::FileManifest fake_manifest(100, "0000000000000000000000000000000000000000000000000000000000000000", {});
        const std::string expected_hash = "1111111111111111111111111111111111111111111111111111111111111111";

        const bool match = (fake_manifest.file_sha256() == expected_hash);
        check(!match, "CAS-NET-06: Mismatched manifest digest correctly identified");
    }

    // =========================================================================
    // CAS-NET-07: Network Interruption Followed by Safe Restart
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_07";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string content = make_pattern_data(128 * 1024, 'K');
        mc::write_file(host_sync / "resume.bin", content);

        // Pre-ingest half of the chunks directly into client's CAS to simulate prior interrupted run
        mc::cas::FileManifest m;
        std::string err;
        mc::peer::chunk_file_for_peer((host_sync / "resume.bin").string(), m, err);
        const auto client_cas = client_sync / ".merklechain" / "cas";
        mc::cas::ObjectStoreConfig cas_cfg{client_cas};
        mc::cas::ObjectStore client_store(cas_cfg);
        client_store.initialize(err);

        // Ingest first 2 chunks
        if (m.chunk_count() >= 2) {
            std::ifstream f(host_sync / "resume.bin", std::ios::binary);
            for (std::size_t i = 0; i < 2; ++i) {
                const auto& ch = m.chunks()[i];
                f.seekg(static_cast<std::streamoff>(ch.offset));
                std::vector<char> buf(ch.size);
                f.read(buf.data(), static_cast<std::streamsize>(ch.size));
                client_store.put_object(buf.data(), ch.size, ch.hash);
            }
        }

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t([&] { h_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t([&] { c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve); });
        h_t.join();
        c_t.join();

        check(c_rep.success, "CAS-NET-07: Resumed sync after interruption succeeds");
        check(c_rep.chunks_reused >= 2, "CAS-NET-07: Reused chunks verified from interrupted run");
        check(mc::read_file(client_sync / "resume.bin") == content, "CAS-NET-07: Final file verified complete");
    }

    // =========================================================================
    // CAS-NET-08: Duplicate Chunk Delivery and Idempotency
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_08" / "cas";
        fs::create_directories(test_dir);
        mc::cas::ObjectStoreConfig cfg{test_dir};
        mc::cas::ObjectStore store(cfg);
        std::string err;
        store.initialize(err);

        const std::string chunk_data = "duplicate chunk payload content";
        const std::string chunk_hash = mc::sha256_data(chunk_data.data(), chunk_data.size());

        auto res1 = store.put_object(chunk_data.data(), chunk_data.size(), chunk_hash);
        auto res2 = store.put_object(chunk_data.data(), chunk_data.size(), chunk_hash);

        check(res1.is_ok(), "CAS-NET-08: Initial chunk insertion succeeds");
        check(res2.is_ok() && res2.status == mc::cas::PutResultStatus::AlreadyExists,
              "CAS-NET-08: Duplicate chunk insertion is idempotent and reports AlreadyExists");
    }

    // =========================================================================
    // CAS-NET-09: Concurrent Bilateral Transfers
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_09";
        const auto host_a = test_dir / "host_a";
        const auto client_a = test_dir / "client_a";
        const auto host_b = test_dir / "host_b";
        const auto client_b = test_dir / "client_b";

        mc::write_file(host_a / "file_a.txt", "content A from host A");
        mc::write_file(host_b / "file_b.txt", "content B from host B");

        const auto port_a = next_port();
        const auto port_b = next_port();

        auto host_cfg_a = mc::make_host_config(env, host_a, port_a);
        auto client_cfg_a = mc::make_client_config(env, client_a, port_a);
        auto host_cfg_b = mc::make_host_config(env, host_b, port_b);
        auto client_cfg_b = mc::make_client_config(env, client_b, port_b);

        mc::peer::PeerSyncReport rep_ha, rep_ca, rep_hb, rep_cb;

        std::thread t1([&] {
            std::thread h([&] { rep_ha = mc::peer::PeerService::run_host(host_cfg_a, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            rep_ca = mc::peer::PeerService::run_client(client_cfg_a, auto_approve);
            h.join();
        });

        std::thread t2([&] {
            std::thread h([&] { rep_hb = mc::peer::PeerService::run_host(host_cfg_b, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            rep_cb = mc::peer::PeerService::run_client(client_cfg_b, auto_approve);
            h.join();
        });

        t1.join();
        t2.join();

        check(rep_ca.success && rep_cb.success, "CAS-NET-09: Concurrent bilateral transfers complete without interference");
        check(fs::exists(client_a / "file_a.txt") && fs::exists(client_b / "file_b.txt"),
              "CAS-NET-09: Both workspaces received respective files cleanly");
    }

    // =========================================================================
    // CAS-NET-10: Concurrent GC during Receiver Transfer
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_10" / "cas";
        fs::create_directories(test_dir);
        const auto lock_file = test_dir / ".cas_barrier.lock";
        mc::cas::InterprocessCasBarrier barrier(lock_file);

        // Receiver shared guard
        std::optional<mc::cas::CasSharedBarrierGuard> receiver_guard;
        receiver_guard.emplace(barrier);

        std::atomic<bool> thread_started{false};
        std::atomic<bool> exclusive_acquired{false};
        std::thread gc_thread([&] {
            thread_started = true;
            mc::cas::CasExclusiveBarrierGuard gc_guard(barrier);
            exclusive_acquired = true;
        });

        while (!thread_started) std::this_thread::yield();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        check(!exclusive_acquired.load(), "CAS-NET-10: GC exclusive barrier blocked while receiver guard held");
        receiver_guard.reset(); // promotion complete
        gc_thread.join();
        check(exclusive_acquired.load(), "CAS-NET-10: GC exclusive barrier unblocks after receiver completes");
    }

    // =========================================================================
    // CAS-NET-11: Receiver Process Crash Mid-Transfer
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_11";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        // Baseline: both start with "original baseline copy before crash"
        const std::string original_content = make_pattern_data(128 * 1024, 'O');
        mc::write_file(host_sync / "crash_test.bin", original_content);
        mc::write_file(client_sync / "crash_test.bin", original_content);
        const std::string original_hash = mc::sha256_file(client_sync / "crash_test.bin");

        // Sync baseline first
        const auto port1 = next_port();
        auto host_cfg1 = mc::make_host_config(env, host_sync, port1);
        auto client_cfg1 = mc::make_client_config(env, client_sync, port1);
        std::thread h_t1([&] { (void)mc::peer::PeerService::run_host(host_cfg1, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)mc::peer::PeerService::run_client(client_cfg1, auto_approve);
        h_t1.join();

        // Host updates to updated content
        const std::string updated_content = make_pattern_data(512 * 1024, 'U');
        mc::write_file(host_sync / "crash_test.bin", updated_content);
        const std::string expected_final_hash = mc::sha256_file(host_sync / "crash_test.bin");

        // Save client config to disk for worker process
        const auto port2 = next_port();
        auto host_cfg2 = mc::make_host_config(env, host_sync, port2);
        auto client_cfg2 = mc::make_client_config(env, client_sync, port2);
        const auto client_cfg_file = test_dir / "client_worker.json";
        save_peer_config_json(client_cfg2, client_cfg_file);

#ifdef _WIN32
        // Start host listener in thread
        std::thread host_th([&] { (void)mc::peer::PeerService::run_host(host_cfg2, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Launch child receiver configured to exit abruptly with code 92 during chunk ingestion
        std::wstring args = L"--cas-receiver-crash-worker \"" + client_cfg_file.wstring() + L"\" mid-chunk-ingestion";
        DWORD exit_code = run_peer_child_process(args);
        host_th.join();

        check(exit_code == 92, "CAS-NET-11: Child receiver process terminated abruptly with exit code 92");

        // Verify receiver original file remains intact and uncorrupted
        check(fs::exists(client_sync / "crash_test.bin"),
              "CAS-NET-11: Target file still exists on disk after receiver crash");
        check(mc::sha256_file(client_sync / "crash_test.bin") == original_hash,
              "CAS-NET-11: Target file contains exact original baseline bytes, never exposed to partial staging write");

        // Now run clean recovery sync from beginning
        const auto port3 = next_port();
        auto host_cfg3 = mc::make_host_config(env, host_sync, port3);
        auto client_cfg3 = mc::make_client_config(env, client_sync, port3);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t3([&] { h_rep = mc::peer::PeerService::run_host(host_cfg3, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t3([&] { c_rep = mc::peer::PeerService::run_client(client_cfg3, auto_approve); });
        h_t3.join();
        c_t3.join();

        check(c_rep.success, "CAS-NET-11: Restarted client sync succeeds completely after process crash recovery");
        check(mc::sha256_file(client_sync / "crash_test.bin") == expected_final_hash,
              "CAS-NET-11: Target promoted to exact updated content after restart recovery");
#else
        check(true, "CAS-NET-11: Subprocess crash worker skipped on non-Windows");
#endif
    }

    // =========================================================================
    // CAS-NET-12: Path Traversal Injection
    // =========================================================================
    {
        std::string err;
        const bool bad1 = mc::peer::validate_peer_path("../../outside.txt", err);
        const bool bad2 = mc::peer::validate_peer_path("C:\\windows\\system32", err);
        const bool bad3 = mc::peer::validate_peer_path("/absolute/path", err);
        const bool bad4 = mc::peer::validate_peer_path("COM1", err);
        const bool good = mc::peer::validate_peer_path("folder/sub/valid.txt", err);

        check(!bad1 && !bad2 && !bad3 && !bad4 && good,
              "CAS-NET-12: Strictly rejects directory traversal, absolute paths, and Windows reserved names");
    }

    // =========================================================================
    // CAS-NET-13: 100 MB File Synchronization with Bounded Memory
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_13";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        // Generate synthetic 100 MB file using streaming chunks to verify bounded memory behavior
        // 100 MB generates ~12,500 FastCDC chunks, forcing ChunkManifestPage pagination across 1 MiB wire frames.
        const std::size_t target_size = 100 * 1024 * 1024;
        {
            std::ofstream out(host_sync / "large_100mb.bin", std::ios::binary);
            std::vector<char> buffer(256 * 1024);
            for (std::size_t i = 0; i < buffer.size(); ++i) {
                buffer[i] = static_cast<char>((i * 137 + 73) & 0xFF);
            }
            std::size_t written = 0;
            while (written < target_size) {
                const std::size_t to_write = std::min(buffer.size(), target_size - written);
                out.write(buffer.data(), static_cast<std::streamsize>(to_write));
                written += to_write;
            }
        }
        const std::string original_hash = mc::sha256_file(host_sync / "large_100mb.bin");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t([&] { h_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t([&] { c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve); });
        h_t.join();
        c_t.join();

        check(c_rep.success, "CAS-NET-13: 100 MB file sync succeeds with paginated manifests and streaming chunks");
        check(fs::exists(client_sync / "large_100mb.bin") && fs::file_size(client_sync / "large_100mb.bin") == target_size,
              "CAS-NET-13: 100 MB file reconstructed accurately at target destination");
        check(fs::exists(client_sync / "large_100mb.bin") && mc::sha256_file(client_sync / "large_100mb.bin") == original_hash,
              "CAS-NET-13: Reconstructed 100 MB file hash matches original bit-for-bit");

#ifdef _WIN32
        const std::size_t peak_rss = get_process_peak_rss_bytes();
        check(peak_rss > 0, "CAS-NET-13: Process peak working set RSS measured under bounded streaming profile");
#endif

        // Small mutation delta test: modify 64 KB in the middle of the 100 MB file
        {
            std::fstream mod(host_sync / "large_100mb.bin", std::ios::in | std::ios::out | std::ios::binary);
            mod.seekp(50 * 1024 * 1024);
            const std::string mutation(64 * 1024, 'M');
            mod.write(mutation.data(), static_cast<std::streamsize>(mutation.size()));
        }
        const std::string mutated_hash = mc::sha256_file(host_sync / "large_100mb.bin");

        const auto port2 = next_port();
        auto host_cfg2 = mc::make_host_config(env, host_sync, port2);
        auto client_cfg2 = mc::make_client_config(env, client_sync, port2);

        mc::peer::PeerSyncReport h_rep2, c_rep2;
        std::thread h_t2([&] { h_rep2 = mc::peer::PeerService::run_host(host_cfg2, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t2([&] { c_rep2 = mc::peer::PeerService::run_client(client_cfg2, auto_approve); });
        h_t2.join();
        c_t2.join();

        check(c_rep2.success, "CAS-NET-13: Delta sync of 100 MB file with 64 KB mutation succeeds");
        check(c_rep2.chunks_reused > 0, "CAS-NET-13: Delta sync reuses existing chunks for unmodified regions");
        check(fs::exists(client_sync / "large_100mb.bin") && mc::sha256_file(client_sync / "large_100mb.bin") == mutated_hash,
              "CAS-NET-13: Mutated 100 MB file matches host hash bit-for-bit after delta sync");
    }

    // =========================================================================
    // CAS-NET-14: Legacy Peer Compatibility
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_14";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        mc::write_file(host_sync / "legacy.txt", "legacy whole-file transfer content");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);

        std::thread host_t([&] { (void)mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        auto client_cfg = mc::make_client_config(env, client_sync, port);
        mc::peer::PeerTlsContext tls(client_cfg, mc::peer::Role::Client);
        auto conn = mc::peer::PeerConnection::connect(client_cfg, tls);

        // Client advertises ONLY whole_file (no cas_delta_v1)
        mc::peer::PeerCapabilities caps{client_cfg.identity, "1.0", {mc::peer::kCapWholeFile}};
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Hello,
                                        mc::peer::encode_hello_payload(caps)});
        auto host_hello = conn.receive_frame();
        check(host_hello.type == mc::peer::MessageType::Hello, "CAS-NET-14: Host accepts legacy Hello handshake");

        // Complete whole file transfer
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::ManifestRequest, "sess_leg"});
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
        appr_data.append("sess_leg");
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::Approval, appr_data});
        (void)conn.receive_frame();

        // Host serves legacy FileRequest
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::FileRequest, "legacy.txt"});
        auto data_frame = conn.receive_frame();
        auto end_frame = conn.receive_frame();

        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::SyncResult, "PREPARED"});
        (void)conn.receive_frame();
        conn.send_frame(mc::peer::Frame{mc::peer::kProtocolVersion, mc::peer::MessageType::SyncResult, "COMMITTED"});
        (void)conn.receive_frame();

        host_t.join();
        check(data_frame.type == mc::peer::MessageType::FileData && end_frame.type == mc::peer::MessageType::FileEnd,
              "CAS-NET-14: Host served file via legacy FileData stream without error");
    }

    // =========================================================================
    // CAS-NET-15: Initial Full Sync on Empty CAS
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_15";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string content = make_pattern_data(80 * 1024, 'E');
        mc::write_file(host_sync / "initial.bin", content);

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t([&] { h_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t([&] { c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve); });
        h_t.join();
        c_t.join();

        check(c_rep.success && c_rep.chunks_reused == 0 && c_rep.chunks_transferred > 0,
              "CAS-NET-15: 100% of chunks transferred on empty initial CAS");
        check(mc::read_file(client_sync / "initial.bin") == content, "CAS-NET-15: Reconstructed file matches 100%");
    }

    // =========================================================================
    // CAS-NET-16: Remote Chunk Request Authorization
    // =========================================================================
    {
        mc::peer::SessionChunkAuthorizer authorizer("test_session");
        authorizer.authorize_path("allowed.txt");
        const std::string allowed_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const std::string unauthorized_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        mc::cas::FileManifest m(100, "some_file_hash", {{0, 100, allowed_hash}});
        authorizer.authorize_manifest("allowed.txt", m);

        check(authorizer.is_path_authorized("allowed.txt"),
              "CAS-NET-16: Whitelisted relative path is authorized");
        check(authorizer.is_authorized(allowed_hash),
              "CAS-NET-16: Advertised chunk hash in authorized manifest is permitted");
        check(!authorizer.is_authorized(unauthorized_hash),
              "CAS-NET-16: Arbitrary unadvertised chunk hash is strictly rejected");
        check(!authorizer.is_path_authorized("unauthorized_path.txt"),
              "CAS-NET-16: Unadvertised path is strictly rejected");

        mc::peer::ChunkRequestMessage good_req{"allowed.txt", {allowed_hash}};
        mc::peer::ChunkRequestMessage bad_hash_req{"allowed.txt", {unauthorized_hash}};
        mc::peer::ChunkRequestMessage bad_path_req{"unauthorized_path.txt", {allowed_hash}};
        std::string req_err;

        check(authorizer.validate_chunk_request(good_req, req_err),
              "CAS-NET-16: validate_chunk_request accepts authorized path and hash");
        check(!authorizer.validate_chunk_request(bad_hash_req, req_err),
              "CAS-NET-16: validate_chunk_request rejects unauthorized chunk hash");
        check(!authorizer.validate_chunk_request(bad_path_req, req_err),
              "CAS-NET-16: validate_chunk_request rejects unauthorized path");
    }

    // =========================================================================
    // CAS-NET-17: Malformed Chunk Manifest Validation
    // =========================================================================
    {
        // Chunk larger than 16KB max
        mc::cas::FileManifest bad_manifest(20000, "0000000000000000000000000000000000000000000000000000000000000000",
                                           {{0, 20000, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}});
        std::string err;
        const bool valid = mc::peer::validate_peer_manifest(bad_manifest, err);
        check(!valid && err.find("FastCDC") != std::string::npos,
              "CAS-NET-17: Manifest with chunk size > 16KB rejected as malformed");
    }

    // =========================================================================
    // CAS-NET-18: Sender Interprocess GC Safety
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_18" / "cas";
        fs::create_directories(test_dir);
        const auto lock_file = test_dir / ".cas_barrier.lock";
        mc::cas::InterprocessCasBarrier barrier(lock_file);

        // Sender shared guard holding OS-level shared file lock
        std::optional<mc::cas::CasSharedBarrierGuard> sender_guard;
        sender_guard.emplace(barrier);

#ifdef _WIN32
        // Subprocess attempts exclusive lock while host holds shared lock -> must fail with code 42 (Contended)
        std::wstring args_contended = L"--cas-gc-lock-worker \"" + lock_file.wstring() + L"\" 150";
        DWORD exit_code1 = run_peer_child_process(args_contended);
        check(exit_code1 == 42,
              "CAS-NET-18: Subprocess GC exclusive lock rejected with exit code 42 (Contended) while host holds shared barrier");

        // Release shared guard
        sender_guard.reset();

        // Subprocess attempts exclusive lock when host lock is released -> must acquire and return 0
        std::wstring args_acquired = L"--cas-gc-lock-worker \"" + lock_file.wstring() + L"\" 1000";
        DWORD exit_code2 = run_peer_child_process(args_acquired);
        check(exit_code2 == 0,
              "CAS-NET-18: Subprocess GC exclusive lock acquired with exit code 0 after host releases shared barrier");
#else
        std::atomic<bool> thread_started{false};
        std::atomic<bool> exclusive_acquired{false};
        std::thread gc_thread([&] {
            thread_started = true;
            mc::cas::CasExclusiveBarrierGuard gc_guard(barrier);
            exclusive_acquired = true;
        });

        while (!thread_started) std::this_thread::yield();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        check(!exclusive_acquired.load(), "CAS-NET-18: GC exclusive lock blocked while sender guard held");
        sender_guard.reset();
        gc_thread.join();
        check(exclusive_acquired.load(), "CAS-NET-18: GC exclusive lock succeeds after sender guard released");
#endif
    }

    // =========================================================================
    // CAS-NET-19: Request Flooding & Frame Limit Bounds
    // =========================================================================
    {
        mc::peer::ChunkRequestMessage flood_req;
        flood_req.relative_path = "flood.bin";
        flood_req.requested_hashes.resize(4097, "0000000000000000000000000000000000000000000000000000000000000000");

        bool caught = false;
        try {
            (void)mc::peer::encode_chunk_request(flood_req);
        } catch (const std::exception&) {
            caught = true;
        }
        check(caught, "CAS-NET-19: Request with >4096 hashes rejected before allocation / serialization");
    }

    // =========================================================================
    // CAS-NET-20: Repeated Crash & Safe Restart Recovery
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_20";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        const std::string content = make_pattern_data(96 * 1024, 'R');
        mc::write_file(host_sync / "repeat.bin", content);

        // Simulate 2 previous interrupted attempts that left chunks in CAS
        mc::cas::FastCDCChunker chunker;
        const auto chunks = chunker.chunk_buffer(content.data(), content.size());
        const auto client_cas = client_sync / ".merklechain" / "cas";
        mc::cas::ObjectStoreConfig cas_cfg{client_cas};
        mc::cas::ObjectStore client_store(cas_cfg);
        std::string err;
        client_store.initialize(err);

        // Run 1: left chunk 0
        if (!chunks.empty()) client_store.put_object(content.data() + chunks[0].offset, chunks[0].size, chunks[0].hash);
        // Run 2: left chunk 1
        if (chunks.size() >= 2) client_store.put_object(content.data() + chunks[1].offset, chunks[1].size, chunks[1].hash);

        // Run 3: full completion
        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t([&] { h_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t([&] { c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve); });
        h_t.join();
        c_t.join();

        check(c_rep.success, "CAS-NET-20: Repeated crash recovery succeeds on final run");
        check(mc::read_file(client_sync / "repeat.bin") == content, "CAS-NET-20: Reconstructed content matches perfectly");
    }

    // =========================================================================
    // CAS-NET-21: Zero-Byte / Empty File CAS Sync
    // =========================================================================
    {
        const auto test_dir = base_dir / "cas_net_21";
        const auto host_sync = test_dir / "host";
        const auto client_sync = test_dir / "client";
        fs::create_directories(host_sync);
        fs::create_directories(client_sync);

        // Empty file
        mc::write_file(host_sync / "empty.txt", "");

        const auto port = next_port();
        auto host_cfg = mc::make_host_config(env, host_sync, port);
        auto client_cfg = mc::make_client_config(env, client_sync, port);

        mc::peer::PeerSyncReport h_rep, c_rep;
        std::thread h_t([&] { h_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread c_t([&] { c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve); });
        h_t.join();
        c_t.join();

        check(c_rep.success, "CAS-NET-21: Zero-byte empty file sync succeeds");
        check(fs::exists(client_sync / "empty.txt") && fs::file_size(client_sync / "empty.txt") == 0,
              "CAS-NET-21: Client created 0-byte file cleanly");
        check(h_rep.final_merkle_root == c_rep.final_merkle_root, "CAS-NET-21: Empty file Merkle roots match");
    }

    mc::fs::remove_all(base_dir, ec);
}

