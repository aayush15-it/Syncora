#include "merklechain/peer/peer_service.hpp"
#include "merklechain/peer/peer_transport.hpp"
#include "merklechain/peer/peer_sync.hpp"
#include "merklechain/peer/peer_protocol.hpp"
#include "merklechain/cas/chunker.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace fs = std::filesystem;

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
    auto ca_cert = make_certificate(ca_key.get(), "Benchmark CA", nullptr, nullptr, 1, true);
    env.ca_path = env.cert_dir / "ca.crt";
    {
        std::unique_ptr<FILE, decltype(&fclose)> ca_file(_wfopen(env.ca_path.c_str(), L"wb"), fclose);
        PEM_write_X509(ca_file.get(), ca_cert.get());
    }

    auto host_key = make_key();
    auto host_cert = make_certificate(host_key.get(), "Benchmark Host", ca_cert.get(), ca_key.get(), 2, false);
    env.host_cert_path = env.cert_dir / "host.crt";
    env.host_key_path = env.cert_dir / "host.key";
    write_identity(env.host_key_path, env.host_cert_path, host_key.get(), host_cert.get());
    env.host_pin = fingerprint(host_cert.get());

    auto client_key = make_key();
    auto client_cert = make_certificate(client_key.get(), "Benchmark Client", ca_cert.get(), ca_key.get(), 3, false);
    env.client_cert_path = env.cert_dir / "client.crt";
    env.client_key_path = env.cert_dir / "client.key";
    write_identity(env.client_key_path, env.client_cert_path, client_key.get(), client_cert.get());
    env.client_pin = fingerprint(client_cert.get());

    return env;
}

mc::peer::PeerConfig make_host_config(const TlsTestEnvironment& env, const fs::path& sync_root, std::uint16_t port) {
    mc::peer::PeerConfig cfg;
    cfg.role = mc::peer::Role::Host;
    cfg.identity = "bench_host";
    cfg.sync_root = sync_root;
    cfg.bind_address = "127.0.0.1";
    cfg.port = port;
    cfg.ca_file = env.ca_path;
    cfg.certificate_file = env.host_cert_path;
    cfg.private_key_file = env.host_key_path;
    cfg.expected_peer_sha256 = env.client_pin;
    cfg.handshake_timeout_seconds = 10;
    cfg.io_timeout_seconds = 10;
    return cfg;
}

mc::peer::PeerConfig make_client_config(const TlsTestEnvironment& env, const fs::path& sync_root, std::uint16_t port) {
    mc::peer::PeerConfig cfg;
    cfg.role = mc::peer::Role::Client;
    cfg.identity = "bench_client";
    cfg.sync_root = sync_root;
    cfg.host_address = "127.0.0.1";
    cfg.port = port;
    cfg.ca_file = env.ca_path;
    cfg.certificate_file = env.client_cert_path;
    cfg.private_key_file = env.client_key_path;
    cfg.expected_peer_sha256 = env.host_pin;
    cfg.handshake_timeout_seconds = 10;
    cfg.io_timeout_seconds = 10;
    return cfg;
}

std::size_t get_peak_memory_bytes() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.PeakWorkingSetSize;
    }
#endif
    return 0;
}

struct BenchmarkResult {
    std::string dataset_name;
    std::size_t logical_file_size{0};
    std::size_t wire_bytes_transferred{0};
    std::size_t bytes_saved{0};
    std::size_t chunks_reused{0};
    std::size_t chunks_transferred{0};
    double duration_ms{0.0};
    double bandwidth_reduction_pct{0.0};
    std::size_t peak_ram_bytes{0};
};

std::string make_pattern_data(std::size_t size, char start_char) {
    std::string s(size, ' ');
    for (std::size_t i = 0; i < size; ++i) {
        s[i] = static_cast<char>(start_char + (i % 26));
    }
    return s;
}

} // namespace

int main() {
    std::cout << "===============================================================================\n";
    std::cout << "  SYNCORA MILESTONE 3.4 — CAS DELTA NETWORK PROTOCOL BENCHMARK SUITE\n";
    std::cout << "===============================================================================\n\n";

    const auto root_dir = fs::temp_directory_path() / "syncora_cas_benchmark";
    std::error_code ec;
    fs::remove_all(root_dir, ec);
    fs::create_directories(root_dir);

    const auto env = setup_tls_env(root_dir);

    std::uint16_t current_port = 45200;
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

    enum class TestMode { LegacyWholeFile, CasDelta };

    const auto run_single_benchmark = [&](const std::string& name,
                                          TestMode mode,
                                          std::size_t file_size,
                                          const std::function<void(const fs::path& host, const fs::path& client)>& setup_fn) -> BenchmarkResult {
        const int repetitions = 3;
        std::vector<BenchmarkResult> runs;

        for (int rep = 0; rep < repetitions; ++rep) {
            const auto run_dir = root_dir / ("run_" + std::to_string(rep));
            fs::remove_all(run_dir, ec);
            const auto host_sync = run_dir / "host";
            const auto client_sync = run_dir / "client";
            fs::create_directories(host_sync);
            fs::create_directories(client_sync);

            setup_fn(host_sync, client_sync);

            const auto port = next_port();
            auto host_cfg = make_host_config(env, host_sync, port);
            auto client_cfg = make_client_config(env, client_sync, port);

            if (mode == TestMode::LegacyWholeFile) {
                host_cfg.enable_cas_delta = false;
                client_cfg.enable_cas_delta = false;
            }

            mc::peer::PeerSyncReport h_rep, c_rep;
            const auto start_time = std::chrono::steady_clock::now();

            std::thread h_t([&] { h_rep = mc::peer::PeerService::run_host(host_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            c_rep = mc::peer::PeerService::run_client(client_cfg, auto_approve);
            h_t.join();

            const auto end_time = std::chrono::steady_clock::now();
            const double duration_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

            BenchmarkResult r;
            r.dataset_name = name;
            r.logical_file_size = file_size;
            r.wire_bytes_transferred = c_rep.bytes_transferred;
            r.bytes_saved = c_rep.cas_delta_bytes_saved;
            r.chunks_reused = c_rep.chunks_reused;
            r.chunks_transferred = c_rep.chunks_transferred;
            r.duration_ms = duration_ms;
            r.peak_ram_bytes = get_peak_memory_bytes();
            runs.push_back(r);
        }

        // Return median based on duration
        std::sort(runs.begin(), runs.end(), [](const BenchmarkResult& a, const BenchmarkResult& b) {
            return a.duration_ms < b.duration_ms;
        });
        return runs[repetitions / 2];
    };

    struct Comparison {
        std::string dataset;
        BenchmarkResult legacy;
        BenchmarkResult cas_delta;
    };

    std::vector<Comparison> comparisons;

    // -------------------------------------------------------------------------
    // Dataset 1: Identical Files (Pre-Populated CAS)
    // -------------------------------------------------------------------------
    {
        const std::size_t size = 1024 * 1024; // 1 MB
        const auto content = make_pattern_data(size, 'A');

        auto setup = [&](const fs::path& host, const fs::path& client) {
            write_file(host / "doc.bin", content);
            write_file(client / "doc.bin", content);
            // Baseline sync
            const auto p = next_port();
            auto h_cfg = make_host_config(env, host, p);
            auto c_cfg = make_client_config(env, client, p);
            std::thread h([&] { (void)mc::peer::PeerService::run_host(h_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            (void)mc::peer::PeerService::run_client(c_cfg, auto_approve);
            h.join();
        };

        auto leg = run_single_benchmark("1. Identical Files (1 MB)", TestMode::LegacyWholeFile, size, setup);
        auto cas = run_single_benchmark("1. Identical Files (1 MB)", TestMode::CasDelta, size, setup);
        comparisons.push_back({"1. Identical Files (1 MB)", leg, cas});
    }

    // -------------------------------------------------------------------------
    // Dataset 2: Small In-Place Edit (4 KB edit inside 1 MB file, ~99% match)
    // -------------------------------------------------------------------------
    {
        const std::size_t size = 1024 * 1024;
        const auto base_content = make_pattern_data(size, 'B');
        auto edited_content = base_content;
        for (std::size_t i = 100 * 1024; i < 104 * 1024; ++i) edited_content[i] = '#';

        auto setup = [&](const fs::path& host, const fs::path& client) {
            write_file(host / "doc.bin", base_content);
            write_file(client / "doc.bin", base_content);
            const auto p = next_port();
            auto h_cfg = make_host_config(env, host, p);
            auto c_cfg = make_client_config(env, client, p);
            std::thread h([&] { (void)mc::peer::PeerService::run_host(h_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            (void)mc::peer::PeerService::run_client(c_cfg, auto_approve);
            h.join();
            write_file(host / "doc.bin", edited_content);
        };

        auto leg = run_single_benchmark("2. Small Edit (4KB / 1MB)", TestMode::LegacyWholeFile, size, setup);
        auto cas = run_single_benchmark("2. Small Edit (4KB / 1MB)", TestMode::CasDelta, size, setup);
        comparisons.push_back({"2. Small Edit (4KB / 1MB)", leg, cas});
    }

    // -------------------------------------------------------------------------
    // Dataset 3: Middle Insertion (64 KB edit inside 2 MB file)
    // -------------------------------------------------------------------------
    {
        const std::size_t size = 2 * 1024 * 1024;
        const auto base_content = make_pattern_data(size, 'C');
        auto edited_content = base_content;
        for (std::size_t i = 1024 * 1024; i < 1024 * 1024 + 64 * 1024; ++i) edited_content[i] = '!';

        auto setup = [&](const fs::path& host, const fs::path& client) {
            write_file(host / "doc.bin", base_content);
            write_file(client / "doc.bin", base_content);
            const auto p = next_port();
            auto h_cfg = make_host_config(env, host, p);
            auto c_cfg = make_client_config(env, client, p);
            std::thread h([&] { (void)mc::peer::PeerService::run_host(h_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            (void)mc::peer::PeerService::run_client(c_cfg, auto_approve);
            h.join();
            write_file(host / "doc.bin", edited_content);
        };

        auto leg = run_single_benchmark("3. Middle Edit (64KB / 2MB)", TestMode::LegacyWholeFile, size, setup);
        auto cas = run_single_benchmark("3. Middle Edit (64KB / 2MB)", TestMode::CasDelta, size, setup);
        comparisons.push_back({"3. Middle Edit (64KB / 2MB)", leg, cas});
    }

    // -------------------------------------------------------------------------
    // Dataset 4: Large Modification (~20% edit inside 2 MB file, ~80% reuse)
    // -------------------------------------------------------------------------
    {
        const std::size_t size = 2 * 1024 * 1024;
        const auto base_content = make_pattern_data(size, 'D');
        auto edited_content = base_content;
        for (std::size_t i = size - 400 * 1024; i < size; ++i) edited_content[i] = '%';

        auto setup = [&](const fs::path& host, const fs::path& client) {
            write_file(host / "doc.bin", base_content);
            write_file(client / "doc.bin", base_content);
            const auto p = next_port();
            auto h_cfg = make_host_config(env, host, p);
            auto c_cfg = make_client_config(env, client, p);
            std::thread h([&] { (void)mc::peer::PeerService::run_host(h_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            (void)mc::peer::PeerService::run_client(c_cfg, auto_approve);
            h.join();
            write_file(host / "doc.bin", edited_content);
        };

        auto leg = run_single_benchmark("4. Large Edit (20% edit / 2MB)", TestMode::LegacyWholeFile, size, setup);
        auto cas = run_single_benchmark("4. Large Edit (20% edit / 2MB)", TestMode::CasDelta, size, setup);
        comparisons.push_back({"4. Large Edit (20% edit / 2MB)", leg, cas});
    }

    // -------------------------------------------------------------------------
    // Dataset 5: File Rename with Pre-Populated CAS (1 MB)
    // -------------------------------------------------------------------------
    {
        const std::size_t size = 1024 * 1024;
        const auto content = make_pattern_data(size, 'E');

        auto setup = [&](const fs::path& host, const fs::path& client) {
            write_file(host / "before_rename.bin", content);
            write_file(client / "before_rename.bin", content);
            const auto p = next_port();
            auto h_cfg = make_host_config(env, host, p);
            auto c_cfg = make_client_config(env, client, p);
            std::thread h([&] { (void)mc::peer::PeerService::run_host(h_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            (void)mc::peer::PeerService::run_client(c_cfg, auto_approve);
            h.join();
            fs::remove(host / "before_rename.bin");
            write_file(host / "after_rename.bin", content);
        };

        auto leg = run_single_benchmark("5. File Rename (1 MB)", TestMode::LegacyWholeFile, size, setup);
        auto cas = run_single_benchmark("5. File Rename (1 MB)", TestMode::CasDelta, size, setup);
        comparisons.push_back({"5. File Rename (1 MB)", leg, cas});
    }

    // -------------------------------------------------------------------------
    // Dataset 6: Initial Full Sync on Empty CAS (1 MB)
    // -------------------------------------------------------------------------
    {
        const std::size_t size = 1024 * 1024;
        const auto content = make_pattern_data(size, 'F');

        auto setup = [&](const fs::path& host, const fs::path&) {
            write_file(host / "initial.bin", content);
        };

        auto leg = run_single_benchmark("6. Initial Full Sync (1 MB)", TestMode::LegacyWholeFile, size, setup);
        auto cas = run_single_benchmark("6. Initial Full Sync (1 MB)", TestMode::CasDelta, size, setup);
        comparisons.push_back({"6. Initial Full Sync (1 MB)", leg, cas});
    }

    // -------------------------------------------------------------------------
    // Dataset 7: Multiple Files with Repeated Content (4 x 256 KB)
    // -------------------------------------------------------------------------
    {
        const std::size_t file_size = 256 * 1024;
        const auto content = make_pattern_data(file_size, 'G');

        auto setup = [&](const fs::path& host, const fs::path& client) {
            for (int i = 0; i < 4; ++i) {
                write_file(host / ("file_" + std::to_string(i) + ".bin"), content);
                write_file(client / ("file_" + std::to_string(i) + ".bin"), content);
            }
            const auto p = next_port();
            auto h_cfg = make_host_config(env, host, p);
            auto c_cfg = make_client_config(env, client, p);
            std::thread h([&] { (void)mc::peer::PeerService::run_host(h_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            (void)mc::peer::PeerService::run_client(c_cfg, auto_approve);
            h.join();

            // Modify only file_2
            auto mod_content = content;
            for (std::size_t j = 0; j < 4096; ++j) mod_content[j] = 'X';
            write_file(host / "file_2.bin", mod_content);
        };

        auto leg = run_single_benchmark("7. Repeated Multi-File (1 MB total)", TestMode::LegacyWholeFile, 4 * file_size, setup);
        auto cas = run_single_benchmark("7. Repeated Multi-File (1 MB total)", TestMode::CasDelta, 4 * file_size, setup);
        comparisons.push_back({"7. Repeated Multi-File (1 MB total)", leg, cas});
    }

    // -------------------------------------------------------------------------
    // Dataset 8: Large File Transfer (10 MB Synthetic)
    // -------------------------------------------------------------------------
    {
        const std::size_t size = 10 * 1024 * 1024;
        auto setup = [&](const fs::path& host, const fs::path& client) {
            // Write base 10 MB file using streaming chunks
            const auto block = make_pattern_data(64 * 1024, 'H');
            {
                std::ofstream f(host / "large_file.bin", std::ios::binary);
                for (std::size_t written = 0; written < size; written += block.size()) {
                    f.write(block.data(), static_cast<std::streamsize>(block.size()));
                }
            }
            fs::copy_file(host / "large_file.bin", client / "large_file.bin");

            const auto p = next_port();
            auto h_cfg = make_host_config(env, host, p);
            auto c_cfg = make_client_config(env, client, p);
            std::thread h([&] { (void)mc::peer::PeerService::run_host(h_cfg, auto_approve); });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            (void)mc::peer::PeerService::run_client(c_cfg, auto_approve);
            h.join();

            // Edit 16 KB in the middle of 10 MB
            std::fstream f(host / "large_file.bin", std::ios::binary | std::ios::in | std::ios::out);
            f.seekp(5 * 1024 * 1024);
            const std::string edit(16 * 1024, '@');
            f.write(edit.data(), static_cast<std::streamsize>(edit.size()));
        };

        auto leg = run_single_benchmark("8. Large 10 MB (16KB edit)", TestMode::LegacyWholeFile, size, setup);
        auto cas = run_single_benchmark("8. Large 10 MB (16KB edit)", TestMode::CasDelta, size, setup);
        comparisons.push_back({"8. Large 10 MB (16KB edit)", leg, cas});
    }

    // Print Results Table
    std::cout << std::left << std::setw(32) << "Dataset Scenario"
              << std::right << std::setw(14) << "Legacy Wire"
              << std::setw(14) << "CAS Wire"
              << std::setw(14) << "CAS Saved"
              << std::setw(12) << "Reduction"
              << std::setw(14) << "Legacy Time"
              << std::setw(14) << "CAS Time"
              << "\n";
    std::cout << std::string(114, '-') << "\n";

    for (const auto& c : comparisons) {
        const double reduction = c.legacy.wire_bytes_transferred > 0
            ? (1.0 - (static_cast<double>(c.cas_delta.wire_bytes_transferred) / static_cast<double>(c.legacy.wire_bytes_transferred))) * 100.0
            : 0.0;

        std::cout << std::left << std::setw(32) << c.dataset
                  << std::right << std::setw(12) << c.legacy.wire_bytes_transferred << " B"
                  << std::setw(12) << c.cas_delta.wire_bytes_transferred << " B"
                  << std::setw(12) << c.cas_delta.bytes_saved << " B"
                  << std::setw(10) << std::fixed << std::setprecision(1) << reduction << " %"
                  << std::setw(11) << std::fixed << std::setprecision(1) << c.legacy.duration_ms << " ms"
                  << std::setw(11) << std::fixed << std::setprecision(1) << c.cas_delta.duration_ms << " ms"
                  << "\n";
    }

    std::cout << "\n===============================================================================\n";
    std::cout << "  BENCHMARK SUITE EXECUTION COMPLETE\n";
    std::cout << "===============================================================================\n";

    fs::remove_all(root_dir, ec);
    return 0;
}

