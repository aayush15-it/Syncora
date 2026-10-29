#pragma once

#include "merklechain/types.hpp"

#include <cstdint>
#include <string>

namespace mc::peer {

enum class Role { Host, Client };

struct PeerConfig {
    Role role{Role::Client};
    std::string identity;
    fs::path sync_root;
    std::string bind_address;
    std::string host_address;
    std::uint16_t port{};
    fs::path certificate_file;
    fs::path private_key_file;
    fs::path ca_file;
    std::string expected_peer_sha256;
    std::uint32_t handshake_timeout_seconds{10};
    std::uint32_t io_timeout_seconds{30};
    std::uint32_t max_manifest_files{100000};
    std::uint64_t max_file_size_bytes{1ULL << 40U};
};

PeerConfig load_peer_config(const fs::path& config_path, Role expected_role);

} // namespace mc::peer
