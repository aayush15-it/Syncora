#pragma once

#include "merklechain/cas/file_manifest.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace mc::cas {

class ManifestSerializer {
public:
    // JSON Serialization
    static std::string serialize_json(const FileManifest& manifest, bool pretty = false);
    static bool deserialize_json(const std::string& json_str, FileManifest& out_manifest, std::string& err);

    // Compact Binary Serialization:
    // Format:
    // - Magic: 'M', 'C', 'A', 'S' (4 bytes)
    // - Version: uint32_t (4 bytes)
    // - Total Size: uint64_t (8 bytes)
    // - File SHA-256: 64 ascii hex bytes
    // - Chunk Count: uint32_t (4 bytes)
    // - Repeated Chunk Entries:
    //     - Offset: uint64_t (8 bytes)
    //     - Size: uint64_t (8 bytes)
    //     - Chunk SHA-256: 64 ascii hex bytes
    static std::vector<std::uint8_t> serialize_binary(const FileManifest& manifest);
    static bool deserialize_binary(const std::uint8_t* data, std::size_t size, FileManifest& out_manifest, std::string& err);
};

} // namespace mc::cas

