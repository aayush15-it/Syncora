#include "merklechain/cas/manifest_serializer.hpp"
#include <cstring>
#include <sstream>

namespace mc::cas {

namespace {

// Helper functions for binary serialization
template <typename T>
void write_le(std::vector<std::uint8_t>& buf, T val) {
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        buf.push_back(static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF));
    }
}

template <typename T>
bool read_le(const std::uint8_t*& ptr, std::size_t& remaining, T& out_val) {
    if (remaining < sizeof(T)) return false;
    out_val = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out_val |= (static_cast<T>(ptr[i]) << (i * 8));
    }
    ptr += sizeof(T);
    remaining -= sizeof(T);
    return true;
}

// Minimal JSON token extraction
std::string find_json_string(const std::string& json, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    auto pos = json.find(pattern);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    auto end_pos = json.find('"', pos + 1);
    if (end_pos == std::string::npos) return "";
    return json.substr(pos + 1, end_pos - pos - 1);
}

std::uint64_t find_json_uint64(const std::string& json, const std::string& key, std::uint64_t def = 0) {
    const std::string pattern = "\"" + key + "\"";
    auto pos = json.find(pattern);
    if (pos == std::string::npos) return def;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return def;
    while (pos < json.size() && (json[pos] == ':' || json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) {
        ++pos;
    }
    if (pos >= json.size()) return def;
    char* end = nullptr;
    auto val = std::strtoull(&json[pos], &end, 10);
    return (end != &json[pos]) ? val : def;
}

} // namespace

std::string ManifestSerializer::serialize_json(const FileManifest& manifest, bool pretty) {
    std::ostringstream ss;
    const std::string indent = pretty ? "  " : "";
    const std::string indent2 = pretty ? "    " : "";
    const std::string nl = pretty ? "\n" : "";
    const std::string sp = pretty ? " " : "";

    ss << "{" << nl;
    ss << indent << "\"version\":" << sp << manifest.version() << "," << nl;
    ss << indent << "\"total_size\":" << sp << manifest.total_size() << "," << nl;
    ss << indent << "\"file_sha256\":" << sp << "\"" << manifest.file_sha256() << "\"," << nl;
    ss << indent << "\"chunks\":" << sp << "[" << nl;

    const auto& chunks = manifest.chunks();
    for (std::size_t i = 0; i < chunks.size(); ++i) {
        const auto& c = chunks[i];
        ss << indent2 << "{"
           << "\"offset\":" << sp << c.offset << "," << sp
           << "\"size\":" << sp << c.size << "," << sp
           << "\"hash\":" << sp << "\"" << c.hash << "\""
           << "}";
        if (i + 1 < chunks.size()) {
            ss << ",";
        }
        ss << nl;
    }

    ss << indent << "]" << nl;
    ss << "}";
    return ss.str();
}

bool ManifestSerializer::deserialize_json(const std::string& json_str, FileManifest& out_manifest, std::string& err) {
    if (json_str.empty()) {
        err = "Empty JSON input";
        return false;
    }

    if (json_str.size() > 64 * 1024 * 1024) {
        err = "JSON manifest exceeds maximum safety size limit (64 MB)";
        return false;
    }

    const auto version = static_cast<std::uint32_t>(find_json_uint64(json_str, "version", 0));
    if (version == 0 || version > FileManifest::kCurrentVersion) {
        err = "Invalid or unsupported manifest version in JSON";
        return false;
    }

    const auto total_size = find_json_uint64(json_str, "total_size", 0);
    const auto file_sha256 = find_json_string(json_str, "file_sha256");
    if (file_sha256.size() != 64) {
        err = "Invalid or missing file_sha256 in JSON manifest";
        return false;
    }

    std::vector<ChunkInfo> chunks;
    auto chunks_pos = json_str.find("\"chunks\"");
    if (chunks_pos != std::string::npos) {
        auto arr_start = json_str.find('[', chunks_pos);
        auto arr_end = json_str.rfind(']');
        if (arr_start != std::string::npos && arr_end != std::string::npos && arr_end > arr_start) {
            std::size_t cur = arr_start + 1;
            while (cur < arr_end) {
                auto obj_start = json_str.find('{', cur);
                if (obj_start == std::string::npos || obj_start >= arr_end) break;
                auto obj_end = json_str.find('}', obj_start);
                if (obj_end == std::string::npos || obj_end > arr_end) break;

                const std::string obj = json_str.substr(obj_start, obj_end - obj_start + 1);
                const auto offset = find_json_uint64(obj, "offset", 0);
                const auto size = find_json_uint64(obj, "size", 0);
                const auto hash = find_json_string(obj, "hash");

                if (size == 0 || hash.size() != 64) {
                    err = "Malformed chunk entry inside JSON manifest";
                    return false;
                }

                chunks.push_back(ChunkInfo{offset, size, hash});
                cur = obj_end + 1;
            }
        }
    }

    out_manifest.set_version(version);
    out_manifest.set_total_size(total_size);
    out_manifest.set_file_sha256(file_sha256);
    out_manifest.set_chunks(std::move(chunks));

    return out_manifest.validate(err);
}

std::vector<std::uint8_t> ManifestSerializer::serialize_binary(const FileManifest& manifest) {
    std::vector<std::uint8_t> buf;
    // Pre-allocate buffer
    const std::size_t estimated_size = 4 + 4 + 8 + 64 + 4 + manifest.chunks().size() * (8 + 8 + 64);
    buf.reserve(estimated_size);

    // Magic: 'MCAS'
    buf.push_back('M');
    buf.push_back('C');
    buf.push_back('A');
    buf.push_back('S');

    // Version
    write_le(buf, manifest.version());

    // Total Size
    write_le(buf, manifest.total_size());

    // Whole-file SHA-256 (64 bytes ascii hex)
    const std::string& fsha = manifest.file_sha256();
    for (std::size_t i = 0; i < 64; ++i) {
        buf.push_back(i < fsha.size() ? static_cast<std::uint8_t>(fsha[i]) : '0');
    }

    // Chunk count
    const auto count = static_cast<std::uint32_t>(manifest.chunks().size());
    write_le(buf, count);

    // Chunks
    for (const auto& c : manifest.chunks()) {
        write_le(buf, c.offset);
        write_le(buf, c.size);
        for (std::size_t i = 0; i < 64; ++i) {
            buf.push_back(i < c.hash.size() ? static_cast<std::uint8_t>(c.hash[i]) : '0');
        }
    }

    return buf;
}

bool ManifestSerializer::deserialize_binary(const std::uint8_t* data, std::size_t size, FileManifest& out_manifest, std::string& err) {
    if (data == nullptr || size < 4 + 4 + 8 + 64 + 4) {
        err = "Truncated binary manifest header";
        return false;
    }

    const std::uint8_t* ptr = data;
    std::size_t remaining = size;

    // Check Magic
    if (ptr[0] != 'M' || ptr[1] != 'C' || ptr[2] != 'A' || ptr[3] != 'S') {
        err = "Invalid binary manifest magic header (expected MCAS)";
        return false;
    }
    ptr += 4;
    remaining -= 4;

    std::uint32_t version = 0;
    if (!read_le(ptr, remaining, version) || version != FileManifest::kCurrentVersion) {
        err = "Unsupported binary manifest version";
        return false;
    }

    std::uint64_t total_size = 0;
    if (!read_le(ptr, remaining, total_size)) {
        err = "Truncated total_size field";
        return false;
    }

    if (remaining < 64) {
        err = "Truncated file_sha256 field";
        return false;
    }
    std::string file_sha(reinterpret_cast<const char*>(ptr), 64);
    ptr += 64;
    remaining -= 64;

    std::uint32_t chunk_count = 0;
    if (!read_le(ptr, remaining, chunk_count)) {
        err = "Truncated chunk_count field";
        return false;
    }

    constexpr std::size_t kChunkRecordSize = 8 + 8 + 64; // 80 bytes
    constexpr std::uint32_t kMaxAllowedChunks = 10000000; // 10 million chunks safety limit
    if (chunk_count > kMaxAllowedChunks) {
        err = "Binary manifest chunk_count (" + std::to_string(chunk_count) + ") exceeds maximum safety threshold";
        return false;
    }

    if (chunk_count > remaining / kChunkRecordSize) {
        err = "Binary manifest body shorter than expected for " + std::to_string(chunk_count) + " chunks";
        return false;
    }

    std::vector<ChunkInfo> chunks;
    chunks.reserve(chunk_count);

    for (std::uint32_t i = 0; i < chunk_count; ++i) {
        std::uint64_t offset = 0;
        std::uint64_t csize = 0;
        read_le(ptr, remaining, offset);
        read_le(ptr, remaining, csize);
        std::string chash(reinterpret_cast<const char*>(ptr), 64);
        ptr += 64;
        remaining -= 64;
        chunks.push_back(ChunkInfo{offset, csize, chash});
    }

    out_manifest.set_version(version);
    out_manifest.set_total_size(total_size);
    out_manifest.set_file_sha256(file_sha);
    out_manifest.set_chunks(std::move(chunks));

    return out_manifest.validate(err);
}

} // namespace mc::cas

