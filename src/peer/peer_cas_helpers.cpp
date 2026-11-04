#include "merklechain/peer/peer_cas_helpers.hpp"
#include "merklechain/cas/manifest_serializer.hpp"
#include "merklechain/hash.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace mc::peer {

mc::cas::ChunkerConfig get_peer_chunker_config() {
    mc::cas::ChunkerConfig cfg;
    cfg.min_size = kPeerFastCdcMinSize;
    cfg.avg_size = kPeerFastCdcAvgSize;
    cfg.max_size = kPeerFastCdcMaxSize;
    cfg.normalization_level = 1;
    return cfg;
}

bool validate_peer_path(const std::string& path, std::string& err) {
    if (path.empty()) {
        err = "relative path cannot be empty";
        return false;
    }
    if (path.size() > 1024U) {
        err = "relative path exceeds 1024 characters";
        return false;
    }
    if (path[0] == '/' || path[0] == '\\') {
        err = "path must be relative, got leading slash: " + path;
        return false;
    }
    if (path.size() >= 2U && path[1] == ':') {
        err = "path must not contain drive letter: " + path;
        return false;
    }

    // Inspect individual characters and path segments
    std::string segment;
    for (std::size_t i = 0; i <= path.size(); ++i) {
        const char c = (i < path.size()) ? path[i] : '/';
        if (i < path.size()) {
            if (c == '\0') {
                err = "path contains null byte";
                return false;
            }
            const auto uc = static_cast<unsigned char>(c);
            if (uc < 32U) {
                err = "path contains non-printable control character";
                return false;
            }
        }

        if (c == '/' || c == '\\') {
            if (segment == "..") {
                err = "path contains directory traversal ('..'): " + path;
                return false;
            }
            segment.clear();
        } else {
            segment.push_back(c);
        }
    }
    return true;
}

bool validate_peer_manifest(const mc::cas::FileManifest& manifest, std::string& err) {
    if (!manifest.validate(err)) {
        return false;
    }
    if (manifest.version() != mc::cas::FileManifest::kCurrentVersion) {
        err = "unsupported manifest version: " + std::to_string(manifest.version());
        return false;
    }
    if (!is_valid_hex_sha256(manifest.file_sha256())) {
        err = "invalid whole-file SHA-256 hash: " + manifest.file_sha256();
        return false;
    }

    if (manifest.is_empty()) {
        if (manifest.total_size() != 0 || manifest.chunk_count() != 0 ||
            manifest.file_sha256() != mc::cas::kEmptySha256) {
            err = "empty file manifest must have 0 size, 0 chunks, and canonical empty SHA-256";
            return false;
        }
        return true;
    }

    const auto& chunks = manifest.chunks();
    const std::size_t n = chunks.size();
    if (n > kMaxPeerManifestChunks) {
        err = "manifest chunk count (" + std::to_string(n) + ") exceeds maximum limit (" +
              std::to_string(kMaxPeerManifestChunks) + ")";
        return false;
    }

    std::uint64_t expected_offset = 0;
    std::uint64_t accumulated_size = 0;

    for (std::size_t i = 0; i < n; ++i) {
        const auto& c = chunks[i];
        if (c.offset != expected_offset) {
            err = "chunk " + std::to_string(i) + " offset gap or overlap: expected " +
                  std::to_string(expected_offset) + ", got " + std::to_string(c.offset);
            return false;
        }
        if (!is_valid_hex_sha256(c.hash)) {
            err = "chunk " + std::to_string(i) + " has invalid SHA-256 hash: " + c.hash;
            return false;
        }

        const bool is_final_chunk = (i == n - 1U);
        if (!is_final_chunk) {
            if (c.size < kPeerFastCdcMinSize || c.size > kPeerFastCdcMaxSize) {
                err = "non-final chunk " + std::to_string(i) + " size (" + std::to_string(c.size) +
                      ") out of FastCDC bounds [" + std::to_string(kPeerFastCdcMinSize) + ", " +
                      std::to_string(kPeerFastCdcMaxSize) + "]";
                return false;
            }
        } else {
            if (c.size < 1U || c.size > kPeerFastCdcMaxSize) {
                err = "final chunk " + std::to_string(i) + " size (" + std::to_string(c.size) +
                      ") out of FastCDC bounds [1, " + std::to_string(kPeerFastCdcMaxSize) + "]";
                return false;
            }
        }

        expected_offset += c.size;
        accumulated_size += c.size;
    }

    if (accumulated_size != manifest.total_size()) {
        err = "sum of chunk sizes (" + std::to_string(accumulated_size) +
              ") does not match manifest total_size (" + std::to_string(manifest.total_size()) + ")";
        return false;
    }

    return true;
}

std::vector<std::uint8_t> serialize_peer_manifest(const mc::cas::FileManifest& manifest) {
    return mc::cas::ManifestSerializer::serialize_binary(manifest);
}

bool deserialize_peer_manifest(
    const std::uint8_t* data,
    std::size_t size,
    mc::cas::FileManifest& out_manifest,
    std::string& err) {
    if (!mc::cas::ManifestSerializer::deserialize_binary(data, size, out_manifest, err)) {
        return false;
    }
    return validate_peer_manifest(out_manifest, err);
}

void SessionChunkAuthorizer::authorize_manifest(const mc::cas::FileManifest& manifest) {
    for (const auto& c : manifest.chunks()) {
        if (is_valid_hex_sha256(c.hash)) {
            authorized_hashes_.insert(c.hash);
        }
    }
}

bool SessionChunkAuthorizer::authorize_hash(const std::string& chunk_hash) {
    if (!is_valid_hex_sha256(chunk_hash)) {
        return false;
    }
    authorized_hashes_.insert(chunk_hash);
    return true;
}

bool SessionChunkAuthorizer::is_authorized(const std::string& chunk_hash) const noexcept {
    return authorized_hashes_.find(chunk_hash) != authorized_hashes_.end();
}

bool SessionChunkAuthorizer::validate_chunk_request(
    const ChunkRequestMessage& request,
    std::string& err) const {
    if (!validate_peer_path(request.relative_path, err)) {
        return false;
    }
    if (request.requested_hashes.empty()) {
        err = "chunk request contains zero requested hashes";
        return false;
    }
    if (request.requested_hashes.size() > kMaxRequestedChunksPerRequest) {
        err = "chunk request exceeds maximum limit of " +
              std::to_string(kMaxRequestedChunksPerRequest) + " hashes";
        return false;
    }

    for (const auto& h : request.requested_hashes) {
        if (!is_valid_hex_sha256(h)) {
            err = "invalid SHA-256 chunk hash syntax in request: " + h;
            return false;
        }
        if (!is_authorized(h)) {
            err = "unauthorized chunk request: hash not in session manifest (" + h + ")";
            return false;
        }
    }
    return true;
}

std::vector<std::string> compute_missing_chunks(
    const mc::cas::FileManifest& manifest,
    const mc::cas::ObjectStore& object_store) {
    std::vector<std::string> missing;
    if (manifest.is_empty()) {
        return missing;
    }
    std::unordered_set<std::string> seen;
    for (const auto& c : manifest.chunks()) {
        if (seen.insert(c.hash).second) {
            if (!object_store.has_object(c.hash)) {
                missing.push_back(c.hash);
            }
        }
    }
    return missing;
}

std::vector<ChunkRequestMessage> build_chunk_requests(
    const std::string& relative_path,
    const std::vector<std::string>& missing_hashes,
    std::size_t max_chunks_per_request) {
    std::string path_err;
    if (!validate_peer_path(relative_path, path_err)) {
        throw std::invalid_argument("invalid relative path in build_chunk_requests: " + path_err);
    }
    if (missing_hashes.empty()) {
        return {};
    }
    if (max_chunks_per_request == 0 || max_chunks_per_request > kMaxRequestedChunksPerRequest) {
        max_chunks_per_request = kMaxRequestedChunksPerRequest;
    }

    std::vector<ChunkRequestMessage> result;
    std::size_t offset = 0;
    while (offset < missing_hashes.size()) {
        const std::size_t count = std::min(max_chunks_per_request, missing_hashes.size() - offset);
        std::vector<std::string> batch(missing_hashes.begin() + static_cast<std::ptrdiff_t>(offset),
                                       missing_hashes.begin() + static_cast<std::ptrdiff_t>(offset + count));
        result.push_back(ChunkRequestMessage{relative_path, std::move(batch)});
        offset += count;
    }
    return result;
}

bool chunk_file_for_peer(
    const std::string& file_path,
    mc::cas::FileManifest& out_manifest,
    std::string& err) {
    std::error_code ec;
    const fs::path p(file_path);
    if (!fs::exists(p, ec) || !fs::is_regular_file(p, ec)) {
        err = "file does not exist or is not a regular file: " + file_path;
        return false;
    }
    const auto file_size = fs::file_size(p, ec);
    if (ec) {
        err = "failed to get file size for " + file_path + ": " + ec.message();
        return false;
    }

    if (file_size == 0) {
        out_manifest.clear();
        out_manifest.set_version(mc::cas::FileManifest::kCurrentVersion);
        out_manifest.set_total_size(0);
        out_manifest.set_file_sha256(mc::cas::kEmptySha256);
        return true;
    }

    const std::string whole_sha = mc::sha256_file(p);
    mc::cas::FastCDCChunker chunker(get_peer_chunker_config());
    auto chunks = chunker.chunk_file(p);

    out_manifest.set_version(mc::cas::FileManifest::kCurrentVersion);
    out_manifest.set_file_sha256(whole_sha);
    out_manifest.set_chunks(std::move(chunks));

    return validate_peer_manifest(out_manifest, err);
}

bool chunk_buffer_for_peer(
    const void* data,
    std::size_t size,
    mc::cas::FileManifest& out_manifest,
    std::string& err) {
    if (size == 0) {
        out_manifest.clear();
        out_manifest.set_version(mc::cas::FileManifest::kCurrentVersion);
        out_manifest.set_total_size(0);
        out_manifest.set_file_sha256(mc::cas::kEmptySha256);
        return true;
    }
    if (data == nullptr) {
        err = "null data buffer pointer with non-zero size";
        return false;
    }

    const std::string whole_sha = mc::sha256_data(data, size);
    mc::cas::FastCDCChunker chunker(get_peer_chunker_config());
    auto chunks = chunker.chunk_buffer(data, size);

    out_manifest.set_version(mc::cas::FileManifest::kCurrentVersion);
    out_manifest.set_file_sha256(whole_sha);
    out_manifest.set_chunks(std::move(chunks));

    return validate_peer_manifest(out_manifest, err);
}

bool verify_chunk_payload(
    const std::string& claimed_hash,
    const void* data,
    std::size_t size,
    std::string& err) {
    if (size == 0) {
        err = "chunk payload cannot be empty";
        return false;
    }
    if (size > kPeerFastCdcMaxSize) {
        err = "chunk payload size (" + std::to_string(size) + ") exceeds maximum FastCDC limit (" +
              std::to_string(kPeerFastCdcMaxSize) + " bytes)";
        return false;
    }
    if (data == nullptr) {
        err = "null chunk data buffer";
        return false;
    }
    if (!is_valid_hex_sha256(claimed_hash)) {
        err = "invalid claimed SHA-256 hash format: " + claimed_hash;
        return false;
    }

    const std::string actual_hash = mc::sha256_data(data, size);
    if (actual_hash != claimed_hash) {
        err = "cryptographic verification failed: claimed=" + claimed_hash + ", actual=" + actual_hash;
        return false;
    }
    return true;
}

} // namespace mc::peer
