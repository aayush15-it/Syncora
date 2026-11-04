#include "merklechain/peer/peer_cas_helpers.hpp"
#include "merklechain/cas/manifest_serializer.hpp"
#include "merklechain/hash.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <unordered_map>
#include <cstring>
#include <openssl/evp.h>

namespace mc::peer {

namespace {
bool is_windows_reserved_device_name(const std::string& segment) {
    if (segment.empty()) return false;
    auto dot_pos = segment.find('.');
    std::string base = (dot_pos == std::string::npos) ? segment : segment.substr(0, dot_pos);
    if (base.empty()) return false;
    std::string upper;
    upper.reserve(base.size());
    for (char ch : base) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
    }
    if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL") {
        return true;
    }
    if (upper.size() == 4) {
        if ((upper.rfind("COM", 0) == 0 || upper.rfind("LPT", 0) == 0) &&
            upper[3] >= '1' && upper[3] <= '9') {
            return true;
        }
    }
    return false;
}
}

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
    if (path.back() == '/' || path.back() == '\\') {
        err = "path must refer to a file, got trailing slash: " + path;
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
            if (segment.empty() && i > 0 && i < path.size()) {
                err = "path contains empty directory segment (consecutive slashes): " + path;
                return false;
            }
            if (segment == "..") {
                err = "path contains directory traversal ('..'): " + path;
                return false;
            }
            if (!segment.empty() && (segment.back() == ' ' || segment.back() == '.')) {
                err = "path segment ends with trailing space or dot: " + segment;
                return false;
            }
            if (is_windows_reserved_device_name(segment)) {
                err = "path contains reserved Windows device name: " + segment;
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

        // Integer overflow checks
        if (std::numeric_limits<std::uint64_t>::max() - expected_offset < c.size) {
            err = "manifest offset integer overflow at chunk " + std::to_string(i);
            return false;
        }
        if (std::numeric_limits<std::uint64_t>::max() - accumulated_size < c.size) {
            err = "manifest total size integer overflow at chunk " + std::to_string(i);
            return false;
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

std::vector<std::uint8_t> encode_peer_manifest_page_payload(const std::vector<mc::cas::ChunkInfo>& chunks) {
    std::vector<std::uint8_t> payload(chunks.size() * 80);
    std::uint8_t* ptr = payload.data();
    for (const auto& c : chunks) {
        std::uint64_t off = c.offset;
        std::uint64_t sz = c.size;
        std::memcpy(ptr, &off, 8);
        ptr += 8;
        std::memcpy(ptr, &sz, 8);
        ptr += 8;
        std::memcpy(ptr, c.hash.data(), 64);
        ptr += 64;
    }
    return payload;
}

bool decode_peer_manifest_page_payload(const std::vector<std::uint8_t>& payload, std::uint32_t expected_chunks,
                                       std::vector<mc::cas::ChunkInfo>& out_chunks, std::string& err) {
    if (payload.size() != static_cast<std::size_t>(expected_chunks) * 80) {
        err = "manifest page payload size mismatch: expected " + std::to_string(expected_chunks * 80) +
              " bytes, got " + std::to_string(payload.size());
        return false;
    }
    out_chunks.clear();
    out_chunks.reserve(expected_chunks);
    const std::uint8_t* ptr = payload.data();
    for (std::uint32_t i = 0; i < expected_chunks; ++i) {
        std::uint64_t off = 0;
        std::uint64_t sz = 0;
        std::memcpy(&off, ptr, 8);
        ptr += 8;
        std::memcpy(&sz, ptr, 8);
        ptr += 8;
        std::string hash(reinterpret_cast<const char*>(ptr), 64);
        ptr += 64;
        if (!is_valid_hex_sha256(hash)) {
            err = "manifest page chunk " + std::to_string(i) + " contains invalid hash";
            return false;
        }
        out_chunks.push_back({off, sz, std::move(hash)});
    }
    return true;
}

void SessionChunkAuthorizer::authorize_manifest(const mc::cas::FileManifest& manifest) {
    for (const auto& c : manifest.chunks()) {
        if (is_valid_hex_sha256(c.hash)) {
            authorized_hashes_.insert(c.hash);
        }
    }
}

void SessionChunkAuthorizer::authorize_manifest(const std::string& relative_path, const mc::cas::FileManifest& manifest) {
    std::string path_err;
    if (validate_peer_path(relative_path, path_err)) {
        authorized_paths_.insert(relative_path);
    }
    authorize_manifest(manifest);
}

bool SessionChunkAuthorizer::authorize_path(const std::string& relative_path) {
    std::string path_err;
    if (!validate_peer_path(relative_path, path_err)) {
        return false;
    }
    authorized_paths_.insert(relative_path);
    return true;
}

bool SessionChunkAuthorizer::is_path_authorized(const std::string& relative_path) const noexcept {
    return authorized_paths_.find(relative_path) != authorized_paths_.end();
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
    if (!authorized_paths_.empty() && !is_path_authorized(request.relative_path)) {
        err = "unauthorized relative path in chunk request: " + request.relative_path;
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

bool compute_missing_chunks(
    const mc::cas::FileManifest& manifest,
    const mc::cas::ObjectStore& object_store,
    MissingChunksResult& out_result,
    std::string& err) {
    out_result.missing_hashes.clear();
    out_result.corrupt_hashes.clear();
    out_result.valid_hashes.clear();
    out_result.total_chunks = 0;
    out_result.missing_bytes = 0;
    out_result.local_reused_bytes = 0;

    if (manifest.is_empty()) {
        return true;
    }

    std::unordered_map<std::string, mc::cas::ObjectAvailability> seen_status;

    for (const auto& c : manifest.chunks()) {
        out_result.total_chunks++;

        auto it = seen_status.find(c.hash);
        if (it == seen_status.end()) {
            const auto st = object_store.verify_object(c.hash, c.size);
            if (st.availability == mc::cas::ObjectAvailability::InvalidHash) {
                err = "manifest contains invalid chunk hash format: " + c.hash;
                return false;
            }
            if (st.availability == mc::cas::ObjectAvailability::IoError) {
                err = "I/O error verifying chunk " + c.hash + ": " + st.error;
                return false;
            }

            seen_status[c.hash] = st.availability;

            if (st.availability == mc::cas::ObjectAvailability::AvailableValid) {
                out_result.valid_hashes.push_back(c.hash);
                out_result.local_reused_bytes += c.size;
            } else if (st.availability == mc::cas::ObjectAvailability::Missing) {
                out_result.missing_hashes.push_back(c.hash);
                out_result.missing_bytes += c.size;
            } else if (st.availability == mc::cas::ObjectAvailability::Corrupt) {
                out_result.corrupt_hashes.push_back(c.hash);
                out_result.missing_hashes.push_back(c.hash);
                out_result.missing_bytes += c.size;
            }
        } else {
            const auto prev_avail = it->second;
            if (prev_avail == mc::cas::ObjectAvailability::AvailableValid) {
                out_result.local_reused_bytes += c.size;
            } else {
                out_result.missing_bytes += c.size;
            }
        }
    }
    return true;
}

std::vector<std::string> compute_missing_chunks(
    const mc::cas::FileManifest& manifest,
    const mc::cas::ObjectStore& object_store) {
    MissingChunksResult res;
    std::string err;
    if (!compute_missing_chunks(manifest, object_store, res, err)) {
        throw std::runtime_error("compute_missing_chunks failed: " + err);
    }
    return res.missing_hashes;
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

namespace {
std::function<void()>& testing_mutation_hook() {
    static std::function<void()> hook;
    return hook;
}
PeerCasFaultPointForTesting& peer_cas_fault_point_ref() noexcept {
    static PeerCasFaultPointForTesting fp = PeerCasFaultPointForTesting::None;
    return fp;
}
} // namespace

void set_peer_cas_fault_point_for_testing(PeerCasFaultPointForTesting fp) {
    peer_cas_fault_point_ref() = fp;
}

PeerCasFaultPointForTesting get_peer_cas_fault_point_for_testing() {
    return peer_cas_fault_point_ref();
}

void set_chunk_stream_mutation_hook(std::function<void()> hook) {
    testing_mutation_hook() = std::move(hook);
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
    const auto initial_size = fs::file_size(p, ec);
    if (ec) {
        err = "failed to get file size for " + file_path + ": " + ec.message();
        return false;
    }
    const auto initial_mtime = fs::last_write_time(p, ec);

    if (initial_size == 0) {
        out_manifest.clear();
        out_manifest.set_version(mc::cas::FileManifest::kCurrentVersion);
        out_manifest.set_total_size(0);
        out_manifest.set_file_sha256(mc::cas::kEmptySha256);
        return true;
    }

    // Incremental EVP SHA-256 computation in single streaming pass
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        err = "failed to allocate EVP_MD_CTX";
        return false;
    }
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(md_ctx);
        err = "failed to initialize SHA-256 context";
        return false;
    }

    std::vector<mc::cas::ChunkInfo> chunks;
    std::uint64_t accumulated_bytes = 0;
    bool stream_failed = false;
    std::string stream_err;
    bool invoked_hook = false;

    try {
        mc::cas::FastCDCChunker chunker(get_peer_chunker_config());
        chunker.chunk_file_stream(p, [&](const mc::cas::ChunkInfo& info, const std::uint8_t* data) {
            chunks.push_back(info);
            accumulated_bytes += info.size;
            if (EVP_DigestUpdate(md_ctx, data, static_cast<size_t>(info.size)) != 1) {
                stream_failed = true;
                stream_err = "failed to update SHA-256 digest during stream";
            }
            if (!invoked_hook && testing_mutation_hook()) {
                invoked_hook = true;
                testing_mutation_hook()();
            }
        });
    } catch (const std::exception& e) {
        stream_failed = true;
        stream_err = e.what();
    }

    if (stream_failed) {
        EVP_MD_CTX_free(md_ctx);
        err = "error during chunk streaming: " + stream_err;
        return false;
    }

    std::array<unsigned char, 32> hash_buf{};
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(md_ctx, hash_buf.data(), &hash_len) != 1 || hash_len != 32) {
        EVP_MD_CTX_free(md_ctx);
        err = "failed to finalize SHA-256 digest";
        return false;
    }
    EVP_MD_CTX_free(md_ctx);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash_buf[i]);
    }
    const std::string computed_whole_sha = ss.str();

    // Verify consistency: verify post-read size, timestamp and accumulated bytes
    const auto post_size = fs::file_size(p, ec);
    if (!ec && post_size != initial_size) {
        err = "source file size mutated during chunking pass: was " + std::to_string(initial_size) +
              ", now " + std::to_string(post_size);
        return false;
    }
    const auto post_mtime = fs::last_write_time(p, ec);
    if (!ec && post_mtime != initial_mtime) {
        err = "source file modification timestamp mutated during chunking pass";
        return false;
    }
    if (accumulated_bytes != initial_size) {
        err = "accumulated chunk bytes (" + std::to_string(accumulated_bytes) +
              ") does not match file size (" + std::to_string(initial_size) + ")";
        return false;
    }

    out_manifest.set_version(mc::cas::FileManifest::kCurrentVersion);
    out_manifest.set_total_size(accumulated_bytes);
    out_manifest.set_file_sha256(computed_whole_sha);
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
    out_manifest.set_total_size(size);
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
