#include "merklechain/cas/file_manifest.hpp"

namespace mc::cas {

namespace {

bool is_valid_sha256(const std::string& h) {
    if (h.size() != 64) return false;
    for (char c : h) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

} // namespace

bool FileManifest::validate(std::string& err) const {
    if (version_ != kCurrentVersion) {
        err = "Unsupported manifest version: " + std::to_string(version_);
        return false;
    }

    if (!is_valid_sha256(file_sha256_)) {
        err = "Invalid whole-file SHA-256 hash: " + file_sha256_;
        return false;
    }

    if (total_size_ == 0) {
        if (!chunks_.empty()) {
            err = "Empty file manifest cannot contain chunk records";
            return false;
        }
        if (file_sha256_ != kEmptySha256) {
            err = "Zero-byte file must have canonical empty SHA-256";
            return false;
        }
        return true;
    }

    if (chunks_.empty()) {
        err = "Non-empty file manifest must contain at least one chunk";
        return false;
    }

    if (chunks_[0].offset != 0) {
        err = "First chunk offset must be 0, got: " + std::to_string(chunks_[0].offset);
        return false;
    }

    std::uint64_t expected_offset = 0;
    std::uint64_t accumulated_size = 0;

    for (std::size_t i = 0; i < chunks_.size(); ++i) {
        const auto& c = chunks_[i];
        if (c.size == 0) {
            err = "Chunk " + std::to_string(i) + " has zero size";
            return false;
        }
        if (c.offset != expected_offset) {
            err = "Chunk " + std::to_string(i) + " offset gap or overlap: expected " +
                  std::to_string(expected_offset) + ", got " + std::to_string(c.offset);
            return false;
        }
        if (!is_valid_sha256(c.hash)) {
            err = "Chunk " + std::to_string(i) + " has invalid SHA-256: " + c.hash;
            return false;
        }

        expected_offset += c.size;
        accumulated_size += c.size;
    }

    if (accumulated_size != total_size_) {
        err = "Sum of chunk sizes (" + std::to_string(accumulated_size) +
              ") does not match manifest total_size (" + std::to_string(total_size_) + ")";
        return false;
    }

    return true;
}

} // namespace mc::cas

