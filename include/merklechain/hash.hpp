#pragma once
#include "merklechain/types.hpp"
#include <cstddef>
#include <string>
#include <vector>

namespace mc {
std::string sha256_file(const fs::path& path, std::uintmax_t* bytes_read=nullptr);
std::string sha256_data(const void* data, std::size_t size);
std::string merkle_root(const std::vector<FileMetadata>& files);

struct MerkleLeafDetail {
    std::string relative_path;
    std::string file_sha256;
    std::string leaf_hash;
};

struct MerkleTreeInfo {
    std::string root_hash;
    std::size_t file_count{0};
    std::size_t tree_depth{0};
    std::vector<MerkleLeafDetail> leaves;
    std::vector<std::vector<std::string>> levels;
};

MerkleTreeInfo build_merkle_tree_info(const std::vector<FileMetadata>& files);
}
