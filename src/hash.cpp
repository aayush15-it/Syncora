#include "merklechain/hash.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace mc {
static std::string digest_hex(const unsigned char* data, unsigned int n) {
    std::ostringstream out; out << std::hex << std::setfill('0');
    for (unsigned int i=0;i<n;++i) out << std::setw(2) << static_cast<unsigned>(data[i]);
    return out.str();
}
std::string sha256_data(const void* data,std::size_t size) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{}; unsigned int n=0;
    if (EVP_Digest(data,size,digest.data(),&n,EVP_sha256(),nullptr)!=1) throw std::runtime_error("SHA-256 failed");
    return digest_hex(digest.data(), n);
}
static std::string sha256_bytes(const std::string& value) { return sha256_data(value.data(),value.size()); }
std::string sha256_file(const fs::path& path,std::uintmax_t* bytes_read) {
    std::ifstream in(path, std::ios::binary); if (!in) throw std::runtime_error("cannot open file for hashing: " + path.string());
    EVP_MD_CTX* raw=EVP_MD_CTX_new(); if (!raw) throw std::runtime_error("cannot allocate digest context");
    struct Guard { EVP_MD_CTX* p; ~Guard(){EVP_MD_CTX_free(p);} } guard{raw};
    if (EVP_DigestInit_ex(raw, EVP_sha256(), nullptr) != 1) throw std::runtime_error("SHA-256 initialization failed");
    std::array<char, 1024*1024> buffer{};
    while (in) { in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())); auto n=in.gcount(); if (n>0) { if (EVP_DigestUpdate(raw, buffer.data(), static_cast<std::size_t>(n)) != 1) throw std::runtime_error("SHA-256 update failed"); if(bytes_read){const auto count=static_cast<std::uintmax_t>(n);*bytes_read=(*bytes_read>std::numeric_limits<std::uintmax_t>::max()-count)?std::numeric_limits<std::uintmax_t>::max():*bytes_read+count;} } }
    if (!in.eof()) throw std::runtime_error("file read failed while hashing: " + path.string());
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{}; unsigned int n=0;
    if (EVP_DigestFinal_ex(raw,digest.data(),&n)!=1) throw std::runtime_error("SHA-256 finalization failed");
    return digest_hex(digest.data(),n);
}
std::string merkle_root(const std::vector<FileMetadata>& input) {
    if (input.empty()) return sha256_bytes("MERKLECHAIN-EMPTY-v1");
    auto files=input; std::sort(files.begin(),files.end(),[](const auto& x,const auto& y){return x.relative_path<y.relative_path;});
    std::vector<std::string> level; level.reserve(files.size());
    for (const auto& f:files) level.push_back(sha256_bytes("leaf" + f.relative_path + f.sha256));
    while (level.size()>1) {
        std::vector<std::string> next; next.reserve((level.size()+1)/2);
        for (std::size_t i=0;i<level.size();i+=2) {
            const auto& right=(i+1<level.size())?level[i+1]:level[i];
            next.push_back(sha256_bytes("node"+level[i]+right));
        }
        level=std::move(next);
    }
    return level.front();
}

MerkleTreeInfo build_merkle_tree_info(const std::vector<FileMetadata>& input) {
    MerkleTreeInfo info;
    info.file_count = input.size();
    if (input.empty()) {
        info.root_hash = sha256_bytes("MERKLECHAIN-EMPTY-v1");
        info.tree_depth = 1;
        info.levels.push_back({info.root_hash});
        return info;
    }
    auto files = input;
    std::sort(files.begin(), files.end(), [](const auto& x, const auto& y) {
        return x.relative_path < y.relative_path;
    });
    info.leaves.reserve(files.size());
    std::vector<std::string> current_level;
    current_level.reserve(files.size());
    for (const auto& f : files) {
        std::string leaf_hash = sha256_bytes("leaf" + f.relative_path + f.sha256);
        info.leaves.push_back({f.relative_path, f.sha256, leaf_hash});
        current_level.push_back(leaf_hash);
    }
    info.levels.push_back(current_level);
    while (current_level.size() > 1) {
        std::vector<std::string> next_level;
        next_level.reserve((current_level.size() + 1) / 2);
        for (std::size_t i = 0; i < current_level.size(); i += 2) {
            const auto& right = (i + 1 < current_level.size()) ? current_level[i + 1] : current_level[i];
            next_level.push_back(sha256_bytes("node" + current_level[i] + right));
        }
        current_level = std::move(next_level);
        info.levels.push_back(current_level);
    }
    info.tree_depth = info.levels.size();
    info.root_hash = current_level.front();
    return info;
}
}
