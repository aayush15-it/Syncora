#pragma once
#include "merklechain/types.hpp"
namespace mc {
FileManifest scan_folder(const fs::path& root);
std::string canonical_relative(const fs::path& path);
bool safe_relative_path(const std::string& path);
}
