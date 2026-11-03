#pragma once
#include "merklechain/types.hpp"
namespace mc {
FileManifest scan_folder(const fs::path& root);
std::string canonical_relative(const fs::path& path);
bool safe_relative_path(const std::string& path);
bool is_reparse_point_or_symlink(const fs::path& path);
bool is_path_within_boundary(const fs::path& base, const fs::path& target);
}
