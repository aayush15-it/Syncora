#include "merklechain/scanner.hpp"
#include "merklechain/hash.hpp"
#include <algorithm>
#include <cctype>
#include <system_error>

namespace mc {
std::string canonical_relative(const fs::path& path) { auto s=path.generic_u8string(); std::replace(s.begin(),s.end(),'\\','/'); return s; }

static bool is_windows_reserved_component(const std::string& comp) {
    if (comp.empty()) return true;
    if (comp.back() == ' ' || comp.back() == '.') return true;
    for (unsigned char c : comp) {
        if (c < 32 || c == '<' || c == '>' || c == ':' || c == '"' ||
            c == '/' || c == '\\' || c == '|' || c == '?' || c == '*') {
            return true;
        }
    }
    if (comp.front() == '.') return false;

    std::string base = comp;
    const auto dot_pos = base.find('.');
    if (dot_pos != std::string::npos) {
        base = base.substr(0, dot_pos);
    }
    std::string lower_base = base;
    std::transform(lower_base.begin(), lower_base.end(), lower_base.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (lower_base == "con" || lower_base == "prn" || lower_base == "aux" || lower_base == "nul") {
        return true;
    }
    if (lower_base.size() == 4) {
        if ((lower_base.rfind("com", 0) == 0 || lower_base.rfind("lpt", 0) == 0) &&
            (lower_base[3] >= '1' && lower_base[3] <= '9')) {
            return true;
        }
    }
    return false;
}

bool safe_relative_path(const std::string& value) {
    if (value.empty() || value.front() == '/' || value.front() == '\\') return false;
    if (value.size() > 1 && std::isalpha(static_cast<unsigned char>(value[0])) && value[1] == ':') return false;
    if (value.find(':') != std::string::npos) return false;
    fs::path p = fs::u8path(value);
    if (p.is_absolute() || p.has_root_name() || p.has_root_directory()) return false;
    for (const auto& part : p) {
        auto s = part.u8string();
        if (s == ".." || s == "." || s.empty()) return false;
        if (is_windows_reserved_component(s)) return false;
    }
    return true;
}
FileManifest scan_folder(const fs::path& input) {
    FileManifest manifest; std::error_code ec; auto root=fs::weakly_canonical(input,ec);
    if(ec || !fs::is_directory(root,ec) || ec) { manifest.complete=false; manifest.warnings.push_back("Folder is missing or inaccessible: "+input.string()); return manifest; }
    fs::recursive_directory_iterator it(root,fs::directory_options::none,ec), end;
    if(ec){manifest.complete=false;manifest.warnings.push_back(ec.message());ec.clear();}
    for(;it!=end;it.increment(ec)) {
        if(ec){manifest.complete=false;manifest.warnings.push_back(ec.message());ec.clear();continue;}
        auto p=it->path(); auto status=it->symlink_status(ec);
        if(ec){manifest.complete=false;manifest.warnings.push_back(p.string()+": "+ec.message());ec.clear();continue;}
        if(fs::is_symlink(status)){ it.disable_recursion_pending(); continue; }
        auto rel=canonical_relative(fs::relative(p,root,ec));
        if(ec || !safe_relative_path(rel)){manifest.complete=false;manifest.warnings.push_back("Unsafe or unavailable path: "+p.string());ec.clear();continue;}
        auto app_path=rel;std::transform(app_path.begin(),app_path.end(),app_path.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
        if(app_path==".merklechain" || app_path.rfind(".merklechain/",0)==0){if(it->is_directory(ec))it.disable_recursion_pending();continue;}
        if(!fs::is_regular_file(status)) continue;
        try {
            FileMetadata f; f.relative_path=rel; f.size=it->file_size(ec); if(ec)throw std::runtime_error(ec.message());
            f.modified_ticks=it->last_write_time(ec).time_since_epoch().count(); if(ec)throw std::runtime_error(ec.message());
            f.sha256=sha256_file(p); manifest.files.push_back(std::move(f));
        } catch(const std::exception& e){manifest.complete=false;manifest.warnings.push_back(rel+": "+e.what());ec.clear();}
    }
    std::sort(manifest.files.begin(),manifest.files.end(),[](const auto& a,const auto& b){return a.relative_path<b.relative_path;});
    manifest.merkle_root=merkle_root(manifest.files); return manifest;
}
}
