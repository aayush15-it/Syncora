#include "merklechain/scanner.hpp"
#include "merklechain/hash.hpp"
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <system_error>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

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

bool is_reparse_point_or_symlink(const fs::path& path) {
#ifdef _WIN32
    DWORD attrs = GetFileAttributesW(path.wstring().c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return true;
    }
#endif
    std::error_code ec;
    auto status = fs::symlink_status(path, ec);
    return (!ec && fs::is_symlink(status));
}

static bool is_canon_path_within_boundary(const fs::path& canon_base, const fs::path& target) {
    std::error_code ec;
    auto canon_target = fs::weakly_canonical(target, ec);
    if (ec) return false;

    auto it_base = canon_base.begin();
    auto end_base = canon_base.end();
    auto it_target = canon_target.begin();
    auto end_target = canon_target.end();

    for (; it_base != end_base; ++it_base, ++it_target) {
        if (it_target == end_target) {
            return false;
        }
#ifdef _WIN32
        std::wstring s_base = it_base->wstring();
        std::wstring s_target = it_target->wstring();
        while (s_base.size() > 1 && (s_base.back() == L'/' || s_base.back() == L'\\')) s_base.pop_back();
        while (s_target.size() > 1 && (s_target.back() == L'/' || s_target.back() == L'\\')) s_target.pop_back();
        if (s_base.size() != s_target.size()) return false;
        for (std::size_t i = 0; i < s_base.size(); ++i) {
            wchar_t ca = s_base[i] == L'/' ? L'\\' : towlower(s_base[i]);
            wchar_t cb = s_target[i] == L'/' ? L'\\' : towlower(s_target[i]);
            if (ca != cb) return false;
        }
#else
        if (*it_base != *it_target) return false;
#endif
    }
    return true;
}

bool is_path_within_boundary(const fs::path& base, const fs::path& target) {
    std::error_code ec;
    auto canon_base = fs::weakly_canonical(base, ec);
    if (ec) return false;
    return is_canon_path_within_boundary(canon_base, target);
}

FileManifest scan_folder(const fs::path& input) {
    FileManifest manifest; std::error_code ec; auto root=fs::weakly_canonical(input,ec);
    if(ec || !fs::is_directory(root,ec) || ec) { manifest.complete=false; manifest.warnings.push_back("Folder is missing or inaccessible: "+input.string()); return manifest; }
    if(is_reparse_point_or_symlink(root)) { manifest.complete=false; manifest.warnings.push_back("Folder cannot be a symbolic link or directory junction: "+input.string()); return manifest; }
    fs::recursive_directory_iterator it(root,fs::directory_options::none,ec), end;
    if(ec){manifest.complete=false;manifest.warnings.push_back(ec.message());ec.clear();}
    for(;it!=end;it.increment(ec)) {
        if(ec){manifest.complete=false;manifest.warnings.push_back(ec.message());ec.clear();continue;}
        auto p=it->path(); auto status=it->symlink_status(ec);
        if(ec){manifest.complete=false;manifest.warnings.push_back(p.string()+": "+ec.message());ec.clear();continue;}
        if(fs::is_symlink(status) || is_reparse_point_or_symlink(p)){ it.disable_recursion_pending(); continue; }
        if(!is_canon_path_within_boundary(root, p)){
            manifest.complete=false;
            manifest.warnings.push_back("Path escapes root boundary: "+p.string());
            it.disable_recursion_pending();
            continue;
        }
        auto rel=canonical_relative(fs::relative(p,root,ec));
        if(ec || !safe_relative_path(rel)){manifest.complete=false;manifest.warnings.push_back("Unsafe or unavailable path: "+p.string());ec.clear();continue;}
        auto app_path=rel;std::transform(app_path.begin(),app_path.end(),app_path.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
        if(app_path==".merklechain" || app_path.rfind(".merklechain/",0)==0){if(it->is_directory(ec))it.disable_recursion_pending();continue;}
        if(app_path==".syncora_op_sentinel" || app_path.rfind(".syncora_op_sentinel/",0)==0){if(it->is_directory(ec))it.disable_recursion_pending();continue;}

        // Auto-ignore transient system, lock, and OS cache files that cause sharing violations
        std::string filename = p.filename().u8string();
        std::string lower_fn = filename;
        std::transform(lower_fn.begin(), lower_fn.end(), lower_fn.begin(), [](unsigned char c){return static_cast<char>(std::tolower(c));});
        if (lower_fn == "thumbs.db" || lower_fn == "desktop.ini" || lower_fn == ".ds_store" ||
            lower_fn.rfind(".lock") != std::string::npos || lower_fn.rfind(".guard") != std::string::npos) {
            continue;
        }

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
