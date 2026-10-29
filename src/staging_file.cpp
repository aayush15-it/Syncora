#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "merklechain/staging_file.hpp"
#include "merklechain/hash.hpp"

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace mc {
namespace {
std::runtime_error win_error(const char* operation) {
    return std::runtime_error(std::string(operation) + " failed with Windows error " +
                              std::to_string(GetLastError()));
}

std::wstring final_path(HANDLE handle) {
    const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
    if (required == 0) throw win_error("GetFinalPathNameByHandleW");
    std::vector<wchar_t> buffer(static_cast<std::size_t>(required) + 1U);
    const DWORD written = GetFinalPathNameByHandleW(handle, buffer.data(),
        static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED);
    if (written == 0 || written >= buffer.size()) throw win_error("GetFinalPathNameByHandleW");
    return std::wstring(buffer.data(), written);
}

bool same_path(std::wstring left, std::wstring right) {
    while (!left.empty() && (left.back() == L'\\' || left.back() == L'/')) left.pop_back();
    while (!right.empty() && (right.back() == L'\\' || right.back() == L'/')) right.pop_back();
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        const auto a = left[i] == L'/' ? L'\\' : towlower(left[i]);
        const auto b = right[i] == L'/' ? L'\\' : towlower(right[i]);
        if (a != b) return false;
    }
    return true;
}
}

struct StagingFile::Impl {
    fs::path path;
    fs::path parent_path;
    HANDLE directory{INVALID_HANDLE_VALUE};
    HANDLE file{INVALID_HANDLE_VALUE};
    bool committed{false};
    std::uintmax_t bytes_written{0};

    explicit Impl(fs::path value) : path(std::move(value)), parent_path(path.parent_path()) {
        directory = CreateFileW(parent_path.c_str(), FILE_READ_ATTRIBUTES | FILE_ADD_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (directory == INVALID_HANDLE_VALUE) throw win_error("open staging directory");
        BY_HANDLE_FILE_INFORMATION directory_info{};
        if (!GetFileInformationByHandle(directory, &directory_info)) {
            const auto error = win_error("inspect staging directory");
            CloseHandle(directory); directory = INVALID_HANDLE_VALUE; throw error;
        }
        if ((directory_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (directory_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            CloseHandle(directory); directory = INVALID_HANDLE_VALUE;
            throw std::runtime_error("staging parent must be a non-reparse directory");
        }
        file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            const auto error = win_error("create staging file exclusively");
            CloseHandle(directory); directory = INVALID_HANDLE_VALUE; throw error;
        }
        try {
            FILE_ATTRIBUTE_TAG_INFO tag{};
            if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)))
                throw win_error("inspect staging file attributes");
            if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw std::runtime_error("staging file cannot be a reparse point");
            const auto full_file = final_path(file);
            const auto full_parent = final_path(directory);
            const auto separator = full_file.find_last_of(L"\\/");
            if (separator == std::wstring::npos || !same_path(full_file.substr(0, separator), full_parent))
                throw std::runtime_error("staging file resolved outside its validated parent directory");
        } catch (...) {
            FILE_DISPOSITION_INFO disposition{TRUE};
            SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition));
            CloseHandle(file); file = INVALID_HANDLE_VALUE;
            CloseHandle(directory); directory = INVALID_HANDLE_VALUE;
            throw;
        }
    }

    ~Impl() {
        if (file != INVALID_HANDLE_VALUE) {
            if (!committed) {
                FILE_DISPOSITION_INFO disposition{TRUE};
                SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition));
            }
            CloseHandle(file);
        }
        if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
    }
};

StagingFile::StagingFile(fs::path path) : impl_(std::make_unique<Impl>(std::move(path))) {}
StagingFile::~StagingFile() = default;
StagingFile::StagingFile(StagingFile&&) noexcept = default;
StagingFile& StagingFile::operator=(StagingFile&&) noexcept = default;
const fs::path& StagingFile::path() const noexcept { return impl_->path; }

void StagingFile::reset() {
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(impl_->file, start, nullptr, FILE_BEGIN) || !SetEndOfFile(impl_->file))
        throw win_error("truncate staging file");
    impl_->bytes_written=0;
}

void StagingFile::write(const void* data, std::size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    while (size != 0) {
        const DWORD count = static_cast<DWORD>(std::min<std::size_t>(size, MAXDWORD));
        DWORD written = 0;
        if (!WriteFile(impl_->file, bytes, count, &written, nullptr) || written != count)
            throw win_error("write staging file");
        bytes += written;
        size -= written;
        const auto written_bytes=static_cast<std::uintmax_t>(written);
        impl_->bytes_written=impl_->bytes_written>std::numeric_limits<std::uintmax_t>::max()-written_bytes
            ?std::numeric_limits<std::uintmax_t>::max():impl_->bytes_written+written_bytes;
    }
}

void StagingFile::flush() {
    if (!FlushFileBuffers(impl_->file)) throw win_error("flush staging file");
}

std::uintmax_t StagingFile::size() const {
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(impl_->file, &length) || length.QuadPart < 0)
        throw win_error("read staging file size");
    return static_cast<std::uintmax_t>(length.QuadPart);
}

std::uintmax_t StagingFile::bytes_written() const noexcept { return impl_?impl_->bytes_written:0; }

std::string StagingFile::sha256_range(std::uintmax_t offset, std::uintmax_t length) {
    const auto max_offset=static_cast<std::uintmax_t>(std::numeric_limits<LONGLONG>::max());
    if (offset > max_offset || length > max_offset - offset)
        throw std::runtime_error("staging hash range exceeds Windows file limits");
    LARGE_INTEGER position{};position.QuadPart=static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(impl_->file, position, nullptr, FILE_BEGIN)) throw win_error("seek staging file for hashing");
    EVP_MD_CTX* context=EVP_MD_CTX_new();if(!context)throw std::runtime_error("cannot allocate staging digest context");
    struct ContextGuard { EVP_MD_CTX* value; ~ContextGuard(){EVP_MD_CTX_free(value);} } guard{context};
    if(EVP_DigestInit_ex(context,EVP_sha256(),nullptr)!=1)throw std::runtime_error("cannot initialize staging digest");
    std::array<unsigned char,64U*1024U> buffer{};std::uintmax_t remaining=length;
    while(remaining){const DWORD requested=static_cast<DWORD>(std::min<std::uintmax_t>(remaining,buffer.size()));DWORD read=0;
        if(!ReadFile(impl_->file,buffer.data(),requested,&read,nullptr)||read!=requested)throw win_error("read staging file for hashing");
        if(EVP_DigestUpdate(context,buffer.data(),read)!=1)throw std::runtime_error("cannot update staging digest");
        remaining-=read;
    }
    std::array<unsigned char,EVP_MAX_MD_SIZE> digest{};unsigned int digest_length=0;
    if(EVP_DigestFinal_ex(context,digest.data(),&digest_length)!=1)throw std::runtime_error("cannot finalize staging digest");
    std::ostringstream result;result<<std::hex<<std::setfill('0');for(unsigned int i=0;i<digest_length;++i)result<<std::setw(2)<<static_cast<unsigned>(digest[i]);
    return result.str();
}

std::string StagingFile::sha256() { return sha256_range(0,size()); }

namespace {
void rename_owned_handle(HANDLE handle, const fs::path& owned_parent,
                         const fs::path& target) {
    if (target.parent_path().lexically_normal() != owned_parent.lexically_normal())
        throw std::runtime_error("staging rename target is outside the validated directory");
    const auto name = fs::absolute(target).native();
    if (name.size() > (MAXDWORD - sizeof(FILE_RENAME_INFO)) / sizeof(wchar_t))
        throw std::runtime_error("staging rename filename is too long");
    std::vector<unsigned char> storage(sizeof(FILE_RENAME_INFO) + name.size() * sizeof(wchar_t));
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    rename->ReplaceIfExists = FALSE;
    // A fully-qualified name with a null RootDirectory works consistently
    // across local volumes and Windows file-system providers.
    rename->RootDirectory = nullptr;
    rename->FileNameLength = static_cast<DWORD>(name.size() * sizeof(wchar_t));
    std::memcpy(rename->FileName, name.data(), rename->FileNameLength);
    if (!SetFileInformationByHandle(handle, FileRenameInfo, rename,
                                    static_cast<DWORD>(storage.size())))
        throw win_error("rename staging file by handle");
}
}

void StagingFile::commit_to(const fs::path& target, const std::string& expected_sha256) {
    flush();
    if (sha256() != expected_sha256)
        throw std::runtime_error("refusing to commit staging file with an unverified SHA-256");
    rename_owned_handle(impl_->file, impl_->parent_path, target);
    impl_->path = target;
    impl_->committed = true;
}

void StagingFile::move_failed_commit_to(const fs::path& quarantine) {
    if (!impl_->committed) throw std::logic_error("only a committed staging file can be quarantined");
    rename_owned_handle(impl_->file, impl_->parent_path, quarantine);
    impl_->path = quarantine;
    impl_->committed = false;
}

void StagingFile::keep() noexcept {
    if (impl_) impl_->committed = true;
}

bool StagingFile::discard() noexcept {
    if (!impl_ || impl_->file == INVALID_HANDLE_VALUE || impl_->committed) return true;
    FILE_DISPOSITION_INFO disposition{TRUE};
    return SetFileInformationByHandle(impl_->file, FileDispositionInfo, &disposition, sizeof(disposition)) != 0;
}

void copy_file_to_staging(const fs::path& source, StagingFile& staging,
                          const std::string& expected_sha256,std::uintmax_t* source_bytes_read) {
    staging.reset();
    std::ifstream input(source, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open source for whole-file staging");
    std::array<char, 64U * 1024U> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) { staging.write(buffer.data(), static_cast<std::size_t>(count)); if(source_bytes_read){const auto read=static_cast<std::uintmax_t>(count);*source_bytes_read=*source_bytes_read>std::numeric_limits<std::uintmax_t>::max()-read?std::numeric_limits<std::uintmax_t>::max():*source_bytes_read+read;} }
    }
    if (!input.eof()) throw std::runtime_error("whole-file staging read failed");
    staging.flush();
    if (staging.sha256() != expected_sha256)
        throw std::runtime_error("whole-file staging failed SHA-256 verification");
}

} // namespace mc
