#include "merklechain/peer/peer_config.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <map>
#include <stdexcept>

namespace mc::peer {
namespace {
struct Scalar {
    bool is_string{};
    std::string string_value;
    std::uint64_t number_value{};
};

class FlatJsonParser {
public:
    explicit FlatJsonParser(std::string input) : input_(std::move(input)) {}
    std::map<std::string, Scalar> parse() {
        skip(); expect('{'); skip(); std::map<std::string, Scalar> result;
        if (consume('}')) { skip(); end(); return result; }
        while (true) {
            skip(); auto key = string(); skip(); expect(':'); skip(); Scalar value;
            if (peek() == '"') { value.is_string = true; value.string_value = string(); }
            else value.number_value = number();
            if (!result.emplace(std::move(key), std::move(value)).second)
                fail("duplicate configuration property");
            skip(); if (consume('}')) break; expect(',');
        }
        skip(); end(); return result;
    }
private:
    std::string input_; std::size_t pos_{};
    char peek() const { return pos_ < input_.size() ? input_[pos_] : '\0'; }
    void skip() { while (peek() == ' ' || peek() == '\t' || peek() == '\r' || peek() == '\n') ++pos_; }
    [[noreturn]] void fail(const char* message) const { throw std::runtime_error(std::string("invalid peer configuration: ") + message); }
    void expect(char c) { if (peek() != c) fail("malformed JSON"); ++pos_; }
    bool consume(char c) { if (peek() != c) return false; ++pos_; return true; }
    void end() const { if (pos_ != input_.size()) fail("trailing data"); }
    std::string string() {
        expect('"'); std::string out;
        while (true) {
            if (pos_ == input_.size()) fail("unterminated string");
            const auto c = input_[pos_++];
            if (c == '"') return out;
            if (static_cast<unsigned char>(c) < 0x20U) fail("control character in string");
            if (c != '\\') { out.push_back(c); continue; }
            if (pos_ == input_.size()) fail("truncated escape");
            const auto escaped = input_[pos_++];
            switch (escaped) {
                case '"': case '\\': case '/': out.push_back(escaped); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                default: fail("unsupported escape (use UTF-8 directly)");
            }
        }
    }
    std::uint64_t number() {
        const auto start = pos_;
        if (peek() < '0' || peek() > '9') fail("only unsigned integer or string values are allowed");
        if (peek() == '0') ++pos_;
        else while (peek() >= '0' && peek() <= '9') ++pos_;
        std::uint64_t value = 0;
        for (auto i = start; i < pos_; ++i) {
            const auto digit = static_cast<std::uint64_t>(input_[i] - '0');
            if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
                fail("integer overflow");
            value = value * 10U + digit;
        }
        return value;
    }
};

const Scalar& required(const std::map<std::string, Scalar>& values, const char* key, bool string) {
    const auto found = values.find(key);
    if (found == values.end() || found->second.is_string != string)
        throw std::runtime_error(std::string("peer config requires ") + key + (string ? " as a string" : " as an integer"));
    return found->second;
}

bool valid_identity(const std::string& value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_';
           });
}

bool valid_fingerprint(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

bool valid_ipv4(const std::string& address) {
    std::size_t start = 0;
    for (int part = 0; part < 4; ++part) {
        const auto end = part == 3 ? address.size() : address.find('.', start);
        if (end == std::string::npos || end == start || end - start > 3) return false;
        unsigned value = 0;
        for (auto i = start; i < end; ++i) {
            const auto c = static_cast<unsigned char>(address[i]);
            if (c < '0' || c > '9') return false;
            value = value * 10U + static_cast<unsigned>(c - '0');
        }
        if (value > 255U) return false;
        start = end + 1;
    }
    return start == address.size() + 1;
}

fs::path resolve_file(const fs::path& base, const std::string& value, const char* label) {
    if (value.empty() || value.size() > 4096) throw std::runtime_error(std::string("invalid peer config path: ") + label);
    auto path = fs::u8path(value);
    if (path.is_relative()) path = base / path;
    path = fs::absolute(path).lexically_normal();
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_regular_file(status))
        throw std::runtime_error(std::string("peer config ") + label + " must be an existing regular file, not a symlink");
    return path;
}
} // namespace

PeerConfig load_peer_config(const fs::path& config_path, Role expected_role) {
    std::error_code ec;
    const auto status = fs::symlink_status(config_path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_regular_file(status))
        throw std::runtime_error("peer config must be an existing regular file, not a symlink");
    const auto size = fs::file_size(config_path, ec);
    if (ec || size > 64U * 1024U) throw std::runtime_error("peer config is unreadable or exceeds 64 KiB");
    std::ifstream input(config_path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open peer config");
    std::string contents(static_cast<std::size_t>(size), '\0');
    if (size != 0 && !input.read(contents.data(), static_cast<std::streamsize>(size)))
        throw std::runtime_error("cannot read complete peer config");
    const auto values = FlatJsonParser(std::move(contents)).parse();
    const std::vector<std::string> common{"schema_version", "role", "identity", "sync_root", "port",
        "certificate_file", "private_key_file", "ca_file", "expected_peer_sha256",
        "handshake_timeout_seconds", "io_timeout_seconds", "max_manifest_files", "max_file_size_bytes"};
    std::vector<std::string> allowed = common;
    allowed.push_back(expected_role == Role::Host ? "bind_address" : "host_address");
    for (const auto& [key, unused] : values) {
        (void)unused;
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end())
            throw std::runtime_error("unknown peer config property: " + key);
    }
    if (required(values, "schema_version", false).number_value != 1)
        throw std::runtime_error("unsupported peer config schema_version");
    PeerConfig result; result.role = expected_role;
    const auto role = required(values, "role", true).string_value;
    if ((expected_role == Role::Host && role != "host") ||
        (expected_role == Role::Client && role != "client"))
        throw std::runtime_error("peer config role does not match the requested command");
    result.identity = required(values, "identity", true).string_value;
    if (!valid_identity(result.identity)) throw std::runtime_error("peer identity must be 1-128 ASCII letters, digits, '-' or '_'");
    auto root = fs::u8path(required(values, "sync_root", true).string_value);
    if (root.is_relative()) root = config_path.parent_path() / root;
    result.sync_root = fs::weakly_canonical(root, ec);
    if (ec || !fs::is_directory(result.sync_root, ec) || ec)
        throw std::runtime_error("peer sync_root must be an existing accessible directory");
    const auto port = required(values, "port", false).number_value;
    if (port == 0 || port > 65535) throw std::runtime_error("peer port must be between 1 and 65535");
    result.port = static_cast<std::uint16_t>(port);
    if (expected_role == Role::Host) {
        result.bind_address = required(values, "bind_address", true).string_value;
        if (!valid_ipv4(result.bind_address)) throw std::runtime_error("host bind_address must be a numeric IPv4 address");
    } else {
        result.host_address = required(values, "host_address", true).string_value;
        if (!valid_ipv4(result.host_address))
            throw std::runtime_error("client host_address must be a numeric IPv4 address");
    }
    result.certificate_file = resolve_file(config_path.parent_path(), required(values, "certificate_file", true).string_value, "certificate_file");
    result.private_key_file = resolve_file(config_path.parent_path(), required(values, "private_key_file", true).string_value, "private_key_file");
    result.ca_file = resolve_file(config_path.parent_path(), required(values, "ca_file", true).string_value, "ca_file");
    result.expected_peer_sha256 = required(values, "expected_peer_sha256", true).string_value;
    if (!valid_fingerprint(result.expected_peer_sha256))
        throw std::runtime_error("expected_peer_sha256 must be a 64-character certificate SHA-256 fingerprint");
    std::transform(result.expected_peer_sha256.begin(), result.expected_peer_sha256.end(), result.expected_peer_sha256.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const auto timeout = [&](const char* key, std::uint32_t fallback, std::uint32_t max) {
        const auto found = values.find(key);
        if (found == values.end()) return fallback;
        if (found->second.is_string || found->second.number_value == 0 || found->second.number_value > max)
            throw std::runtime_error(std::string("peer config ") + key + " is outside its allowed range");
        return static_cast<std::uint32_t>(found->second.number_value);
    };
    result.handshake_timeout_seconds = timeout("handshake_timeout_seconds", 10, 120);
    result.io_timeout_seconds = timeout("io_timeout_seconds", 30, 600);
    result.max_manifest_files = timeout("max_manifest_files", 100000, 1000000);
    const auto max_file = values.find("max_file_size_bytes");
    if (max_file != values.end()) {
        if (max_file->second.is_string || max_file->second.number_value == 0 || max_file->second.number_value > (1ULL << 50U))
            throw std::runtime_error("peer config max_file_size_bytes must be 1..1 PiB");
        result.max_file_size_bytes = max_file->second.number_value;
    }
    return result;
}

} // namespace mc::peer
