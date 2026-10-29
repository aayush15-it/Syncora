#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/rand.h>

#include "merklechain/web_server.hpp"
#include "merklechain/folder_picker.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/sync.hpp"
#include "merklechain/versioning.hpp"
#include "merklechain/peer/peer_config.hpp"
#include "merklechain/peer/peer_controller.hpp"
#include "merklechain/collab_store.hpp"

#include <sqlite3.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <climits>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <map>
#include <memory>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mc {
namespace {
constexpr std::size_t kMaxHeaderBytes = 16U * 1024U;
constexpr std::size_t kMaxBodyBytes = 1024U * 1024U;
constexpr std::size_t kMaxResponseBytes = 8U * 1024U * 1024U;
constexpr auto kPlanLifetime = std::chrono::minutes(10);

struct Socket {
    SOCKET value{INVALID_SOCKET};
    explicit Socket(SOCKET handle = INVALID_SOCKET) : value(handle) {}
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};

std::string random_token() {
    std::array<unsigned char,32> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
        throw std::runtime_error("OpenSSL secure random-number generator failed");
    constexpr char hex[]="0123456789abcdef";std::string output;output.reserve(bytes.size()*2U);
    for(const auto byte:bytes){output.push_back(hex[byte>>4U]);output.push_back(hex[byte&0x0fU]);}
    return output;
}

void append_utf8(std::string& output, std::uint32_t codepoint) {
    if (codepoint <= 0x7fU) output.push_back(static_cast<char>(codepoint));
    else if (codepoint <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else if (codepoint <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    }
}

class JsonObjectParser {
public:
    explicit JsonObjectParser(std::string input) : input_(std::move(input)) {}
    std::map<std::string, std::string> strings;
    std::map<std::string, bool> booleans;
    std::map<std::string, std::int64_t> numbers;
    std::map<std::string, std::vector<std::string>> string_arrays;
    std::map<std::string, std::shared_ptr<JsonObjectParser>> objects;

    void parse() {
        whitespace(); expect('{'); whitespace();
        if (consume('}')) { finish(); return; }
        for (;;) {
            whitespace(); const auto key = parse_string(); whitespace(); expect(':'); whitespace();
            if (peek() == '"') {
                if (has_field(key)) fail("duplicate JSON field");
                strings.emplace(key, parse_string());
            } else if (literal("true")) {
                if (has_field(key)) fail("duplicate JSON field");
                booleans.emplace(key, true);
            } else if (literal("false")) {
                if (has_field(key)) fail("duplicate JSON field");
                booleans.emplace(key, false);
            } else if ((peek() >= '0' && peek() <= '9') || peek() == '-') {
                if (has_field(key)) fail("duplicate JSON field");
                numbers.emplace(key, parse_number());
            } else if (peek() == '[') {
                if (has_field(key)) fail("duplicate JSON field");
                string_arrays.emplace(key, parse_string_array());
            } else if (peek() == '{') {
                if (has_field(key)) fail("duplicate JSON field");
                objects.emplace(key, parse_sub_object());
            } else fail("expected string, number, boolean, array, or object JSON field");
            whitespace(); if (consume('}')) break; expect(',');
        }
        finish();
    }
private:
    bool has_field(const std::string& k) const {
        return strings.count(k) || booleans.count(k) || numbers.count(k) || string_arrays.count(k) || objects.count(k);
    }
    std::vector<std::string> parse_string_array() {
        expect('['); whitespace();
        std::vector<std::string> arr;
        if (consume(']')) return arr;
        for (;;) {
            whitespace();
            arr.push_back(parse_string());
            whitespace();
            if (consume(']')) break;
            expect(',');
        }
        return arr;
    }
    std::shared_ptr<JsonObjectParser> parse_sub_object() {
        std::size_t start = position_;
        int depth = 0;
        while (position_ < input_.size()) {
            if (input_[position_] == '{') {
                depth++;
            } else if (input_[position_] == '}') {
                depth--;
                if (depth == 0) { position_++; break; }
            } else if (input_[position_] == '"') {
                position_++;
                while (position_ < input_.size() && input_[position_] != '"') {
                    if (input_[position_] == '\\') position_++;
                    position_++;
                }
            }
            position_++;
        }
        std::string sub_str = input_.substr(start, position_ - start);
        auto sub_parser = std::make_shared<JsonObjectParser>(sub_str);
        sub_parser->parse();
        return sub_parser;
    }
private:
    std::string input_; std::size_t position_{};
    char peek() const { return position_ < input_.size() ? input_[position_] : '\0'; }
    void whitespace() {
        if (position_ == 0 && input_.size() >= 3 &&
            static_cast<unsigned char>(input_[0]) == 0xef &&
            static_cast<unsigned char>(input_[1]) == 0xbb &&
            static_cast<unsigned char>(input_[2]) == 0xbf) {
            position_ += 3;
        }
        while (peek()==' ' || peek()=='\t' || peek()=='\r' || peek()=='\n') ++position_;
    }
    bool consume(char expected) { if (peek()!=expected) return false; ++position_; return true; }
    void expect(char expected) { if (!consume(expected)) fail("malformed JSON object"); }
    [[noreturn]] void fail(const char* message) const { throw std::runtime_error(message); }
    bool literal(const char* value) {
        const std::string token(value);
        if (input_.compare(position_, token.size(), token)!=0) return false;
        position_+=token.size(); return true;
    }
    std::int64_t parse_number() {
        const std::size_t start = position_;
        if (peek() == '-') ++position_;
        if (peek() < '0' || peek() > '9') fail("invalid JSON number");
        while (peek() >= '0' && peek() <= '9') ++position_;
        std::int64_t val = 0;
        const auto res = std::from_chars(input_.data() + start, input_.data() + position_, val);
        if (res.ec != std::errc{}) fail("number out of range");
        return val;
    }
    std::uint32_t hex4() {
        std::uint32_t result=0;
        for (int i=0;i<4;++i) {
            const char c=peek(); ++position_; result<<=4U;
            if(c>='0'&&c<='9')result|=static_cast<std::uint32_t>(c-'0');
            else if(c>='a'&&c<='f')result|=static_cast<std::uint32_t>(c-'a'+10);
            else if(c>='A'&&c<='F')result|=static_cast<std::uint32_t>(c-'A'+10);
            else fail("invalid JSON Unicode escape");
        }
        return result;
    }
    std::string parse_string() {
        expect('"'); std::string result;
        while (peek()!='"') {
            if (peek()=='\0') fail("unterminated JSON string");
            const unsigned char c=static_cast<unsigned char>(input_[position_++]);
            if (c<0x20U) fail("control character in JSON string");
            if (c!='\\') { result.push_back(static_cast<char>(c)); continue; }
            const char escaped=peek(); ++position_;
            switch(escaped) {
                case '"': result.push_back('"'); break; case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break; case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break; case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break; case 't': result.push_back('\t'); break;
                case 'u': {
                    auto cp=hex4();
                    if(cp>=0xd800U&&cp<=0xdbffU) {
                        if(peek()!='\\'||position_+1>=input_.size()||input_[position_+1]!='u')fail("unpaired JSON high surrogate");
                        position_+=2; const auto low=hex4(); if(low<0xdc00U||low>0xdfffU)fail("invalid JSON surrogate pair");
                        cp=0x10000U+((cp-0xd800U)<<10U)+(low-0xdc00U);
                    } else if(cp>=0xdc00U&&cp<=0xdfffU)fail("unpaired JSON low surrogate");
                    append_utf8(result,cp); break;
                }
                default: fail("invalid JSON escape");
            }
        }
        expect('"'); return result;
    }
    void finish() { whitespace(); if(position_!=input_.size())fail("trailing JSON data"); }
};

std::string quote(const std::string& value) {
    std::ostringstream out; out << '"';
    constexpr char hex[]="0123456789abcdef";
    for (const unsigned char c : value) {
        switch(c) {
            case '"': out << "\\\""; break; case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break; case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break; case '\r': out << "\\r"; break; case '\t': out << "\\t"; break;
            default: if(c<0x20U)out << "\\u00" << hex[c>>4U] << hex[c&0x0fU]; else out << static_cast<char>(c);
        }
    }
    out << '"'; return out.str();
}
std::string json_error(const std::string& message) { return "{\"error\":"+quote(message)+"}"; }
std::string number(std::uintmax_t value) { return std::to_string(value); }

std::string lower(std::string value) {
    std::transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
    return value;
}
std::string path_utf8(const fs::path& path) { return path.u8string(); }
fs::path input_path(const std::string& value) {
    if(value.empty()||value.size()>32767U||value.find('\0')!=std::string::npos)throw std::runtime_error("path is empty, contains a null byte, or exceeds the supported length");
    return fs::u8path(value);
}
fs::path canonical_directory(const fs::path& input) {
    std::error_code error; const auto result=fs::canonical(input,error);
    if(error||!fs::is_directory(result,error)||error)throw std::runtime_error("folder is missing or inaccessible: "+path_utf8(input));
    return result;
}
bool path_contains(const fs::path& parent,const fs::path& child) {
    auto left=parent.begin(),right=child.begin();
    for(;left!=parent.end()&&right!=child.end();++left,++right) {
        const auto& a=left->native();const auto& b=right->native();
        if(a.size()>static_cast<std::size_t>(std::numeric_limits<int>::max())||b.size()>static_cast<std::size_t>(std::numeric_limits<int>::max())||
           CompareStringOrdinal(a.data(),static_cast<int>(a.size()),b.data(),static_cast<int>(b.size()),TRUE)!=CSTR_EQUAL)return false;
    }
    return left==parent.end();
}
bool paths_equal(const fs::path& left,const fs::path& right) { return path_contains(left,right)&&path_contains(right,left); }
void validate_distinct_roots(const fs::path& source,const fs::path& destination) {
    if(path_contains(source,destination)||path_contains(destination,source))throw std::runtime_error("source and destination folders must not overlap");
}

struct Request { std::string method,target,body; std::map<std::string,std::string> headers; };
std::string receive_request(SOCKET socket) {
    std::string data; std::array<char,8192> buffer{}; std::size_t expected=0; std::size_t header_end=std::string::npos;
    for (;;) {
        const int count=recv(socket,buffer.data(),static_cast<int>(buffer.size()),0);
        if(count<=0)throw std::runtime_error("incomplete HTTP request");
        data.append(buffer.data(),static_cast<std::size_t>(count));
        if(data.size()>kMaxHeaderBytes+kMaxBodyBytes)throw std::runtime_error("HTTP request exceeds the size limit");
        if(header_end==std::string::npos) {
            header_end=data.find("\r\n\r\n");
            if(header_end==std::string::npos) { if(data.size()>kMaxHeaderBytes)throw std::runtime_error("HTTP headers exceed the size limit"); continue; }
            if(header_end>kMaxHeaderBytes)throw std::runtime_error("HTTP headers exceed the size limit");
            const auto first_end=data.find("\r\n");
            if(first_end==std::string::npos)throw std::runtime_error("malformed HTTP request line");
            std::size_t cursor=first_end+2; bool has_length=false; std::size_t length=0;
            std::set<std::string> names;
            while(cursor<header_end) {
                const auto end=data.find("\r\n",cursor); if(end==std::string::npos||end>header_end)throw std::runtime_error("malformed HTTP header");
                const auto line=data.substr(cursor,end-cursor); const auto colon=line.find(':');
                if(colon==std::string::npos||colon==0)throw std::runtime_error("malformed HTTP header");
                const auto name=lower(line.substr(0,colon)); auto value=line.substr(colon+1);
                while(!value.empty()&&(value.front()==' '||value.front()=='\t'))value.erase(value.begin());
                if(!names.insert(name).second)throw std::runtime_error("duplicate HTTP header");
                if(name=="content-length") {
                    if(has_length)throw std::runtime_error("duplicate Content-Length header");
                    const auto parsed=std::from_chars(value.data(),value.data()+value.size(),length);
                    if(parsed.ec!=std::errc{}||parsed.ptr!=value.data()+value.size()||length>kMaxBodyBytes)throw std::runtime_error("invalid or oversized Content-Length");
                    has_length=true;
                }
                if(name=="transfer-encoding")throw std::runtime_error("Transfer-Encoding is not supported");
                if(name=="expect" && lower(value).find("100-continue")!=std::string::npos) {
                    const char continue_reply[] = "HTTP/1.1 100 Continue\r\n\r\n";
                    send(socket, continue_reply, static_cast<int>(sizeof(continue_reply)-1), 0);
                }
                cursor=end+2;
            }
            expected=header_end+4+(has_length?length:0);
            if(expected>kMaxHeaderBytes+kMaxBodyBytes)throw std::runtime_error("HTTP request exceeds the size limit");
            if(!has_length&&data.size()>expected)throw std::runtime_error("HTTP request body requires Content-Length");
        }
        if(data.size()>=expected)return data.substr(0,expected);
    }
}

Request parse_request(const std::string& raw) {
    Request request;
    const auto header_end=raw.find("\r\n\r\n");
    if(header_end==std::string::npos)throw std::runtime_error("malformed HTTP request");
    const auto first_end=raw.find("\r\n");
    std::istringstream first(raw.substr(0,first_end));
    std::string version,extra;
    if(!(first>>request.method>>request.target>>version)||(first>>extra)||version!="HTTP/1.1")
        throw std::runtime_error("unsupported HTTP request line");
    std::size_t cursor=first_end+2;
    while(cursor<header_end) {
        const auto end=raw.find("\r\n",cursor);const auto line=raw.substr(cursor,end-cursor);
        const auto colon=line.find(':');if(colon==std::string::npos)throw std::runtime_error("malformed HTTP header");
        auto value=line.substr(colon+1);while(!value.empty()&&(value.front()==' '||value.front()=='\t'))value.erase(value.begin());
        if(!request.headers.emplace(lower(line.substr(0,colon)),std::move(value)).second)throw std::runtime_error("duplicate HTTP header");
        cursor=end+2;
    }
    request.body=raw.substr(header_end+4);
    return request;
}

struct HttpResponse { int status{200}; std::string type{"application/json; charset=utf-8"}; std::string body; };
struct PendingPlan {
    std::string id, source_root, destination_root, source_merkle, destination_merkle, expected_merkle;
    std::vector<SyncJob> jobs;
    SyncScope scope;
    std::chrono::steady_clock::time_point created;
};
struct RestoreGrant { fs::path destination; std::string version_id; std::chrono::steady_clock::time_point created; };
struct ServerState {
    std::string csrf{random_token()};
    std::optional<PendingPlan> plan;
    std::unordered_map<std::string,RestoreGrant> restore_grants;
    std::unique_ptr<CollabStore> collab;
};

const std::string& require_string(const JsonObjectParser& json,const std::string& key) {
    const auto found=json.strings.find(key);if(found==json.strings.end())throw std::runtime_error("missing string field: "+key);return found->second;
}
bool require_bool(const JsonObjectParser& json,const std::string& key) {
    const auto found=json.booleans.find(key);if(found==json.booleans.end())throw std::runtime_error("missing boolean field: "+key);return found->second;
}
std::int64_t require_number(const JsonObjectParser& json,const std::string& key) {
    const auto found=json.numbers.find(key);
    if(found!=json.numbers.end())return found->second;
    const auto sfound=json.strings.find(key);
    if(sfound!=json.strings.end()&&!sfound->second.empty()) {
        std::int64_t val=0;
        const auto res=std::from_chars(sfound->second.data(),sfound->second.data()+sfound->second.size(),val);
        if(res.ec==std::errc{})return val;
    }
    throw std::runtime_error("missing number field: "+key);
}
std::string optional_string(const JsonObjectParser& json,const std::string& key,const std::string& fallback={}) {
    const auto found=json.strings.find(key);return found!=json.strings.end()?found->second:fallback;
}
std::int64_t optional_number(const JsonObjectParser& json,const std::string& key,std::int64_t fallback=0) {
    const auto found=json.numbers.find(key);if(found!=json.numbers.end())return found->second;
    const auto sfound=json.strings.find(key);
    if(sfound!=json.strings.end()&&!sfound->second.empty()) {
        std::int64_t val=0;
        const auto res=std::from_chars(sfound->second.data(),sfound->second.data()+sfound->second.size(),val);
        if(res.ec==std::errc{})return val;
    }
    return fallback;
}
[[maybe_unused]] bool optional_bool(const JsonObjectParser& json,const std::string& key,bool fallback=false) {
    const auto found=json.booleans.find(key);return found!=json.booleans.end()?found->second:fallback;
}
void parse_body(const Request& request,JsonObjectParser& body) {
    const auto type=request.headers.find("content-type");
    if(type==request.headers.end())throw std::runtime_error("request must use application/json");
    auto media_type=lower(type->second);const auto semicolon=media_type.find(';');if(semicolon!=std::string::npos)media_type.resize(semicolon);
    while(!media_type.empty()&&media_type.back()==' ')media_type.pop_back();
    if(media_type!="application/json")throw std::runtime_error("request must use application/json");
    body.parse();
}
void require_fields(const JsonObjectParser& json,std::initializer_list<const char*> strings,
                    std::initializer_list<const char*> booleans={},
                    std::initializer_list<const char*> numbers={}) {
    std::set<std::string> allowed;
    for(const auto* key:strings)allowed.emplace(key);
    for(const auto* key:booleans)allowed.emplace(key);
    for(const auto* key:numbers)allowed.emplace(key);
    for(const auto& [key,value]:json.strings){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.booleans){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.numbers){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto* key:strings)(void)require_string(json,key);
    for(const auto* key:booleans)(void)require_bool(json,key);
    for(const auto* key:numbers)(void)require_number(json,key);
}
void validate_allowed_fields(const JsonObjectParser& json,
                            std::initializer_list<const char*> strings,
                            std::initializer_list<const char*> booleans={},
                            std::initializer_list<const char*> numbers={},
                            std::initializer_list<const char*> arrays={},
                            std::initializer_list<const char*> objects={}) {
    std::set<std::string> allowed;
    for(const auto* key:strings)allowed.emplace(key);
    for(const auto* key:booleans)allowed.emplace(key);
    for(const auto* key:numbers)allowed.emplace(key);
    for(const auto* key:arrays)allowed.emplace(key);
    for(const auto* key:objects)allowed.emplace(key);
    for(const auto& [key,value]:json.strings){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.booleans){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.numbers){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.string_arrays){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.objects){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
}

void require_fields_ext(const JsonObjectParser& json,
                        std::initializer_list<const char*> req_strings,
                        std::initializer_list<const char*> opt_strings={},
                        std::initializer_list<const char*> opt_booleans={},
                        std::initializer_list<const char*> opt_arrays={},
                        std::initializer_list<const char*> opt_objects={}) {
    std::set<std::string> allowed;
    for(const auto* key:req_strings)allowed.emplace(key);
    for(const auto* key:opt_strings)allowed.emplace(key);
    for(const auto* key:opt_booleans)allowed.emplace(key);
    for(const auto* key:opt_arrays)allowed.emplace(key);
    for(const auto* key:opt_objects)allowed.emplace(key);
    for(const auto& [key,value]:json.strings){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.booleans){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.numbers){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.string_arrays){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto& [key,value]:json.objects){(void)value;if(!allowed.count(key))throw std::runtime_error("unexpected request field: "+key);}
    for(const auto* key:req_strings)(void)require_string(json,key);
}

bool constant_time_equal(const std::string& left,const std::string& right) {
    if(left.size()!=right.size())return false;
    unsigned char difference=0;
    for(std::size_t i=0;i<left.size();++i)difference|=static_cast<unsigned char>(left[i]^right[i]);
    return difference==0;
}
void require_csrf(const JsonObjectParser& json,const ServerState& state) {
    if(!constant_time_equal(require_string(json,"csrf"),state.csrf))throw std::runtime_error("invalid or expired session token");
}
std::string plan_fingerprint(const std::string& source_root,const std::string& destination_root,
                             const std::string& source_merkle,const std::string& destination_merkle,
                             const std::vector<SyncJob>& jobs,
                             const SyncScope& scope = {}) {
    std::vector<std::string> rows;
    rows.reserve(jobs.size());
    for(const auto& job:jobs)rows.push_back(operation_name(job.operation)+"\n"+job.relative_path+"\n"+job.content_hash+"\n"+job.expected_destination_hash+"\n");
    std::sort(rows.begin(),rows.end());
    std::string material=source_root+"\n"+destination_root+"\n"+source_merkle+"\n"+destination_merkle+"\n"+scope.mode+"\n";
    auto sorted_paths = scope.paths;
    std::sort(sorted_paths.begin(), sorted_paths.end());
    for (const auto& sp : sorted_paths) material += "scope:" + sp + "\n";
    for(const auto& row:rows)material+=row;
    return sha256_data(material.data(),material.size());
}
bool mutating(const SyncJob& job) { return job.operation==Operation::Add||job.operation==Operation::Modify||job.operation==Operation::Delete; }
std::int64_t system_millis_from_file_ticks(std::int64_t ticks) {
    using FileClock=fs::file_time_type::clock;
    const auto file_time=fs::file_time_type(FileClock::duration(ticks));
    const auto system_time=std::chrono::system_clock::now()+
        std::chrono::duration_cast<std::chrono::system_clock::duration>(file_time-FileClock::now());
    return std::chrono::duration_cast<std::chrono::milliseconds>(system_time.time_since_epoch()).count();
}

std::string manifest_expected_root(const FileManifest& source,const FileManifest& destination,
                                   const SyncScope& scope = {},
                                   const std::vector<SyncJob>& jobs = {}) {
    if (scope.mode != "selective") {
        FileManifest expected;expected.files=source.files;
        for(const auto& old:destination.files)if(std::none_of(source.files.begin(),source.files.end(),[&](const auto& current){return current.relative_path==old.relative_path;}))expected.files.push_back(old);
        std::sort(expected.files.begin(),expected.files.end(),[](const auto& left,const auto& right){return left.relative_path<right.relative_path;});
        return merkle_root(expected.files);
    }
    // Selective scope: destination files retain their content unless modified/added/deleted by an in-scope job
    std::map<std::string, FileMetadata> expected_map;
    for (const auto& f : destination.files) {
        expected_map[f.relative_path] = f;
    }
    for (const auto& job : jobs) {
        if (job.operation == Operation::Add || job.operation == Operation::Modify) {
            auto it = std::find_if(source.files.begin(), source.files.end(),
                [&](const FileMetadata& sm) { return sm.relative_path == job.relative_path; });
            if (it != source.files.end()) {
                expected_map[job.relative_path] = *it;
            }
        } else if (job.operation == Operation::Delete) {
            expected_map.erase(job.relative_path);
        }
    }
    std::vector<FileMetadata> expected_files;
    expected_files.reserve(expected_map.size());
    for (auto& [p, m] : expected_map) {
        expected_files.push_back(std::move(m));
    }
    std::sort(expected_files.begin(), expected_files.end(),
        [](const FileMetadata& a, const FileMetadata& b) { return a.relative_path < b.relative_path; });
    return merkle_root(expected_files);
}

SyncScope parse_scope_from_json(const JsonObjectParser& json) {
    SyncScope scope;
    if (json.objects.count("scope")) {
        const auto& sub = *json.objects.at("scope");
        if (sub.strings.count("mode")) scope.mode = sub.strings.at("mode");
        if (sub.string_arrays.count("paths")) {
            scope.paths = sub.string_arrays.at("paths");
        } else if (sub.strings.count("paths")) {
            scope.paths = { sub.strings.at("paths") };
        }
    }
    if (json.strings.count("scope_mode")) {
        scope.mode = json.strings.at("scope_mode");
    }
    if (json.string_arrays.count("scope_paths")) {
        scope.paths = json.string_arrays.at("scope_paths");
    } else if (json.strings.count("scope_paths")) {
        scope.paths = { json.strings.at("scope_paths") };
    }
    if (scope.mode != "selective") {
        scope.mode = "all";
        scope.paths.clear();
    }
    for (const auto& p : scope.paths) {
        if (!safe_relative_path(p)) {
            throw std::runtime_error("Invalid or unsafe relative path in selection scope: " + p);
        }
    }
    if (scope.mode == "selective" && scope.paths.empty()) {
        throw std::runtime_error("Empty selection: at least one file or folder must be selected in selective mode");
    }
    return scope;
}

std::string serialize_merkle_explorer(const FileManifest& source, const FileManifest& destination,
                                      const std::vector<SyncJob>& jobs) {
    const auto source_tree = build_merkle_tree_info(source.files);
    const auto dest_tree = build_merkle_tree_info(destination.files);
    const bool roots_match = (source.merkle_root == destination.merkle_root);

    std::map<std::string, const FileMetadata*> left, right;
    for (const auto& f : source.files) left[f.relative_path] = &f;
    for (const auto& f : destination.files) right[f.relative_path] = &f;

    std::map<std::string, const SyncJob*> planned;
    for (const auto& j : jobs) planned[j.relative_path] = &j;

    std::map<std::string, std::string> source_leaf_hashes, dest_leaf_hashes;
    for (const auto& l : source_tree.leaves) source_leaf_hashes[l.relative_path] = l.leaf_hash;
    for (const auto& l : dest_tree.leaves) dest_leaf_hashes[l.relative_path] = l.leaf_hash;

    std::set<std::string> all_paths;
    for (const auto& [p, _] : left) all_paths.insert(p);
    for (const auto& [p, _] : right) all_paths.insert(p);

    std::size_t diff_count = 0;
    std::string leaves_json = "[";
    bool first = true;
    for (const auto& path : all_paths) {
        auto lit = left.find(path);
        auto rit = right.find(path);
        std::string op = "UNCHANGED";
        std::string reason = "Identical content and leaf hash";
        std::string state = "UNCHANGED";

        if (lit != left.end() && rit == right.end()) {
            op = "ADD";
            state = "PLANNED";
            reason = "File present only in source manifest";
            ++diff_count;
        } else if (lit == left.end() && rit != right.end()) {
            auto pit = planned.find(path);
            if (pit != planned.end() && pit->second->operation == Operation::Delete) {
                op = "DELETE";
                state = "PLANNED";
                reason = "Scheduled for deletion from destination";
                ++diff_count;
            } else {
                op = "PRESERVE";
                state = "PRESERVED";
                reason = "Destination-only file preserved untouched";
                ++diff_count;
            }
        } else if (lit != left.end() && rit != right.end()) {
            if (lit->second->sha256 != rit->second->sha256) {
                op = "MODIFY";
                state = "PLANNED";
                reason = "Content SHA-256 mismatch between source and destination";
                ++diff_count;
            }
        }

        std::string s_hash = lit != left.end() ? lit->second->sha256 : "";
        std::string d_hash = rit != right.end() ? rit->second->sha256 : "";
        std::string s_leaf = source_leaf_hashes.count(path) ? source_leaf_hashes[path] : "";
        std::string d_leaf = dest_leaf_hashes.count(path) ? dest_leaf_hashes[path] : "";

        if (!first) leaves_json += ',';
        first = false;
        leaves_json += "{\"path\":" + quote(path) +
            ",\"operation\":" + quote(op) +
            ",\"state\":" + quote(state) +
            ",\"reason\":" + quote(reason) +
            ",\"source_sha256\":" + quote(s_hash) +
            ",\"destination_sha256\":" + quote(d_hash) +
            ",\"source_leaf_hash\":" + quote(s_leaf) +
            ",\"destination_leaf_hash\":" + quote(d_leaf) + "}";
    }
    leaves_json += "]";

    std::string differ_summary = roots_match
        ? "Source and destination Merkle roots are identical. Folders are fully synchronized."
        : "Source and destination Merkle roots differ (" + std::to_string(diff_count) + " differing leaf paths).";

    std::string source_levels_json = "[";
    for (std::size_t l = 0; l < source_tree.levels.size(); ++l) {
        if (l) source_levels_json += ',';
        source_levels_json += "{\"level\":" + std::to_string(l) + ",\"node_count\":" + std::to_string(source_tree.levels[l].size()) + "}";
    }
    source_levels_json += "]";

    std::string dest_levels_json = "[";
    for (std::size_t l = 0; l < dest_tree.levels.size(); ++l) {
        if (l) dest_levels_json += ',';
        dest_levels_json += "{\"level\":" + std::to_string(l) + ",\"node_count\":" + std::to_string(dest_tree.levels[l].size()) + "}";
    }
    dest_levels_json += "]";

    return "{\"roots_match\":" + std::string(roots_match ? "true" : "false") +
        ",\"source_root\":" + quote(source.merkle_root) +
        ",\"destination_root\":" + quote(destination.merkle_root) +
        ",\"differ_reason\":" + quote(differ_summary) +
        ",\"differ_count\":" + std::to_string(diff_count) +
        ",\"source_tree\":{\"file_count\":" + std::to_string(source_tree.file_count) +
            ",\"depth\":" + std::to_string(source_tree.tree_depth) +
            ",\"levels\":" + source_levels_json + "}" +
        ",\"destination_tree\":{\"file_count\":" + std::to_string(dest_tree.file_count) +
            ",\"depth\":" + std::to_string(dest_tree.tree_depth) +
            ",\"levels\":" + dest_levels_json + "}" +
        ",\"leaves\":" + leaves_json + "}";
}
std::string serialize_jobs(const std::vector<SyncJob>& jobs) {
    std::string output="[";
    for(std::size_t i=0;i<jobs.size();++i) {
        const auto& job=jobs[i];if(i)output+=',';
        std::uintmax_t size=0;std::error_code error;
        const auto size_path=(job.operation==Operation::Preserve)?job.destination:job.source;
        if(fs::is_regular_file(size_path,error)&&!error)size=fs::file_size(size_path,error);
        output+="{\"path\":"+quote(job.relative_path)+",\"operation\":"+quote(operation_name(job.operation))+
            ",\"size\":"+number(size)+",\"state\":"+quote(job_state_name(job.state))+
            ",\"verified\":"+(job.verified?"true":"false")+",\"priority\":"+std::to_string(job.priority)+
            ",\"bytes_transferred\":"+number(job.bytes_transferred)+",\"source_bytes_processed\":"+number(job.source_bytes_processed)+",\"bytes_reused\":"+number(job.bytes_reused)+
            ",\"bytes_written\":"+number(job.bytes_written)+",\"chunk_size_bytes\":"+number(job.chunk_size_bytes)+
            ",\"chunks_total\":"+number(job.chunks_total)+",\"chunks_reused\":"+number(job.chunks_reused)+
            ",\"chunked_transfer\":"+(job.chunked_transfer?"true":"false")+",\"fallback_reason\":"+quote(job.transfer_fallback_reason)+
            ",\"error\":"+quote(job.error)+"}";
    }
    return output+"]";
}
std::string serialize_comparison(const FileManifest& source,const FileManifest& destination,
                                 const std::vector<SyncJob>& jobs) {
    std::map<std::string,FileMetadata> left,right;
    for(const auto& file:source.files)left.emplace(file.relative_path,file);
    for(const auto& file:destination.files)right.emplace(file.relative_path,file);
    std::map<std::string,SyncJob> planned;
    for(const auto& job:jobs)planned.emplace(job.relative_path,job);
    std::size_t add=0,modify=0,remove=0,preserve=0,unchanged=0,excluded=0;
    for(const auto& job:jobs) {
        if(job.operation==Operation::Add)++add;
        else if(job.operation==Operation::Modify)++modify;
        else if(job.operation==Operation::Delete)++remove;
        else if(job.operation==Operation::Preserve)++preserve;
    }
    for(const auto& [path,file]:left) {
        if(planned.count(path)) continue;
        const auto found=right.find(path);
        if(found!=right.end()&&found->second.sha256==file.sha256)++unchanged;
        else ++excluded;
    }
    std::string output="{\"counts\":{\"add\":"+number(add)+",\"modify\":"+number(modify)+",\"delete\":"+number(remove)+",\"unchanged\":"+number(unchanged)+",\"preserve\":"+number(preserve)+",\"excluded\":"+number(excluded)+"},\"files\":[";
    bool first=true;
    for(const auto& [path,file]:left) {
        const auto found=right.find(path);
        const auto pjob=planned.find(path);
        std::string op="EXCLUDED", state="EXCLUDED";
        if(pjob!=planned.end()) {
            op = (pjob->second.operation==Operation::Add ? "ADD" : "MODIFY");
            state = "PLANNED";
        } else if(found!=right.end()&&found->second.sha256==file.sha256) {
            op = "UNCHANGED";
            state = "UNCHANGED";
        }
        if(!first) output+=',';
        first=false;
        output+="{\"path\":"+quote(path)+",\"operation\":"+quote(op)+",\"size\":"+number(file.size)+",\"state\":"+quote(state)+",\"verified\":false,\"source_hash\":"+quote(file.sha256)+",\"source_modified_ms\":"+std::to_string(system_millis_from_file_ticks(file.modified_ticks)) +",\"destination_hash\":"+quote(found==right.end()?std::string{}:found->second.sha256)+",\"destination_modified_ms\":"+std::to_string(found==right.end()?0:system_millis_from_file_ticks(found->second.modified_ticks))+",\"error\":"+quote(op=="EXCLUDED"?"Excluded from selection scope":"")+"}";
    }
    for(const auto& [path,file]:right)if(!left.count(path)) {
        const auto found=planned.find(path);const bool deletion=found!=planned.end()&&found->second.operation==Operation::Delete;
        if(!first) output+=',';
        first=false;
        output+="{\"path\":"+quote(path)+",\"operation\":"+quote(deletion?"DELETE":"PRESERVE")+
            ",\"size\":"+number(file.size)+",\"state\":"+quote(deletion?"PLANNED":"PRESERVED")+
            ",\"verified\":false,\"source_hash\":\"\",\"source_modified_ms\":0,\"destination_hash\":"+quote(file.sha256)+
            ",\"destination_modified_ms\":"+std::to_string(system_millis_from_file_ticks(file.modified_ticks))+",\"error\":"+quote(deletion?"":"Destination-only file is preserved")+"}";
    }
    return output+"]}";
}

std::string serialize_scheduler_preview(const std::vector<SyncJob>& jobs,const FileManifest& source,const FileManifest& destination) {
    BinaryHeapScheduler scheduler;
    const auto preview_time=BinaryHeapScheduler::Clock::now();
    const auto file_time=fs::file_time_type::clock::now();
    std::map<std::string,const FileMetadata*> source_by_path,destination_by_path;
    for(const auto& file:source.files)source_by_path.emplace(file.relative_path,&file);
    for(const auto& file:destination.files)destination_by_path.emplace(file.relative_path,&file);
    for(const auto& job:jobs) {
        if(job.operation!=Operation::Add&&job.operation!=Operation::Modify&&job.operation!=Operation::Delete)continue;
        const auto& index=job.operation==Operation::Delete?destination_by_path:source_by_path;
        const auto metadata=index.find(job.relative_path);
        const FileMetadata scheduled=metadata==index.end()?FileMetadata{job.relative_path,0,0,{}}:*metadata->second;
        scheduler.enqueue(job,scheduled,job.enqueued_at,file_time);
    }
    std::string output="[";std::size_t order=0;bool first=true;
    while(auto job=scheduler.try_dequeue(preview_time,{true,true})) {
        if(!first) output+=',';
        first=false;
        ++order;
        const auto& index=job->operation==Operation::Delete?destination_by_path:source_by_path;
        const auto file=index.find(job->relative_path);
        const auto size=file==index.end()?0:file->second->size;
        const auto modified=file==index.end()?0:file->second->modified_ticks;
        output+="{\"order\":"+number(order)+",\"path\":"+quote(job->relative_path)+",\"operation\":"+quote(operation_name(job->operation))+
            ",\"priority\":"+std::to_string(job->priority)+",\"size\":"+number(size)+",\"modified_ticks\":"+std::to_string(modified)+",\"state\":\"QUEUED\"}";
    }
    return output+"]";
}

std::string serialize_versions(VersionStore& versions,ServerState& state,const fs::path& destination) {
    const auto rows=versions.list_versions();std::string output="{\"versions\":[";
    for(std::size_t i=0;i<rows.size();++i) {
        const auto& version=rows[i];if(i)output+=',';
        auto grant=random_token();state.restore_grants[grant]={destination,version.record.id,std::chrono::steady_clock::now()};
        output+="{\"id\":"+quote(version.record.id)+",\"label\":"+quote(version.label)+
            ",\"timestamp_ms\":"+std::to_string(version.record.timestamp)+",\"file_count\":"+std::to_string(version.file_count)+
            ",\"integrity_hash\":"+quote(version.record.integrity_hash)+",\"parent_id\":"+quote(version.record.parent_id)+",\"restore_token\":"+quote(grant)+"}";
    }
    while(state.restore_grants.size()>200)state.restore_grants.erase(state.restore_grants.begin());
    return output+"]}";
}

std::string activity_json(const fs::path& database) {
    sqlite3* db=nullptr;
    const int opened=sqlite3_open_v2(database.u8string().c_str(),&db,SQLITE_OPEN_READONLY,nullptr);
    if(opened!=SQLITE_OK){const std::string message=db?sqlite3_errmsg(db):"cannot open activity database";if(db)sqlite3_close(db);throw std::runtime_error(message);}
    struct DbGuard { sqlite3* value; ~DbGuard(){if(value)sqlite3_close(value);} } db_guard{db};
    sqlite3_stmt* query=nullptr;
    struct StatementGuard { sqlite3_stmt* value; ~StatementGuard(){if(value)sqlite3_finalize(value);} } statement_guard{nullptr};
    const char* sql="SELECT job_id,path,operation,source,destination,content_hash,bytes_transferred,state,verified,error,started_at_ms,completed_at_ms,source_bytes_processed,bytes_reused,bytes_written,chunk_size_bytes,chunks_total,chunks_reused,chunked_transfer,transfer_fallback_reason FROM file_activity ORDER BY id DESC LIMIT 100";
    if(sqlite3_prepare_v2(db,sql,-1,&query,nullptr)!=SQLITE_OK)throw std::runtime_error(sqlite3_errmsg(db));
    statement_guard.value=query;
    auto text=[&](int column){const auto* value=reinterpret_cast<const char*>(sqlite3_column_text(query,column));return std::string(value?value:"");};
    std::string output="{\"activity\":[";bool first=true;
    int step=SQLITE_ROW;
    while((step=sqlite3_step(query))==SQLITE_ROW) {
        if(!first) output+=',';
        first=false;
        output+="{\"job_id\":"+quote(text(0))+",\"path\":"+quote(text(1))+",\"operation\":"+quote(text(2))+
            ",\"source\":"+quote(text(3))+",\"destination\":"+quote(text(4))+",\"content_hash\":"+quote(text(5))+
            ",\"bytes\":"+std::to_string(sqlite3_column_int64(query,6))+
            ",\"bytes_transferred\":"+std::to_string(sqlite3_column_int64(query,6))+
            ",\"state\":"+quote(text(7))+",\"verified\":"+(sqlite3_column_int(query,8)?"true":"false")+
            ",\"error\":"+quote(text(9))+",\"started_at_ms\":"+std::to_string(sqlite3_column_int64(query,10))+
            ",\"completed_at_ms\":"+std::to_string(sqlite3_column_int64(query,11))+
            ",\"source_bytes_processed\":"+std::to_string(sqlite3_column_int64(query,12))+
            ",\"bytes_reused\":"+std::to_string(sqlite3_column_int64(query,13))+
            ",\"bytes_written\":"+std::to_string(sqlite3_column_int64(query,14))+
            ",\"chunk_size_bytes\":"+std::to_string(sqlite3_column_int64(query,15))+
            ",\"chunks_total\":"+std::to_string(sqlite3_column_int64(query,16))+
            ",\"chunks_reused\":"+std::to_string(sqlite3_column_int64(query,17))+
            ",\"chunked_transfer\":"+(sqlite3_column_int(query,18)?"true":"false")+
            ",\"fallback_reason\":"+quote(text(19))+"}";
    }
    if(step!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(db));
    return output+"]}";
}

std::string serialize_peer_status(const peer::PeerControllerStatus& s, const std::string& csrf) {
    const bool is_peer = (s.role == "host" || s.role == "client");
    std::ostringstream json;
    json << "{\"csrf\":" << quote(csrf)
         << ",\"mode\":" << quote(is_peer ? s.role : "local")
         << ",\"network_enabled\":" << (is_peer ? "true" : "false")
         << ",\"role\":" << quote(s.role)
         << ",\"state\":" << quote(s.state_name)
         << ",\"running\":" << (s.running ? "true" : "false")
         << ",\"identity\":" << quote(s.identity)
         << ",\"device_id\":" << quote(s.identity)
         << ",\"peer_identity\":" << quote(s.peer_identity)
         << ",\"remote_peer_id\":" << quote(s.peer_identity)
         << ",\"address\":" << quote(s.address)
         << ",\"peer_address\":" << quote(s.address)
         << ",\"port\":" << s.port
         << ",\"peer_port\":" << s.port
         << ",\"sync_root\":" << quote(s.sync_root)
         << ",\"expected_peer_sha256\":" << quote(s.expected_peer_sha256)
         << ",\"expected_peer_pin\":" << quote(s.expected_peer_sha256)
         << ",\"local_cert_sha256\":" << quote(s.local_cert_sha256)
         << ",\"local_certificate_pin\":" << quote(s.local_cert_sha256)
         << ",\"pin_verified\":" << (s.pin_verified ? "true" : "false")
         << ",\"peer_pin_verified\":" << (s.pin_verified ? "true" : "false")
         << ",\"session_id\":" << quote(s.session_id)
         << ",\"plan_hash\":" << quote(s.plan_hash)
         << ",\"phase\":" << quote(s.phase)
         << ",\"detail\":" << quote(s.detail)
         << ",\"current_file\":" << quote(s.current_file)
         << ",\"files_transferred\":" << s.files_transferred
         << ",\"bytes_transferred\":" << s.bytes_transferred
         << ",\"final_merkle_root\":" << quote(s.final_merkle_root)
         << ",\"last_error\":" << quote(s.last_error)
         << ",\"last_sync_time_ms\":" << s.last_sync_time_ms
         << ",\"last_sync_success\":" << (s.last_sync_success ? "true" : "false")
         << ",\"peer\":{"
         << "\"role\":" << quote(s.role)
         << ",\"state\":" << quote(s.state_name)
         << ",\"running\":" << (s.running ? "true" : "false")
         << ",\"identity\":" << quote(s.identity)
         << ",\"device_id\":" << quote(s.identity)
         << ",\"peer_identity\":" << quote(s.peer_identity)
         << ",\"remote_peer_id\":" << quote(s.peer_identity)
         << ",\"address\":" << quote(s.address)
         << ",\"peer_address\":" << quote(s.address)
         << ",\"port\":" << s.port
         << ",\"peer_port\":" << s.port
         << ",\"sync_root\":" << quote(s.sync_root)
         << ",\"expected_peer_sha256\":" << quote(s.expected_peer_sha256)
         << ",\"expected_peer_pin\":" << quote(s.expected_peer_sha256)
         << ",\"local_cert_sha256\":" << quote(s.local_cert_sha256)
         << ",\"local_certificate_pin\":" << quote(s.local_cert_sha256)
         << ",\"pin_verified\":" << (s.pin_verified ? "true" : "false")
         << ",\"peer_pin_verified\":" << (s.pin_verified ? "true" : "false")
         << ",\"session_id\":" << quote(s.session_id)
         << ",\"plan_hash\":" << quote(s.plan_hash)
         << ",\"phase\":" << quote(s.phase)
         << ",\"detail\":" << quote(s.detail)
         << ",\"current_file\":" << quote(s.current_file)
         << ",\"files_transferred\":" << s.files_transferred
         << ",\"bytes_transferred\":" << s.bytes_transferred
         << ",\"final_merkle_root\":" << quote(s.final_merkle_root)
         << ",\"last_error\":" << quote(s.last_error)
         << ",\"last_sync_time_ms\":" << s.last_sync_time_ms
         << ",\"last_sync_success\":" << (s.last_sync_success ? "true" : "false")
         << "}}";
    return json.str();
}

std::string serialize_peer_plan(const peer::PeerSyncPlan& plan, const std::string& session_id) {
    std::size_t add_local = 0, update_local = 0, delete_local = 0;
    std::size_t add_remote = 0, update_remote = 0, delete_remote = 0;
    std::size_t conflicts = 0, no_change = 0, preserve_both = 0;
    for (const auto& e : plan.entries) {
        switch (e.action) {
            case peer::PeerPlanAction::AddLocal: ++add_local; break;
            case peer::PeerPlanAction::UpdateLocal: ++update_local; break;
            case peer::PeerPlanAction::DeleteLocal: ++delete_local; break;
            case peer::PeerPlanAction::AddRemote: ++add_remote; break;
            case peer::PeerPlanAction::UpdateRemote: ++update_remote; break;
            case peer::PeerPlanAction::DeleteRemote: ++delete_remote; break;
            case peer::PeerPlanAction::Conflict: ++conflicts; break;
            case peer::PeerPlanAction::PreserveBoth: ++preserve_both; break;
            case peer::PeerPlanAction::NoChange: ++no_change; break;
        }
    }

    std::ostringstream json;
    json << "{\"has_plan\":true"
         << ",\"session_id\":" << quote(session_id)
         << ",\"plan_hash\":" << quote(plan.plan_hash)
         << ",\"valid\":" << (plan.valid ? "true" : "false")
         << ",\"requires_approval\":" << (plan.requires_approval ? "true" : "false")
         << ",\"requires_deletion_confirmation\":" << (plan.requires_deletion_confirmation ? "true" : "false")
         << ",\"has_unresolved_conflicts\":" << (plan.has_unresolved_conflicts ? "true" : "false")
         << ",\"error\":" << quote(plan.error)
         << ",\"counts\":{"
         << "\"add_local\":" << add_local
         << ",\"update_local\":" << update_local
         << ",\"delete_local\":" << delete_local
         << ",\"add_remote\":" << add_remote
         << ",\"update_remote\":" << update_remote
         << ",\"delete_remote\":" << delete_remote
         << ",\"conflicts\":" << conflicts
         << ",\"preserve_both\":" << preserve_both
         << ",\"no_change\":" << no_change
         << "},\"entries\":[";
    for (std::size_t i = 0; i < plan.entries.size(); ++i) {
        if (i) json << ',';
        const auto& entry = plan.entries[i];
        std::string action_name;
        std::string action_label;
        switch (entry.action) {
            case peer::PeerPlanAction::AddLocal: action_name = "AddLocal"; action_label = "+ Add Local (from Peer)"; break;
            case peer::PeerPlanAction::UpdateLocal: action_name = "UpdateLocal"; action_label = "~ Update Local (from Peer)"; break;
            case peer::PeerPlanAction::DeleteLocal: action_name = "DeleteLocal"; action_label = "- Delete Local (Recovery Saved)"; break;
            case peer::PeerPlanAction::AddRemote: action_name = "AddRemote"; action_label = "+ Add Remote (Send to Peer)"; break;
            case peer::PeerPlanAction::UpdateRemote: action_name = "UpdateRemote"; action_label = "~ Update Remote (Send to Peer)"; break;
            case peer::PeerPlanAction::DeleteRemote: action_name = "DeleteRemote"; action_label = "- Delete Remote (Peer Deletes)"; break;
            case peer::PeerPlanAction::Conflict: action_name = "Conflict"; action_label = "! Unresolved Conflict"; break;
            case peer::PeerPlanAction::PreserveBoth: action_name = "PreserveBoth"; action_label = "= Preserve Both"; break;
            case peer::PeerPlanAction::NoChange: action_name = "NoChange"; action_label = "= In Sync"; break;
        }
        std::uintmax_t size = 0;
        std::string src_hash, dst_hash;
        if (entry.local) {
            dst_hash = entry.local->sha256;
            size = entry.local->size;
        }
        if (entry.remote) {
            src_hash = entry.remote->sha256;
            if (!size) size = entry.remote->size;
        }
        json << "{\"relative_path\":" << quote(entry.relative_path)
             << ",\"action\":" << quote(action_name)
             << ",\"action_label\":" << quote(action_label)
             << ",\"size\":" << size
             << ",\"source_hash\":" << quote(src_hash)
             << ",\"destination_hash\":" << quote(dst_hash)
             << ",\"conflict\":" << (entry.action == peer::PeerPlanAction::Conflict ? "true" : "false")
             << "}";
    }
    json << "]}";
    return json.str();
}


std::string url_decode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int v1 = hex_val(in[i+1]);
            int v2 = hex_val(in[i+2]);
            if (v1 >= 0 && v2 >= 0) {
                out.push_back(static_cast<char>((v1 << 4) | v2));
                i += 2;
                continue;
            }
        } else if (in[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(in[i]);
    }
    return out;
}

struct ParsedUrl {
    std::string path;
    std::map<std::string, std::string> query;
};

ParsedUrl parse_url(const std::string& target) {
    ParsedUrl res;
    auto q = target.find('?');
    if (q == std::string::npos) {
        res.path = target;
        return res;
    }
    res.path = target.substr(0, q);
    std::string qs = target.substr(q + 1);
    std::size_t start = 0;
    while (start < qs.size()) {
        auto amp = qs.find('&', start);
        std::string pair = qs.substr(start, amp == std::string::npos ? std::string::npos : amp - start);
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            res.query[url_decode(pair.substr(0, eq))] = url_decode(pair.substr(eq + 1));
        } else if (!pair.empty()) {
            res.query[url_decode(pair)] = "";
        }
        if (amp == std::string::npos) break;
        start = amp + 1;
    }
    return res;
}

std::vector<std::string> split_path_parts(const std::string& path) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start < path.size()) {
        while (start < path.size() && path[start] == '/') ++start;
        if (start >= path.size()) break;
        auto next = path.find('/', start);
        if (next == std::string::npos) {
            parts.push_back(path.substr(start));
            break;
        }
        parts.push_back(path.substr(start, next - start));
        start = next + 1;
    }
    return parts;
}

CollabStore& get_collab(ServerState& state) {
    if (!state.collab) {
        fs::path collab_dir = fs::current_path() / ".merklechain";
        std::error_code ec;
        fs::create_directories(collab_dir, ec);
        fs::path collab_workspaces = fs::current_path() / "collab_workspaces";
        fs::create_directories(collab_workspaces, ec);
        state.collab = std::make_unique<CollabStore>(collab_dir / "collab.sqlite3", collab_workspaces);
    }
    return *state.collab;
}

std::string serialize_collab_user(const CollabUser& u) {
    std::ostringstream ss;
    ss << "{\"id\":" << quote(u.id)
       << ",\"username\":" << quote(u.username)
       << ",\"role\":" << quote(u.role)
       << ",\"status\":" << quote(u.status)
       << ",\"created_at_ms\":" << u.created_at_ms
       << ",\"last_login_ms\":" << u.last_login_ms
       << ",\"permissions\":[";
    for (std::size_t i = 0; i < u.permissions.size(); ++i) {
        if (i) ss << ',';
        ss << quote(u.permissions[i]);
    }
    ss << "]}";
    return ss.str();
}

std::string serialize_collab_workspace(const CollabWorkspace& w, std::size_t file_count = 0) {
    std::ostringstream ss;
    ss << "{\"id\":" << quote(w.id)
       << ",\"name\":" << quote(w.name)
       << ",\"description\":" << quote(w.description)
       << ",\"root_path\":" << quote(path_utf8(w.root_path))
       << ",\"created_at_ms\":" << w.created_at_ms
       << ",\"file_count\":" << file_count
       << "}";
    return ss.str();
}

std::string serialize_collab_submission(const CollabSubmission& s) {
    std::ostringstream ss;
    ss << "{\"id\":" << quote(s.id)
       << ",\"client_id\":" << quote(s.client_id)
       << ",\"client_username\":" << quote(s.client_username)
       << ",\"workspace_id\":" << quote(s.workspace_id)
       << ",\"file_count\":" << s.file_count
       << ",\"total_size\":" << s.total_size
       << ",\"merkle_root\":" << quote(s.merkle_root)
       << ",\"status\":" << quote(s.status)
       << ",\"review_notes\":" << quote(s.review_notes)
       << ",\"submitted_at_ms\":" << s.submitted_at_ms
       << ",\"reviewed_at_ms\":" << s.reviewed_at_ms
       << "}";
    return ss.str();
}

std::string serialize_collab_version(const CollabPublishedVersion& v) {
    std::ostringstream ss;
    ss << "{\"id\":" << quote(v.id)
       << ",\"workspace_id\":" << quote(v.workspace_id)
       << ",\"parent_version_id\":" << quote(v.parent_version_id)
       << ",\"title\":" << quote(v.title)
       << ",\"release_notes\":" << quote(v.release_notes)
       << ",\"merkle_root\":" << quote(v.merkle_root)
       << ",\"file_count\":" << v.file_count
       << ",\"total_size\":" << v.total_size
       << ",\"published_by_id\":" << quote(v.published_by_id)
       << ",\"published_by_username\":" << quote(v.published_by_username)
       << ",\"published_at_ms\":" << v.published_at_ms
       << "}";
    return ss.str();
}

std::string serialize_collab_update(const CollabClientUpdate& u) {
    std::ostringstream ss;
    ss << "{\"id\":" << quote(u.id)
       << ",\"version_id\":" << quote(u.version_id)
       << ",\"client_id\":" << quote(u.client_id)
       << ",\"workspace_id\":" << quote(u.workspace_id)
       << ",\"version_title\":" << quote(u.version_title)
       << ",\"release_notes\":" << quote(u.release_notes)
       << ",\"merkle_root\":" << quote(u.merkle_root)
       << ",\"file_count\":" << u.file_count
       << ",\"total_size\":" << u.total_size
       << ",\"status\":" << quote(u.status)
       << ",\"accepted_at_ms\":" << u.accepted_at_ms
       << ",\"applied_at_ms\":" << u.applied_at_ms
       << ",\"error_message\":" << quote(u.error_message)
       << "}";
    return ss.str();
}

std::string serialize_collab_event(const CollabSecurityEvent& e) {
    std::ostringstream ss;
    ss << "{\"id\":" << e.id
       << ",\"actor_id\":" << quote(e.actor_id)
       << ",\"actor_username\":" << quote(e.actor_username)
       << ",\"action\":" << quote(e.action)
       << ",\"resource\":" << quote(e.resource)
       << ",\"outcome\":" << quote(e.outcome)
       << ",\"detail\":" << quote(e.detail)
       << ",\"timestamp_ms\":" << e.timestamp_ms
       << "}";
    return ss.str();
}

std::string serialize_collab_diff(const CollabFileDiff& d) {
    std::ostringstream ss;
    ss << "{\"relative_path\":" << quote(d.relative_path)
       << ",\"change_type\":" << quote(d.change_type)
       << ",\"baseline_hash\":" << quote(d.baseline_hash)
       << ",\"current_hash\":" << quote(d.current_hash)
       << ",\"baseline_size\":" << d.baseline_size
       << ",\"current_size\":" << d.current_size
       << ",\"baseline_modified_ms\":" << d.baseline_modified_ms
       << ",\"current_modified_ms\":" << d.current_modified_ms
       << ",\"is_binary\":" << (d.is_binary ? "true" : "false")
       << ",\"diff_text\":" << quote(d.diff_text);
    ss << ",\"lines\":[";
    {
        std::istringstream stream(d.diff_text);
        std::string line;
        bool first = true;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!first) ss << ',';
            first = false;
            ss << quote(line);
        }
    }
    ss << "]}";
    return ss.str();
}

struct AuthContext {
    bool authenticated{false};
    CollabUser user;
    CollabSession session;
};

AuthContext resolve_collab_auth(const Request& req, const JsonObjectParser* body, ServerState& state, const ParsedUrl& url) {
    CollabStore& store = get_collab(state);
    std::string token;
    auto hdr = req.headers.find("x-session-token");
    if (hdr != req.headers.end() && !hdr->second.empty()) {
        token = hdr->second;
    } else {
        auto auth = req.headers.find("authorization");
        if (auth != req.headers.end()) {
            const std::string& a = auth->second;
            if (a.rfind("Bearer ", 0) == 0) token = a.substr(7);
            else token = a;
        }
    }
    if (token.empty() && body) {
        token = optional_string(*body, "session_token");
    }
    if (token.empty()) {
        auto q = url.query.find("session_token");
        if (q != url.query.end()) token = q->second;
    }

    if (!token.empty()) {
        auto sess = store.validate_session(token);
        if (sess) {
            auto u = store.find_user_by_id(sess->user_id);
            if (u && u->status == "active") {
                return {true, *u, *sess};
            }
        }
    }

    // Local dashboard fallback: if valid CSRF token matches state.csrf, grant Host user rights
    bool valid_csrf = false;
    if (body) {
        auto c = body->strings.find("csrf");
        if (c != body->strings.end() && constant_time_equal(c->second, state.csrf)) {
            valid_csrf = true;
        }
    }
    auto csrf_q = url.query.find("csrf");
    if (csrf_q != url.query.end() && constant_time_equal(csrf_q->second, state.csrf)) {
        valid_csrf = true;
    }
    if (valid_csrf) {
        auto host_user = store.find_user_by_username("host");
        if (host_user) {
            CollabSession dummy;
            dummy.token = state.csrf;
            dummy.user_id = host_user->id;
            dummy.username = host_user->username;
            dummy.role = "host";
            return {true, *host_user, dummy};
        }
    }

    return {false, {}, {}};
}

HttpResponse handle_collab_api(const Request& request, ServerState& state, std::uint16_t port, const ParsedUrl& url) {
    (void)port;
    try {
        CollabStore& store = get_collab(state);
        std::string body_text = request.body.empty() ? "{}" : request.body;
        JsonObjectParser body_parser(body_text);
        if (!request.body.empty() && (request.method == "POST" || request.method == "PUT" || request.method == "DELETE")) {
            parse_body(request, body_parser);
        }
        const JsonObjectParser* pbody = request.body.empty() ? nullptr : &body_parser;
        AuthContext auth = resolve_collab_auth(request, pbody, state, url);

        const auto parts = split_path_parts(url.path);
        if (parts.size() < 2 || parts[0] != "api") {
            return {404, "application/json; charset=utf-8", json_error("endpoint not found")};
        }

        const std::string& domain = parts[1];

        // ------------------ AUTH ------------------
        if (domain == "auth") {
            if (parts.size() >= 3 && parts[2] == "login" && request.method == "POST") {
                if (!pbody) throw std::runtime_error("request body required");
                const auto username = require_string(*pbody, "username");
                const auto password = require_string(*pbody, "password");
                std::string err;
                auto sess = store.authenticate(username, password, err);
                if (!sess) return {401, "application/json; charset=utf-8", json_error(err.empty() ? "Invalid credentials" : err)};
                auto u = store.find_user_by_id(sess->user_id);
                return {200, "application/json; charset=utf-8",
                    "{\"success\":true,\"session_token\":" + quote(sess->token) +
                    ",\"user\":" + serialize_collab_user(*u) + "}"};
            }
            if (parts.size() >= 3 && parts[2] == "logout" && request.method == "POST") {
                if (auth.authenticated && auth.session.token != state.csrf) {
                    store.revoke_session(auth.session.token);
                }
                return {200, "application/json; charset=utf-8", "{\"success\":true}"};
            }
            if (parts.size() >= 3 && parts[2] == "me" && request.method == "GET") {
                if (!auth.authenticated) return {401, "application/json; charset=utf-8", json_error("Not authenticated")};
                return {200, "application/json; charset=utf-8", "{\"authenticated\":true,\"user\":" + serialize_collab_user(auth.user) + "}"};
            }
        }

        // ------------------ HOST ------------------
        if (domain == "host") {
            if (!auth.authenticated) return {401, "application/json; charset=utf-8", json_error("Authentication required")};
            if (auth.user.role != "host") return {403, "application/json; charset=utf-8", json_error("Forbidden: Host role required")};

            if (parts.size() >= 3 && parts[2] == "clients") {
                if (request.method == "GET") {
                    auto clients = store.list_clients();
                    std::string out = "{\"clients\":[";
                    for (std::size_t i = 0; i < clients.size(); ++i) {
                        if (i) out += ',';
                        out += serialize_collab_user(clients[i]);
                    }
                    out += "]}";
                    return {200, "application/json; charset=utf-8", out};
                }
                if (request.method == "POST") {
                    if (parts.size() >= 4) {
                        std::string target_user_id = parts.size() >= 5 ? parts[3] : optional_string(*pbody, "user_id");
                        std::string client_action = parts.size() >= 5 ? parts[4] : parts[3];
                        if (client_action == "suspend") {
                            std::string status = "suspended";
                            if (pbody) {
                                if (pbody->strings.count("status")) status = pbody->strings.at("status");
                                if (pbody->booleans.count("suspend")) status = pbody->booleans.at("suspend") ? "suspended" : "active";
                            }
                            store.set_user_status(target_user_id, status);
                            return {200, "application/json; charset=utf-8", "{\"success\":true}"};
                        }
                        if (client_action == "reset-password") {
                            std::string new_pass = require_string(*pbody, "new_password");
                            store.reset_user_password(target_user_id, new_pass);
                            return {200, "application/json; charset=utf-8", "{\"success\":true}"};
                        }
                    } else if (pbody) {
                        const auto username = require_string(*pbody, "username");
                        const auto password = require_string(*pbody, "password");
                        std::vector<std::string> perms = {"submit", "view_versions", "download_updates", "accept_updates"};
                        if (pbody->string_arrays.count("permissions")) perms = pbody->string_arrays.at("permissions");
                        auto u = store.create_user(username, password, "client", perms);
                        store.assign_user_to_workspace("ws-default", u.id);
                        return {200, "application/json; charset=utf-8", "{\"success\":true,\"user\":" + serialize_collab_user(u) + "}"};
                    }
                }
            }

            if (parts.size() >= 3 && parts[2] == "workspaces") {
                if (parts.size() == 3) {
                    if (request.method == "GET") {
                        auto workspaces = store.list_workspaces();
                        std::string out = "{\"workspaces\":[";
                        for (std::size_t i = 0; i < workspaces.size(); ++i) {
                            if (i) out += ',';
                            auto files = store.list_working_copy_files(workspaces[i].id);
                            out += serialize_collab_workspace(workspaces[i], files.size());
                        }
                        out += "]}";
                        return {200, "application/json; charset=utf-8", out};
                    }
                    if (request.method == "POST" && pbody) {
                        auto name = require_string(*pbody, "name");
                        auto desc = optional_string(*pbody, "description", "");
                        auto ws = store.create_workspace(name, desc);
                        return {200, "application/json; charset=utf-8", "{\"success\":true,\"workspace\":" + serialize_collab_workspace(ws, 0) + "}"};
                    }
                }

                // Workspace-specific actions
                std::string ws_id;
                std::string action;
                if (parts[3] == "files" || parts[3] == "changes" || parts[3] == "diff" || parts[3] == "publish" || parts[3] == "versions") {
                    action = parts[3];
                    ws_id = url.query.count("workspace_id") ? url.query.at("workspace_id") : (pbody ? optional_string(*pbody, "workspace_id", "ws-default") : "ws-default");
                } else {
                    ws_id = parts[3];
                    action = parts.size() >= 5 ? parts[4] : "files";
                }

                if (action == "files") {
                    bool is_content = (parts.size() >= 6 && parts[5] == "content") || (parts.size() >= 5 && parts[4] == "content") || url.path.find("/content") != std::string::npos;
                    bool is_delete = (parts.size() >= 6 && parts[5] == "delete") || (parts.size() >= 5 && parts[4] == "delete") || request.method == "DELETE" || url.path.find("/delete") != std::string::npos;
                    if (is_content) {
                        if (request.method == "GET") {
                            std::string p = url.query.count("path") ? url.query.at("path") : "";
                            if (p.empty() && pbody) p = optional_string(*pbody, "path");
                            if (p.empty()) throw std::runtime_error("missing path query parameter");
                            std::string content = store.read_working_copy_file_content(ws_id, p);
                            return {200, "application/json; charset=utf-8", "{\"workspace_id\":" + quote(ws_id) + ",\"path\":" + quote(p) + ",\"content\":" + quote(content) + "}"};
                        }
                        if ((request.method == "POST" || request.method == "PUT") && pbody) {
                            std::string p = require_string(*pbody, "path");
                            std::string content = require_string(*pbody, "content");
                            store.write_working_copy_file_content(ws_id, p, content);
                            return {200, "application/json; charset=utf-8", "{\"success\":true,\"path\":" + quote(p) + "}"};
                        }
                    } else if (is_delete) {
                        std::string p = url.query.count("path") ? url.query.at("path") : "";
                        if (p.empty() && pbody) p = optional_string(*pbody, "path");
                        if (p.empty()) throw std::runtime_error("missing path for deletion");
                        store.delete_working_copy_file(ws_id, p);
                        return {200, "application/json; charset=utf-8", "{\"success\":true}"};
                    } else {
                        if (request.method == "GET") {
                            auto files = store.list_working_copy_files(ws_id);
                            std::string out = "{\"workspace_id\":" + quote(ws_id) + ",\"files\":[";
                            for (std::size_t i = 0; i < files.size(); ++i) {
                                if (i) out += ',';
                                out += "{\"path\":" + quote(files[i].relative_path) + ",\"size\":" + number(files[i].size) +
                                       ",\"sha256\":" + quote(files[i].sha256) + ",\"modified_ms\":" + std::to_string(system_millis_from_file_ticks(files[i].modified_ticks)) + "}";
                            }
                            out += "]}";
                            return {200, "application/json; charset=utf-8", out};
                        }
                        if (request.method == "POST" && pbody) {
                            std::string p = require_string(*pbody, "path");
                            std::string content = optional_string(*pbody, "content", "");
                            store.write_working_copy_file_content(ws_id, p, content);
                            return {200, "application/json; charset=utf-8", "{\"success\":true,\"path\":" + quote(p) + "}"};
                        }
                    }
                }

                if (action == "changes" && request.method == "GET") {
                    auto diffs = store.compute_working_copy_diff(ws_id);
                    std::size_t added = 0, modified = 0, deleted = 0, unchanged = 0;
                    for (const auto& d : diffs) {
                        if (d.change_type == "ADDED") ++added;
                        else if (d.change_type == "MODIFIED") ++modified;
                        else if (d.change_type == "DELETED") ++deleted;
                        else ++unchanged;
                    }
                    std::string out = "{\"workspace_id\":" + quote(ws_id) + ",\"counts\":{\"added\":" + std::to_string(added) +
                                      ",\"modified\":" + std::to_string(modified) + ",\"deleted\":" + std::to_string(deleted) +
                                      ",\"unchanged\":" + std::to_string(unchanged) + "},\"diffs\":[";
                    for (std::size_t i = 0; i < diffs.size(); ++i) {
                        if (i) out += ',';
                        out += serialize_collab_diff(diffs[i]);
                    }
                    out += "]}";
                    return {200, "application/json; charset=utf-8", out};
                }

                if (action == "diff" && request.method == "GET") {
                    std::string p = url.query.count("path") ? url.query.at("path") : "";
                    if (p.empty() && pbody) p = optional_string(*pbody, "path");
                    if (p.empty()) throw std::runtime_error("missing path query parameter for diff");
                    auto d = store.compute_file_diff(ws_id, p);
                    return {200, "application/json; charset=utf-8", serialize_collab_diff(d)};
                }

                if (action == "publish" && request.method == "POST" && pbody) {
                    std::string title = optional_string(*pbody, "title");
                    if (title.empty()) title = optional_string(*pbody, "version_name", "v1.0");
                    std::string notes = optional_string(*pbody, "release_notes");
                    if (notes.empty()) notes = optional_string(*pbody, "summary", "Published version updates");
                    auto v = store.publish_version(ws_id, auth.user.id, title, notes);
                    return {200, "application/json; charset=utf-8", "{\"success\":true,\"version\":" + serialize_collab_version(v) + "}"};
                }

                if (action == "versions" && request.method == "GET") {
                    auto vers = store.list_published_versions(ws_id);
                    std::string out = "{\"workspace_id\":" + quote(ws_id) + ",\"versions\":[";
                    for (std::size_t i = 0; i < vers.size(); ++i) {
                        if (i) out += ',';
                        out += serialize_collab_version(vers[i]);
                    }
                    out += "]}";
                    return {200, "application/json; charset=utf-8", out};
                }
            }

            if (parts.size() >= 3 && parts[2] == "submissions") {
                if (request.method == "GET") {
                    std::string ws_id = url.query.count("workspace_id") ? url.query.at("workspace_id") : "";
                    auto subs = store.list_submissions(ws_id);
                    std::string out = "{\"submissions\":[";
                    for (std::size_t i = 0; i < subs.size(); ++i) {
                        if (i) out += ',';
                        out += serialize_collab_submission(subs[i]);
                    }
                    out += "]}";
                    return {200, "application/json; charset=utf-8", out};
                }
                if (request.method == "POST" && pbody) {
                    std::string sub_id = parts.size() >= 5 ? parts[3] : require_string(*pbody, "submission_id");
                    std::string sub_action = parts.size() >= 5 ? parts[4] : (parts.size() >= 4 ? parts[3] : optional_string(*pbody, "action"));
                    std::string notes = optional_string(*pbody, "notes", optional_string(*pbody, "reason", ""));
                    if (sub_action == "accept") {
                        store.accept_submission(sub_id, auth.user.id, notes);
                        return {200, "application/json; charset=utf-8", "{\"success\":true,\"message\":\"Submission accepted. Baseline and working copy established.\"}"};
                    }
                    if (sub_action == "reject") {
                        store.reject_submission(sub_id, auth.user.id, notes);
                        return {200, "application/json; charset=utf-8", "{\"success\":true,\"message\":\"Submission rejected.\"}"};
                    }
                }
            }

            if (parts.size() >= 3 && parts[2] == "activity" && request.method == "GET") {
                auto evs = store.list_events(100);
                std::string out = "{\"events\":[";
                for (std::size_t i = 0; i < evs.size(); ++i) {
                    if (i) out += ',';
                    out += serialize_collab_event(evs[i]);
                }
                out += "]}";
                return {200, "application/json; charset=utf-8", out};
            }
        }

        // ------------------ CLIENT ------------------
        if (domain == "client") {
            if (!auth.authenticated) return {401, "application/json; charset=utf-8", json_error("Authentication required")};

            if (parts.size() >= 3 && parts[2] == "submissions") {
                if (request.method == "GET") {
                    auto subs = store.list_submissions_for_client(auth.user.id);
                    std::string out = "{\"submissions\":[";
                    for (std::size_t i = 0; i < subs.size(); ++i) {
                        if (i) out += ',';
                        out += serialize_collab_submission(subs[i]);
                    }
                    out += "]}";
                    return {200, "application/json; charset=utf-8", out};
                }
                if (request.method == "POST" && pbody) {
                    std::string ws_id = optional_string(*pbody, "workspace_id", "ws-default");
                    std::string folder_str = require_string(*pbody, "source_folder");
                    fs::path folder = canonical_directory(input_path(folder_str));
                    auto sub = store.create_submission(auth.user.id, ws_id, folder);
                    return {200, "application/json; charset=utf-8", "{\"success\":true,\"submission\":" + serialize_collab_submission(sub) + "}"};
                }
            }

            if (parts.size() >= 3 && parts[2] == "updates") {
                if (request.method == "GET") {
                    auto upds = store.list_updates_for_client(auth.user.id);
                    std::string out = "{\"updates\":[";
                    for (std::size_t i = 0; i < upds.size(); ++i) {
                        if (i) out += ',';
                        out += serialize_collab_update(upds[i]);
                    }
                    out += "]}";
                    return {200, "application/json; charset=utf-8", out};
                }
                if (request.method == "POST" && pbody) {
                    std::string upd_id = parts.size() >= 5 ? parts[3] : require_string(*pbody, "update_id");
                    std::string upd_action = parts.size() >= 5 ? parts[4] : (parts.size() >= 4 ? parts[3] : optional_string(*pbody, "action"));
                    if (upd_action == "accept") {
                        store.accept_update(upd_id, auth.user.id);
                        return {200, "application/json; charset=utf-8", "{\"success\":true}"};
                    }
                    if (upd_action == "apply") {
                        std::string target_str = require_string(*pbody, "target_folder");
                        fs::path target = canonical_directory(input_path(target_str));
                        std::string err;
                        bool ok = store.apply_update(upd_id, auth.user.id, target, err);
                        if (!ok) return {400, "application/json; charset=utf-8", json_error(err)};
                        auto manifest = scan_folder(target);
                        return {200, "application/json; charset=utf-8", "{\"success\":true,\"merkle_root\":" + quote(manifest.merkle_root) + ",\"message\":\"Update verified and applied successfully\"}"};
                    }
                }
            }

            if (parts.size() >= 3 && parts[2] == "activity" && request.method == "GET") {
                auto evs = store.list_events_for_actor(auth.user.id, 50);
                std::string out = "{\"events\":[";
                for (std::size_t i = 0; i < evs.size(); ++i) {
                    if (i) out += ',';
                    out += serialize_collab_event(evs[i]);
                }
                out += "]}";
                return {200, "application/json; charset=utf-8", out};
            }
        }

        return {404, "application/json; charset=utf-8", json_error("endpoint not found")};
    } catch (const std::exception& e) {
        return {400, "application/json; charset=utf-8", json_error(e.what())};
    }
}

HttpResponse handle_api(const Request& request,ServerState& state,std::uint16_t port) {
    ParsedUrl url = parse_url(request.target);
    if (url.path.rfind("/api/auth/", 0) == 0 ||
        url.path.rfind("/api/host/", 0) == 0 ||
        url.path.rfind("/api/client/", 0) == 0) {
        return handle_collab_api(request, state, port, url);
    }

    if(request.method=="GET"&&request.target=="/api/status") {
        const auto ps = peer::PeerController::instance().get_status();
        return {200,"application/json; charset=utf-8", serialize_peer_status(ps, state.csrf)};
    }
    if(request.method=="GET"&&request.target=="/api/peer/status") {
        const auto ps = peer::PeerController::instance().get_status();
        return {200,"application/json; charset=utf-8", serialize_peer_status(ps, state.csrf)};
    }
    if(request.method=="GET"&&request.target=="/api/peer/plan") {
        const auto plan = peer::PeerController::instance().get_pending_plan();
        if(!plan) return {200,"application/json; charset=utf-8","{\"has_plan\":false}"};
        const auto ps = peer::PeerController::instance().get_status();
        return {200,"application/json; charset=utf-8", serialize_peer_plan(*plan, ps.session_id)};
    }
    if(request.method=="GET"&&request.target=="/api/peer/activity") {
        return {200,"application/json; charset=utf-8", peer::PeerController::instance().get_history_json()};
    }
    if(request.method=="GET"&&request.target=="/api/peer/diagnostics") {
        return {200,"application/json; charset=utf-8", peer::PeerController::instance().get_diagnostics_json()};
    }
    if(request.method!="POST")return {405,"application/json; charset=utf-8",json_error("method not allowed")};
    const auto origin=request.headers.find("origin");
    const auto expected_origin="http://127.0.0.1:"+std::to_string(port);
    if(origin==request.headers.end()||origin->second!=expected_origin)return {403,"application/json; charset=utf-8",json_error("request origin is not allowed")};
    JsonObjectParser body(request.body);parse_body(request,body);

    if(request.target=="/api/pick-folder") {
        require_fields(body,{"csrf","slot"});require_csrf(body,state);
        const auto slot=require_string(body,"slot");
        std::wstring picker_title = L"Select Folder";
        if(slot=="a") picker_title = L"Select Folder A — Source";
        else if(slot=="b") picker_title = L"Select Folder B — Destination";
        else if(slot=="submission" || slot=="client") picker_title = L"Select Folder to Submit to Host";
        else if(slot=="target") picker_title = L"Select Folder to Receive Update";
        else throw std::runtime_error("slot must be a, b, submission, client, or target");
        const auto selected=pick_folder(picker_title.c_str());
        if(!selected)return {200,"application/json; charset=utf-8","{\"cancelled\":true}"};
        state.plan.reset();
        return {200,"application/json; charset=utf-8","{\"cancelled\":false,\"path\":"+quote(path_utf8(fs::path(*selected)))+"}"};
    }
    if(request.target=="/api/list-files") {
        require_fields(body,{"csrf","path"});require_csrf(body,state);
        const auto dir=canonical_directory(input_path(require_string(body,"path")));
        auto manifest=scan_folder(dir);
        if(!manifest.complete)throw std::runtime_error("Cannot scan folder: permissions or inaccessible paths");
        std::string output="{\"root\":"+quote(path_utf8(dir))+",\"merkle_root\":"+quote(manifest.merkle_root)+",\"files\":[";
        for(std::size_t i=0;i<manifest.files.size();++i){
            if(i) output+=',';
            const auto& f=manifest.files[i];
            output+="{\"path\":"+quote(f.relative_path)+",\"size\":"+number(f.size)+
                ",\"modified_ms\":"+std::to_string(system_millis_from_file_ticks(f.modified_ticks))+
                ",\"sha256\":"+quote(f.sha256)+"}";
        }
        output+="]}";
        return {200,"application/json; charset=utf-8",output};
    }
    if(request.target=="/api/scan") {
        require_fields_ext(body,{"csrf","source","destination"},{"scope_mode","scope_paths"},{},{"scope_paths"},{"scope"});
        require_csrf(body,state);
        state.plan.reset();
        const auto source=canonical_directory(input_path(require_string(body,"source")));
        const auto destination=canonical_directory(input_path(require_string(body,"destination")));
        validate_distinct_roots(source,destination);
        const auto scope=parse_scope_from_json(body);
        auto source_manifest=scan_folder(source);auto destination_manifest=scan_folder(destination);
        if(!source_manifest.complete||!destination_manifest.complete)throw std::runtime_error("scan incomplete; no plan was created. Review folder permissions and scanner warnings.");
        auto jobs=compare_manifests(source_manifest,destination_manifest,source,destination,scope);
        PendingPlan plan;plan.id=random_token();plan.source_root=path_utf8(source);plan.destination_root=path_utf8(destination);
        plan.source_merkle=source_manifest.merkle_root;plan.destination_merkle=destination_manifest.merkle_root;
        plan.expected_merkle=manifest_expected_root(source_manifest,destination_manifest,scope,jobs);
        plan.jobs=jobs;plan.scope=scope;plan.created=std::chrono::steady_clock::now();
        state.plan=plan;

        std::string source_files="[";
        for(std::size_t i=0;i<source_manifest.files.size();++i){
            if(i) source_files+=',';
            const auto& f=source_manifest.files[i];
            source_files+="{\"path\":"+quote(f.relative_path)+",\"size\":"+number(f.size)+
                ",\"modified_ms\":"+std::to_string(system_millis_from_file_ticks(f.modified_ticks))+
                ",\"sha256\":"+quote(f.sha256)+"}";
        }
        source_files+="]";

        std::string scope_paths_json="[";
        for(std::size_t i=0;i<scope.paths.size();++i){
            if(i) scope_paths_json+=',';
            scope_paths_json+=quote(scope.paths[i]);
        }
        scope_paths_json+="]";
        std::string scope_json="{\"mode\":"+quote(scope.mode)+",\"paths\":"+scope_paths_json+"}";

        return {200,"application/json; charset=utf-8","{\"plan_id\":"+quote(plan.id)+",\"source\":"+quote(plan.source_root)+
            ",\"destination\":"+quote(plan.destination_root)+",\"source_merkle_root\":"+quote(plan.source_merkle)+
            ",\"destination_merkle_root\":"+quote(plan.destination_merkle)+",\"expected_merkle_root\":"+quote(plan.expected_merkle)+
            ",\"scope\":"+scope_json+",\"source_files\":"+source_files+
            ",\"comparison\":"+serialize_comparison(source_manifest,destination_manifest,jobs)+
            ",\"scheduler\":"+serialize_scheduler_preview(jobs,source_manifest,destination_manifest)+
            ",\"merkle_explorer\":"+serialize_merkle_explorer(source_manifest,destination_manifest,jobs)+"}"};
    }
    if(request.target=="/api/sync") {
        require_fields_ext(body,{"csrf","plan_id","source","destination"},{"scope_mode","scope_paths"},{"approve","confirm_deletions"},{"scope_paths"},{"scope"});
        require_csrf(body,state);
        if(!state.plan||require_string(body,"plan_id")!=state.plan->id)throw std::runtime_error("reviewed plan is missing or expired; scan again");
        auto plan=*state.plan;
        if(std::chrono::steady_clock::now()-plan.created>kPlanLifetime){state.plan.reset();throw std::runtime_error("reviewed plan expired; scan again");}
        if(!paths_equal(canonical_directory(input_path(require_string(body,"source"))),input_path(plan.source_root))||
           !paths_equal(canonical_directory(input_path(require_string(body,"destination"))),input_path(plan.destination_root)))
            throw std::runtime_error("folder selection changed since review; scan and review again");

        if(body.strings.count("scope_mode") || body.objects.count("scope") || body.string_arrays.count("scope_paths")) {
            const auto req_scope = parse_scope_from_json(body);
            if(req_scope.mode != plan.scope.mode || req_scope.paths != plan.scope.paths) {
                state.plan.reset();
                throw std::runtime_error("selection scope changed since review; scan and review again");
            }
        }

        const bool has_mutations=std::any_of(plan.jobs.begin(),plan.jobs.end(),mutating);
        const bool has_deletions=std::any_of(plan.jobs.begin(),plan.jobs.end(),[](const auto& job){return job.operation==Operation::Delete;});
        if(!has_mutations)throw std::runtime_error("reviewed plan contains no filesystem changes to apply");
        if(has_mutations&&!require_bool(body,"approve"))throw std::runtime_error("explicit change approval is required");
        if(has_deletions&&!require_bool(body,"confirm_deletions"))throw std::runtime_error("separate deletion confirmation is required");

        state.plan.reset();
        const auto source=canonical_directory(input_path(plan.source_root));const auto destination=canonical_directory(input_path(plan.destination_root));
        validate_distinct_roots(source,destination);
        auto source_manifest=scan_folder(source);auto destination_manifest=scan_folder(destination);
        if(!source_manifest.complete||!destination_manifest.complete)throw std::runtime_error("revalidation scan incomplete; synchronization refused");
        auto jobs=compare_manifests(source_manifest,destination_manifest,source,destination,plan.scope);
        const auto fingerprint=plan_fingerprint(plan.source_root,plan.destination_root,plan.source_merkle,plan.destination_merkle,plan.jobs,plan.scope);
        const auto current=plan_fingerprint(path_utf8(source),path_utf8(destination),source_manifest.merkle_root,destination_manifest.merkle_root,jobs,plan.scope);
        if(fingerprint!=current)throw std::runtime_error("source or destination changed since review; scan and review again");

        const auto internal=destination/".merklechain";ActivityStore activity(internal/"activity.sqlite3");
        VersionStore versions(internal/"activity.sqlite3",internal);
        const bool mutations=std::any_of(jobs.begin(),jobs.end(),mutating);
        std::string before_version;if(mutations)before_version=versions.create_snapshot(destination,"before approved dashboard synchronization");
        SyncExecutionOptions options;options.authorization={require_bool(body,"approve"),has_deletions&&require_bool(body,"confirm_deletions")};
        options.use_scheduler=true;options.use_chunking=true;
        const bool executed=execute_plan(jobs,destination,internal/"recovery",{},options);
        for(const auto& job:jobs)activity.record(job);
        const auto final_manifest=scan_folder(destination);
        const bool verified=executed&&final_manifest.complete&&final_manifest.merkle_root==plan.expected_merkle;
        if(verified&&mutations)versions.create_snapshot(destination,"after verified dashboard synchronization",before_version);

        std::uintmax_t chunk_payload=0, chunk_processed=0, chunk_reused=0, chunk_written=0;
        std::size_t chunks_total=0, chunks_reused=0, files_processed=0;
        std::int64_t elapsed_ms=0;
        for(const auto& j : jobs) {
            if(j.operation == Operation::Add || j.operation == Operation::Modify) {
                ++files_processed;
                chunk_payload += j.bytes_transferred;
                chunk_processed += j.source_bytes_processed;
                chunk_reused += j.bytes_reused;
                chunk_written += j.bytes_written;
                chunks_total += j.chunks_total;
                chunks_reused += j.chunks_reused;
                if(j.completed_at_ms > j.started_at_ms) elapsed_ms += (j.completed_at_ms - j.started_at_ms);
            }
        }
        std::string metrics_json = "{\"files_processed\":"+number(files_processed)+
            ",\"payload_bytes\":"+number(chunk_payload)+
            ",\"source_bytes_processed\":"+number(chunk_processed)+
            ",\"bytes_reused\":"+number(chunk_reused)+
            ",\"bytes_written\":"+number(chunk_written)+
            ",\"chunks_total\":"+number(chunks_total)+
            ",\"chunks_reused\":"+number(chunks_reused)+
            ",\"elapsed_ms\":"+std::to_string(elapsed_ms)+
            ",\"verified\":"+(verified?"true":"false")+"}";

        return {200,"application/json; charset=utf-8",std::string("{\"success\":")+(verified?"true":"false")+
            ",\"final_merkle_root\":"+quote(final_manifest.merkle_root)+",\"expected_merkle_root\":"+quote(plan.expected_merkle)+
            ",\"chunk_metrics\":"+metrics_json+",\"jobs\":"+serialize_jobs(jobs)+
            ",\"message\":"+quote(verified?"Synchronization completed and Merkle root verified":"Synchronization failed or final Merkle verification did not match")+"}"};
    }
    if(request.target=="/api/versions") {
        require_fields(body,{"csrf","destination"});require_csrf(body,state);
        const auto destination=canonical_directory(input_path(require_string(body,"destination")));
        const auto internal=destination/".merklechain";const auto database=internal/"activity.sqlite3";
        std::error_code error;if(!fs::is_regular_file(database,error)||error)return {200,"application/json; charset=utf-8","{\"versions\":[]}"};
        VersionStore versions(database,internal);
        return {200,"application/json; charset=utf-8",serialize_versions(versions,state,destination)};
    }
    if(request.target=="/api/restore") {
        require_fields(body,{"csrf","destination","version_id","restore_token","confirmation"});require_csrf(body,state);
        if(require_string(body,"confirmation")!="RESTORE")throw std::runtime_error("type RESTORE to confirm version replacement");
        const auto destination=canonical_directory(input_path(require_string(body,"destination")));
        const auto token=require_string(body,"restore_token");const auto grant=state.restore_grants.find(token);
        if(grant==state.restore_grants.end()||grant->second.destination!=destination||grant->second.version_id!=require_string(body,"version_id")||std::chrono::steady_clock::now()-grant->second.created>kPlanLifetime)
            throw std::runtime_error("restore approval is missing, expired, or belongs to another destination/version");
        state.restore_grants.erase(grant);
        state.plan.reset();
        const auto internal=destination/".merklechain";VersionStore versions(internal/"activity.sqlite3",internal);
        const bool restored=versions.restore(require_string(body,"version_id"),destination,true);
        return {200,"application/json; charset=utf-8",std::string("{\"success\":")+(restored?"true":"false")+
            ",\"message\":"+quote(restored?"Version restored and verified":"Restore failed verification; recovery data was retained")+"}"};
    }
    if(request.target=="/api/activity") {
        require_fields(body,{"csrf","destination"});require_csrf(body,state);
        const auto destination=canonical_directory(input_path(require_string(body,"destination")));
        const auto internal=destination/".merklechain";std::error_code error;
        const auto internal_status=fs::symlink_status(internal,error);
        if(error==std::errc::no_such_file_or_directory||(!error&&!fs::exists(internal_status)))return {200,"application/json; charset=utf-8","{\"activity\":[]}"};
        if(error||fs::is_symlink(internal_status))throw std::runtime_error("application state directory cannot be a symbolic link");
        const auto database=internal/"activity.sqlite3";error.clear();
        if(!fs::is_regular_file(database,error)||error)return {200,"application/json; charset=utf-8","{\"activity\":[]}"};
        const auto db_status=fs::symlink_status(database,error);
        if(error||fs::is_symlink(db_status))throw std::runtime_error("activity database cannot be a symbolic link");
        return {200,"application/json; charset=utf-8",activity_json(database)};
    }
    if(request.target=="/api/peer/validate-config") {
        validate_allowed_fields(body,
            {"csrf","role","identity","device_id","sync_root","bind_address","host_address","peer_address","address","certificate_file","cert_path","private_key_file","key_path","ca_file","ca_path","expected_peer_sha256","expected_peer_pin"},
            {},
            {"port","peer_port"}
        );
        require_csrf(body,state);
        peer::PeerConfig cfg;
        const auto role_str = require_string(body,"role");
        if (role_str != "host" && role_str != "client") {
            throw std::runtime_error("invalid role: must be host or client");
        }
        cfg.role = (role_str == "host") ? peer::Role::Host : peer::Role::Client;
        
        cfg.identity = optional_string(body,"identity");
        if (cfg.identity.empty()) cfg.identity = optional_string(body,"device_id");
        if (cfg.identity.empty()) throw std::runtime_error("device identity is required");

        cfg.sync_root = input_path(require_string(body,"sync_root"));
        
        const auto port_num = optional_number(body, "port", optional_number(body, "peer_port", 47832));
        if (port_num < 1024 || port_num > 65535) {
            throw std::runtime_error("port must be between 1024 and 65535");
        }
        cfg.port = static_cast<std::uint16_t>(port_num);

        std::string addr = optional_string(body, "bind_address");
        if (addr.empty()) addr = optional_string(body, "host_address");
        if (addr.empty()) addr = optional_string(body, "peer_address");
        if (addr.empty()) addr = optional_string(body, "address");
        if (cfg.role == peer::Role::Host) {
            cfg.bind_address = addr.empty() ? "0.0.0.0" : addr;
        } else {
            cfg.host_address = addr.empty() ? "127.0.0.1" : addr;
        }

        std::string cert_file = optional_string(body, "certificate_file");
        if (cert_file.empty()) cert_file = optional_string(body, "cert_path");
        if (!cert_file.empty()) cfg.certificate_file = input_path(cert_file);

        std::string key_file = optional_string(body, "private_key_file");
        if (key_file.empty()) key_file = optional_string(body, "key_path");
        if (!key_file.empty()) cfg.private_key_file = input_path(key_file);

        std::string ca = optional_string(body, "ca_file");
        if (ca.empty()) ca = optional_string(body, "ca_path");
        if (!ca.empty()) cfg.ca_file = input_path(ca);

        cfg.expected_peer_sha256 = optional_string(body, "expected_peer_sha256");
        if (cfg.expected_peer_sha256.empty()) cfg.expected_peer_sha256 = optional_string(body, "expected_peer_pin");

        const auto val = peer::PeerController::instance().validate_config(cfg);
        if(!val.valid) {
            return {200,"application/json; charset=utf-8","{\"valid\":false,\"error\":"+quote(val.error)+",\"message\":"+quote(val.error)+",\"local_cert_sha256\":\"\"}"};
        }
        return {200,"application/json; charset=utf-8","{\"valid\":true,\"error\":\"\",\"message\":\"Configuration valid\",\"local_cert_sha256\":"+quote(val.local_cert_sha256)+"}"};
    }
    if(request.target=="/api/peer/configure") {
        validate_allowed_fields(body,
            {"csrf","config_path","role","identity","device_id","sync_root","bind_address","host_address","peer_address","address","certificate_file","cert_path","private_key_file","key_path","ca_file","ca_path","expected_peer_sha256","expected_peer_pin"},
            {},
            {"port","peer_port"}
        );
        require_csrf(body,state);
        peer::PeerConfig cfg;
        const auto config_path_str = optional_string(body,"config_path");
        if (!config_path_str.empty()) {
            const auto role_str = optional_string(body,"role","client");
            const auto exp_role = (role_str == "host") ? peer::Role::Host : peer::Role::Client;
            cfg = peer::load_peer_config(input_path(config_path_str), exp_role);
        } else {
            const auto role_str = require_string(body,"role");
            if (role_str != "host" && role_str != "client") {
                throw std::runtime_error("invalid role: must be host or client");
            }
            cfg.role = (role_str == "host") ? peer::Role::Host : peer::Role::Client;

            cfg.identity = optional_string(body,"identity");
            if (cfg.identity.empty()) cfg.identity = optional_string(body,"device_id");
            if (cfg.identity.empty()) throw std::runtime_error("device identity is required");

            cfg.sync_root = canonical_directory(input_path(require_string(body,"sync_root")));

            const auto port_num = optional_number(body, "port", optional_number(body, "peer_port", 47832));
            if (port_num < 1024 || port_num > 65535) {
                throw std::runtime_error("port must be between 1024 and 65535");
            }
            cfg.port = static_cast<std::uint16_t>(port_num);

            std::string addr = optional_string(body, "bind_address");
            if (addr.empty()) addr = optional_string(body, "host_address");
            if (addr.empty()) addr = optional_string(body, "peer_address");
            if (addr.empty()) addr = optional_string(body, "address");
            if (cfg.role == peer::Role::Host) {
                cfg.bind_address = addr.empty() ? "0.0.0.0" : addr;
            } else {
                cfg.host_address = addr.empty() ? "127.0.0.1" : addr;
            }

            std::string cert_file = optional_string(body, "certificate_file");
            if (cert_file.empty()) cert_file = optional_string(body, "cert_path");
            if (!cert_file.empty()) cfg.certificate_file = input_path(cert_file);

            std::string key_file = optional_string(body, "private_key_file");
            if (key_file.empty()) key_file = optional_string(body, "key_path");
            if (!key_file.empty()) cfg.private_key_file = input_path(key_file);

            std::string ca = optional_string(body, "ca_file");
            if (ca.empty()) ca = optional_string(body, "ca_path");
            if (!ca.empty()) cfg.ca_file = input_path(ca);

            cfg.expected_peer_sha256 = optional_string(body, "expected_peer_sha256");
            if (cfg.expected_peer_sha256.empty()) cfg.expected_peer_sha256 = optional_string(body, "expected_peer_pin");
        }
        std::string err;
        if (!peer::PeerController::instance().configure(cfg, err)) {
            return {400,"application/json; charset=utf-8",json_error(err)};
        }
        const auto ps = peer::PeerController::instance().get_status();
        return {200,"application/json; charset=utf-8", serialize_peer_status(ps, state.csrf)};
    }
    if(request.target=="/api/peer/start") {
        require_fields(body,{"csrf"});
        require_csrf(body,state);
        std::string err;
        if (!peer::PeerController::instance().start(err)) {
            return {400,"application/json; charset=utf-8",json_error(err)};
        }
        const auto ps = peer::PeerController::instance().get_status();
        return {200,"application/json; charset=utf-8", serialize_peer_status(ps, state.csrf)};
    }
    if(request.target=="/api/peer/stop") {
        require_fields(body,{"csrf"});
        require_csrf(body,state);
        peer::PeerController::instance().stop();
        return {200,"application/json; charset=utf-8","{\"success\":true,\"message\":\"Peer operation stopped or cancelled\"}"};
    }
    if(request.target=="/api/peer/approve") {
        validate_allowed_fields(body,
            {"csrf","session_id","plan_hash"},
            {"approve","confirm_deletions"},
            {}
        );
        require_csrf(body,state);
        const auto session_id = optional_string(body,"session_id");
        const auto plan_hash = optional_string(body,"plan_hash");
        const bool approve = require_bool(body,"approve");
        const bool confirm_deletions = optional_bool(body,"confirm_deletions",false);
        std::string err;
        if (!peer::PeerController::instance().submit_approval(session_id, plan_hash, approve, confirm_deletions, err)) {
            return {400,"application/json; charset=utf-8",json_error(err)};
        }
        return {200,"application/json; charset=utf-8","{\"success\":true,\"approved\":"+(approve?std::string("true"):std::string("false"))+"}"};
    }
    return {404,"application/json; charset=utf-8",json_error("endpoint not found")};
}

std::string mime_type(const std::string& path) {
    if(path=="/"||path=="/index.html")return "text/html; charset=utf-8";
    if(path=="/styles.css")return "text/css; charset=utf-8";
    if(path=="/app.js")return "text/javascript; charset=utf-8";
    return {};
}
std::string read_asset(const std::string& target) {
    const auto type=mime_type(target);if(type.empty())throw std::runtime_error("static asset not found");
    const auto path=fs::current_path()/"web"/(target=="/"?"index.html":target.substr(1));
    std::ifstream input(path,std::ios::binary);if(!input)throw std::runtime_error("dashboard assets are missing; run from the project directory");
    std::ostringstream output;output<<input.rdbuf();return output.str();
}
void send_response(SOCKET socket,const HttpResponse& response) {
    HttpResponse bounded=response;
    if(bounded.body.size()>kMaxResponseBytes)bounded={413,"application/json; charset=utf-8",json_error("response exceeds the dashboard size limit")};
    const char* reason=bounded.status==200?"OK":bounded.status==400?"Bad Request":bounded.status==403?"Forbidden":
        bounded.status==404?"Not Found":bounded.status==405?"Method Not Allowed":bounded.status==413?"Payload Too Large":"Error";
    std::string headers="HTTP/1.1 "+std::to_string(bounded.status)+" "+reason+"\r\nContent-Type: "+bounded.type+
        "\r\nContent-Length: "+std::to_string(bounded.body.size())+
        "\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n";
    headers+="Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n\r\n";
    headers+=bounded.body;std::size_t sent=0;
    while(sent<headers.size()) {const int count=send(socket,headers.data()+sent,static_cast<int>(std::min<std::size_t>(headers.size()-sent,static_cast<std::size_t>(INT_MAX))),0);if(count<=0)break;sent+=static_cast<std::size_t>(count);}
}
HttpResponse handle_request(const Request& request,ServerState& state,std::uint16_t port) {
    const auto host=request.headers.find("host");const auto expected_host="127.0.0.1:"+std::to_string(port);
    if(host==request.headers.end()||host->second!=expected_host)return {403,"application/json; charset=utf-8",json_error("Host header is not allowed")};
    if(request.method=="GET"&&request.target.rfind("/api/",0)==0)return handle_api(request,state,port);
    if(request.method=="GET") {
        try {const auto type=mime_type(request.target);if(type.empty())return {404,"text/plain; charset=utf-8","Not found"};return {200,type,read_asset(request.target)};}
        catch(const std::exception& error){return {404,"text/plain; charset=utf-8",error.what()};}
    }
    if((request.method=="POST"||request.method=="PUT"||request.method=="DELETE")&&request.target.rfind("/api/",0)==0) {
        try {return handle_api(request,state,port);}
        catch(const std::exception& error){return {400,"application/json; charset=utf-8",json_error(error.what())};}
    }
    return {404,"application/json; charset=utf-8",json_error("route not found")};
}
}

void run_web_server(std::uint16_t port) {
    WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data)!=0)throw std::runtime_error("Winsock initialization failed");
    struct WinsockCleanup { ~WinsockCleanup(){WSACleanup();} } cleanup;
    Socket listener(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));if(listener.value==INVALID_SOCKET)throw std::runtime_error("cannot create dashboard socket");
    BOOL exclusive=TRUE;if(setsockopt(listener.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))==SOCKET_ERROR)throw std::runtime_error("cannot set exclusive loopback listener mode");
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(port);address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(listener.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==SOCKET_ERROR)throw std::runtime_error("cannot bind dashboard to 127.0.0.1; Winsock error "+std::to_string(WSAGetLastError()));
    if(listen(listener.value,SOMAXCONN)==SOCKET_ERROR)throw std::runtime_error("cannot listen for local dashboard requests");
    ServerState state;
    std::cout<<"MerkleChain dashboard: http://127.0.0.1:"<<port<<"/\nPress Ctrl+C to stop. Network Mode remains disabled.\n";
    for(;;) {
        Socket client(accept(listener.value,nullptr,nullptr));if(client.value==INVALID_SOCKET)throw std::runtime_error("dashboard accept failed");
        DWORD timeout=15000;setsockopt(client.value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
        try {
            const auto raw=receive_request(client.value);const auto request=parse_request(raw);
            const auto response=handle_request(request,state,port);send_response(client.value,response);
        } catch(const std::exception& error) {
            const std::string message=error.what();const int status=message.find("size limit")!=std::string::npos?413:400;
            try {send_response(client.value,{status,"application/json; charset=utf-8",json_error(message)});}catch(...){}
        }
    }
}
}
