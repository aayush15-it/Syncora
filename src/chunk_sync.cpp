#include "merklechain/chunk_sync.hpp"
#include "merklechain/hash.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <optional>
#include <stdexcept>

namespace mc {
#ifdef MERKLECHAIN_TESTING
namespace { ChunkFaultPointForTesting chunk_fault=ChunkFaultPointForTesting::None; }
void set_chunk_fault_point_for_testing(ChunkFaultPointForTesting point){chunk_fault=point;}
#endif
namespace {
constexpr std::uintmax_t kMaximumChunkSize=64U*1024U*1024U;
void add_bytes(std::uintmax_t& total,std::uintmax_t amount){total=total>std::numeric_limits<std::uintmax_t>::max()-amount?std::numeric_limits<std::uintmax_t>::max():total+amount;}

bool valid_hash(const std::string& value){
    return value.size()==64&&std::all_of(value.begin(),value.end(),[](unsigned char c){return std::isxdigit(c)!=0;});
}

bool valid_manifest(const ChunkManifest& manifest,std::uintmax_t expected_chunk_size){
    if(manifest.format_version!=kChunkManifestVersion||manifest.chunk_size!=expected_chunk_size||
       manifest.chunk_size==0||manifest.chunk_size>kMaximumChunkSize||!valid_hash(manifest.file_sha256))return false;
    const auto count=manifest.file_size/manifest.chunk_size+(manifest.file_size%manifest.chunk_size?1U:0U);
    if(count!=manifest.chunks.size())return false;
    std::uintmax_t offset=0;
    for(const auto& chunk:manifest.chunks){
        const auto expected_size=std::min(manifest.chunk_size,manifest.file_size-offset);
        if(chunk.offset!=offset||chunk.size!=expected_size||chunk.size==0||!valid_hash(chunk.sha256))return false;
        offset+=chunk.size;
    }
    return offset==manifest.file_size;
}

std::vector<unsigned char> read_chunk(std::ifstream& input,const ChunkDescriptor& chunk){
    if(chunk.offset>static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max())||
       chunk.size>static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())||
       chunk.size>static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max()))
        throw std::runtime_error("chunk offset or size exceeds stream limits");
    input.clear();input.seekg(static_cast<std::streamoff>(chunk.offset));
    if(!input)throw std::runtime_error("cannot seek to chunk offset");
    std::vector<unsigned char> bytes(static_cast<std::size_t>(chunk.size));
    input.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    if(input.gcount()!=static_cast<std::streamsize>(bytes.size()))throw std::runtime_error("truncated chunk data");
    if(sha256_data(bytes.data(),bytes.size())!=chunk.sha256)throw std::runtime_error("chunk content hash mismatch");
    return bytes;
}

}

ChunkManifest build_chunk_manifest(const fs::path& file,std::uintmax_t chunk_size,std::uintmax_t* source_bytes_processed){
    if(chunk_size==0||chunk_size>kMaximumChunkSize)throw std::invalid_argument("chunk size must be between 1 byte and 64 MiB");
    ChunkManifest manifest;manifest.chunk_size=chunk_size;
    std::error_code ec;manifest.file_size=fs::file_size(file,ec);if(ec)throw std::runtime_error("cannot read chunked file size: "+ec.message());
    manifest.file_sha256=sha256_file(file,source_bytes_processed);
    std::ifstream input(file,std::ios::binary);if(!input)throw std::runtime_error("cannot open file for chunk hashing: "+file.string());
    std::uintmax_t offset=0;
    while(offset<manifest.file_size){
        const auto size=std::min(chunk_size,manifest.file_size-offset);
        ChunkDescriptor chunk;chunk.offset=offset;chunk.size=size;
        if(size>static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())||size>static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max()))throw std::runtime_error("chunk size exceeds stream limits");
        std::vector<unsigned char> bytes(static_cast<std::size_t>(size));input.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
        if(input.gcount()!=static_cast<std::streamsize>(bytes.size()))throw std::runtime_error("file changed or was truncated while hashing chunks");
        if(source_bytes_processed)add_bytes(*source_bytes_processed,size);
        chunk.sha256=sha256_data(bytes.data(),bytes.size());manifest.chunks.push_back(std::move(chunk));offset+=size;
    }
    if(sha256_file(file,source_bytes_processed)!=manifest.file_sha256||fs::file_size(file)!=manifest.file_size)throw std::runtime_error("file changed while its chunk manifest was being built");
    if(!valid_manifest(manifest,chunk_size))throw std::runtime_error("generated chunk manifest is inconsistent");
    return manifest;
}

ChunkTransferResult copy_file_chunked_or_fallback(const fs::path& source,const fs::path& current_destination,
                                                   StagingFile& staging,const std::string& expected_source_sha256,
                                                   const std::string& expected_destination_sha256,std::uintmax_t chunk_size){
    ChunkTransferResult result;
    if(!valid_hash(expected_source_sha256))throw std::runtime_error("invalid expected source SHA-256");
    if(sha256_file(source,&result.source_bytes_processed)!=expected_source_sha256)throw std::runtime_error("source changed after preview");
    if(!expected_destination_sha256.empty()&&(!fs::is_regular_file(current_destination)||sha256_file(current_destination)!=expected_destination_sha256))
        throw std::runtime_error("destination changed after preview");

#ifdef MERKLECHAIN_TESTING
    const auto fault=chunk_fault;chunk_fault=ChunkFaultPointForTesting::None;
#endif
    try{
        auto source_manifest=build_chunk_manifest(source,chunk_size,&result.source_bytes_processed);
#ifdef MERKLECHAIN_TESTING
        if(fault==ChunkFaultPointForTesting::MissingSourceManifest)throw std::runtime_error("source chunk manifest is missing");
        if(fault==ChunkFaultPointForTesting::IncompatibleSourceManifest)++source_manifest.format_version;
        if(fault==ChunkFaultPointForTesting::MissingChunkDescriptor&&!source_manifest.chunks.empty())source_manifest.chunks.pop_back();
        if(fault==ChunkFaultPointForTesting::OverlappingChunkRange&&source_manifest.chunks.size()>1)source_manifest.chunks[1].offset=source_manifest.chunks[0].offset;
        if(fault==ChunkFaultPointForTesting::IncorrectFinalChunkLength&&!source_manifest.chunks.empty())++source_manifest.chunks.back().size;
        if(fault==ChunkFaultPointForTesting::InvalidChunkHash&&!source_manifest.chunks.empty())source_manifest.chunks[0].sha256="invalid";
#endif
        if(!valid_manifest(source_manifest,chunk_size)||source_manifest.file_sha256!=expected_source_sha256)throw std::runtime_error("source chunk manifest is missing or incompatible");

        std::optional<ChunkManifest> destination_manifest;
        if(!expected_destination_sha256.empty()){
            try{auto candidate=build_chunk_manifest(current_destination,chunk_size);if(valid_manifest(candidate,chunk_size)&&candidate.file_sha256==expected_destination_sha256)destination_manifest=std::move(candidate);}
            catch(const std::exception&){destination_manifest.reset();}
        }
        staging.reset();
        std::ifstream source_input(source,std::ios::binary);if(!source_input)throw std::runtime_error("cannot open source for chunk transfer");
        std::ifstream destination_input;
        if(destination_manifest){destination_input.open(current_destination,std::ios::binary);if(!destination_input)destination_manifest.reset();}
        result.used_chunks=true;
        result.chunk_count=source_manifest.chunks.size();
#ifdef MERKLECHAIN_TESTING
        bool first_chunk=true;
#endif
        for(const auto& chunk:source_manifest.chunks){
            bool reused=false;std::vector<unsigned char> bytes;
            if(destination_manifest&&chunk.offset<destination_manifest->file_size&&chunk.offset/chunk_size<destination_manifest->chunks.size()){
                const auto index=static_cast<std::size_t>(chunk.offset/chunk_size);const auto& old=destination_manifest->chunks[index];
                if(old.offset==chunk.offset&&old.size==chunk.size&&old.sha256==chunk.sha256){bytes=read_chunk(destination_input,old);reused=true;++result.reused_chunks;add_bytes(result.reused_bytes,chunk.size);}
            }
            if(!reused){bytes=read_chunk(source_input,chunk);add_bytes(result.bytes_transferred,chunk.size);add_bytes(result.source_bytes_processed,chunk.size);}
#ifdef MERKLECHAIN_TESTING
            if(first_chunk&&fault==ChunkFaultPointForTesting::CorruptFirstChunk&&!bytes.empty())bytes[0]^=0x01U;
            if(first_chunk&&fault==ChunkFaultPointForTesting::TruncateFirstChunk&&!bytes.empty())bytes.pop_back();
#endif
            staging.write(bytes.data(),bytes.size());
            add_bytes(result.bytes_written,static_cast<std::uintmax_t>(bytes.size()));
#ifdef MERKLECHAIN_TESTING
            if(first_chunk&&fault==ChunkFaultPointForTesting::ChangeSourceAfterFirstChunk){source_input.close();std::ofstream changed(source,std::ios::binary|std::ios::trunc);changed<<"source changed during chunk transfer";changed.close();if(!changed)throw std::runtime_error("test fault could not mutate source");source_input.open(source,std::ios::binary);if(!source_input)throw std::runtime_error("test fault could not reopen mutated source");}
#endif
#ifdef MERKLECHAIN_TESTING
            first_chunk=false;
#endif
        }
        staging.flush();
        if(staging.sha256()!=expected_source_sha256||staging.size()!=source_manifest.file_size)throw std::runtime_error("reconstructed chunk file failed full-file verification");
        for(const auto& chunk:source_manifest.chunks)if(staging.sha256_range(chunk.offset,chunk.size)!=chunk.sha256)throw std::runtime_error("reconstructed chunk failed verification");
        if(sha256_file(source,&result.source_bytes_processed)!=expected_source_sha256)throw std::runtime_error("source changed during chunk transfer");
        result.bytes_written=staging.bytes_written();
        return result;
    }catch(const std::exception& chunk_error){
        const std::string reason=chunk_error.what();
        try{
            std::uintmax_t fallback_source_bytes=0;
            if(sha256_file(source,&fallback_source_bytes)!=expected_source_sha256)throw std::runtime_error("source changed during chunk transfer");
            copy_file_to_staging(source,staging,expected_source_sha256,&fallback_source_bytes);
            ChunkTransferResult fallback;fallback.used_chunks=false;fallback.bytes_transferred=staging.size();fallback.source_bytes_processed=result.source_bytes_processed;add_bytes(fallback.source_bytes_processed,fallback_source_bytes);fallback.bytes_written=staging.bytes_written();fallback.fallback_reason=reason;return fallback;
        }catch(const std::exception& fallback_error){
            staging.reset();
            throw std::runtime_error("chunk transfer failed ("+reason+"); whole-file fallback failed: "+fallback_error.what());
        }
    }
}

} // namespace mc
