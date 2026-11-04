#include "merklechain/peer/peer_protocol.hpp"
#include "merklechain/peer/peer_cas_helpers.hpp"
#include "merklechain/cas/object_store.hpp"
#include "merklechain/cas/cas_types.hpp"
#include "merklechain/cas/interprocess_barrier.hpp"
#include "merklechain/hash.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <cassert>
#include <atomic>
#include <thread>
#include <limits>
#include <optional>

namespace fs = std::filesystem;

namespace mc::peer {

void run_peer_cas_helpers_tests(const fs::path& fixture_root, void (*check)(bool, const char*)) {
    const fs::path test_dir = fixture_root / "peer_cas_helpers_suite";
    std::error_code ec;
    fs::create_directories(test_dir, ec);

    // =========================================================================
    // SECTION 1: Stage 1 Protocol Wire Extensions & Message Types (10, 11, 12, 13)
    // =========================================================================
    {
        // 1.1 ChunkManifestRequestMessage (Type 10) Round-Trip
        ChunkManifestRequestMessage req_in{"docs/notes.txt"};
        const std::string req_wire = encode_chunk_manifest_request(req_in);
        const ChunkManifestRequestMessage req_out = decode_chunk_manifest_request(req_wire);
        check(req_out.relative_path == "docs/notes.txt", "Stage 1: ChunkManifestRequestMessage round-trip");

        // 1.2 ChunkManifestMessage (Type 11) Round-Trip
        ChunkManifestMessage cm_in;
        cm_in.relative_path = "src/main.cpp";
        cm_in.serialized_manifest = {'M', 'C', 'A', 'S', 1, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0};
        const std::string cm_wire = encode_chunk_manifest_message(cm_in);
        const ChunkManifestMessage cm_out = decode_chunk_manifest_message(cm_wire);
        check(cm_out.relative_path == "src/main.cpp" && cm_out.serialized_manifest == cm_in.serialized_manifest,
              "Stage 1: ChunkManifestMessage round-trip");

        // 1.3 ChunkRequestMessage (Type 12) Round-Trip
        const std::string dummy_hash_1(64, 'a');
        const std::string dummy_hash_2(64, 'b');
        ChunkRequestMessage cr_in;
        cr_in.relative_path = "assets/image.png";
        cr_in.requested_hashes = {dummy_hash_1, dummy_hash_2};
        const std::string cr_wire = encode_chunk_request(cr_in);
        const ChunkRequestMessage cr_out = decode_chunk_request(cr_wire);
        check(cr_out.relative_path == "assets/image.png" && cr_out.requested_hashes.size() == 2 &&
              cr_out.requested_hashes[0] == dummy_hash_1 && cr_out.requested_hashes[1] == dummy_hash_2,
              "Stage 1: ChunkRequestMessage round-trip");

        // 1.4 ChunkDataMessage (Type 13) Round-Trip
        const std::string data_hash(64, 'c');
        ChunkDataMessage cd_in;
        cd_in.chunk_hash = data_hash;
        cd_in.data = {0x01, 0x02, 0x03, 0x04, 0x05, 0xAA, 0xBB, 0xCC};
        const std::string cd_wire = encode_chunk_data(cd_in);
        const ChunkDataMessage cd_out = decode_chunk_data(cd_wire);
        check(cd_out.chunk_hash == data_hash && cd_out.data == cd_in.data,
              "Stage 1: ChunkDataMessage round-trip");

        // 1.5 ChunkManifestPageMessage (Type 14) Round-Trip
        ChunkManifestPageMessage cp_in;
        cp_in.relative_path = "large.bin";
        cp_in.file_sha256 = std::string(64, 'd');
        cp_in.total_size = 104857600;
        cp_in.page_index = 0;
        cp_in.total_pages = 5;
        cp_in.chunks_in_page = 2000;
        cp_in.total_chunks = 10000;
        cp_in.page_payload = {0x01, 0x02, 0x03, 0x04};
        const std::string cp_wire = encode_chunk_manifest_page(cp_in);
        const ChunkManifestPageMessage cp_out = decode_chunk_manifest_page(cp_wire);
        check(cp_out == cp_in, "Stage 1: ChunkManifestPageMessage round-trip");

        // 1.6 FrameDecoder with All New Message Types (10, 11, 12, 13)
        Frame f10{kProtocolVersion, MessageType::ChunkManifestRequest, req_wire};
        Frame f11{kProtocolVersion, MessageType::ChunkManifest, cm_wire};
        Frame f12{kProtocolVersion, MessageType::ChunkRequest, cr_wire};
        Frame f13{kProtocolVersion, MessageType::ChunkData, cd_wire};

        auto w10 = encode_frame(f10);
        auto w11 = encode_frame(f11);
        auto w12 = encode_frame(f12);
        auto w13 = encode_frame(f13);

        std::vector<std::uint8_t> all_frames;
        all_frames.insert(all_frames.end(), w10.begin(), w10.end());
        all_frames.insert(all_frames.end(), w11.begin(), w11.end());
        all_frames.insert(all_frames.end(), w12.begin(), w12.end());
        all_frames.insert(all_frames.end(), w13.begin(), w13.end());

        FrameDecoder decoder;
        auto decoded = decoder.feed(all_frames);
        decoder.finish();
        check(decoded.size() == 4 &&
              decoded[0].type == MessageType::ChunkManifestRequest &&
              decoded[1].type == MessageType::ChunkManifest &&
              decoded[2].type == MessageType::ChunkRequest &&
              decoded[3].type == MessageType::ChunkData,
              "Stage 1: FrameDecoder decodes all 4 CAS frame types coalesced");
    }

    // =========================================================================
    // SECTION 2: Capability Negotiation & Backward Compatibility
    // =========================================================================
    {
        // 2.1 Standard Hello Payload with cas_delta_v1
        PeerCapabilities caps_in;
        caps_in.identity = "peer_alpha";
        caps_in.version = "1.0";
        caps_in.capabilities = {kCapCasDeltaV1, kCapWholeFile};
        const std::string hello_wire = encode_hello_payload(caps_in);
        const PeerCapabilities caps_out = decode_hello_payload(hello_wire);
        check(caps_out.identity == "peer_alpha" && caps_out.supports_cas_delta() &&
              caps_out.has_capability("whole_file"),
              "Stage 1: Hello payload negotiation with cas_delta_v1 round-trip");

        // 2.2 Legacy Peer Payload (Plain identity string, no delimiters)
        const PeerCapabilities legacy_caps = decode_hello_payload("legacy_peer_beta");
        check(legacy_caps.identity == "legacy_peer_beta" && !legacy_caps.supports_cas_delta() &&
              legacy_caps.capabilities.empty(),
              "Stage 1: Legacy plain identity string decoded cleanly with cas_delta disabled");

        // 2.3 Forward Compatibility: Tolerates Unknown Tokens and Arbitrary Ordering
        const std::string future_wire = "vendor=syncora;identity=peer_gamma;unknown_flag=true;caps=experimental,cas_delta_v1;proto_ver=2";
        const PeerCapabilities future_caps = decode_hello_payload(future_wire);
        check(future_caps.identity == "peer_gamma" && future_caps.supports_cas_delta() &&
              future_caps.has_capability("experimental"),
              "Stage 1: Hello decoder safely ignores unknown tokens and preserves caps");

        // 2.4 Rejection of Empty Hello Payload
        bool empty_rejected = false;
        try {
            (void)decode_hello_payload("");
        } catch (...) {
            empty_rejected = true;
        }
        check(empty_rejected, "Stage 1: Empty Hello payload rejected");
    }

    // =========================================================================
    // SECTION 3: Wire Malformation, Limits & Error Boundaries
    // =========================================================================
    {
        // 3.1 Invalid Message Types
        check(!valid_message_type(0), "Stage 1: MessageType 0 is invalid");
        check(valid_message_type(14), "Stage 1: MessageType 14 (ChunkManifestPage) is valid");
        check(!valid_message_type(15), "Stage 1: MessageType 15 is invalid");
        check(!valid_message_type(99), "Stage 1: MessageType 99 is invalid");

        // 3.2 Malformed ChunkRequest: truncated count
        bool trunc_cr = false;
        try {
            (void)decode_chunk_request("ab"); // < 6 bytes
        } catch (...) {
            trunc_cr = true;
        }
        check(trunc_cr, "Stage 1: Truncated ChunkRequest header rejected");

        // 3.3 Malformed ChunkRequest: invalid hex hash
        bool bad_hex = false;
        try {
            std::string bad_payload;
            bad_payload.push_back(0); bad_payload.push_back(1); // path len 1
            bad_payload.push_back('x');                         // path
            bad_payload.push_back(0); bad_payload.push_back(0); bad_payload.push_back(0); bad_payload.push_back(1); // 1 hash
            bad_payload.append(std::string(64, 'Z')); // Non-hex characters
            (void)decode_chunk_request(bad_payload);
        } catch (...) {
            bad_hex = true;
        }
        check(bad_hex, "Stage 1: ChunkRequest with non-hex hash characters rejected");

        // 3.4 Oversized ChunkRequest (> 4096 hashes)
        bool oversized_req = false;
        try {
            ChunkRequestMessage huge_req;
            huge_req.relative_path = "big.bin";
            huge_req.requested_hashes.resize(4097, std::string(64, 'a'));
            (void)encode_chunk_request(huge_req);
        } catch (...) {
            oversized_req = true;
        }
        check(oversized_req, "Stage 1: ChunkRequest with > 4096 hashes rejected before encoding");

        // 3.5 Malformed ChunkData: truncated hash (< 64 bytes)
        bool trunc_cd = false;
        try {
            (void)decode_chunk_data("short_hash");
        } catch (...) {
            trunc_cd = true;
        }
        check(trunc_cd, "Stage 1: ChunkData smaller than 64-byte hash rejected");

        // 3.6 Oversized ChunkData Payload (> 16 KB FastCDC bound)
        bool oversized_cd = false;
        try {
            std::string huge_cd(64, 'a');
            huge_cd.append(std::string(kMaxChunkDataPayloadSize + 1, 'x'));
            (void)decode_chunk_data(huge_cd);
        } catch (...) {
            oversized_cd = true;
        }
        check(oversized_cd, "Stage 1: ChunkData exceeding FastCDC maximum chunk size rejected");
    }

    // =========================================================================
    // SECTION 4: Stage 2 CAS Manifest & FastCDC Bounds Validation
    // =========================================================================
    {
        // 4.1 Valid FastCDC Manifest (Min 4KB, Avg 8KB, Max 16KB, Final < 4KB)
        mc::cas::FileManifest valid_manifest;
        valid_manifest.set_version(1);
        const std::string h1(64, '1');
        const std::string h2(64, '2');
        const std::string h3(64, '3');
        valid_manifest.add_chunk(mc::cas::ChunkInfo{0, 4096, h1});       // 4 KB non-final
        valid_manifest.add_chunk(mc::cas::ChunkInfo{4096, 8192, h2});    // 8 KB non-final
        valid_manifest.add_chunk(mc::cas::ChunkInfo{12288, 1500, h3});   // 1.5 KB valid final chunk (< 4KB)
        valid_manifest.set_file_sha256(std::string(64, 'f'));

        std::string manifest_err;
        check(validate_peer_manifest(valid_manifest, manifest_err),
              "Stage 2: FastCDC manifest with valid final chunk (< 4KB) accepted");

        // 4.2 Empty File Manifest
        mc::cas::FileManifest empty_manifest;
        empty_manifest.set_version(1);
        empty_manifest.clear();
        empty_manifest.set_file_sha256(mc::cas::kEmptySha256);
        check(validate_peer_manifest(empty_manifest, manifest_err),
              "Stage 2: Empty file manifest accepted");

        // 4.3 Rejection of Non-Final Chunk < 4096 Bytes
        mc::cas::FileManifest invalid_chunk_manifest;
        invalid_chunk_manifest.set_version(1);
        invalid_chunk_manifest.add_chunk(mc::cas::ChunkInfo{0, 2048, h1}); // 2 KB non-final (illegal)
        invalid_chunk_manifest.add_chunk(mc::cas::ChunkInfo{2048, 8192, h2});
        invalid_chunk_manifest.set_file_sha256(std::string(64, 'e'));
        check(!validate_peer_manifest(invalid_chunk_manifest, manifest_err),
              "Stage 2: Manifest with non-final chunk < 4 KB rejected");

        // 4.4 Rejection of Chunk > 16384 Bytes
        mc::cas::FileManifest oversized_chunk_manifest;
        oversized_chunk_manifest.set_version(1);
        oversized_chunk_manifest.add_chunk(mc::cas::ChunkInfo{0, 20000, h1}); // > 16 KB (illegal)
        oversized_chunk_manifest.set_file_sha256(std::string(64, 'e'));
        check(!validate_peer_manifest(oversized_chunk_manifest, manifest_err),
              "Stage 2: Manifest with chunk > 16 KB rejected");

        // 4.5 Binary Serialization & Deserialization of Manifest
        const auto bin_bytes = serialize_peer_manifest(valid_manifest);
        mc::cas::FileManifest deserialized_manifest;
        check(deserialize_peer_manifest(bin_bytes, deserialized_manifest, manifest_err) &&
              deserialized_manifest == valid_manifest,
              "Stage 2: Binary manifest serialization & FastCDC validation round-trip");
    }

    // =========================================================================
    // SECTION 5: Path Validation & Anti-Traversal Defense
    // =========================================================================
    {
        std::string path_err;
        check(validate_peer_path("code/app.cpp", path_err), "Stage 2: Valid relative path accepted");
        check(validate_peer_path("a.txt", path_err), "Stage 2: Simple file path accepted");
        check(!validate_peer_path("", path_err), "Stage 2: Empty path rejected");
        check(!validate_peer_path("/root/secret.txt", path_err), "Stage 2: Leading slash rejected");
        check(!validate_peer_path("\\windows\\system32", path_err), "Stage 2: Leading backslash rejected");
        check(!validate_peer_path("C:\\secret.txt", path_err), "Stage 2: Drive letter rejected");
        check(!validate_peer_path("../parent.txt", path_err), "Stage 2: Directory traversal ('..') rejected");
        check(!validate_peer_path("dir/../../secret.txt", path_err), "Stage 2: Nested traversal rejected");
    }

    // =========================================================================
    // SECTION 6: SessionChunkAuthorizer & Anti-Probing Security
    // =========================================================================
    {
        SessionChunkAuthorizer authorizer;
        const std::string auth_hash_1(64, '1');
        const std::string auth_hash_2(64, '2');
        const std::string unauth_hash(64, '9');

        authorizer.authorize_hash(auth_hash_1);
        authorizer.authorize_hash(auth_hash_2);

        check(authorizer.is_authorized(auth_hash_1), "Stage 2: Authorized hash recognized");
        check(!authorizer.is_authorized(unauth_hash), "Stage 2: Unadvertised hash recognized as unauthorized");

        std::string auth_err;
        // Valid request with authorized hashes
        ChunkRequestMessage valid_req;
        valid_req.relative_path = "data.bin";
        valid_req.requested_hashes = {auth_hash_1, auth_hash_2};
        check(authorizer.validate_chunk_request(valid_req, auth_err),
              "Stage 2: ChunkRequest with authorized hashes accepted");

        // Probing attempt: request contains unadvertised hash
        ChunkRequestMessage probe_req;
        probe_req.relative_path = "data.bin";
        probe_req.requested_hashes = {auth_hash_1, unauth_hash};
        check(!authorizer.validate_chunk_request(probe_req, auth_err),
              "Stage 2: ChunkRequest containing unadvertised chunk hash rejected (anti-probing)");

        // Traversal path in request
        ChunkRequestMessage traversal_req;
        traversal_req.relative_path = "../escaped.txt";
        traversal_req.requested_hashes = {auth_hash_1};
        check(!authorizer.validate_chunk_request(traversal_req, auth_err),
              "Stage 2: ChunkRequest with traversal path rejected");
    }

    // =========================================================================
    // SECTION 7: Missing Chunk Resolution against Local ObjectStore
    // =========================================================================
    {
        const fs::path cas_root = test_dir / "cas_test_store";
        fs::create_directories(cas_root, ec);
        mc::cas::ObjectStoreConfig cfg;
        cfg.root_path = cas_root;
        mc::cas::ObjectStore store(cfg);
        std::string init_err;
        check(store.initialize(init_err), "Stage 2: ObjectStore initialized");

        // Put one object into the CAS store
        const std::string payload1 = "local chunk payload one";
        const std::string hash1 = mc::sha256_data(payload1.data(), payload1.size());
        auto res1 = store.put_object(payload1.data(), payload1.size(), hash1);
        check(res1.is_ok(), "Stage 2: put_object succeeded for chunk 1");

        const std::string payload2 = "missing chunk payload two";
        const std::string hash2 = mc::sha256_data(payload2.data(), payload2.size());

        mc::cas::FileManifest test_manifest;
        test_manifest.set_version(1);
        test_manifest.add_chunk(mc::cas::ChunkInfo{0, static_cast<std::uint32_t>(payload1.size()), hash1});
        test_manifest.add_chunk(mc::cas::ChunkInfo{static_cast<std::uint64_t>(payload1.size()), static_cast<std::uint32_t>(payload2.size()), hash2});
        test_manifest.set_file_sha256(std::string(64, '0'));

        const auto missing = compute_missing_chunks(test_manifest, store);
        check(missing.size() == 1 && missing[0] == hash2,
              "Stage 2: compute_missing_chunks accurately identifies missing chunk and skips local chunk");

        // If both exist locally -> zero chunk transfer
        auto res2 = store.put_object(payload2.data(), payload2.size(), hash2);
        check(res2.is_ok(), "Stage 2: put_object succeeded for chunk 2");
        const auto zero_missing = compute_missing_chunks(test_manifest, store);
        check(zero_missing.empty(),
              "Stage 2: compute_missing_chunks returns empty vector when all chunks exist in CAS (zero transfer)");
    }

    // =========================================================================
    // SECTION 8: FastCDC Chunking Helpers & Cryptographic Verification
    // =========================================================================
    {
        // 8.1 In-memory buffer chunking
        std::vector<std::uint8_t> buffer(65536, 0x42); // 64 KB buffer
        mc::cas::FileManifest buf_manifest;
        std::string chunk_err;
        check(chunk_buffer_for_peer(buffer.data(), buffer.size(), buf_manifest, chunk_err),
              "Stage 2: chunk_buffer_for_peer produces valid FastCDC manifest");
        check(buf_manifest.total_size() == 65536 && buf_manifest.chunk_count() > 0,
              "Stage 2: chunk_buffer_for_peer sets correct total size and chunk count");

        // 8.2 Bounded Request Builder
        std::vector<std::string> many_hashes;
        for (std::size_t i = 0; i < 5000; ++i) {
            many_hashes.push_back(std::string(64, 'a'));
        }
        auto requests = build_chunk_requests("bigfile.dat", many_hashes, 4096);
        check(requests.size() == 2 && requests[0].requested_hashes.size() == 4096 &&
              requests[1].requested_hashes.size() == 904,
              "Stage 2: build_chunk_requests partitions missing chunks into bounded batches");

        // 8.3 Cryptographic Payload Verification
        const std::string chunk_data = "immutable verified chunk data bytes";
        const std::string good_hash = mc::sha256_data(chunk_data.data(), chunk_data.size());
        std::string verify_err;
        check(verify_chunk_payload(good_hash, chunk_data.data(), chunk_data.size(), verify_err),
              "Stage 2: verify_chunk_payload passes valid SHA-256 chunk");

        // Bit-flip corruption detection
        std::string corrupted_data = chunk_data;
        corrupted_data[5] ^= '\x01';
        check(!verify_chunk_payload(good_hash, corrupted_data.data(), corrupted_data.size(), verify_err),
              "Stage 2: verify_chunk_payload detects bit-flip corruption");
    }

    // =========================================================================
    // SECTION 9: Complete CAS Object Integrity Verification (5 States)
    // =========================================================================
    {
        const fs::path integrity_root = test_dir / "cas_integrity_store";
        fs::create_directories(integrity_root, ec);
        mc::cas::ObjectStoreConfig cfg;
        cfg.root_path = integrity_root;
        mc::cas::ObjectStore store(cfg);
        std::string init_err;
        check(store.initialize(init_err), "Stage 2 Integrity: ObjectStore initialized for verification tests");

        // Test 1: Correct object passes verification
        const std::string valid_payload = "integrity verified payload chunk 12345";
        const std::string valid_hash = mc::sha256_data(valid_payload.data(), valid_payload.size());
        auto put_res = store.put_object(valid_payload.data(), valid_payload.size(), valid_hash);
        check(put_res.is_ok(), "Test 1: Store valid chunk for verification");

        auto st_valid = store.verify_object(valid_hash, valid_payload.size());
        check(st_valid.is_available_and_valid() &&
              st_valid.availability == mc::cas::ObjectAvailability::AvailableValid &&
              st_valid.size == valid_payload.size() &&
              st_valid.actual_hash == valid_hash &&
              st_valid.error.empty(),
              "Test 1: Correct object passes verification with AvailableValid status and exact hash");

        // Test 2: Missing object returns missing
        const std::string missing_hash(64, 'f');
        auto st_missing = store.verify_object(missing_hash, 100);
        check(!st_missing.is_available_and_valid() &&
              st_missing.availability == mc::cas::ObjectAvailability::Missing,
              "Test 2: Missing object returns Missing availability status");

        // Test 3: Same-size corrupted object fails verification
        const std::string victim_payload = "same size corruption victim payload 999";
        const std::string victim_hash = mc::sha256_data(victim_payload.data(), victim_payload.size());
        auto vres = store.put_object(victim_payload.data(), victim_payload.size(), victim_hash);
        check(vres.is_ok(), "Test 3: Store victim chunk for corruption test");

        const fs::path victim_path = store.object_path(victim_hash);
        // Overwrite in place with same-size corrupted bytes
        std::string corrupted_payload = victim_payload;
        corrupted_payload[0] ^= '\x55';
        {
            std::ofstream out(victim_path, std::ios::binary | std::ios::trunc);
            out.write(corrupted_payload.data(), static_cast<std::streamsize>(corrupted_payload.size()));
        }
        auto st_corrupt = store.verify_object(victim_hash, victim_payload.size());
        check(!st_corrupt.is_available_and_valid() &&
              st_corrupt.availability == mc::cas::ObjectAvailability::Corrupt &&
              st_corrupt.actual_hash == mc::sha256_data(corrupted_payload.data(), corrupted_payload.size()),
              "Test 3: Same-size corrupted object fails verification and reports Corrupt status");

        // Test 11: Invalid hash input is rejected
        auto st_invalid1 = store.verify_object("not-a-valid-hex-hash");
        auto st_invalid2 = store.verify_object(std::string(64, 'Z'));
        auto st_invalid3 = store.verify_object("../../etc/passwd");
        check(st_invalid1.availability == mc::cas::ObjectAvailability::InvalidHash &&
              st_invalid2.availability == mc::cas::ObjectAvailability::InvalidHash &&
              st_invalid3.availability == mc::cas::ObjectAvailability::InvalidHash,
              "Test 11: Invalid hash format is strictly rejected with InvalidHash status");

        // Test 12: Object size mismatch detected
        auto st_size_mismatch = store.verify_object(valid_hash, valid_payload.size() + 50);
        check(!st_size_mismatch.is_available_and_valid() &&
              st_size_mismatch.availability == mc::cas::ObjectAvailability::Corrupt,
              "Test 12: Object size mismatch is detected and flagged as Corrupt");
    }

    // =========================================================================
    // SECTION 10: Atomic In-Place Object Repair Without Deletion Gap
    // =========================================================================
    {
        const fs::path repair_root = test_dir / "cas_repair_store";
        fs::create_directories(repair_root, ec);
        mc::cas::ObjectStoreConfig cfg;
        cfg.root_path = repair_root;
        mc::cas::ObjectStore store(cfg);
        std::string init_err;
        check(store.initialize(init_err), "Stage 2 Repair: ObjectStore initialized for repair tests");

        // Test 4: Wrong hash payload is rejected
        const std::string test_data = "correct payload data bytes";
        const std::string bogus_hash(64, 'e');
        auto bad_put = store.put_object(test_data.data(), test_data.size(), bogus_hash);
        check(bad_put.status == mc::cas::PutResultStatus::HashMismatch,
              "Test 4: Wrong hash payload is rejected by put_object with HashMismatch");

        // Test 5: Corrupted object repaired safely
        const std::string repair_data = "data to be repaired after corruption";
        const std::string target_hash = mc::sha256_data(repair_data.data(), repair_data.size());
        const fs::path target_path = store.object_path(target_hash);
        fs::create_directories(target_path.parent_path(), ec);
        {
            // Seed a corrupted file at target path
            std::ofstream out(target_path, std::ios::binary | std::ios::trunc);
            out << "corrupted bytes";
        }
        check(store.verify_object(target_hash, repair_data.size()).availability == mc::cas::ObjectAvailability::Corrupt,
              "Test 5: Target object verified as Corrupt prior to repair");

        auto repair_res = store.repair_object(repair_data.data(), repair_data.size(), target_hash);
        check(repair_res.is_ok(), "Test 5: repair_object succeeds on corrupted target");
        auto st_repaired = store.verify_object(target_hash, repair_data.size());
        check(st_repaired.is_available_and_valid(),
              "Test 5: Corrupted object repaired safely and verified as AvailableValid");

        // Test 6: Failed repair does not destroy valid data
        const std::string pristine_data = "pristine verified object content";
        const std::string pristine_hash = mc::sha256_data(pristine_data.data(), pristine_data.size());
        auto put_pristine = store.put_object(pristine_data.data(), pristine_data.size(), pristine_hash);
        check(put_pristine.is_ok(), "Test 6: Seed pristine object");

        const std::string malicious_data = "malicious altered content attempt";
        auto failed_repair = store.repair_object(malicious_data.data(), malicious_data.size(), pristine_hash);
        check(failed_repair.status == mc::cas::PutResultStatus::HashMismatch,
              "Test 6: Malicious repair payload rejected with HashMismatch");

        // Crucial guarantee: the pristine object on disk remains intact and verified
        auto st_pristine = store.verify_object(pristine_hash, pristine_data.size());
        std::vector<std::uint8_t> read_bytes;
        store.get_object(pristine_hash, read_bytes);
        std::string read_str(read_bytes.begin(), read_bytes.end());
        check(st_pristine.is_available_and_valid() && read_str == pristine_data,
              "Test 6: Failed repair does NOT destroy or overwrite valid object data on disk");

        // Test 7: Concurrent duplicate repair is safe
        const std::string race_data = "concurrent race repair test payload";
        const std::string race_hash = mc::sha256_data(race_data.data(), race_data.size());
        const fs::path race_path = store.object_path(race_hash);
        fs::create_directories(race_path.parent_path(), ec);
        {
            std::ofstream out(race_path, std::ios::binary | std::ios::trunc);
            out << "damaged initial content";
        }

        std::atomic<int> success_count{0};
        std::thread t1([&]() {
            auto r = store.repair_object(race_data.data(), race_data.size(), race_hash);
            if (r.is_ok()) success_count++;
        });
        std::thread t2([&]() {
            auto r = store.repair_object(race_data.data(), race_data.size(), race_hash);
            if (r.is_ok()) success_count++;
        });
        t1.join();
        t2.join();
        check(success_count == 2, "Test 7: Concurrent repair from multiple threads succeeds safely");
        check(store.verify_object(race_hash, race_data.size()).is_available_and_valid(),
              "Test 7: Object verified as AvailableValid after concurrent repair");
    }

    // =========================================================================
    // SECTION 11: Multi-Thread & Cross-Process Verification and Barrier Safety
    // =========================================================================
    {
        const fs::path conc_root = test_dir / "cas_concurrency_store";
        fs::create_directories(conc_root, ec);
        mc::cas::ObjectStoreConfig cfg;
        cfg.root_path = conc_root;
        mc::cas::ObjectStore store(cfg);
        std::string init_err;
        check(store.initialize(init_err), "Stage 2 Concurrency: ObjectStore initialized");

        const std::string shared_payload = "multi-threaded read verification payload";
        const std::string shared_hash = mc::sha256_data(shared_payload.data(), shared_payload.size());
        store.put_object(shared_payload.data(), shared_payload.size(), shared_hash);

        // Test 8: Concurrent verification is safe
        std::atomic<int> valid_verifications{0};
        std::vector<std::thread> threads;
        for (int i = 0; i < 4; ++i) {
            threads.emplace_back([&]() {
                for (int j = 0; j < 25; ++j) {
                    auto st = store.verify_object(shared_hash, shared_payload.size());
                    if (st.is_available_and_valid()) {
                        valid_verifications++;
                    }
                }
            });
        }
        for (auto& t : threads) {
            t.join();
        }
        check(valid_verifications == 100,
              "Test 8: 100 concurrent object verifications across 4 threads all succeeded safely");

        // Test 10: Cross-process / multi-store verification and repair behaves correctly
        mc::cas::ObjectStore store2(cfg);
        check(store2.initialize(init_err), "Test 10: Secondary ObjectStore initialized on same root");
        auto st_cross = store2.verify_object(shared_hash, shared_payload.size());
        check(st_cross.is_available_and_valid(),
              "Test 10: Secondary store verifies object written by primary store");

        // Test 9: GC cannot delete actively protected object (InterprocessCasBarrier shared vs exclusive)
        const fs::path barrier_file = conc_root / ".cas_barrier.lock";
        mc::cas::InterprocessCasBarrier barrier(barrier_file);
        {
            std::optional<mc::cas::CasSharedBarrierGuard> shared_guard;
            shared_guard.emplace(barrier);

            std::atomic<bool> exclusive_acquired{false};
            std::thread excl_thread([&]() {
                barrier.lock_exclusive();
                exclusive_acquired.store(true);
                barrier.unlock_exclusive();
            });

            // Verify exclusive lock cannot be acquired while shared reader guard is active
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            check(!exclusive_acquired.load(),
                  "Test 9: Interprocess CAS Barrier blocks exclusive GC acquisition while shared reader guard is active");

            // Release shared barrier guard
            shared_guard.reset();
            excl_thread.join();
            check(exclusive_acquired.load(),
                  "Test 9: Interprocess CAS Barrier allows exclusive GC acquisition after shared guard is released");
        }
    }

    // =========================================================================
    // SECTION 12: Protocol Edge Cases, Windows Reserved Names & Integer Overflows
    // =========================================================================
    {
        // 12.1 Windows Reserved Names Rejection
        std::string path_err;
        check(!validate_peer_path("CON", path_err), "Stage 2 Edge: CON rejected");
        check(!validate_peer_path("con.txt", path_err), "Stage 2 Edge: con.txt rejected");
        check(!validate_peer_path("PRN", path_err), "Stage 2 Edge: PRN rejected");
        check(!validate_peer_path("aux.cpp", path_err), "Stage 2 Edge: aux.cpp rejected");
        check(!validate_peer_path("docs/NUL.bin", path_err), "Stage 2 Edge: NUL.bin rejected");
        check(!validate_peer_path("COM1", path_err), "Stage 2 Edge: COM1 rejected");
        check(!validate_peer_path("com9.log", path_err), "Stage 2 Edge: com9.log rejected");
        check(!validate_peer_path("LPT1", path_err), "Stage 2 Edge: LPT1 rejected");
        check(!validate_peer_path("src/lpt5.data", path_err), "Stage 2 Edge: lpt5.data rejected");

        // 12.2 Trailing Spaces, Dots and Consecutive Slashes
        check(!validate_peer_path("notes.txt ", path_err), "Stage 2 Edge: Trailing space rejected");
        check(!validate_peer_path("folder/notes.", path_err), "Stage 2 Edge: Trailing dot rejected");
        check(!validate_peer_path("a//b.txt", path_err), "Stage 2 Edge: Consecutive slashes rejected");
        check(!validate_peer_path("folder/", path_err), "Stage 2 Edge: Trailing slash rejected");

        // 12.3 Manifest Integer Overflow Rejection
        mc::cas::FileManifest overflow_manifest;
        overflow_manifest.set_version(1);
        overflow_manifest.add_chunk(mc::cas::ChunkInfo{0, 10000, std::string(64, 'a')});
        overflow_manifest.add_chunk(mc::cas::ChunkInfo{10000, 10000, std::string(64, 'b')});
        // Craft chunk with offset near UINT64_MAX to trigger overflow detection
        overflow_manifest.add_chunk(mc::cas::ChunkInfo{std::numeric_limits<std::uint64_t>::max() - 1000ULL, 8192, std::string(64, 'c')});
        overflow_manifest.set_file_sha256(std::string(64, '0'));
        std::string manifest_err;
        check(!validate_peer_manifest(overflow_manifest, manifest_err),
              "Stage 2 Edge: Manifest with integer overflow offset rejected");

        // 12.4 SessionChunkAuthorizer Path-Scoped Hardening
        SessionChunkAuthorizer authorizer("sess-abc-123");
        check(authorizer.session_id() == "sess-abc-123", "Stage 2 Edge: Authorizer session ID bound");

        mc::cas::FileManifest auth_manifest;
        auth_manifest.set_version(1);
        const std::string h_allowed(64, 'e');
        auth_manifest.add_chunk(mc::cas::ChunkInfo{0, 4096, h_allowed});
        auth_manifest.set_file_sha256(std::string(64, '1'));
        authorizer.authorize_manifest("authorized/file.txt", auth_manifest);

        check(authorizer.is_path_authorized("authorized/file.txt"),
              "Stage 2 Edge: Authorized path recognized");
        check(!authorizer.is_path_authorized("unauthorized/file.txt"),
              "Stage 2 Edge: Unauthorized path recognized");

        ChunkRequestMessage auth_req;
        auth_req.relative_path = "authorized/file.txt";
        auth_req.requested_hashes = {h_allowed};
        std::string req_err;
        check(authorizer.validate_chunk_request(auth_req, req_err),
              "Stage 2 Edge: ChunkRequest with authorized path and hash accepted");

        ChunkRequestMessage unauth_path_req;
        unauth_path_req.relative_path = "unauthorized/file.txt";
        unauth_path_req.requested_hashes = {h_allowed};
        check(!authorizer.validate_chunk_request(unauth_path_req, req_err),
              "Stage 2 Edge: ChunkRequest with unauthorized path rejected even with valid hash");

        // 12.5 MissingChunksResult with Deduplication, Metrics and Corrupt Identification
        const fs::path comp_root = test_dir / "cas_compute_store";
        fs::create_directories(comp_root, ec);
        mc::cas::ObjectStoreConfig comp_cfg;
        comp_cfg.root_path = comp_root;
        mc::cas::ObjectStore comp_store(comp_cfg);
        std::string comp_init_err;
        comp_store.initialize(comp_init_err);

        // Put chunk 1 (valid)
        const std::string chunk1_data(4096, 'A');
        const std::string chunk1_hash = mc::sha256_data(chunk1_data.data(), chunk1_data.size());
        comp_store.put_object(chunk1_data.data(), chunk1_data.size(), chunk1_hash);

        // Put chunk 2 (corrupted on disk)
        const std::string chunk2_data(4096, 'B');
        const std::string chunk2_hash = mc::sha256_data(chunk2_data.data(), chunk2_data.size());
        comp_store.put_object(chunk2_data.data(), chunk2_data.size(), chunk2_hash);
        const fs::path c2_path = comp_store.object_path(chunk2_hash);
        {
            std::ofstream out(c2_path, std::ios::binary | std::ios::trunc);
            out << "corrupt data for chunk 2";
        }

        // Chunk 3 is completely missing
        const std::string chunk3_data(4096, 'C');
        const std::string chunk3_hash = mc::sha256_data(chunk3_data.data(), chunk3_data.size());

        // Manifest has chunk1, chunk2, chunk3, and duplicate chunk1 (repeated block)
        mc::cas::FileManifest complex_manifest;
        complex_manifest.set_version(1);
        complex_manifest.add_chunk(mc::cas::ChunkInfo{0, 4096, chunk1_hash});
        complex_manifest.add_chunk(mc::cas::ChunkInfo{4096, 4096, chunk2_hash});
        complex_manifest.add_chunk(mc::cas::ChunkInfo{8192, 4096, chunk3_hash});
        complex_manifest.add_chunk(mc::cas::ChunkInfo{12288, 4096, chunk1_hash}); // Duplicate block!
        complex_manifest.set_file_sha256(std::string(64, '2'));

        MissingChunksResult mc_res;
        std::string mc_err;
        check(compute_missing_chunks(complex_manifest, comp_store, mc_res, mc_err),
              "Stage 2 Edge: compute_missing_chunks succeeds on complex manifest");
        check(mc_res.total_chunks == 4, "Stage 2 Edge: total_chunks counts all 4 manifest chunk entries");
        check(mc_res.valid_hashes.size() == 1 && mc_res.valid_hashes[0] == chunk1_hash,
              "Stage 2 Edge: valid_hashes contains unique valid chunk 1");
        check(mc_res.corrupt_hashes.size() == 1 && mc_res.corrupt_hashes[0] == chunk2_hash,
              "Stage 2 Edge: corrupt_hashes accurately identifies corrupted chunk 2 for repair");
        check(mc_res.missing_hashes.size() == 2 &&
              mc_res.missing_hashes[0] == chunk2_hash &&
              mc_res.missing_hashes[1] == chunk3_hash,
              "Stage 2 Edge: missing_hashes contains chunk 2 (for repair) and chunk 3 (missing), with chunk 1 deduplicated");
        check(mc_res.local_reused_bytes == 8192,
              "Stage 2 Edge: local_reused_bytes accounts for both occurrences of chunk 1 (2 * 4096 = 8192)");
        check(mc_res.missing_bytes == 8192,
              "Stage 2 Edge: missing_bytes accounts for chunk 2 and chunk 3 (4096 + 4096 = 8192)");
    }

    // =========================================================================
    // SECTION 13: Deterministic Fail-Closed Interprocess Barrier Tests (SEC-05)
    // =========================================================================
    {
        const fs::path sec5_dir = fixture_root / "sec5_barrier_suite";
        fs::create_directories(sec5_dir);
        const fs::path lock_file = sec5_dir / ".barrier_test.lock";

        // 13.1 Normal Lock Acquisition & Status
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            barrier.lock_shared();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.1: Shared lock acquires OS lock file successfully");
            barrier.unlock_shared();
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.1: OS lock released on shared unlock");

            barrier.lock_exclusive();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.1: Exclusive lock acquires OS lock file successfully");
            barrier.unlock_exclusive();
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.1: OS lock released on exclusive unlock");
        }

        // 13.2 Fail-Closed on EnsureFileOpen failure
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailEnsureFileOpen);

            bool shared_threw = false;
            try {
                barrier.lock_shared();
            } catch (const mc::cas::InterprocessLockException& ex) {
                shared_threw = true;
                check(ex.status() == mc::cas::BarrierLockStatus::OperatingSystemError,
                      "SEC-05 13.2: Shared lock throws InterprocessLockException with OperatingSystemError");
            }
            check(shared_threw, "SEC-05 13.2: lock_shared fails closed when file cannot be opened");
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.2: OS lock not marked acquired on open failure");

            bool excl_threw = false;
            try {
                barrier.lock_exclusive();
            } catch (const mc::cas::InterprocessLockException& ex) {
                excl_threw = true;
                check(ex.status() == mc::cas::BarrierLockStatus::OperatingSystemError,
                      "SEC-05 13.2: Exclusive lock throws InterprocessLockException with OperatingSystemError");
            }
            check(excl_threw, "SEC-05 13.2: lock_exclusive fails closed when file cannot be opened");
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.2: OS lock not marked acquired on open failure");

            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
        }

        // 13.3 Fail-Closed on Shared OS Lock Failure (State Unwinding)
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailLockShared);

            bool threw = false;
            try {
                barrier.lock_shared();
            } catch (const mc::cas::InterprocessLockException&) {
                threw = true;
            }
            check(threw, "SEC-05 13.3: Injected FailLockShared throws exception");
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.3: In-process reader state unwound cleanly");

            // Verify in-process mutex is NOT held and can be re-locked
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            barrier.lock_shared();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.3: Barrier successfully acquires lock after fault cleared");
            barrier.unlock_shared();
        }

        // 13.4 Fail-Closed on Exclusive OS Lock Failure (State Unwinding)
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailLockExclusive);

            bool threw = false;
            try {
                barrier.lock_exclusive();
            } catch (const mc::cas::InterprocessLockException&) {
                threw = true;
            }
            check(threw, "SEC-05 13.4: Injected FailLockExclusive throws exception");
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.4: In-process exclusive state unwound cleanly");

            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            barrier.lock_exclusive();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.4: Barrier acquires exclusive lock after fault cleared");
            barrier.unlock_exclusive();
        }

        // 13.5 Reentrant Depth Tracking on Calling Thread
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            barrier.lock_shared();
            barrier.lock_shared(); // Reentrant
            check(barrier.is_os_lock_acquired(), "SEC-05 13.5: Nested shared lock remains acquired");
            barrier.unlock_shared();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.5: Inner unlock leaves outer lock acquired");
            barrier.unlock_shared();
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.5: Outer unlock releases OS lock");
        }

        // 13.6 TryLock Contention & Status
        {
            mc::cas::InterprocessCasBarrier barrier1(lock_file);
            barrier1.lock_exclusive();

            mc::cas::InterprocessCasBarrier barrier2(lock_file);
            auto st = barrier2.try_lock_shared(std::chrono::milliseconds(50));
            check(st == mc::cas::BarrierLockStatus::Contended,
                  "SEC-05 13.6: try_lock_shared reports Contended status while exclusive held");

            barrier1.unlock_exclusive();

            st = barrier2.try_lock_shared(std::chrono::milliseconds(50));
            check(st == mc::cas::BarrierLockStatus::Acquired,
                  "SEC-05 13.6: try_lock_shared acquires after exclusive lock released");
            barrier2.unlock_shared();
        }

        // 13.7 RAII Guards Exception Safety
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailLockShared);
            bool guard_threw = false;
            try {
                mc::cas::CasSharedBarrierGuard guard(barrier);
            } catch (const mc::cas::InterprocessLockException&) {
                guard_threw = true;
            }
            check(guard_threw, "SEC-05 13.7: CasSharedBarrierGuard constructor throws on failed OS lock");
            check(!barrier.is_os_lock_acquired(), "SEC-05 13.7: Destructor does not double-unlock failed guard");
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
        }

        // 13.8 Simulated Shared Unlock Failure (Poison State & Lock Retention)
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            barrier.lock_shared();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.8: Shared lock acquired before injected unlock fault");

            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailUnlock);
            barrier.unlock_shared();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);

            check(barrier.is_poisoned(), "SEC-05 13.8: Barrier enters poisoned state upon shared unlock failure");
            check(barrier.is_os_lock_acquired(), "SEC-05 13.8: os_lock_acquired remains true to reflect kernel lock retention");
            check(barrier.poison_reason().find("FailUnlock") != std::string::npos,
                  "SEC-05 13.8: Poison reason contains diagnostic failure details");
            barrier.close_file();
        }

        // 13.9 Simulated Syscall Unlock Failure with Captured OS Error Code
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            barrier.lock_exclusive();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.9: Exclusive lock acquired before syscall unlock fault");

            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::SimulateSyscallUnlockFailure);
            barrier.unlock_exclusive();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);

            check(barrier.is_poisoned(), "SEC-05 13.9: Barrier enters poisoned state upon syscall unlock failure");
            check(barrier.is_os_lock_acquired(), "SEC-05 13.9: os_lock_acquired remains true after syscall failure");
            check(barrier.last_unlock_error() != 0, "SEC-05 13.9: Raw OS error code captured during unlock failure");
            check(!barrier.poison_reason().empty(), "SEC-05 13.9: Diagnostic poison reason formatted from OS error");
            barrier.close_file();
        }

        // 13.10 Subsequent Shared Acquisition Rejected on Poisoned Barrier
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            barrier.lock_shared();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailUnlock);
            barrier.unlock_shared();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            check(barrier.is_poisoned(), "SEC-05 13.10: Barrier verified poisoned");

            bool threw = false;
            try {
                barrier.lock_shared();
            } catch (const mc::cas::InterprocessLockException& ex) {
                threw = true;
                check(ex.status() == mc::cas::BarrierLockStatus::OperatingSystemError,
                      "SEC-05 13.10: lock_shared throws InterprocessLockException with OperatingSystemError");
                check(std::string(ex.what()).find("poisoned") != std::string::npos,
                      "SEC-05 13.10: Exception message mentions poisoned barrier state");
            }
            check(threw, "SEC-05 13.10: lock_shared fails closed on poisoned barrier");

            const auto try_st = barrier.try_lock_shared(std::chrono::milliseconds(10));
            check(try_st == mc::cas::BarrierLockStatus::OperatingSystemError,
                  "SEC-05 13.10: try_lock_shared immediately returns OperatingSystemError on poisoned barrier");
            barrier.close_file();
        }

        // 13.11 Subsequent Exclusive Acquisition Rejected on Poisoned Barrier
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            barrier.lock_exclusive();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailUnlock);
            barrier.unlock_exclusive();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            check(barrier.is_poisoned(), "SEC-05 13.11: Barrier verified poisoned");

            bool threw = false;
            try {
                barrier.lock_exclusive();
            } catch (const mc::cas::InterprocessLockException& ex) {
                threw = true;
                check(ex.status() == mc::cas::BarrierLockStatus::OperatingSystemError,
                      "SEC-05 13.11: lock_exclusive throws InterprocessLockException with OperatingSystemError");
            }
            check(threw, "SEC-05 13.11: lock_exclusive fails closed on poisoned barrier");

            const auto try_st = barrier.try_lock_exclusive(std::chrono::milliseconds(10));
            check(try_st == mc::cas::BarrierLockStatus::OperatingSystemError,
                  "SEC-05 13.11: try_lock_exclusive immediately returns OperatingSystemError on poisoned barrier");
            barrier.close_file();
        }

        // 13.12 Concurrent Local Readers with Final Reader Unlock Failure
        {
            mc::cas::InterprocessCasBarrier barrier(lock_file);
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);

            std::atomic<bool> t1_acquired{false};
            std::atomic<bool> t1_release{false};
            std::atomic<bool> t1_done{false};

            std::thread t1([&]() {
                barrier.lock_shared();
                t1_acquired = true;
                while (!t1_release) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                barrier.unlock_shared();
                t1_done = true;
            });

            while (!t1_acquired) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }

            // Reader 2 (main thread) also acquires shared lock
            barrier.lock_shared();
            check(barrier.is_os_lock_acquired(), "SEC-05 13.12: Reader 2 joins Reader 1 under shared lock");

            // Reader 1 unlocks while fault point is None; reader count drops to 1, no OS unlock
            t1_release = true;
            t1.join();
            check(t1_done, "SEC-05 13.12: Reader 1 exited cleanly");
            check(!barrier.is_poisoned(), "SEC-05 13.12: Barrier not poisoned after non-final reader unlock");

            // Now inject unlock fault for the final reader (Reader 2)
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::SimulateSyscallUnlockFailure);
            barrier.unlock_shared();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);

            check(barrier.is_poisoned(), "SEC-05 13.12: Final reader unlock failure triggers barrier poisoning");
            check(barrier.is_os_lock_acquired(), "SEC-05 13.12: Kernel lock remains marked acquired");

            // Reader 3 on a separate thread attempts acquisition: must fail closed without deadlock
            std::atomic<bool> t3_rejected{false};
            std::thread t3([&]() {
                try {
                    barrier.lock_shared();
                } catch (const mc::cas::InterprocessLockException&) {
                    t3_rejected = true;
                }
            });
            t3.join();
            check(t3_rejected, "SEC-05 13.12: Subsequent reader thread fails closed without deadlocking");
            barrier.close_file();
        }

        // 13.13 Repeated Cleanup and Destructor Execution After Failure
        {
            {
                mc::cas::InterprocessCasBarrier barrier(lock_file);
                barrier.lock_shared();
                mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::FailUnlock);
                barrier.unlock_shared();
                mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);

                // Multiple explicit close_file() calls must be idempotent and noexcept
                barrier.close_file();
                barrier.close_file();
                check(!barrier.is_os_lock_acquired(), "SEC-05 13.13: close_file resets os_lock_acquired");
            } // Destructor runs after explicit close_file: must not throw or crash
            check(true, "SEC-05 13.13: Destructor executes cleanly on previously closed poisoned barrier");
        }

        // 13.14 Separate Barrier Contention After Failed Unlock & Release on Close
        {
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            auto barrier1 = std::make_unique<mc::cas::InterprocessCasBarrier>(lock_file);
            barrier1->lock_exclusive();

            // Simulate syscall failure on unlock: kernel lock NOT released
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::SimulateSyscallUnlockFailure);
            barrier1->unlock_exclusive();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);

            check(barrier1->is_poisoned(), "SEC-05 13.14: barrier1 is poisoned");
            check(barrier1->is_os_lock_acquired(), "SEC-05 13.14: barrier1 retains OS lock in kernel");

            // barrier2 attempts to acquire lock: OS kernel must deny it because barrier1 still holds lock
            mc::cas::InterprocessCasBarrier barrier2(lock_file);
            auto st2 = barrier2.try_lock_exclusive(std::chrono::milliseconds(50));
            check(st2 == mc::cas::BarrierLockStatus::Contended,
                  "SEC-05 13.14: barrier2 is blocked (Contended) by kernel lock retained by barrier1");

            // Destroy barrier1: CloseHandle / close(fd) causes OS kernel to release retained file locks
            barrier1.reset();

            // Now barrier2 can acquire exclusive lock
            st2 = barrier2.try_lock_exclusive(std::chrono::milliseconds(100));
            check(st2 == mc::cas::BarrierLockStatus::Acquired,
                  "SEC-05 13.14: barrier2 acquires exclusive lock after barrier1 is destroyed and handle closed");
            barrier2.unlock_exclusive();
        }

        // 13.15 POSIX / Windows Lock Diagnostic Formatting & Documentation
        {
            // Verify format_os_error_message diagnostics
            const std::string no_err = mc::cas::InterprocessCasBarrier::format_os_error_message(0);
            check(no_err == "no OS error recorded", "SEC-05 13.15: Zero error code produces correct diagnostic string");

            const std::string err_desc = mc::cas::InterprocessCasBarrier::format_os_error_message(5); // ERROR_ACCESS_DENIED on Win / EIO on POSIX
            check(!err_desc.empty() && err_desc != "no OS error recorded",
                  "SEC-05 13.15: Non-zero OS error code formats meaningful diagnostic description");
        }

        // 13.16 Same-File Kernel Lock Retention on Shared Unlock Failure
        {
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);
            auto barrierA = std::make_unique<mc::cas::InterprocessCasBarrier>(lock_file);

            // 1. Barrier A acquires a shared OS-level lock on the CAS barrier file
            barrierA->lock_shared();
            check(barrierA->is_os_lock_acquired(),
                  "SEC-05 13.16: Barrier A acquires shared OS-level lock on CAS barrier file");

            // 2. Barrier A experiences a simulated unlock failure
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::SimulateSyscallUnlockFailure);
            barrierA->unlock_shared();
            mc::cas::set_barrier_fault_point_for_testing(mc::cas::BarrierFaultPoint::None);

            // 3. Barrier A becomes poisoned
            check(barrierA->is_poisoned(),
                  "SEC-05 13.16: Barrier A becomes poisoned after shared unlock failure");

            // 4. os_lock_acquired_ remains true to reflect kernel lock retention
            check(barrierA->is_os_lock_acquired(),
                  "SEC-05 13.16: Barrier A os_lock_acquired remains true (kernel lock retained)");

            // 5. Barrier B uses a separate barrier instance on the SAME underlying lock file
            mc::cas::InterprocessCasBarrier barrierB(lock_file);

            // 6. Barrier B cannot acquire an exclusive OS lock while Barrier A's handle remains open
            auto stB = barrierB.try_lock_exclusive(std::chrono::milliseconds(50));
            check(stB == mc::cas::BarrierLockStatus::Contended,
                  "SEC-05 13.16: Barrier B cannot acquire exclusive OS lock while Barrier A retains kernel lock");

            // 7. Barrier A is destroyed and its OS handle is closed
            barrierA.reset();

            // 8. Barrier B can subsequently acquire the exclusive lock
            stB = barrierB.try_lock_exclusive(std::chrono::milliseconds(100));
            check(stB == mc::cas::BarrierLockStatus::Acquired,
                  "SEC-05 13.16: Barrier B subsequently acquires exclusive lock after Barrier A handle closure");
            barrierB.unlock_exclusive();
        }
    }

    // =========================================================================
    // SECTION 14: Source File Mutation During Chunking Pass (SEC-08)
    // =========================================================================
    {
        const fs::path sec8_dir = fixture_root / "sec8_mutation_suite";
        fs::create_directories(sec8_dir);
        const fs::path test_file = sec8_dir / "target.bin";

        // Create initial 64 KB file
        {
            std::ofstream out(test_file, std::ios::binary);
            std::string buf(64 * 1024, 'X');
            out.write(buf.data(), static_cast<std::streamsize>(buf.size()));
        }

        // 14.1 Normal chunking pass produces valid manifest
        {
            set_chunk_stream_mutation_hook(nullptr);
            mc::cas::FileManifest manifest;
            std::string err;
            check(chunk_file_for_peer(test_file.string(), manifest, err),
                  "SEC-08 14.1: Normal file chunking produces valid manifest");
            check(manifest.total_size() == 64 * 1024,
                  "SEC-08 14.1: Manifest total size matches unmutated file");
        }

        // 14.2 File mutation mid-stream is detected and rejected
        {
            set_chunk_stream_mutation_hook([&]() {
                // Mutate the file on disk during chunk streaming
                std::ofstream mutate_out(test_file, std::ios::binary | std::ios::app);
                mutate_out << "CONCURRENT_APPENDED_BYTES_MUTATION";
            });

            mc::cas::FileManifest manifest;
            std::string err;
            const bool ok = chunk_file_for_peer(test_file.string(), manifest, err);
            check(!ok, "SEC-08 14.2: Concurrent file append during chunking is detected and rejected");
            check(err.find("mutated") != std::string::npos || err.find("does not match") != std::string::npos,
                  "SEC-08 14.2: Explicit mutation error reported to caller");
            set_chunk_stream_mutation_hook(nullptr);
        }

        // 14.3 File truncation mid-stream is detected and rejected
        {
            set_chunk_stream_mutation_hook([&]() {
                // Truncate the file to 10 bytes mid-chunking
                std::ofstream trunc_out(test_file, std::ios::binary | std::ios::trunc);
                trunc_out << "truncated";
            });

            mc::cas::FileManifest manifest;
            std::string err;
            const bool ok = chunk_file_for_peer(test_file.string(), manifest, err);
            check(!ok, "SEC-08 14.3: Concurrent file truncation during chunking is detected and rejected");
            set_chunk_stream_mutation_hook(nullptr);
        }
    }
}

} // namespace mc::peer
