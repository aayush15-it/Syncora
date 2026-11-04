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

        // 1.5 FrameDecoder with All New Message Types (10, 11, 12, 13)
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
        check(!valid_message_type(14), "Stage 1: MessageType 14 is invalid");
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
}

} // namespace mc::peer
