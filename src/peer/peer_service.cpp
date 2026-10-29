#include "merklechain/peer/peer_service.hpp"

#include "merklechain/hash.hpp"
#include "merklechain/peer/peer_transport.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/staging_file.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/versioning.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace mc::peer {
namespace {

constexpr std::size_t kChunkTransferSize = 64U * 1024U;

struct ApprovalPayload {
    std::string plan_hash;
    std::string expected_final_root;
    bool approved{false};
    bool deletion_confirmed{false};
    std::string session_id;
};

std::string encode_approval(const ApprovalPayload& payload) {
    std::string data;
    data.reserve(130U + payload.session_id.size());
    data.append(payload.plan_hash);
    while (data.size() < 64U) data.push_back(' ');
    data.append(payload.expected_final_root);
    while (data.size() < 128U) data.push_back(' ');
    data.push_back(payload.approved ? '\1' : '\0');
    data.push_back(payload.deletion_confirmed ? '\1' : '\0');
    data.append(payload.session_id);
    return data;
}

ApprovalPayload decode_approval(const std::string& data) {
    if (data.size() < 130U) throw std::runtime_error("truncated approval frame payload");
    ApprovalPayload payload;
    payload.plan_hash = data.substr(0, 64U);
    payload.expected_final_root = data.substr(64U, 64U);
    payload.approved = (data[128U] == '\1');
    payload.deletion_confirmed = (data[129U] == '\1');
    payload.session_id = data.substr(130U);
    return payload;
}

void stream_file_to_peer(PeerConnection& connection,
                         const fs::path& full_path,
                         const std::string& relative_path,
                         std::size_t& total_bytes) {
    std::ifstream file(full_path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot open file for peer transfer: " + relative_path);

    std::vector<char> buffer(kChunkTransferSize);
    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto read_count = static_cast<std::size_t>(file.gcount());
        if (read_count > 0) {
            connection.send_frame(Frame{kProtocolVersion, MessageType::FileData,
                                        std::string(buffer.data(), read_count)});
            total_bytes += read_count;
        }
    }
    const auto digest = sha256_file(full_path);
    connection.send_frame(Frame{kProtocolVersion, MessageType::FileEnd,
                                relative_path + "\n" + digest});
}

void receive_file_from_peer(PeerConnection& connection,
                            StagingFile& staging,
                            const std::string& expected_relative_path,
                            const std::string& expected_hash,
                            std::size_t& total_bytes) {
    while (true) {
        const auto frame = connection.receive_frame();
        if (frame.type == MessageType::Error) {
            throw std::runtime_error("peer reported error during transfer: " + frame.payload);
        }
        if (frame.type == MessageType::FileData) {
            staging.write(frame.payload.data(), frame.payload.size());
            total_bytes += frame.payload.size();
        } else if (frame.type == MessageType::FileEnd) {
            const auto split = frame.payload.find('\n');
            const std::string remote_path = (split != std::string::npos) ? frame.payload.substr(0, split) : "";
            const std::string remote_hash = (split != std::string::npos) ? frame.payload.substr(split + 1U) : frame.payload;
            if (!remote_path.empty() && remote_path != expected_relative_path) {
                throw std::runtime_error("peer sent FileEnd for unexpected path: " + remote_path);
            }
            if (!remote_hash.empty() && remote_hash != expected_hash) {
                throw std::runtime_error("peer digest in FileEnd does not match expected hash: " + remote_hash);
            }
            staging.flush();
            break;
        } else {
            throw std::runtime_error("unexpected frame type during file transfer: " +
                                     std::to_string(static_cast<int>(frame.type)));
        }
    }
}

} // namespace

PeerSyncReport PeerService::run_host(const PeerConfig& config,
                                     PeerApprovalCallback approval_cb,
                                     PeerProgressCallback progress_cb) {
    PeerSyncReport report;
    const std::string folder_pair_id = "default";
    const auto state_dir = config.sync_root / ".merklechain";
    fs::create_directories(state_dir);
    const auto db_path = (state_dir / "activity.sqlite3").string();
    const auto recovery_dir = state_dir / "recovery";

    PeerSessionJournal journal(db_path);
    PeerBaselineStore baseline_store(state_dir / "baselines.sqlite3");
    ActivityStore activity_store(db_path);
    VersionStore version_store(db_path, state_dir);

    PeerTransactionCoordinator coordinator(journal, config.sync_root, recovery_dir,
                                           &baseline_store, &version_store, &activity_store);

    try {
        std::cout << "[Host] Initializing TLS listener on " << config.bind_address << ":" << config.port << "...\n";
        if (progress_cb) progress_cb({"Listening", "Waiting for authenticated peer connection on port " + std::to_string(config.port), "", "", "", "", 0, 0});
        PeerTlsContext tls(config, Role::Host);
        PeerListener listener(config);

        std::cout << "[Host] Waiting for authenticated client connection...\n";
        PeerConnection connection = listener.accept_authenticated(tls);
        std::cout << "[Host] Client connected and verified via TLS certificate pin.\n";
        if (progress_cb) progress_cb({"Connected", "Client connected and TLS certificate pin verified", "", "", "", "", 0, 0});

        try {
            // Step 1: Handshake
        const auto hello_frame = connection.receive_frame();
        if (hello_frame.type != MessageType::Hello) {
            throw std::runtime_error("expected Hello frame from client");
        }
        const std::string client_identity = hello_frame.payload;
        if (client_identity.empty()) throw std::runtime_error("empty client identity");
        connection.send_frame(Frame{kProtocolVersion, MessageType::Hello, config.identity});

        // Step 2: Manifest Request
        const auto req_frame = connection.receive_frame();
        if (req_frame.type != MessageType::ManifestRequest) {
            throw std::runtime_error("expected ManifestRequest frame from client");
        }
        const std::string session_id = req_frame.payload.empty()
            ? journal.create(config.identity, client_identity)
            : req_frame.payload;
        report.session_id = session_id;

        // Ensure session exists locally
        try {
            (void)journal.load(session_id);
        } catch (...) {
            // If created on client, record local entry with same ID
            (void)journal.create(config.identity, client_identity, session_id);
        }
        journal.mark_authenticated(session_id, client_identity);
        if (progress_cb) progress_cb({"Handshake", "Authenticated client: " + client_identity, client_identity, session_id, "", "", 0, 0});

        std::cout << "[Host] Scanning local directory: " << config.sync_root.string() << "...\n";
        const auto host_manifest = scan_folder(config.sync_root);
        if (!host_manifest.complete) throw std::runtime_error("host directory scan is incomplete");

        // Send host manifest to client
        if (progress_cb) progress_cb({"ManifestExchange", "Exchanging manifests with client", client_identity, session_id, "", "", 0, 0});
        const auto encoded_host_manifest = encode_peer_manifest(host_manifest,
                                                                config.max_manifest_files,
                                                                config.max_file_size_bytes);
        connection.send_frame(Frame{kProtocolVersion, MessageType::Manifest, encoded_host_manifest});

        // Receive client manifest
        const auto client_manifest_frame = connection.receive_frame();
        if (client_manifest_frame.type != MessageType::Manifest) {
            throw std::runtime_error("expected Manifest frame from client");
        }
        const auto client_manifest = decode_peer_manifest(client_manifest_frame.payload,
                                                          config.max_manifest_files,
                                                          config.max_file_size_bytes);

        const auto baseline = baseline_store.load(client_identity, folder_pair_id);
        journal.record_manifests(session_id, host_manifest.merkle_root,
                                 client_manifest.merkle_root, baseline.merkle_root);

        // Host calculates both perspectives for symmetry and exact verification
        const auto host_plan = plan_bidirectional(client_identity, folder_pair_id, baseline,
                                                  host_manifest, client_manifest);
        PeerBaseline client_baseline = baseline;
        client_baseline.peer_id = config.identity;
        const auto client_perspective_plan = plan_bidirectional(config.identity, folder_pair_id, client_baseline,
                                                               client_manifest, host_manifest);
        if (progress_cb) progress_cb({"Planning", "Computed bilateral plan (" + std::to_string(client_perspective_plan.entries.size()) + " entries)", client_identity, session_id, client_perspective_plan.plan_hash, "", 0, 0});

        if (host_plan.has_unresolved_conflicts || client_perspective_plan.has_unresolved_conflicts) {
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "unresolved conflicts in peer plan"});
            report.cancelled = true;
            report.error = "peer plan contains unresolved conflicts";
            return report;
        }

        // Step 3: Receive Client's Proposed Plan Approval
        const auto client_approval_frame = connection.receive_frame();
        if (client_approval_frame.type == MessageType::Error) {
            report.cancelled = true;
            report.error = "client cancelled approval: " + client_approval_frame.payload;
            return report;
        }
        if (client_approval_frame.type != MessageType::Approval) {
            throw std::runtime_error("expected Approval frame from client");
        }
        const auto client_approval = decode_approval(client_approval_frame.payload);
        if (client_approval.plan_hash != client_perspective_plan.plan_hash) {
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "plan hash mismatch"});
            throw std::runtime_error("client plan hash does not match expected bidirectional plan");
        }
        if (!client_approval.approved ||
            (client_perspective_plan.requires_deletion_confirmation && !client_approval.deletion_confirmed)) {
            report.cancelled = true;
            report.error = "client declined plan approval";
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "client declined plan approval"});
            return report;
        }

        // Host authorization check
        bool host_approved = true;
        bool host_deletions_confirmed = true;
        if (host_plan.requires_approval || host_plan.requires_deletion_confirmation) {
            if (progress_cb) progress_cb({"AwaitingApproval", "Awaiting plan authorization", client_identity, session_id, client_perspective_plan.plan_hash, "", 0, 0});
            if (approval_cb) {
                const auto decision = approval_cb(host_plan);
                host_approved = decision.first;
                host_deletions_confirmed = decision.second;
            } else {
                host_approved = true;
                host_deletions_confirmed = true;
            }
        }

        if (!host_approved || (host_plan.requires_deletion_confirmation && !host_deletions_confirmed)) {
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "host declined plan approval"});
            report.cancelled = true;
            report.error = "host declined plan approval";
            return report;
        }

        // Both peers agree on plan
        journal.agree_plan(session_id, client_perspective_plan.plan_hash,
                           client_approval.plan_hash, client_approval.expected_final_root,
                           client_perspective_plan.requires_approval,
                           client_perspective_plan.requires_deletion_confirmation);
        journal.begin_approval(session_id);
        journal.record_approval(session_id, client_perspective_plan.plan_hash,
                                client_approval.approved && host_approved,
                                client_approval.deletion_confirmed && host_deletions_confirmed);

        // Send host approval back
        ApprovalPayload host_reply;
        host_reply.plan_hash = client_perspective_plan.plan_hash;
        host_reply.expected_final_root = client_approval.expected_final_root;
        host_reply.approved = host_approved;
        host_reply.deletion_confirmed = host_deletions_confirmed;
        host_reply.session_id = session_id;
        connection.send_frame(Frame{kProtocolVersion, MessageType::Approval, encode_approval(host_reply)});

        // Step 4: Plan and Prepare Operations
        coordinator.plan_operations(session_id, client_perspective_plan, /*as_remote_peer=*/true);

        // Host serves files requested by Client
        // Loop handling client requests until Client indicates prepare completion
        while (true) {
            const auto req = connection.receive_frame();
            if (req.type == MessageType::FileRequest) {
                if (!safe_relative_path(req.payload) ||
                    req.payload.rfind(".merklechain", 0) == 0 ||
                    req.payload.find("/.merklechain") != std::string::npos ||
                    req.payload.find("\\.merklechain") != std::string::npos) {
                    connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "invalid file request path"});
                    throw std::runtime_error("rejected unsafe file request path: " + req.payload);
                }
                bool authorized = false;
                for (const auto& entry : client_perspective_plan.entries) {
                    if (entry.relative_path == req.payload &&
                        (entry.action == PeerPlanAction::AddLocal || entry.action == PeerPlanAction::UpdateLocal)) {
                        authorized = true;
                        break;
                    }
                }
                if (!authorized) {
                    connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "unauthorized file request path"});
                    throw std::runtime_error("rejected unauthorized file request path: " + req.payload);
                }
                const auto target_file = config.sync_root / fs::u8path(req.payload);
                stream_file_to_peer(connection, target_file, req.payload, report.bytes_transferred);
                ++report.files_transferred;
                if (progress_cb) progress_cb({"Transferring", "Streaming " + req.payload + " to client", client_identity, session_id, client_perspective_plan.plan_hash, req.payload, report.files_transferred, report.bytes_transferred});
            } else if (req.type == MessageType::SyncResult && req.payload == "PREPARED") {
                journal.acknowledge_peer_prepared(session_id, client_identity, client_perspective_plan.plan_hash);
                break;
            } else if (req.type == MessageType::Error) {
                throw std::runtime_error("client aborted during preparation: " + req.payload);
            } else {
                throw std::runtime_error("unexpected frame during host file serving: " +
                                         std::to_string(static_cast<int>(req.type)));
            }
        }

        // Prepare local operations on Host (if Host needs files from Client)
        coordinator.prepare_operations(session_id, client_perspective_plan.plan_hash,
            [&](const PeerOperationRecord& op, StagingFile& staging) {
                connection.send_frame(Frame{kProtocolVersion, MessageType::FileRequest, op.relative_path});
                receive_file_from_peer(connection, staging, op.relative_path, op.expected_new_hash, report.bytes_transferred);
                ++report.files_transferred;
                if (progress_cb) progress_cb({"Transferring", "Staging " + op.relative_path + " from client", client_identity, session_id, client_perspective_plan.plan_hash, op.relative_path, report.files_transferred, report.bytes_transferred});
            });

        // Notify client host is prepared
        connection.send_frame(Frame{kProtocolVersion, MessageType::SyncResult, "PREPARED"});

        // Step 5: Commit Local Changes
        if (progress_cb) progress_cb({"Committing", "Committing verified local changes and baseline", client_identity, session_id, client_perspective_plan.plan_hash, "", report.files_transferred, report.bytes_transferred});
        const auto commit_res = coordinator.commit_local(session_id, client_perspective_plan.plan_hash);
        if (!commit_res.success) {
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "host commit failed: " + commit_res.error});
            throw std::runtime_error("host local commit failed: " + commit_res.error);
        }
        report.operations_executed = commit_res.operations_committed;
        report.final_merkle_root = commit_res.final_merkle_root;

        // Exchange commit results
        connection.send_frame(Frame{kProtocolVersion, MessageType::SyncResult, "COMMITTED:" + commit_res.final_merkle_root});
        const auto client_commit_frame = connection.receive_frame();
        if (client_commit_frame.type != MessageType::SyncResult ||
            client_commit_frame.payload.rfind("COMMITTED:", 0) != 0) {
            throw std::runtime_error("client commit verification failed or missing");
        }
        const std::string client_final_root = client_commit_frame.payload.substr(10);
        journal.acknowledge_peer_commit(session_id, client_identity, client_perspective_plan.plan_hash, client_final_root);

        // Step 6: Advance Baseline & Finalize
        const auto post_commit_manifest = scan_folder(config.sync_root);
        const bool finalized = coordinator.finalize_bilateral_commit(session_id, client_identity,
                                                                     folder_pair_id, post_commit_manifest);
        report.baseline_advanced = finalized;
        report.success = finalized;
        report.plan_hash = client_perspective_plan.plan_hash;

        std::cout << "[Host] Bilateral synchronization completed successfully. Final root: "
                  << post_commit_manifest.merkle_root << "\n";
        if (progress_cb) progress_cb({"Completed", "Bilateral synchronization completed and verified", client_identity, session_id, client_perspective_plan.plan_hash, "", report.files_transferred, report.bytes_transferred});
        } catch (const std::exception& e) {
            report.success = false;
            report.error = e.what();
            try {
                connection.send_frame(Frame{kProtocolVersion, MessageType::Error, e.what()});
            } catch (...) {}
        }
    } catch (const std::exception& e) {
        report.success = false;
        report.error = e.what();
    }

    return report;
}

PeerSyncReport PeerService::run_client(const PeerConfig& config,
                                       PeerApprovalCallback approval_cb,
                                       PeerProgressCallback progress_cb) {
    PeerSyncReport report;
    const std::string folder_pair_id = "default";
    const auto state_dir = config.sync_root / ".merklechain";
    fs::create_directories(state_dir);
    const auto db_path = (state_dir / "activity.sqlite3").string();
    const auto recovery_dir = state_dir / "recovery";

    PeerSessionJournal journal(db_path);
    PeerBaselineStore baseline_store(state_dir / "baselines.sqlite3");
    ActivityStore activity_store(db_path);
    VersionStore version_store(db_path, state_dir);

    PeerTransactionCoordinator coordinator(journal, config.sync_root, recovery_dir,
                                           &baseline_store, &version_store, &activity_store);

    try {
        std::cout << "[Client] Connecting to host " << config.host_address << ":" << config.port << " over TLS...\n";
        if (progress_cb) progress_cb({"Connecting", "Connecting to host " + config.host_address + ":" + std::to_string(config.port) + " over TLS...", "", "", "", "", 0, 0});
        PeerTlsContext tls(config, Role::Client);
        PeerConnection connection = PeerConnection::connect(config, tls);
        std::cout << "[Client] Connected and host authenticated via TLS certificate pin.\n";
        if (progress_cb) progress_cb({"Connected", "Connected to host and certificate pin verified", "", "", "", "", 0, 0});

        try {
            // Step 1: Handshake
        connection.send_frame(Frame{kProtocolVersion, MessageType::Hello, config.identity});
        const auto hello_frame = connection.receive_frame();
        if (hello_frame.type != MessageType::Hello) {
            throw std::runtime_error("expected Hello frame from host");
        }
        const std::string host_identity = hello_frame.payload;
        if (host_identity.empty()) throw std::runtime_error("empty host identity");

        const std::string session_id = journal.create(config.identity, host_identity);
        report.session_id = session_id;
        journal.mark_authenticated(session_id, host_identity);
        if (progress_cb) progress_cb({"Handshake", "Authenticated host: " + host_identity, host_identity, session_id, "", "", 0, 0});

        // Step 2: Manifest Exchange
        if (progress_cb) progress_cb({"ManifestExchange", "Exchanging manifests with host", host_identity, session_id, "", "", 0, 0});
        connection.send_frame(Frame{kProtocolVersion, MessageType::ManifestRequest, session_id});
        const auto host_manifest_frame = connection.receive_frame();
        if (host_manifest_frame.type != MessageType::Manifest) {
            throw std::runtime_error("expected Manifest frame from host");
        }
        const auto host_manifest = decode_peer_manifest(host_manifest_frame.payload,
                                                        config.max_manifest_files,
                                                        config.max_file_size_bytes);

        std::cout << "[Client] Scanning local directory: " << config.sync_root.string() << "...\n";
        const auto client_manifest = scan_folder(config.sync_root);
        if (!client_manifest.complete) throw std::runtime_error("client directory scan is incomplete");

        const auto encoded_client_manifest = encode_peer_manifest(client_manifest,
                                                                  config.max_manifest_files,
                                                                  config.max_file_size_bytes);
        connection.send_frame(Frame{kProtocolVersion, MessageType::Manifest, encoded_client_manifest});

        const auto baseline = baseline_store.load(host_identity, folder_pair_id);
        journal.record_manifests(session_id, client_manifest.merkle_root,
                                 host_manifest.merkle_root, baseline.merkle_root);

        // Step 3: Compute Bidirectional Plan
        const auto plan = plan_bidirectional(host_identity, folder_pair_id, baseline,
                                             client_manifest, host_manifest);
        if (!plan.valid) {
            throw std::runtime_error("failed to compute bidirectional plan: " + plan.error);
        }
        report.plan_hash = plan.plan_hash;
        if (progress_cb) progress_cb({"Planning", "Computed bilateral plan (" + std::to_string(plan.entries.size()) + " entries)", host_identity, session_id, plan.plan_hash, "", 0, 0});

        if (plan.has_unresolved_conflicts) {
            std::cerr << "\n[!] Sync plan contains unresolved conflicts. Synchronization cannot proceed automatically.\n";
            for (const auto& entry : plan.entries) {
                if (entry.action == PeerPlanAction::Conflict) {
                    std::cerr << "  CONFLICT: " << entry.relative_path << "\n";
                }
            }
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "unresolved conflicts"});
            report.cancelled = true;
            report.error = "sync plan contains unresolved conflicts";
            return report;
        }

        // Display proposed plan
        std::cout << "\nProposed Peer Synchronization Plan (Local <-> Host):\n";
        std::size_t local_mutations = 0;
        std::size_t remote_mutations = 0;
        for (const auto& entry : plan.entries) {
            if (entry.action == PeerPlanAction::AddLocal) {
                std::cout << "  [+ Add Local]    " << entry.relative_path << " (from Host)\n";
                ++local_mutations;
            } else if (entry.action == PeerPlanAction::UpdateLocal) {
                std::cout << "  [~ Update Local] " << entry.relative_path << " (from Host)\n";
                ++local_mutations;
            } else if (entry.action == PeerPlanAction::DeleteLocal) {
                std::cout << "  [- Delete Local] " << entry.relative_path << " (recovery copy saved)\n";
                ++local_mutations;
            } else if (entry.action == PeerPlanAction::AddRemote) {
                std::cout << "  [+ Add Host]     " << entry.relative_path << " (upload to Host)\n";
                ++remote_mutations;
            } else if (entry.action == PeerPlanAction::UpdateRemote) {
                std::cout << "  [~ Update Host]  " << entry.relative_path << " (upload to Host)\n";
                ++remote_mutations;
            } else if (entry.action == PeerPlanAction::DeleteRemote) {
                std::cout << "  [- Delete Host]  " << entry.relative_path << " (Host deletes)\n";
                ++remote_mutations;
            }
        }

        if (local_mutations == 0 && remote_mutations == 0) {
            std::cout << "Both peers are completely up to date. No changes needed.\n";
        }

        bool approved = true;
        bool deletions_confirmed = true;
        if (progress_cb) progress_cb({"AwaitingApproval", "Awaiting plan authorization", host_identity, session_id, plan.plan_hash, "", 0, 0});
        if (approval_cb) {
            const auto decision = approval_cb(plan);
            approved = decision.first;
            deletions_confirmed = decision.second;
        } else if (plan.requires_approval || plan.requires_deletion_confirmation) {
            if (plan.requires_approval) {
                std::cout << "\nApprove planned peer changes? Type YES: ";
                std::string conf;
                std::getline(std::cin, conf);
                approved = (conf == "YES");
            }
            if (approved && plan.requires_deletion_confirmation) {
                std::cout << "DELETE operations remove paths after saving recovery copies. Type YES to confirm deletion: ";
                std::string conf;
                std::getline(std::cin, conf);
                deletions_confirmed = (conf == "YES");
            }
        }

        if (!approved || (plan.requires_deletion_confirmation && !deletions_confirmed)) {
            std::cout << "Synchronization cancelled by user.\n";
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "client cancelled approval"});
            report.cancelled = true;
            report.error = "cancelled by user";
            return report;
        }

        // Calculate expected final Merkle root
        // From plan entries, simulate final manifest
        std::vector<FileMetadata> expected_files;
        for (const auto& f : client_manifest.files) {
            const auto it = std::find_if(plan.entries.begin(), plan.entries.end(), [&](const auto& e) {
                return e.relative_path == f.relative_path;
            });
            if (it == plan.entries.end() || (it->action != PeerPlanAction::DeleteLocal && it->action != PeerPlanAction::UpdateLocal)) {
                expected_files.push_back(f);
            }
        }
        for (const auto& entry : plan.entries) {
            if (entry.action == PeerPlanAction::AddLocal || entry.action == PeerPlanAction::UpdateLocal) {
                if (entry.remote) expected_files.push_back(*entry.remote);
            }
        }
        std::sort(expected_files.begin(), expected_files.end(), [](const auto& a, const auto& b) {
            return a.relative_path < b.relative_path;
        });
        const std::string expected_final_root = merkle_root(expected_files);

        // Send Approval Proposal to Host
        ApprovalPayload proposal;
        proposal.plan_hash = plan.plan_hash;
        proposal.expected_final_root = expected_final_root;
        proposal.approved = approved;
        proposal.deletion_confirmed = deletions_confirmed;
        proposal.session_id = session_id;
        connection.send_frame(Frame{kProtocolVersion, MessageType::Approval, encode_approval(proposal)});

        // Receive Host's Approval
        const auto host_reply_frame = connection.receive_frame();
        if (host_reply_frame.type == MessageType::Error) {
            report.cancelled = true;
            report.error = "host rejected plan proposal: " + host_reply_frame.payload;
            return report;
        }
        if (host_reply_frame.type != MessageType::Approval) {
            throw std::runtime_error("expected Approval response from host");
        }
        const auto host_reply = decode_approval(host_reply_frame.payload);
        if (host_reply.plan_hash != plan.plan_hash || !host_reply.approved) {
            report.cancelled = true;
            report.error = "host declined plan authorization";
            return report;
        }

        journal.agree_plan(session_id, plan.plan_hash, host_reply.plan_hash,
                           expected_final_root, plan.requires_approval,
                           plan.requires_deletion_confirmation);
        journal.begin_approval(session_id);
        journal.record_approval(session_id, plan.plan_hash, approved, deletions_confirmed);

        // Step 4: Plan Operations & Prepare
        coordinator.plan_operations(session_id, plan);

        // Request needed files from Host into StagingFile
        coordinator.prepare_operations(session_id, plan.plan_hash,
            [&](const PeerOperationRecord& op, StagingFile& staging) {
                connection.send_frame(Frame{kProtocolVersion, MessageType::FileRequest, op.relative_path});
                receive_file_from_peer(connection, staging, op.relative_path, op.expected_new_hash, report.bytes_transferred);
                ++report.files_transferred;
                if (progress_cb) progress_cb({"Transferring", "Staging " + op.relative_path + " from host", host_identity, session_id, plan.plan_hash, op.relative_path, report.files_transferred, report.bytes_transferred});
            });

        // Notify host that client is prepared
        connection.send_frame(Frame{kProtocolVersion, MessageType::SyncResult, "PREPARED"});

        // Serve files that host requests from client
        while (true) {
            const auto req = connection.receive_frame();
            if (req.type == MessageType::FileRequest) {
                if (!safe_relative_path(req.payload) ||
                    req.payload.rfind(".merklechain", 0) == 0 ||
                    req.payload.find("/.merklechain") != std::string::npos ||
                    req.payload.find("\\.merklechain") != std::string::npos) {
                    connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "invalid file request path"});
                    throw std::runtime_error("rejected unsafe file request path: " + req.payload);
                }
                bool authorized = false;
                for (const auto& entry : plan.entries) {
                    if (entry.relative_path == req.payload &&
                        (entry.action == PeerPlanAction::AddRemote || entry.action == PeerPlanAction::UpdateRemote)) {
                        authorized = true;
                        break;
                    }
                }
                if (!authorized) {
                    connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "unauthorized file request path"});
                    throw std::runtime_error("rejected unauthorized file request path: " + req.payload);
                }
                const auto target_file = config.sync_root / fs::u8path(req.payload);
                stream_file_to_peer(connection, target_file, req.payload, report.bytes_transferred);
                ++report.files_transferred;
                if (progress_cb) progress_cb({"Transferring", "Streaming " + req.payload + " to host", host_identity, session_id, plan.plan_hash, req.payload, report.files_transferred, report.bytes_transferred});
            } else if (req.type == MessageType::SyncResult && req.payload == "PREPARED") {
                journal.acknowledge_peer_prepared(session_id, host_identity, plan.plan_hash);
                break;
            } else if (req.type == MessageType::Error) {
                throw std::runtime_error("host aborted during preparation: " + req.payload);
            } else {
                throw std::runtime_error("unexpected frame during client file serving: " +
                                         std::to_string(static_cast<int>(req.type)));
            }
        }

        // Step 5: Commit Local Changes
        if (progress_cb) progress_cb({"Committing", "Committing verified local changes and baseline", host_identity, session_id, plan.plan_hash, "", report.files_transferred, report.bytes_transferred});
        const auto commit_res = coordinator.commit_local(session_id, plan.plan_hash);
        if (!commit_res.success) {
            connection.send_frame(Frame{kProtocolVersion, MessageType::Error, "client commit failed: " + commit_res.error});
            throw std::runtime_error("client local commit failed: " + commit_res.error);
        }
        report.operations_executed = commit_res.operations_committed;
        report.final_merkle_root = commit_res.final_merkle_root;

        // Exchange commit results
        connection.send_frame(Frame{kProtocolVersion, MessageType::SyncResult, "COMMITTED:" + commit_res.final_merkle_root});
        const auto host_commit_frame = connection.receive_frame();
        if (host_commit_frame.type != MessageType::SyncResult ||
            host_commit_frame.payload.rfind("COMMITTED:", 0) != 0) {
            throw std::runtime_error("host commit verification failed or missing");
        }
        const std::string host_final_root = host_commit_frame.payload.substr(10);
        journal.acknowledge_peer_commit(session_id, host_identity, plan.plan_hash, host_final_root);

        // Step 6: Advance Baseline & Finalize
        const auto post_commit_manifest = scan_folder(config.sync_root);
        const bool finalized = coordinator.finalize_bilateral_commit(session_id, host_identity,
                                                                     folder_pair_id, post_commit_manifest);
        report.baseline_advanced = finalized;
        report.success = finalized;

        std::cout << "[Client] Bilateral synchronization completed successfully. Final root: "
                  << post_commit_manifest.merkle_root << "\n";
        if (progress_cb) progress_cb({"Completed", "Bilateral synchronization completed and verified", host_identity, session_id, plan.plan_hash, "", report.files_transferred, report.bytes_transferred});
        } catch (const std::exception& e) {
            report.success = false;
            report.error = e.what();
            try {
                connection.send_frame(Frame{kProtocolVersion, MessageType::Error, e.what()});
            } catch (...) {}
        }
    } catch (const std::exception& e) {
        report.success = false;
        report.error = e.what();
    }

    return report;
}

} // namespace mc::peer
