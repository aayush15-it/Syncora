#pragma once

#include "merklechain/peer/peer_auth.hpp"
#include "merklechain/peer/peer_config.hpp"
#include "merklechain/peer/peer_protocol.hpp"
#include "merklechain/peer/peer_session.hpp"
#include "merklechain/peer/peer_sync.hpp"
#include "merklechain/types.hpp"

#include <functional>
#include <string>
#include <utility>

namespace mc::peer {

struct PeerSyncReport {
    bool success{false};
    std::string session_id;
    std::string error;
    std::string plan_hash;
    std::string final_merkle_root;
    std::size_t operations_executed{0};
    std::size_t files_transferred{0};
    std::size_t bytes_transferred{0};
    bool baseline_advanced{false};
    bool cancelled{false};
};

using PeerApprovalCallback = std::function<std::pair<bool, bool>(const PeerSyncPlan& plan)>;

struct PeerProgressEvent {
    std::string phase;
    std::string detail;
    std::string peer_identity;
    std::string session_id;
    std::string plan_hash;
    std::string current_file;
    std::size_t files_transferred{0};
    std::size_t bytes_transferred{0};
};

using PeerProgressCallback = std::function<void(const PeerProgressEvent& event)>;

// Dedicated peer session coordinator and wire protocol handler.
// Connects authenticated TLS transport, bounded protocol, manifest codec,
// bidirectional planner, interactive/non-interactive approval flow,
// staging file verification, and durable transaction coordination.
// Kept strictly separate from src/web_server.cpp.
class PeerService {
public:
    // Host daemon / listener workflow.
    // Listens on configured bind_address:port.
    // Authenticates incoming client using mTLS and configured peer certificate pin.
    // Exchanges manifests, validates bilateral plan agreement.
    // Does NOT mutate files upon simple connection.
    // Serves files or stages incoming content only under verified transactions.
    static PeerSyncReport run_host(const PeerConfig& config,
                                   PeerApprovalCallback approval_cb = nullptr,
                                   PeerProgressCallback progress_cb = nullptr);

    // Client sync workflow.
    // Connects to configured host_address:port over TLS.
    // Authenticates host using certificate pin.
    // Exchanges manifests, computes bidirectional plan, displays proposed plan,
    // prompts for explicit approvals (YES), transfers data into staging,
    // verifies hashes, executes verified commit, and advances baseline.
    static PeerSyncReport run_client(const PeerConfig& config,
                                     PeerApprovalCallback approval_cb = nullptr,
                                     PeerProgressCallback progress_cb = nullptr);
};

} // namespace mc::peer
