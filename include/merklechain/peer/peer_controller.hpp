#pragma once

#include "merklechain/peer/peer_config.hpp"
#include "merklechain/peer/peer_service.hpp"
#include "merklechain/peer/peer_sync.hpp"
#include "merklechain/types.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace mc::peer {

enum class PeerOperationalState {
    Idle = 0,
    Configured,
    Starting,
    Listening,
    Connecting,
    Handshake,
    ManifestExchange,
    Planning,
    AwaitingApproval,
    Transferring,
    Committing,
    Completed,
    Cancelled,
    Failed
};

const char* peer_operational_state_name(PeerOperationalState state) noexcept;

struct PeerControllerStatus {
    std::string role{"none"}; // "host", "client", "none"
    PeerOperationalState state{PeerOperationalState::Idle};
    std::string state_name{"IDLE"};
    bool running{false};
    std::string identity;
    std::string peer_identity;
    std::string address;
    std::uint16_t port{0};
    std::string sync_root;
    std::string expected_peer_sha256;
    std::string local_cert_sha256;
    bool pin_verified{false};
    std::string session_id;
    std::string plan_hash;
    std::string phase{"Idle"};
    std::string detail;
    std::string current_file;
    std::size_t files_transferred{0};
    std::size_t bytes_transferred{0};
    std::string final_merkle_root;
    std::string last_error;
    std::int64_t last_sync_time_ms{0};
    bool last_sync_success{false};
};

struct PeerConfigValidationResult {
    bool valid{false};
    std::string error;
    std::string local_cert_sha256;
};

// Thread-safe controller bridging loopback HTTP API and C++ peer engine.
// Isolates peer networking from loopback HTTP listener.
// Never exposes private key material or accepts shell execution.
class PeerController {
public:
    static PeerController& instance();

    PeerController();
    ~PeerController();
    PeerController(const PeerController&) = delete;
    PeerController& operator=(const PeerController&) = delete;

    // Configuration validation & activation
    PeerConfigValidationResult validate_config(const PeerConfig& config);
    bool configure(const PeerConfig& config, std::string& error);
    std::optional<PeerConfig> active_config() const;

    // Daemon lifecycle
    bool start(std::string& error);
    void stop();

    // Telemetry & state
    PeerControllerStatus get_status() const;
    std::optional<PeerSyncPlan> get_pending_plan() const;

    // Interactive approval flow
    bool submit_approval(const std::string& session_id,
                         const std::string& plan_hash,
                         bool approve,
                         bool confirm_deletions,
                         std::string& error);

    // Durable SQLite diagnostics
    std::string get_history_json(std::size_t limit = 50) const;
    std::string get_diagnostics_json() const;

private:
    void run_worker();
    void update_progress(const PeerProgressEvent& event);
    std::pair<bool, bool> approval_callback(const PeerSyncPlan& plan);

    mutable std::mutex mutex_;
    std::condition_variable approval_cv_;
    std::unique_ptr<std::thread> worker_thread_;
    std::atomic<bool> stop_requested_{false};

    std::optional<PeerConfig> config_;
    PeerOperationalState state_{PeerOperationalState::Idle};
    std::string phase_{"Idle"};
    std::string detail_{"Unconfigured"};
    std::string peer_identity_;
    std::string session_id_;
    std::string plan_hash_;
    std::string current_file_;
    std::size_t files_transferred_{0};
    std::size_t bytes_transferred_{0};
    std::string final_merkle_root_;
    std::string last_error_;
    std::int64_t last_sync_time_ms_{0};
    bool last_sync_success_{false};
    bool pin_verified_{false};

    // Approval coordination
    std::optional<PeerSyncPlan> pending_plan_;
    bool approval_decision_made_{false};
    bool user_approved_{false};
    bool user_confirm_deletions_{false};
};

} // namespace mc::peer
