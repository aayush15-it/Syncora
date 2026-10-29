#include "merklechain/peer/peer_controller.hpp"

#include "merklechain/hash.hpp"
#include "merklechain/peer/peer_session.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <sstream>

namespace mc::peer {

namespace {

std::int64_t current_time_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string compute_certificate_fingerprint(const fs::path& cert_path) {
    std::error_code ec;
    if (!fs::is_regular_file(cert_path, ec) || ec) return {};
#if defined(_WIN32)
    FILE* fp = _wfopen(cert_path.c_str(), L"rb");
#else
    FILE* fp = fopen(cert_path.u8string().c_str(), "rb");
#endif
    if (!fp) return {};
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!cert) return {};
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    const int res = X509_digest(cert, EVP_sha256(), md, &md_len);
    X509_free(cert);
    if (!res || md_len != 32U) return {};
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (unsigned int i = 0; i < md_len; ++i) {
        out.push_back(hex[md[i] >> 4U]);
        out.push_back(hex[md[i] & 0x0fU]);
    }
    return out;
}

bool valid_identifier(const std::string& value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_';
           });
}

bool valid_ipv4_address(const std::string& address) {
    std::size_t start = 0;
    for (int part = 0; part < 4; ++part) {
        const auto end = (part == 3) ? address.size() : address.find('.', start);
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

bool valid_hex_fingerprint(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

std::string quote_json(const std::string& s) {
    std::ostringstream out;
    out << '"';
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20U) out << "\\u00" << hex[c >> 4U] << hex[c & 0x0fU];
                else out << static_cast<char>(c);
        }
    }
    out << '"';
    return out.str();
}

} // namespace

const char* peer_operational_state_name(PeerOperationalState state) noexcept {
    switch (state) {
        case PeerOperationalState::Idle: return "IDLE";
        case PeerOperationalState::Configured: return "CONFIGURED";
        case PeerOperationalState::Starting: return "STARTING";
        case PeerOperationalState::Listening: return "LISTENING";
        case PeerOperationalState::Connecting: return "CONNECTING";
        case PeerOperationalState::Handshake: return "HANDSHAKE";
        case PeerOperationalState::ManifestExchange: return "MANIFEST_EXCHANGE";
        case PeerOperationalState::Planning: return "PLANNING";
        case PeerOperationalState::AwaitingApproval: return "AWAITING_APPROVAL";
        case PeerOperationalState::Transferring: return "TRANSFERRING";
        case PeerOperationalState::Committing: return "COMMITTING";
        case PeerOperationalState::Completed: return "COMPLETED";
        case PeerOperationalState::Cancelled: return "CANCELLED";
        case PeerOperationalState::Failed: return "FAILED";
    }
    return "UNKNOWN";
}

PeerController& PeerController::instance() {
    static PeerController s_instance;
    return s_instance;
}

PeerController::PeerController() = default;

PeerController::~PeerController() {
    stop();
    if (worker_thread_ && worker_thread_->joinable()) {
        worker_thread_->join();
    }
}

PeerConfigValidationResult PeerController::validate_config(const PeerConfig& config) {
    PeerConfigValidationResult result;
    if (!valid_identifier(config.identity)) {
        result.error = "identity must be 1-128 alphanumeric characters, hyphens, or underscores";
        return result;
    }
    std::error_code ec;
    const auto root_status = fs::symlink_status(config.sync_root, ec);
    if (ec || fs::is_symlink(root_status) || !fs::is_directory(root_status)) {
        result.error = "sync_root must be an existing accessible directory, not a symbolic link";
        return result;
    }
    if (config.port == 0) {
        result.error = "port must be between 1 and 65535";
        return result;
    }
    if (config.role == Role::Host) {
        if (!valid_ipv4_address(config.bind_address)) {
            result.error = "host bind_address must be a valid numeric IPv4 address (e.g. 0.0.0.0)";
            return result;
        }
    } else {
        if (!valid_ipv4_address(config.host_address)) {
            result.error = "client host_address must be a valid numeric IPv4 address";
            return result;
        }
    }
    auto validate_cert_file = [&](const fs::path& path, const char* name) -> bool {
        std::error_code fec;
        const auto status = fs::symlink_status(path, fec);
        if (fec || fs::is_symlink(status) || !fs::is_regular_file(status)) {
            result.error = std::string(name) + " must be an existing regular file, not a symlink";
            return false;
        }
        return true;
    };
    if (!validate_cert_file(config.certificate_file, "certificate_file")) return result;
    if (!validate_cert_file(config.private_key_file, "private_key_file")) return result;
    if (!validate_cert_file(config.ca_file, "ca_file")) return result;

    if (!valid_hex_fingerprint(config.expected_peer_sha256)) {
        result.error = "expected_peer_sha256 must be a 64-character hex SHA-256 fingerprint";
        return result;
    }
    const auto cert_fp = compute_certificate_fingerprint(config.certificate_file);
    if (cert_fp.empty()) {
        result.error = "cannot parse certificate_file as PEM X.509 certificate";
        return result;
    }
    result.local_cert_sha256 = cert_fp;
    result.valid = true;
    return result;
}

bool PeerController::configure(const PeerConfig& config, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == PeerOperationalState::Listening ||
        state_ == PeerOperationalState::Connecting ||
        state_ == PeerOperationalState::Transferring ||
        state_ == PeerOperationalState::Committing) {
        error = "cannot reconfigure while a peer operation is actively running";
        return false;
    }
    const auto val = validate_config(config);
    if (!val.valid) {
        error = val.error;
        return false;
    }
    config_ = config;
    std::transform(config_->expected_peer_sha256.begin(), config_->expected_peer_sha256.end(),
                   config_->expected_peer_sha256.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    state_ = PeerOperationalState::Configured;
    phase_ = "Configured";
    detail_ = config_->role == Role::Host ? "Ready to start Host listener" : "Ready to connect as Client";
    return true;
}

std::optional<PeerConfig> PeerController::active_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

bool PeerController::start(std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!config_) {
        error = "peer configuration has not been set";
        return false;
    }
    if (worker_thread_ && worker_thread_->joinable()) {
        if (state_ == PeerOperationalState::Listening ||
            state_ == PeerOperationalState::Connecting ||
            state_ == PeerOperationalState::Transferring ||
            state_ == PeerOperationalState::Committing ||
            state_ == PeerOperationalState::AwaitingApproval) {
            error = "peer operation is already in progress";
            return false;
        }
        worker_thread_->join();
    }
    stop_requested_ = false;
    approval_decision_made_ = false;
    user_approved_ = false;
    user_confirm_deletions_ = false;
    pending_plan_.reset();
    session_id_.clear();
    plan_hash_.clear();
    current_file_.clear();
    files_transferred_ = 0;
    bytes_transferred_ = 0;
    final_merkle_root_.clear();
    last_error_.clear();
    pin_verified_ = false;

    state_ = PeerOperationalState::Starting;
    phase_ = "Starting";
    detail_ = config_->role == Role::Host ? "Launching Host listener" : "Initiating Client connection";

    worker_thread_ = std::make_unique<std::thread>(&PeerController::run_worker, this);
    return true;
}

void PeerController::stop() {
    stop_requested_ = true;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        approval_decision_made_ = true;
        user_approved_ = false;
        user_confirm_deletions_ = false;
        if (state_ == PeerOperationalState::Listening ||
            state_ == PeerOperationalState::Connecting ||
            state_ == PeerOperationalState::Starting ||
            state_ == PeerOperationalState::AwaitingApproval) {
            state_ = PeerOperationalState::Cancelled;
            phase_ = "Stopped";
            detail_ = "Peer operation stopped by user";
        }
    }
    approval_cv_.notify_all();
}

void PeerController::update_progress(const PeerProgressEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    phase_ = event.phase;
    detail_ = event.detail;
    if (!event.peer_identity.empty()) peer_identity_ = event.peer_identity;
    if (!event.session_id.empty()) session_id_ = event.session_id;
    if (!event.plan_hash.empty()) plan_hash_ = event.plan_hash;
    if (!event.current_file.empty()) current_file_ = event.current_file;
    if (event.files_transferred > 0) files_transferred_ = event.files_transferred;
    if (event.bytes_transferred > 0) bytes_transferred_ = event.bytes_transferred;

    if (event.phase == "Connected") {
        pin_verified_ = true;
    } else if (event.phase == "ManifestExchange") {
        state_ = PeerOperationalState::ManifestExchange;
    } else if (event.phase == "Planning") {
        state_ = PeerOperationalState::Planning;
    } else if (event.phase == "AwaitingApproval") {
        state_ = PeerOperationalState::AwaitingApproval;
    } else if (event.phase == "Transferring") {
        state_ = PeerOperationalState::Transferring;
    } else if (event.phase == "Committing") {
        state_ = PeerOperationalState::Committing;
    }
}

std::pair<bool, bool> PeerController::approval_callback(const PeerSyncPlan& plan) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (plan.has_unresolved_conflicts) {
        state_ = PeerOperationalState::Failed;
        last_error_ = "cannot plan operations with unresolved conflicts";
        return {false, false};
    }
    pending_plan_ = plan;
    plan_hash_ = plan.plan_hash;
    state_ = PeerOperationalState::AwaitingApproval;
    phase_ = "AwaitingApproval";
    detail_ = "Waiting for user authorization";
    approval_decision_made_ = false;
    user_approved_ = false;
    user_confirm_deletions_ = false;

    // Wait up to 10 minutes for user decision via dashboard API
    const auto timeout = std::chrono::minutes(10);
    const bool decided = approval_cv_.wait_for(lock, timeout, [&]() {
        return approval_decision_made_ || stop_requested_.load();
    });

    if (!decided || stop_requested_.load() || !user_approved_) {
        state_ = PeerOperationalState::Cancelled;
        phase_ = "Cancelled";
        detail_ = "Plan approval declined or cancelled";
        return {false, false};
    }

    state_ = PeerOperationalState::Transferring;
    phase_ = "Transferring";
    detail_ = "Starting file transfers";
    return {user_approved_, user_confirm_deletions_};
}

void PeerController::run_worker() {
    PeerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!config_) return;
        cfg = *config_;
        state_ = cfg.role == Role::Host ? PeerOperationalState::Listening : PeerOperationalState::Connecting;
    }

    auto approval_fn = [this](const PeerSyncPlan& plan) {
        return this->approval_callback(plan);
    };
    auto progress_fn = [this](const PeerProgressEvent& ev) {
        this->update_progress(ev);
    };

    PeerSyncReport report;
    try {
        if (cfg.role == Role::Host) {
            report = PeerService::run_host(cfg, approval_fn, progress_fn);
        } else {
            report = PeerService::run_client(cfg, approval_fn, progress_fn);
        }
    } catch (const std::exception& e) {
        report.success = false;
        report.error = e.what();
    }

    std::lock_guard<std::mutex> lock(mutex_);
    pending_plan_.reset();
    last_sync_time_ms_ = current_time_ms();
    last_sync_success_ = report.success;
    final_merkle_root_ = report.final_merkle_root;
    files_transferred_ = report.files_transferred;
    bytes_transferred_ = report.bytes_transferred;

    if (report.success) {
        state_ = PeerOperationalState::Completed;
        phase_ = "Completed";
        detail_ = "Synchronization completed and baseline verified";
    } else if (report.cancelled) {
        state_ = PeerOperationalState::Cancelled;
        phase_ = "Cancelled";
        detail_ = report.error.empty() ? "Operation was cancelled" : report.error;
    } else {
        state_ = PeerOperationalState::Failed;
        phase_ = "Failed";
        last_error_ = report.error;
        detail_ = "Error: " + report.error;
    }
}

PeerControllerStatus PeerController::get_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    PeerControllerStatus s;
    if (config_) {
        s.role = config_->role == Role::Host ? "host" : "client";
        s.identity = config_->identity;
        s.port = config_->port;
        s.address = config_->role == Role::Host ? config_->bind_address : config_->host_address;
        s.sync_root = config_->sync_root.u8string();
        s.expected_peer_sha256 = config_->expected_peer_sha256;
        s.local_cert_sha256 = compute_certificate_fingerprint(config_->certificate_file);
    }
    s.state = state_;
    s.state_name = peer_operational_state_name(state_);
    s.running = (state_ == PeerOperationalState::Listening ||
                 state_ == PeerOperationalState::Connecting ||
                 state_ == PeerOperationalState::Handshake ||
                 state_ == PeerOperationalState::ManifestExchange ||
                 state_ == PeerOperationalState::Planning ||
                 state_ == PeerOperationalState::AwaitingApproval ||
                 state_ == PeerOperationalState::Transferring ||
                 state_ == PeerOperationalState::Committing);
    s.peer_identity = peer_identity_;
    s.pin_verified = pin_verified_;
    s.session_id = session_id_;
    s.plan_hash = plan_hash_;
    s.phase = phase_;
    s.detail = detail_;
    s.current_file = current_file_;
    s.files_transferred = files_transferred_;
    s.bytes_transferred = bytes_transferred_;
    s.final_merkle_root = final_merkle_root_;
    s.last_error = last_error_;
    s.last_sync_time_ms = last_sync_time_ms_;
    s.last_sync_success = last_sync_success_;
    return s;
}

std::optional<PeerSyncPlan> PeerController::get_pending_plan() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_plan_;
}

bool PeerController::submit_approval(const std::string& session_id,
                                     const std::string& plan_hash,
                                     bool approve,
                                     bool confirm_deletions,
                                     std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != PeerOperationalState::AwaitingApproval || !pending_plan_) {
        error = "no pending plan awaiting approval";
        return false;
    }
    if (!plan_hash_.empty() && plan_hash != plan_hash_) {
        error = "submitted plan hash does not match active proposed plan";
        return false;
    }
    if (!session_id_.empty() && !session_id.empty() && session_id != session_id_) {
        error = "submitted session ID does not match active session";
        return false;
    }
    if (pending_plan_->has_unresolved_conflicts) {
        error = "cannot approve plan with unresolved conflicts";
        return false;
    }
    if (approve && pending_plan_->requires_deletion_confirmation && !confirm_deletions) {
        error = "destructive deletions require separate explicit confirmation";
        return false;
    }
    user_approved_ = approve;
    user_confirm_deletions_ = confirm_deletions;
    approval_decision_made_ = true;
    approval_cv_.notify_all();
    return true;
}

std::string PeerController::get_history_json(std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!config_) return "{\"sessions\":[],\"operations\":[]}";
    const auto db_path = config_->sync_root / ".merklechain" / "activity.sqlite3";
    std::error_code ec;
    if (!fs::is_regular_file(db_path, ec) || ec) {
        return "{\"sessions\":[],\"operations\":[]}";
    }

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(db_path.u8string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return "{\"sessions\":[],\"operations\":[]}";
    }
    struct Guard { sqlite3* d; ~Guard() { if (d) sqlite3_close(d); } } g{db};

    std::ostringstream json;
    json << "{\"sessions\":[";

    const std::string sess_sql =
        "SELECT session_id, local_peer, remote_peer, state, local_manifest_root, "
        "remote_manifest_root, baseline_root, plan_hash, expected_final_root, "
        "recovery_diagnostic, created_at_ms, updated_at_ms "
        "FROM peer_sessions ORDER BY created_at_ms DESC LIMIT " + std::to_string(limit);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sess_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json << ',';
            first = false;
            auto col_text = [&](int col) {
                const auto* p = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
                return p ? std::string(p) : std::string{};
            };
            json << "{\"session_id\":" << quote_json(col_text(0))
                 << ",\"local_peer\":" << quote_json(col_text(1))
                 << ",\"remote_peer\":" << quote_json(col_text(2))
                 << ",\"state\":" << sqlite3_column_int(stmt, 3)
                 << ",\"state_name\":" << quote_json(peer_session_state_name(static_cast<PeerSessionState>(sqlite3_column_int(stmt, 3))))
                 << ",\"local_manifest_root\":" << quote_json(col_text(4))
                 << ",\"remote_manifest_root\":" << quote_json(col_text(5))
                 << ",\"baseline_root\":" << quote_json(col_text(6))
                 << ",\"plan_hash\":" << quote_json(col_text(7))
                 << ",\"expected_final_root\":" << quote_json(col_text(8))
                 << ",\"recovery_diagnostic\":" << quote_json(col_text(9))
                 << ",\"created_at_ms\":" << sqlite3_column_int64(stmt, 10)
                 << ",\"updated_at_ms\":" << sqlite3_column_int64(stmt, 11)
                 << "}";
        }
        sqlite3_finalize(stmt);
    }
    json << "],\"operations\":[";

    const std::string op_sql =
        "SELECT transaction_id, operation_id, session_id, plan_hash, relative_path, "
        "action, prior_content_hash, expected_new_hash, state, error, created_at_ms "
        "FROM peer_operations ORDER BY created_at_ms DESC LIMIT " + std::to_string(limit);

    if (sqlite3_prepare_v2(db, op_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json << ',';
            first = false;
            auto col_text = [&](int col) {
                const auto* p = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
                return p ? std::string(p) : std::string{};
            };
            json << "{\"transaction_id\":" << quote_json(col_text(0))
                 << ",\"operation_id\":" << quote_json(col_text(1))
                 << ",\"session_id\":" << quote_json(col_text(2))
                 << ",\"plan_hash\":" << quote_json(col_text(3))
                 << ",\"relative_path\":" << quote_json(col_text(4))
                 << ",\"action\":" << sqlite3_column_int(stmt, 5)
                 << ",\"prior_content_hash\":" << quote_json(col_text(6))
                 << ",\"expected_new_hash\":" << quote_json(col_text(7))
                 << ",\"state\":" << quote_json(peer_operation_state_name(static_cast<PeerOperationState>(sqlite3_column_int(stmt, 8))))
                 << ",\"error\":" << quote_json(col_text(9))
                 << ",\"created_at_ms\":" << sqlite3_column_int64(stmt, 10)
                 << "}";
        }
        sqlite3_finalize(stmt);
    }
    json << "]}";
    return json.str();
}

std::string PeerController::get_diagnostics_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!config_) {
        return "{\"status\":\"ok\",\"configured\":false,\"unfinished_sessions\":[],\"unfinished_sessions_count\":0,\"recovery_required\":false,\"recovery_advice\":\"No peer configuration active.\"}";
    }
    const auto db_path = config_->sync_root / ".merklechain" / "activity.sqlite3";
    std::error_code ec;
    if (!fs::is_regular_file(db_path, ec) || ec) {
        return "{\"status\":\"ok\",\"configured\":true,\"unfinished_sessions\":[],\"unfinished_sessions_count\":0,\"recovery_required\":false,\"recovery_advice\":\"Ledger database clean or not yet created.\"}";
    }

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(db_path.u8string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return "{\"status\":\"ok\",\"configured\":true,\"unfinished_sessions\":[],\"unfinished_sessions_count\":0,\"recovery_required\":false,\"recovery_advice\":\"Ledger accessible.\"}";
    }
    struct Guard { sqlite3* d; ~Guard() { if (d) sqlite3_close(d); } } g{db};

    // Find sessions in RecoveryRequired or non-final states
    const char* sql =
        "SELECT session_id, local_peer, remote_peer, state, plan_hash, recovery_diagnostic, created_at_ms "
        "FROM peer_sessions WHERE state IN (4, 5, 6, 8, 9) ORDER BY created_at_ms DESC";

    sqlite3_stmt* stmt = nullptr;
    std::ostringstream json;
    json << "{\"status\":\"ok\",\"configured\":true";
    bool recovery_needed = false;
    std::size_t unfinished_count = 0;
    std::ostringstream rows;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) rows << ',';
            first = false;
            ++unfinished_count;
            const int st = sqlite3_column_int(stmt, 3);
            if (st == static_cast<int>(PeerSessionState::RecoveryRequired)) {
                recovery_needed = true;
            }
            auto col_text = [&](int col) {
                const auto* p = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
                return p ? std::string(p) : std::string{};
            };
            rows << "{\"session_id\":" << quote_json(col_text(0))
                 << ",\"local_peer\":" << quote_json(col_text(1))
                 << ",\"remote_peer\":" << quote_json(col_text(2))
                 << ",\"state\":" << st
                 << ",\"state_name\":" << quote_json(peer_session_state_name(static_cast<PeerSessionState>(st)))
                 << ",\"plan_hash\":" << quote_json(col_text(4))
                 << ",\"recovery_diagnostic\":" << quote_json(col_text(5))
                 << ",\"created_at_ms\":" << sqlite3_column_int64(stmt, 6)
                 << "}";
        }
        sqlite3_finalize(stmt);
    }
    json << ",\"unfinished_sessions\":[" << rows.str() << "]"
         << ",\"unfinished_sessions_count\":" << unfinished_count
         << ",\"recovery_required\":" << (recovery_needed ? "true" : "false")
         << ",\"recovery_advice\":" << quote_json(recovery_needed ? "Crash recovery required. Run with CLI --peer-sync to perform atomic rollback." : (unfinished_count > 0 ? "Unfinished transactions present." : "No unfinished sessions detected. System clean."))
         << "}";
    return json.str();
}

} // namespace mc::peer
