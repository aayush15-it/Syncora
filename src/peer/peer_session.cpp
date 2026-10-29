#include "merklechain/peer/peer_session.hpp"

#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/staging_file.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/versioning.hpp"

#include <openssl/rand.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <system_error>

namespace mc::peer {
namespace {
std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void execute(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : sqlite3_errmsg(db);
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void require_sql(sqlite3* db, int result, const char* action) {
    if (result != SQLITE_OK && result != SQLITE_ROW && result != SQLITE_DONE)
        throw std::runtime_error(std::string(action) + ": " + sqlite3_errmsg(db));
}

bool has_column(sqlite3* db, const char* name) {
    sqlite3_stmt* statement = nullptr;
    require_sql(db, sqlite3_prepare_v2(db, "PRAGMA table_info(peer_sessions)", -1,
                                      &statement, nullptr), "inspect peer session schema");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* column = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
        if (column && std::string(column) == name) return true;
    }
    return false;
}

void bind_text(sqlite3* db, sqlite3_stmt* statement, int index, const std::string& value) {
    require_sql(db, sqlite3_bind_text(statement, index, value.data(),
                static_cast<int>(value.size()), SQLITE_TRANSIENT), "bind peer session text");
}

std::string column_text(sqlite3_stmt* statement, int column) {
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    const int length = sqlite3_column_bytes(statement, column);
    if (!value || length < 0) throw std::runtime_error("peer session database contains NULL text");
    return std::string(value, static_cast<std::size_t>(length));
}

bool valid_identity(const std::string& value) {
    if (value.empty() || value.size() > 128U) return false;
    for (const unsigned char c : value) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    return true;
}

bool valid_hash(const std::string& value, bool allow_empty = false) {
    if (allow_empty && value.empty()) return true;
    if (value.size() != 64U) return false;
    for (const unsigned char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

PeerSessionState parse_state(std::int64_t value) {
    if (value < static_cast<std::int64_t>(PeerSessionState::Created) ||
        value > static_cast<std::int64_t>(PeerSessionState::RecoveryRequired))
        throw std::runtime_error("peer session database contains an unknown state");
    return static_cast<PeerSessionState>(value);
}

PeerSessionRecord read_record(sqlite3* db, const std::string& session_id) {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "SELECT session_id,local_peer,remote_peer,state,local_manifest_root,remote_manifest_root,baseline_root,plan_hash,expected_final_root,recovery_diagnostic,plan_requires_approval,plan_requires_deletion_confirmation,approval_recorded,approved,deletion_confirmed,local_prepared,peer_prepared,local_commit_verified,peer_commit_verified,local_rollback_verified,peer_abort_acknowledged,recovery_material_retained,created_at_ms,updated_at_ms FROM peer_sessions WHERE session_id=?";
    require_sql(db, sqlite3_prepare_v2(db, sql, -1, &statement, nullptr), "prepare peer session lookup");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    bind_text(db, statement, 1, session_id);
    const int result = sqlite3_step(statement);
    if (result == SQLITE_DONE) throw std::runtime_error("peer session does not exist");
    require_sql(db, result, "read peer session");
    PeerSessionRecord value;
    value.session_id = column_text(statement, 0);
    value.local_peer = column_text(statement, 1);
    value.remote_peer = column_text(statement, 2);
    value.state = parse_state(sqlite3_column_int64(statement, 3));
    value.local_manifest_root = column_text(statement, 4);
    value.remote_manifest_root = column_text(statement, 5);
    value.baseline_root = column_text(statement, 6);
    value.plan_hash = column_text(statement, 7);
    value.expected_final_root = column_text(statement, 8);
    value.recovery_diagnostic = column_text(statement, 9);
    value.plan_requires_approval = sqlite3_column_int(statement, 10) != 0;
    value.plan_requires_deletion_confirmation = sqlite3_column_int(statement, 11) != 0;
    value.approval_recorded = sqlite3_column_int(statement, 12) != 0;
    value.approved = sqlite3_column_int(statement, 13) != 0;
    value.deletion_confirmed = sqlite3_column_int(statement, 14) != 0;
    value.local_prepared = sqlite3_column_int(statement, 15) != 0;
    value.peer_prepared = sqlite3_column_int(statement, 16) != 0;
    value.local_commit_verified = sqlite3_column_int(statement, 17) != 0;
    value.peer_commit_verified = sqlite3_column_int(statement, 18) != 0;
    value.local_rollback_verified = sqlite3_column_int(statement, 19) != 0;
    value.peer_abort_acknowledged = sqlite3_column_int(statement, 20) != 0;
    value.recovery_material_retained = sqlite3_column_int(statement, 21) != 0;
    value.created_at_ms = sqlite3_column_int64(statement, 22);
    value.updated_at_ms = sqlite3_column_int64(statement, 23);
    return value;
}

bool terminal(PeerSessionState state) {
    return state == PeerSessionState::Committed || state == PeerSessionState::Aborted;
}

void require_plan_binding(const PeerSessionRecord& record, const std::string& hash) {
    if (record.plan_hash.empty() || hash != record.plan_hash)
        throw std::runtime_error("peer session message has a stale or mismatched plan hash");
}

template<class Mutator>
void update_record(sqlite3* db, const std::string& session_id, Mutator mutator) {
    execute(db, "BEGIN IMMEDIATE;");
    try {
        auto value = read_record(db, session_id);
        mutator(value);
        value.updated_at_ms = now_ms();
        sqlite3_stmt* statement = nullptr;
        const char* sql = "UPDATE peer_sessions SET state=?,local_manifest_root=?,remote_manifest_root=?,baseline_root=?,plan_hash=?,expected_final_root=?,recovery_diagnostic=?,plan_requires_approval=?,plan_requires_deletion_confirmation=?,approval_recorded=?,approved=?,deletion_confirmed=?,local_prepared=?,peer_prepared=?,local_commit_verified=?,peer_commit_verified=?,local_rollback_verified=?,peer_abort_acknowledged=?,recovery_material_retained=?,updated_at_ms=? WHERE session_id=?";
        require_sql(db, sqlite3_prepare_v2(db, sql, -1, &statement, nullptr), "prepare peer session update");
        struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
        sqlite3_bind_int(statement, 1, static_cast<int>(value.state));
        bind_text(db, statement, 2, value.local_manifest_root);
        bind_text(db, statement, 3, value.remote_manifest_root);
        bind_text(db, statement, 4, value.baseline_root);
        bind_text(db, statement, 5, value.plan_hash);
        bind_text(db, statement, 6, value.expected_final_root);
        bind_text(db, statement, 7, value.recovery_diagnostic);
        sqlite3_bind_int(statement, 8, value.plan_requires_approval ? 1 : 0);
        sqlite3_bind_int(statement, 9, value.plan_requires_deletion_confirmation ? 1 : 0);
        sqlite3_bind_int(statement, 10, value.approval_recorded ? 1 : 0);
        sqlite3_bind_int(statement, 11, value.approved ? 1 : 0);
        sqlite3_bind_int(statement, 12, value.deletion_confirmed ? 1 : 0);
        sqlite3_bind_int(statement, 13, value.local_prepared ? 1 : 0);
        sqlite3_bind_int(statement, 14, value.peer_prepared ? 1 : 0);
        sqlite3_bind_int(statement, 15, value.local_commit_verified ? 1 : 0);
        sqlite3_bind_int(statement, 16, value.peer_commit_verified ? 1 : 0);
        sqlite3_bind_int(statement, 17, value.local_rollback_verified ? 1 : 0);
        sqlite3_bind_int(statement, 18, value.peer_abort_acknowledged ? 1 : 0);
        sqlite3_bind_int(statement, 19, value.recovery_material_retained ? 1 : 0);
        sqlite3_bind_int64(statement, 20, value.updated_at_ms);
        bind_text(db, statement, 21, session_id);
        require_sql(db, sqlite3_step(statement), "persist peer session transition");
        if (sqlite3_changes(db) != 1) throw std::runtime_error("peer session update affected an unexpected row count");
        execute(db, "COMMIT;");
    } catch (...) {
        try { execute(db, "ROLLBACK;"); } catch (...) {}
        throw;
    }
}
} // namespace

struct PeerSessionJournal::Impl { sqlite3* db{}; };

PeerSessionJournal::PeerSessionJournal(const std::string& database_path) : impl_(new Impl) {
    try {
        const std::filesystem::path file = std::filesystem::u8path(database_path);
        const auto reject_link = [](const std::filesystem::path& path) {
            std::error_code error;
            const auto status = std::filesystem::symlink_status(path, error);
            if (error == std::errc::no_such_file_or_directory) return;
            if (error) throw std::runtime_error("cannot inspect peer journal path: " + error.message());
            if (std::filesystem::is_symlink(status))
                throw std::runtime_error("peer journal path cannot be a symbolic link");
        };
        if (!file.parent_path().empty()) {
            reject_link(file.parent_path());
            std::filesystem::create_directories(file.parent_path());
            reject_link(file.parent_path());
        }
        reject_link(file);
        if (sqlite3_open_v2(file.string().c_str(), &impl_->db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK)
            throw std::runtime_error(std::string("cannot open peer session journal: ") +
                                     (impl_->db ? sqlite3_errmsg(impl_->db) : "SQLite allocation failure"));
        sqlite3_busy_timeout(impl_->db, 5000);
        execute(impl_->db, "PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS peer_sessions("
            "session_id TEXT PRIMARY KEY,local_peer TEXT NOT NULL,remote_peer TEXT NOT NULL,state INTEGER NOT NULL,"
            "local_manifest_root TEXT NOT NULL DEFAULT '',remote_manifest_root TEXT NOT NULL DEFAULT '',"
            "baseline_root TEXT NOT NULL DEFAULT '',plan_hash TEXT NOT NULL DEFAULT '',expected_final_root TEXT NOT NULL DEFAULT '',"
            "recovery_diagnostic TEXT NOT NULL DEFAULT '',plan_requires_approval INTEGER NOT NULL DEFAULT 0,"
            "plan_requires_deletion_confirmation INTEGER NOT NULL DEFAULT 0,approval_recorded INTEGER NOT NULL DEFAULT 0,approved INTEGER NOT NULL DEFAULT 0,"
            "deletion_confirmed INTEGER NOT NULL DEFAULT 0,local_prepared INTEGER NOT NULL DEFAULT 0,peer_prepared INTEGER NOT NULL DEFAULT 0,"
            "local_commit_verified INTEGER NOT NULL DEFAULT 0,peer_commit_verified INTEGER NOT NULL DEFAULT 0,"
            "local_rollback_verified INTEGER NOT NULL DEFAULT 0,peer_abort_acknowledged INTEGER NOT NULL DEFAULT 0,"
            "recovery_material_retained INTEGER NOT NULL DEFAULT 1,created_at_ms INTEGER NOT NULL,updated_at_ms INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS peer_session_operations("
            "transaction_id TEXT NOT NULL,operation_id TEXT NOT NULL PRIMARY KEY,session_id TEXT NOT NULL,"
            "plan_hash TEXT NOT NULL,relative_path TEXT NOT NULL,action INTEGER NOT NULL,"
            "prior_content_hash TEXT NOT NULL DEFAULT '',expected_new_hash TEXT NOT NULL DEFAULT '',"
            "staging_artifact TEXT NOT NULL DEFAULT '',recovery_artifact TEXT NOT NULL DEFAULT '',"
            "state INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',"
            "created_at_ms INTEGER NOT NULL,updated_at_ms INTEGER NOT NULL,"
            "FOREIGN KEY(session_id) REFERENCES peer_sessions(session_id) ON DELETE CASCADE);");
        if (!has_column(impl_->db, "approval_recorded"))
            execute(impl_->db, "ALTER TABLE peer_sessions ADD COLUMN approval_recorded INTEGER NOT NULL DEFAULT 0;");
    } catch (...) {
        if (impl_->db) sqlite3_close(impl_->db);
        impl_.reset();
        throw;
    }
}

PeerSessionJournal::~PeerSessionJournal() {
    if (impl_ && impl_->db) sqlite3_close(impl_->db);
}

std::string PeerSessionJournal::create(const std::string& local_peer, const std::string& remote_peer,
                                       const std::string& existing_session_id) {
    if (!valid_identity(local_peer) || !valid_identity(remote_peer) || local_peer == remote_peer)
        throw std::runtime_error("peer session requires distinct valid peer identities");
    std::string id;
    if (!existing_session_id.empty()) {
        if (!valid_identity(existing_session_id))
            throw std::runtime_error("invalid peer session identity");
        id = existing_session_id;
    } else {
        std::array<unsigned char, 16> random{};
        if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
            throw std::runtime_error("cryptographic random session ID generation failed");
        static constexpr char hex[] = "0123456789abcdef";
        id.reserve(32U);
        for (const auto byte : random) { id.push_back(hex[byte >> 4U]); id.push_back(hex[byte & 0x0fU]); }
    }
    const auto timestamp = now_ms();
    sqlite3_stmt* statement = nullptr;
    const char* sql = "INSERT INTO peer_sessions(session_id,local_peer,remote_peer,state,created_at_ms,updated_at_ms) VALUES(?,?,?,0,?,?)";
    require_sql(impl_->db, sqlite3_prepare_v2(impl_->db, sql, -1, &statement, nullptr), "prepare new peer session");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    bind_text(impl_->db, statement, 1, id);
    bind_text(impl_->db, statement, 2, local_peer);
    bind_text(impl_->db, statement, 3, remote_peer);
    sqlite3_bind_int64(statement, 4, timestamp);
    sqlite3_bind_int64(statement, 5, timestamp);
    require_sql(impl_->db, sqlite3_step(statement), "create peer session");
    return id;
}

PeerSessionRecord PeerSessionJournal::load(const std::string& session_id) const {
    return read_record(impl_->db, session_id);
}

void PeerSessionJournal::mark_authenticated(const std::string& id, const std::string& peer) {
    update_record(impl_->db, id, [&](auto& value) {
        if (peer != value.remote_peer) throw std::runtime_error("authenticated peer identity does not match the session");
        if (value.state != PeerSessionState::Created) return;
        value.state = PeerSessionState::Authenticated;
    });
}

void PeerSessionJournal::record_manifests(const std::string& id, const std::string& local,
                                           const std::string& remote, const std::string& baseline) {
    if (!valid_hash(local) || !valid_hash(remote) || !valid_hash(baseline, true))
        throw std::runtime_error("peer session manifest or baseline root is malformed");
    update_record(impl_->db, id, [&](auto& value) {
        if (value.state != PeerSessionState::Authenticated) {
            if (value.state >= PeerSessionState::ManifestsValidated &&
                value.local_manifest_root == local && value.remote_manifest_root == remote && value.baseline_root == baseline)
                return;
            throw std::runtime_error("manifests are out of order or contradict the recorded roots");
        }
        value.local_manifest_root = local;
        value.remote_manifest_root = remote;
        value.baseline_root = baseline;
        value.state = PeerSessionState::ManifestsValidated;
    });
}

void PeerSessionJournal::agree_plan(const std::string& id, const std::string& local_hash,
                                    const std::string& remote_hash, const std::string& final_root,
                                    bool approval_required, bool deletion_required) {
    if (!valid_hash(local_hash) || !valid_hash(final_root))
        throw std::runtime_error("peer plan or final Merkle root is malformed");
    update_record(impl_->db, id, [&](auto& value) {
        if (local_hash != remote_hash) throw std::runtime_error("peers computed different plan hashes");
        if (value.state != PeerSessionState::ManifestsValidated) {
            if (value.state >= PeerSessionState::PlanAgreed && value.plan_hash == local_hash &&
                value.expected_final_root == final_root && value.plan_requires_approval == approval_required &&
                value.plan_requires_deletion_confirmation == deletion_required) return;
            throw std::runtime_error("plan agreement is out of order or contradictory");
        }
        value.plan_hash = local_hash;
        value.expected_final_root = final_root;
        value.plan_requires_approval = approval_required;
        value.plan_requires_deletion_confirmation = deletion_required;
        value.state = PeerSessionState::PlanAgreed;
    });
}

void PeerSessionJournal::begin_approval(const std::string& id) {
    update_record(impl_->db, id, [](auto& value) {
        if (value.state == PeerSessionState::ApprovalPending) return;
        if (value.state != PeerSessionState::PlanAgreed) throw std::runtime_error("approval cannot begin before plan agreement");
        value.state = PeerSessionState::ApprovalPending;
    });
}

void PeerSessionJournal::record_approval(const std::string& id, const std::string& hash,
                                          bool approved, bool deletion_confirmed) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (value.approval_recorded) {
            if (value.approved == approved && value.deletion_confirmed == deletion_confirmed) return;
            throw std::runtime_error("peer session approval is contradictory");
        }
        if (value.state != PeerSessionState::ApprovalPending)
            throw std::runtime_error("approval is out of order");
        if (approved && value.plan_requires_deletion_confirmation && !deletion_confirmed)
            throw std::runtime_error("deletion plan requires separate explicit confirmation");
        if (deletion_confirmed && !approved)
            throw std::runtime_error("deletion confirmation cannot be recorded without change approval");
        value.approval_recorded = true;
        value.approved = approved;
        value.deletion_confirmed = deletion_confirmed;
        if (!approved) value.state = PeerSessionState::Aborted;
    });
}

void PeerSessionJournal::mark_local_prepared(const std::string& id, const std::string& hash) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (value.local_prepared) return;
        if ((value.state != PeerSessionState::ApprovalPending && value.state != PeerSessionState::RecoveryRequired) ||
            !value.approved ||
            (value.plan_requires_deletion_confirmation && !value.deletion_confirmed))
            throw std::runtime_error("local preparation requires the bound approval and deletion confirmation");
        value.local_prepared = true;
        if (value.peer_prepared) { value.state = PeerSessionState::Prepared; value.recovery_diagnostic.clear(); }
    });
}

void PeerSessionJournal::acknowledge_peer_prepared(const std::string& id, const std::string& peer,
                                                    const std::string& hash) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (peer != value.remote_peer) throw std::runtime_error("prepare acknowledgment peer identity mismatch");
        if (value.peer_prepared) return;
        if ((value.state != PeerSessionState::ApprovalPending && value.state != PeerSessionState::RecoveryRequired) ||
            !value.approved ||
            (value.plan_requires_deletion_confirmation && !value.deletion_confirmed))
            throw std::runtime_error("peer prepare acknowledgment is out of order");
        value.peer_prepared = true;
        if (value.local_prepared) { value.state = PeerSessionState::Prepared; value.recovery_diagnostic.clear(); }
    });
}

void PeerSessionJournal::begin_commit(const std::string& id, const std::string& hash) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (value.state == PeerSessionState::CommitPending) return;
        if ((value.state != PeerSessionState::Prepared && value.state != PeerSessionState::RecoveryRequired) ||
            !value.local_prepared || !value.peer_prepared || value.local_commit_verified || value.peer_commit_verified)
            throw std::runtime_error("commit requires durable preparation acknowledgments from both peers");
        value.state = PeerSessionState::CommitPending;
    });
}

void PeerSessionJournal::mark_local_commit_verified(const std::string& id, const std::string& hash,
                                                     const std::string& root) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (root != value.expected_final_root) throw std::runtime_error("local committed Merkle root does not match the agreed result");
        if (value.local_commit_verified) return;
        if (value.state != PeerSessionState::CommitPending && value.state != PeerSessionState::RecoveryRequired)
            throw std::runtime_error("local commit acknowledgment is out of order");
        if (!value.local_prepared || !value.peer_prepared) throw std::runtime_error("local commit lacks bilateral preparation");
        value.local_commit_verified = true;
        if (value.peer_commit_verified) { value.state = PeerSessionState::Committed; value.recovery_diagnostic.clear(); }
    });
}

void PeerSessionJournal::acknowledge_peer_commit(const std::string& id, const std::string& peer,
                                                  const std::string& hash, const std::string& root) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (peer != value.remote_peer) throw std::runtime_error("commit acknowledgment peer identity mismatch");
        if (root != value.expected_final_root) throw std::runtime_error("peer committed Merkle root does not match the agreed result");
        if (value.peer_commit_verified) return;
        if (value.state != PeerSessionState::CommitPending && value.state != PeerSessionState::RecoveryRequired)
            throw std::runtime_error("peer commit acknowledgment is out of order");
        if (!value.local_prepared) throw std::runtime_error("peer commit arrived before local durable preparation");
        // A matching authenticated commit acknowledgment proves that the
        // remote side reached its prepared state even if its earlier prepare
        // acknowledgment was lost in transit.
        value.peer_prepared = true;
        value.peer_commit_verified = true;
        if (value.local_commit_verified) { value.state = PeerSessionState::Committed; value.recovery_diagnostic.clear(); }
    });
}

void PeerSessionJournal::mark_recovery_required(const std::string& id, const std::string& diagnostic) {
    if (diagnostic.empty() || diagnostic.size() > 4096U)
        throw std::runtime_error("peer recovery diagnostic must contain 1-4096 bytes");
    update_record(impl_->db, id, [&](auto& value) {
        if (terminal(value.state)) throw std::runtime_error("terminal peer session cannot enter recovery-required state");
        value.state = PeerSessionState::RecoveryRequired;
        value.recovery_diagnostic = diagnostic;
        value.recovery_material_retained = true;
    });
}

void PeerSessionJournal::mark_local_rollback_verified(const std::string& id, const std::string& hash) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (value.local_commit_verified || value.peer_commit_verified)
            throw std::runtime_error("cannot abort after either peer has committed");
        if (value.local_rollback_verified) return;
        if (value.state != PeerSessionState::RecoveryRequired && value.state != PeerSessionState::ApprovalPending &&
            value.state != PeerSessionState::Prepared && value.state != PeerSessionState::CommitPending)
            throw std::runtime_error("local rollback acknowledgment is out of order");
        value.local_rollback_verified = true;
        if (value.peer_abort_acknowledged) value.state = PeerSessionState::Aborted;
    });
}

void PeerSessionJournal::acknowledge_peer_abort(const std::string& id, const std::string& peer,
                                                 const std::string& hash) {
    update_record(impl_->db, id, [&](auto& value) {
        require_plan_binding(value, hash);
        if (peer != value.remote_peer) throw std::runtime_error("abort acknowledgment peer identity mismatch");
        if (value.local_commit_verified || value.peer_commit_verified)
            throw std::runtime_error("abort acknowledgment contradicts a verified commit");
        if (value.peer_abort_acknowledged) return;
        if (value.state != PeerSessionState::RecoveryRequired && value.state != PeerSessionState::ApprovalPending &&
            value.state != PeerSessionState::Prepared && value.state != PeerSessionState::CommitPending)
            throw std::runtime_error("peer abort acknowledgment is out of order");
        value.peer_abort_acknowledged = true;
        if (value.local_rollback_verified) value.state = PeerSessionState::Aborted;
    });
}

void PeerSessionJournal::release_recovery_material(const std::string& id) {
    update_record(impl_->db, id, [](auto& value) {
        if (!terminal(value.state)) throw std::runtime_error("recovery material must remain until a safe terminal state");
        value.recovery_material_retained = false;
    });
}

std::vector<PeerSessionRecord> PeerSessionJournal::list_unfinished_sessions() const {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "SELECT session_id,local_peer,remote_peer,state,local_manifest_root,remote_manifest_root,baseline_root,plan_hash,expected_final_root,recovery_diagnostic,plan_requires_approval,plan_requires_deletion_confirmation,approval_recorded,approved,deletion_confirmed,local_prepared,peer_prepared,local_commit_verified,peer_commit_verified,local_rollback_verified,peer_abort_acknowledged,recovery_material_retained,created_at_ms,updated_at_ms FROM peer_sessions WHERE state NOT IN (7, 8) OR recovery_material_retained=1 ORDER BY created_at_ms ASC;";
    require_sql(impl_->db, sqlite3_prepare_v2(impl_->db, sql, -1, &statement, nullptr), "prepare list unfinished sessions");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    std::vector<PeerSessionRecord> records;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        PeerSessionRecord value;
        value.session_id = column_text(statement, 0);
        value.local_peer = column_text(statement, 1);
        value.remote_peer = column_text(statement, 2);
        value.state = parse_state(sqlite3_column_int64(statement, 3));
        value.local_manifest_root = column_text(statement, 4);
        value.remote_manifest_root = column_text(statement, 5);
        value.baseline_root = column_text(statement, 6);
        value.plan_hash = column_text(statement, 7);
        value.expected_final_root = column_text(statement, 8);
        value.recovery_diagnostic = column_text(statement, 9);
        value.plan_requires_approval = sqlite3_column_int(statement, 10) != 0;
        value.plan_requires_deletion_confirmation = sqlite3_column_int(statement, 11) != 0;
        value.approval_recorded = sqlite3_column_int(statement, 12) != 0;
        value.approved = sqlite3_column_int(statement, 13) != 0;
        value.deletion_confirmed = sqlite3_column_int(statement, 14) != 0;
        value.local_prepared = sqlite3_column_int(statement, 15) != 0;
        value.peer_prepared = sqlite3_column_int(statement, 16) != 0;
        value.local_commit_verified = sqlite3_column_int(statement, 17) != 0;
        value.peer_commit_verified = sqlite3_column_int(statement, 18) != 0;
        value.local_rollback_verified = sqlite3_column_int(statement, 19) != 0;
        value.peer_abort_acknowledged = sqlite3_column_int(statement, 20) != 0;
        value.recovery_material_retained = sqlite3_column_int(statement, 21) != 0;
        value.created_at_ms = sqlite3_column_int64(statement, 22);
        value.updated_at_ms = sqlite3_column_int64(statement, 23);
        records.push_back(std::move(value));
    }
    return records;
}

PeerRecoveryAction evaluate_peer_recovery(const PeerSessionRecord& local,
                                         const PeerSessionObservation& remote) {
    if (remote.session_id != local.session_id || remote.peer_id != local.remote_peer)
        return PeerRecoveryAction::ManualRecovery;
    if (!remote.plan_hash.empty() && remote.plan_hash != local.plan_hash)
        return PeerRecoveryAction::ManualRecovery;
    if ((remote.state == PeerObservedState::Prepared || remote.state == PeerObservedState::CommitPending ||
         remote.state == PeerObservedState::Committed || remote.state == PeerObservedState::Aborted) &&
        remote.plan_hash != local.plan_hash)
        return PeerRecoveryAction::ManualRecovery;
    if ((remote.state == PeerObservedState::Prepared || remote.state == PeerObservedState::CommitPending ||
         remote.state == PeerObservedState::Committed) && remote.final_root != local.expected_final_root)
        return PeerRecoveryAction::ManualRecovery;
    if (!remote.final_root.empty() && remote.final_root != local.expected_final_root &&
        remote.state != PeerObservedState::Created && remote.state != PeerObservedState::NotFound)
        return PeerRecoveryAction::ManualRecovery;
    if (local.state == PeerSessionState::Committed)
        return remote.state == PeerObservedState::Committed
            ? PeerRecoveryAction::CompleteCommit : PeerRecoveryAction::ManualRecovery;
    if (local.state == PeerSessionState::Aborted)
        return remote.state == PeerObservedState::Aborted ? PeerRecoveryAction::AbortUncommitted
                                                           : PeerRecoveryAction::ManualRecovery;
    if (local.peer_commit_verified && remote.state != PeerObservedState::Committed)
        return PeerRecoveryAction::ManualRecovery;
    const bool remote_committed = remote.state == PeerObservedState::Committed;
    const bool remote_may_commit = remote.state == PeerObservedState::CommitPending;
    const bool remote_prepared = remote.state == PeerObservedState::Prepared || remote_may_commit || remote_committed;
    const bool locally_authorized = local.approval_recorded && local.approved &&
        (!local.plan_requires_deletion_confirmation || local.deletion_confirmed);
    if (remote_prepared && !locally_authorized) return PeerRecoveryAction::ManualRecovery;
    if (local.local_commit_verified) {
        if (remote_committed) return PeerRecoveryAction::CompleteCommit;
        if (remote_prepared) return PeerRecoveryAction::ResumeCommit;
        if (remote.state == PeerObservedState::Unknown) return PeerRecoveryAction::WaitForPeer;
        return PeerRecoveryAction::ManualRecovery;
    }
    if (remote_committed)
        return local.local_prepared ? PeerRecoveryAction::ResumeCommit : PeerRecoveryAction::ManualRecovery;
    if (remote.state == PeerObservedState::Aborted || remote.state == PeerObservedState::NotFound) {
        if (local.state == PeerSessionState::CommitPending || local.local_commit_verified)
            return PeerRecoveryAction::ManualRecovery;
        return PeerRecoveryAction::AbortUncommitted;
    }
    if (local.local_prepared && remote_prepared) return PeerRecoveryAction::ResumeCommit;
    if (remote_prepared && !local.local_prepared) return PeerRecoveryAction::PrepareLocal;
    if (remote.state == PeerObservedState::Unknown) return PeerRecoveryAction::WaitForPeer;
    if (local.local_prepared && remote.state == PeerObservedState::Created)
        return PeerRecoveryAction::WaitForPeer;
    if (local.state == PeerSessionState::ApprovalPending && local.approved)
        return PeerRecoveryAction::PrepareLocal;
    return PeerRecoveryAction::WaitForPeer;
}

const char* peer_session_state_name(PeerSessionState state) noexcept {
    switch (state) {
        case PeerSessionState::Created: return "CREATED";
        case PeerSessionState::Authenticated: return "AUTHENTICATED";
        case PeerSessionState::ManifestsValidated: return "MANIFESTS_VALIDATED";
        case PeerSessionState::PlanAgreed: return "PLAN_AGREED";
        case PeerSessionState::ApprovalPending: return "APPROVAL_PENDING";
        case PeerSessionState::Prepared: return "PREPARED";
        case PeerSessionState::CommitPending: return "COMMIT_PENDING";
        case PeerSessionState::Committed: return "COMMITTED";
        case PeerSessionState::Aborted: return "ABORTED";
        case PeerSessionState::RecoveryRequired: return "RECOVERY_REQUIRED";
    }
    return "UNKNOWN";
}

const char* peer_operation_state_name(PeerOperationState state) noexcept {
    switch (state) {
        case PeerOperationState::Planned: return "PLANNED";
        case PeerOperationState::Staged: return "STAGED";
        case PeerOperationState::RecoveryPrepared: return "RECOVERY_PREPARED";
        case PeerOperationState::Prepared: return "PREPARED";
        case PeerOperationState::Committed: return "COMMITTED";
        case PeerOperationState::Finalized: return "FINALIZED";
        case PeerOperationState::RolledBack: return "ROLLED_BACK";
        case PeerOperationState::Failed: return "FAILED";
    }
    return "UNKNOWN";
}

std::string make_deterministic_operation_id(const std::string& session_id,
                                           const std::string& relative_path,
                                           PeerPlanAction action,
                                           const std::string& expected_new_hash) {
    const std::string seed = session_id + ":" + relative_path + ":" +
                             std::to_string(static_cast<int>(action)) + ":" +
                             expected_new_hash;
    return sha256_data(seed.data(), seed.size());
}

namespace {
PeerOperationRecord read_operation(sqlite3_stmt* statement) {
    PeerOperationRecord record;
    record.transaction_id = column_text(statement, 0);
    record.operation_id = column_text(statement, 1);
    record.session_id = column_text(statement, 2);
    record.plan_hash = column_text(statement, 3);
    record.relative_path = column_text(statement, 4);
    record.action = static_cast<PeerPlanAction>(sqlite3_column_int(statement, 5));
    record.prior_content_hash = column_text(statement, 6);
    record.expected_new_hash = column_text(statement, 7);
    record.staging_artifact = column_text(statement, 8);
    record.recovery_artifact = column_text(statement, 9);
    record.state = static_cast<PeerOperationState>(sqlite3_column_int(statement, 10));
    record.error = column_text(statement, 11);
    record.created_at_ms = sqlite3_column_int64(statement, 12);
    record.updated_at_ms = sqlite3_column_int64(statement, 13);
    return record;
}
} // namespace

void PeerSessionJournal::record_operation(const PeerOperationRecord& record) {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "INSERT INTO peer_session_operations(transaction_id,operation_id,session_id,plan_hash,relative_path,action,prior_content_hash,expected_new_hash,staging_artifact,recovery_artifact,state,error,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(operation_id) DO UPDATE SET staging_artifact=excluded.staging_artifact,recovery_artifact=excluded.recovery_artifact,state=excluded.state,error=excluded.error,updated_at_ms=excluded.updated_at_ms;";
    require_sql(impl_->db, sqlite3_prepare_v2(impl_->db, sql, -1, &statement, nullptr), "prepare record operation");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    bind_text(impl_->db, statement, 1, record.transaction_id);
    bind_text(impl_->db, statement, 2, record.operation_id);
    bind_text(impl_->db, statement, 3, record.session_id);
    bind_text(impl_->db, statement, 4, record.plan_hash);
    bind_text(impl_->db, statement, 5, record.relative_path);
    sqlite3_bind_int(statement, 6, static_cast<int>(record.action));
    bind_text(impl_->db, statement, 7, record.prior_content_hash);
    bind_text(impl_->db, statement, 8, record.expected_new_hash);
    bind_text(impl_->db, statement, 9, record.staging_artifact);
    bind_text(impl_->db, statement, 10, record.recovery_artifact);
    sqlite3_bind_int(statement, 11, static_cast<int>(record.state));
    bind_text(impl_->db, statement, 12, record.error);
    const auto ts = record.created_at_ms > 0 ? record.created_at_ms : now_ms();
    sqlite3_bind_int64(statement, 13, ts);
    sqlite3_bind_int64(statement, 14, now_ms());
    require_sql(impl_->db, sqlite3_step(statement), "execute record operation");
}

std::vector<PeerOperationRecord> PeerSessionJournal::load_operations(const std::string& session_id) const {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "SELECT transaction_id,operation_id,session_id,plan_hash,relative_path,action,prior_content_hash,expected_new_hash,staging_artifact,recovery_artifact,state,error,created_at_ms,updated_at_ms FROM peer_session_operations WHERE session_id=? ORDER BY relative_path ASC;";
    require_sql(impl_->db, sqlite3_prepare_v2(impl_->db, sql, -1, &statement, nullptr), "prepare load operations");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    bind_text(impl_->db, statement, 1, session_id);
    std::vector<PeerOperationRecord> result;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        result.push_back(read_operation(statement));
    }
    return result;
}

PeerOperationRecord PeerSessionJournal::load_operation(const std::string& operation_id) const {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "SELECT transaction_id,operation_id,session_id,plan_hash,relative_path,action,prior_content_hash,expected_new_hash,staging_artifact,recovery_artifact,state,error,created_at_ms,updated_at_ms FROM peer_session_operations WHERE operation_id=?;";
    require_sql(impl_->db, sqlite3_prepare_v2(impl_->db, sql, -1, &statement, nullptr), "prepare load operation");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    bind_text(impl_->db, statement, 1, operation_id);
    const int status = sqlite3_step(statement);
    if (status == SQLITE_DONE) throw std::runtime_error("peer session operation does not exist");
    require_sql(impl_->db, status, "read peer session operation");
    return read_operation(statement);
}

void PeerSessionJournal::update_operation(const PeerOperationRecord& record) {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "UPDATE peer_session_operations SET state=?,staging_artifact=?,recovery_artifact=?,error=?,updated_at_ms=? WHERE operation_id=?;";
    require_sql(impl_->db, sqlite3_prepare_v2(impl_->db, sql, -1, &statement, nullptr), "prepare update operation");
    struct Finalize { sqlite3_stmt* statement; ~Finalize() { sqlite3_finalize(statement); } } finalize{statement};
    sqlite3_bind_int(statement, 1, static_cast<int>(record.state));
    bind_text(impl_->db, statement, 2, record.staging_artifact);
    bind_text(impl_->db, statement, 3, record.recovery_artifact);
    bind_text(impl_->db, statement, 4, record.error);
    sqlite3_bind_int64(statement, 5, now_ms());
    bind_text(impl_->db, statement, 6, record.operation_id);
    require_sql(impl_->db, sqlite3_step(statement), "execute update operation");
}

PeerTransactionCoordinator::PeerTransactionCoordinator(PeerSessionJournal& journal,
                                                       const fs::path& sync_root,
                                                       const fs::path& recovery_root,
                                                       PeerBaselineStore* baseline_store,
                                                       VersionStore* version_store,
                                                       ActivityStore* activity_store)
    : journal_(journal),
      sync_root_(sync_root),
      recovery_root_(recovery_root),
      baseline_store_(baseline_store),
      version_store_(version_store),
      activity_store_(activity_store) {}

std::vector<PeerOperationRecord> PeerTransactionCoordinator::plan_operations(
    const std::string& session_id, const PeerSyncPlan& plan, bool as_remote_peer) {
    if (!plan.valid || !plan.error.empty())
        throw std::runtime_error("cannot plan operations from an invalid sync plan: " + plan.error);
    if (plan.has_unresolved_conflicts)
        throw std::runtime_error("cannot plan operations with unresolved conflicts");
    const auto session = journal_.load(session_id);
    if (session.plan_hash.empty() || session.plan_hash != plan.plan_hash)
        throw std::runtime_error("plan hash does not match agreed session plan");

    fs::create_directories(recovery_root_);

    std::vector<PeerOperationRecord> operations;
    for (const auto& entry : plan.entries) {
        PeerPlanAction action = entry.action;
        if (as_remote_peer) {
            if (entry.action == PeerPlanAction::AddRemote) action = PeerPlanAction::AddLocal;
            else if (entry.action == PeerPlanAction::UpdateRemote) action = PeerPlanAction::UpdateLocal;
            else if (entry.action == PeerPlanAction::DeleteRemote) action = PeerPlanAction::DeleteLocal;
            else continue;
        } else {
            if (entry.action != PeerPlanAction::AddLocal &&
                entry.action != PeerPlanAction::UpdateLocal &&
                entry.action != PeerPlanAction::DeleteLocal) {
                continue;
            }
        }
        if (!safe_relative_path(entry.relative_path))
            throw std::runtime_error("unsafe relative path in peer plan: " + entry.relative_path);

        PeerOperationRecord op;
        op.transaction_id = session_id;
        op.session_id = session_id;
        op.plan_hash = plan.plan_hash;
        op.relative_path = entry.relative_path;
        op.action = action;
        op.state = PeerOperationState::Planned;

        if (as_remote_peer) {
            if (action == PeerPlanAction::AddLocal) {
                op.prior_content_hash = "";
                op.expected_new_hash = entry.local.has_value() ? entry.local->sha256 : "";
            } else if (action == PeerPlanAction::UpdateLocal) {
                op.prior_content_hash = entry.remote.has_value() ? entry.remote->sha256 :
                    (entry.baseline.has_value() ? entry.baseline->sha256 : "");
                op.expected_new_hash = entry.local.has_value() ? entry.local->sha256 : "";
            } else if (action == PeerPlanAction::DeleteLocal) {
                op.prior_content_hash = entry.remote.has_value() ? entry.remote->sha256 : "";
                op.expected_new_hash = "";
            }
        } else {
            if (action == PeerPlanAction::AddLocal) {
                op.prior_content_hash = "";
                op.expected_new_hash = entry.remote.has_value() ? entry.remote->sha256 : "";
            } else if (action == PeerPlanAction::UpdateLocal) {
                op.prior_content_hash = entry.local.has_value() ? entry.local->sha256 :
                    (entry.baseline.has_value() ? entry.baseline->sha256 : "");
                op.expected_new_hash = entry.remote.has_value() ? entry.remote->sha256 : "";
            } else if (action == PeerPlanAction::DeleteLocal) {
                op.prior_content_hash = entry.local.has_value() ? entry.local->sha256 : "";
                op.expected_new_hash = "";
            }
        }

        op.operation_id = make_deterministic_operation_id(session_id, op.relative_path, op.action, op.expected_new_hash);
        op.staging_artifact = (sync_root_ / fs::u8path(op.relative_path)).string() + ".mc-stage-" + op.operation_id.substr(0, 16);
        op.recovery_artifact = (recovery_root_ / (op.operation_id + ".bak")).string();
        op.created_at_ms = now_ms();
        op.updated_at_ms = op.created_at_ms;

        journal_.record_operation(op);
        operations.push_back(std::move(op));
    }
    return operations;
}

static void reject_symlink_destination_path(const fs::path& root, const std::string& relative) {
    fs::path current = root;
    for (const auto& part : fs::u8path(relative)) {
        current /= part;
        std::error_code ec;
        const auto status = fs::symlink_status(current, ec);
        if (ec == std::errc::no_such_file_or_directory) continue;
        if (ec) throw std::runtime_error("cannot inspect destination path: " + ec.message());
        if (fs::is_symlink(status)) throw std::runtime_error("destination path crosses a symbolic link: " + relative);
    }
}

bool PeerTransactionCoordinator::prepare_operations(
    const std::string& session_id,
    const std::string& bound_plan_hash,
    const std::function<void(const PeerOperationRecord&, StagingFile&)>& staging_writer,
    const PeerExecutorOptions& options) {
    const auto session = journal_.load(session_id);
    if (session.plan_hash != bound_plan_hash)
        throw std::runtime_error("stale plan hash during preparation");
    if (session.plan_requires_approval && (!session.approval_recorded || !session.approved))
        throw std::runtime_error("cannot prepare unapproved plan");
    if (session.plan_requires_deletion_confirmation && !session.deletion_confirmed)
        throw std::runtime_error("cannot prepare deletion without explicit confirmation");

    fs::create_directories(recovery_root_);
    auto operations = journal_.load_operations(session_id);

    for (auto& op : operations) {
        if (op.state == PeerOperationState::Prepared ||
            op.state == PeerOperationState::Committed ||
            op.state == PeerOperationState::Finalized) {
            continue;
        }

        const auto target = sync_root_ / fs::u8path(op.relative_path);
        reject_symlink_destination_path(sync_root_, op.relative_path);

        if (op.action == PeerPlanAction::AddLocal) {
            if (fs::exists(target))
                throw std::runtime_error("destination appeared before preparation for " + op.relative_path);
            const auto stage_path = fs::u8path(op.staging_artifact);
            fs::create_directories(stage_path.parent_path());
            std::error_code ec;
            fs::remove(stage_path, ec);

            StagingFile staging(stage_path);
            if (staging_writer) staging_writer(op, staging);
            staging.flush();
            if (staging.sha256() != op.expected_new_hash)
                throw std::runtime_error("staging hash mismatch for " + op.relative_path);
            staging.keep();

            op.state = PeerOperationState::Prepared;
            journal_.update_operation(op);
        } else if (op.action == PeerPlanAction::UpdateLocal) {
            if (!fs::exists(target))
                throw std::runtime_error("destination missing before preparation for " + op.relative_path);
            if (sha256_file(target) != op.prior_content_hash)
                throw std::runtime_error("destination changed before preparation for " + op.relative_path);

            // Step A: Stage new content
            const auto stage_path = fs::u8path(op.staging_artifact);
            fs::create_directories(stage_path.parent_path());
            std::error_code ec;
            fs::remove(stage_path, ec);

            StagingFile staging(stage_path);
            if (staging_writer) staging_writer(op, staging);
            staging.flush();
            if (staging.sha256() != op.expected_new_hash)
                throw std::runtime_error("staging hash mismatch for " + op.relative_path);
            staging.keep();

            // Step B (Requirement 3): Create and verify recovery artifact BEFORE commit
            const auto recovery_path = fs::u8path(op.recovery_artifact);
            fs::create_directories(recovery_path.parent_path());
            fs::copy_file(target, recovery_path, fs::copy_options::overwrite_existing);
            if (sha256_file(recovery_path) != op.prior_content_hash)
                throw std::runtime_error("recovery artifact verification failed for " + op.relative_path);

            op.state = PeerOperationState::Prepared;
            journal_.update_operation(op);
        } else if (op.action == PeerPlanAction::DeleteLocal) {
            if (!fs::exists(target))
                throw std::runtime_error("destination missing before deletion preparation for " + op.relative_path);
            if (sha256_file(target) != op.prior_content_hash)
                throw std::runtime_error("destination changed before deletion preparation for " + op.relative_path);

            // Requirement 3: Create and verify recovery artifact BEFORE deletion
            const auto recovery_path = fs::u8path(op.recovery_artifact);
            fs::create_directories(recovery_path.parent_path());
            fs::copy_file(target, recovery_path, fs::copy_options::overwrite_existing);
            if (sha256_file(recovery_path) != op.prior_content_hash)
                throw std::runtime_error("recovery artifact verification failed for " + op.relative_path);

            op.state = PeerOperationState::Prepared;
            journal_.update_operation(op);
        }
    }

    if (options.simulate_crash_before_commit) {
        journal_.mark_recovery_required(session_id, "interrupted before commit");
        throw std::runtime_error("simulated crash before commit");
    }

    journal_.mark_local_prepared(session_id, bound_plan_hash);
    return true;
}

PeerExecutionResult PeerTransactionCoordinator::commit_local(
    const std::string& session_id,
    const std::string& bound_plan_hash,
    const PeerExecutorOptions& options) {
    PeerExecutionResult result;
    result.session_id = session_id;

    auto session = journal_.load(session_id);
    if (session.plan_hash != bound_plan_hash) {
        result.error = "stale plan hash during commit";
        return result;
    }

    // Require bilateral preparation before commit
    if (session.state == PeerSessionState::Prepared) {
        journal_.begin_commit(session_id, bound_plan_hash);
        session = journal_.load(session_id);
    }
    if (session.state != PeerSessionState::CommitPending &&
        session.state != PeerSessionState::RecoveryRequired &&
        session.state != PeerSessionState::Committed) {
        result.error = "commit requires bilateral preparation";
        return result;
    }

    auto operations = journal_.load_operations(session_id);

    for (auto& op : operations) {
        const auto target = sync_root_ / fs::u8path(op.relative_path);
        reject_symlink_destination_path(sync_root_, op.relative_path);

        if (op.state == PeerOperationState::Committed || op.state == PeerOperationState::Finalized) {
            // Idempotent retry check: verify destination
            if (op.action == PeerPlanAction::DeleteLocal) {
                if (fs::exists(target)) {
                    result.error = "committed deleted file reappeared: " + op.relative_path;
                    return result;
                }
            } else {
                if (!fs::exists(target) || sha256_file(target) != op.expected_new_hash) {
                    result.error = "committed file mismatch: " + op.relative_path;
                    return result;
                }
            }
            ++result.operations_committed;
            continue;
        }

        if (op.action == PeerPlanAction::AddLocal) {
            if (fs::exists(target)) {
                journal_.mark_recovery_required(session_id, "destination collision before commit: " + op.relative_path);
                result.error = "destination collision before commit: " + op.relative_path;
                return result;
            }
            const auto stage_path = fs::u8path(op.staging_artifact);
            if (!fs::exists(stage_path)) {
                journal_.mark_recovery_required(session_id, "staging file missing for commit: " + op.relative_path);
                result.error = "staging file missing for commit: " + op.relative_path;
                return result;
            }
            if (sha256_file(stage_path) != op.expected_new_hash) {
                journal_.mark_recovery_required(session_id, "staging file hash mismatch before commit: " + op.relative_path);
                result.error = "staging file hash mismatch before commit: " + op.relative_path;
                return result;
            }
            fs::rename(stage_path, target);
            if (sha256_file(target) != op.expected_new_hash) {
                journal_.mark_recovery_required(session_id, "post-commit verification failed for " + op.relative_path);
                result.error = "post-commit verification failed for " + op.relative_path;
                return result;
            }
            op.state = PeerOperationState::Committed;
            journal_.update_operation(op);
            ++result.operations_committed;
        } else if (op.action == PeerPlanAction::UpdateLocal) {
            const auto stage_path = fs::u8path(op.staging_artifact);
            const auto recovery_path = fs::u8path(op.recovery_artifact);
            if (!fs::exists(recovery_path) || sha256_file(recovery_path) != op.prior_content_hash) {
                journal_.mark_recovery_required(session_id, "recovery artifact missing or corrupt for " + op.relative_path);
                result.error = "recovery artifact missing or corrupt for " + op.relative_path;
                return result;
            }
            if (!fs::exists(stage_path) || sha256_file(stage_path) != op.expected_new_hash) {
                journal_.mark_recovery_required(session_id, "staging file missing or corrupt for commit: " + op.relative_path);
                result.error = "staging file missing or corrupt for commit: " + op.relative_path;
                return result;
            }

            // CRITICAL AUDIT CHECK: verify destination contents immediately before destructive replacement
            if (!fs::exists(target) || sha256_file(target) != op.prior_content_hash) {
                journal_.mark_recovery_required(session_id, "stale destination contents before commit for " + op.relative_path);
                result.error = "stale destination contents before commit for " + op.relative_path;
                return result;
            }

            fs::path retiring = target;
            retiring += ".mc-retiring-" + op.operation_id.substr(0, 16);

            if (options.simulate_crash_during_replacement) {
                fs::rename(target, retiring);
                journal_.mark_recovery_required(session_id, "crash during replacement: " + op.relative_path);
                throw std::runtime_error("simulated crash during replacement for " + op.relative_path);
            }

            fs::rename(target, retiring);
            try {
                fs::rename(stage_path, target);
                if (sha256_file(target) != op.expected_new_hash)
                    throw std::runtime_error("post-commit hash mismatch for " + op.relative_path);
                std::error_code ec;
                fs::remove(retiring, ec);
            } catch (...) {
                std::error_code ec;
                if (!fs::exists(target) && fs::exists(retiring)) {
                    fs::rename(retiring, target, ec);
                }
                throw;
            }
            op.state = PeerOperationState::Committed;
            journal_.update_operation(op);
            ++result.operations_committed;
        } else if (op.action == PeerPlanAction::DeleteLocal) {
            const auto recovery_path = fs::u8path(op.recovery_artifact);
            if (!fs::exists(recovery_path) || sha256_file(recovery_path) != op.prior_content_hash) {
                journal_.mark_recovery_required(session_id, "recovery artifact missing or corrupt for " + op.relative_path);
                result.error = "recovery artifact missing or corrupt for " + op.relative_path;
                return result;
            }

            // CRITICAL AUDIT CHECK: verify destination contents immediately before destructive deletion
            if (!fs::exists(target) || sha256_file(target) != op.prior_content_hash) {
                journal_.mark_recovery_required(session_id, "stale destination contents before commit for " + op.relative_path);
                result.error = "stale destination contents before commit for " + op.relative_path;
                return result;
            }

            std::error_code ec;
            fs::remove(target, ec);
            if (fs::exists(target)) {
                journal_.mark_recovery_required(session_id, "failed to delete target file: " + op.relative_path);
                result.error = "failed to delete target file: " + op.relative_path;
                return result;
            }
            op.state = PeerOperationState::Committed;
            journal_.update_operation(op);
            ++result.operations_committed;
        }
    }

    // Verify full folder Merkle root
    const auto scanned = mc::scan_folder(sync_root_);
    if (!scanned.complete) {
        result.error = "post-commit scan was incomplete";
        return result;
    }
    if (scanned.merkle_root != session.expected_final_root) {
        result.error = "post-commit Merkle root mismatch: expected " + session.expected_final_root +
                       " got " + scanned.merkle_root;
        return result;
    }

    journal_.mark_local_commit_verified(session_id, bound_plan_hash, scanned.merkle_root);
    result.final_merkle_root = scanned.merkle_root;

    if (options.simulate_crash_after_file_commit) {
        journal_.mark_recovery_required(session_id, "simulated crash after file commit");
        throw std::runtime_error("simulated crash after file commit");
    }

    if (options.simulate_history_write_failure) {
        journal_.mark_recovery_required(session_id, "simulated history write failure");
        throw std::runtime_error("simulated history write failure");
    }

    // History and Version records
    if (version_store_) {
        try {
            version_store_->create_snapshot(sync_root_, "Peer sync: " + session_id);
        } catch (const std::exception& e) {
            journal_.mark_recovery_required(session_id, "version snapshot failed: " + std::string(e.what()));
            result.error = "version snapshot failed: " + std::string(e.what());
            return result;
        }
    }

    if (activity_store_) {
        try {
            for (const auto& op : operations) {
                SyncJob job;
                job.id = op.operation_id;
                job.relative_path = op.relative_path;
                job.destination = sync_root_ / fs::u8path(op.relative_path);
                job.content_hash = op.expected_new_hash;
                job.state = JobState::SucceededVerified;
                job.verified = true;
                if (op.action == PeerPlanAction::AddLocal) job.operation = Operation::Add;
                else if (op.action == PeerPlanAction::UpdateLocal) job.operation = Operation::Modify;
                else if (op.action == PeerPlanAction::DeleteLocal) job.operation = Operation::Delete;
                activity_store_->record(job);
            }
        } catch (const std::exception& e) {
            journal_.mark_recovery_required(session_id, "activity record failed: " + std::string(e.what()));
            result.error = "activity record failed: " + std::string(e.what());
            return result;
        }
    }

    for (auto& op : operations) {
        op.state = PeerOperationState::Finalized;
        journal_.update_operation(op);
    }

    result.success = true;
    return result;
}

bool PeerTransactionCoordinator::finalize_bilateral_commit(
    const std::string& session_id,
    const std::string& remote_peer,
    const std::string& folder_pair_id,
    const FileManifest& final_manifest,
    const PeerExecutorOptions& options) {
    const auto session = journal_.load(session_id);
    if (!session.local_commit_verified || !session.peer_commit_verified) {
        return false;
    }
    if (session.state != PeerSessionState::Committed) {
        return false;
    }

    const auto operations = journal_.load_operations(session_id);
    for (const auto& op : operations) {
        if (op.state != PeerOperationState::Committed && op.state != PeerOperationState::Finalized) {
            return false;
        }
    }

    if (options.simulate_baseline_write_failure) {
        throw std::runtime_error("simulated baseline write failure");
    }

    if (baseline_store_) {
        baseline_store_->commit_reconciled_manifest(remote_peer, folder_pair_id, final_manifest);
    }

    // Safely release recovery material
    journal_.release_recovery_material(session_id);
    for (const auto& op : operations) {
        std::error_code ec;
        if (!op.recovery_artifact.empty()) fs::remove(fs::u8path(op.recovery_artifact), ec);
        if (!op.staging_artifact.empty()) fs::remove(fs::u8path(op.staging_artifact), ec);
    }
    return true;
}

bool PeerTransactionCoordinator::rollback_operations(
    const std::string& session_id,
    const std::string& bound_plan_hash,
    const PeerExecutorOptions& options) {
    const auto session = journal_.load(session_id);
    if (session.local_commit_verified || session.peer_commit_verified) {
        throw std::runtime_error("cannot rollback after verified commit");
    }

    if (options.simulate_rollback_failure) {
        journal_.mark_recovery_required(session_id, "rollback failed: simulated rollback failure");
        throw std::runtime_error("simulated rollback failure");
    }

    auto operations = journal_.load_operations(session_id);
    for (auto& op : operations) {
        const auto target = sync_root_ / fs::u8path(op.relative_path);
        const auto recovery_path = fs::u8path(op.recovery_artifact);
        const auto stage_path = fs::u8path(op.staging_artifact);

        if (op.action == PeerPlanAction::AddLocal) {
            std::error_code ec;
            if (fs::exists(target)) fs::remove(target, ec);
            if (fs::exists(stage_path)) fs::remove(stage_path, ec);
            op.state = PeerOperationState::RolledBack;
            journal_.update_operation(op);
        } else if (op.action == PeerPlanAction::UpdateLocal || op.action == PeerPlanAction::DeleteLocal) {
            if (!fs::exists(recovery_path) || sha256_file(recovery_path) != op.prior_content_hash) {
                op.state = PeerOperationState::Failed;
                op.error = "recovery artifact missing or corrupt for rollback";
                journal_.update_operation(op);
                journal_.mark_recovery_required(session_id, "rollback failed: recovery artifact corrupt or missing for " + op.relative_path);
                return false;
            }

            fs::path retiring = target;
            retiring += ".mc-retiring-" + op.operation_id.substr(0, 16);
            std::error_code ec;
            if (fs::exists(retiring)) fs::remove(retiring, ec);

            fs::copy_file(recovery_path, target, fs::copy_options::overwrite_existing);
            if (sha256_file(target) != op.prior_content_hash) {
                op.state = PeerOperationState::Failed;
                op.error = "rollback destination verification failed";
                journal_.update_operation(op);
                journal_.mark_recovery_required(session_id, "rollback failed for " + op.relative_path);
                return false;
            }
            if (fs::exists(stage_path)) fs::remove(stage_path, ec);
            op.state = PeerOperationState::RolledBack;
            journal_.update_operation(op);
        }
    }

    journal_.mark_local_rollback_verified(session_id, bound_plan_hash);
    return true;
}

bool PeerTransactionCoordinator::verify_recovery_artifacts(const std::string& session_id) const {
    const auto operations = journal_.load_operations(session_id);
    for (const auto& op : operations) {
        if (op.action == PeerPlanAction::UpdateLocal || op.action == PeerPlanAction::DeleteLocal) {
            const auto recovery_path = fs::u8path(op.recovery_artifact);
            if (!fs::exists(recovery_path)) return false;
            if (sha256_file(recovery_path) != op.prior_content_hash) return false;
        }
    }
    return true;
}

PeerRecoveryAction PeerTransactionCoordinator::reconcile_and_recover(
    const std::string& session_id,
    const PeerSessionObservation& remote,
    const PeerExecutorOptions& options) {
    const auto local = journal_.load(session_id);
    const auto advice = evaluate_peer_recovery(local, remote);

    // If destination was interrupted during replacement, check retiring files or target
    const auto operations = journal_.load_operations(session_id);
    for (auto op : operations) {
        const auto target = sync_root_ / fs::u8path(op.relative_path);
        fs::path retiring = target;
        retiring += ".mc-retiring-" + op.operation_id.substr(0, 16);
        if (fs::exists(retiring)) {
            // A crash occurred mid-replacement
            if (fs::exists(target) && sha256_file(target) == op.expected_new_hash) {
                // Staged commit completed before retiring file was deleted
                std::error_code ec;
                fs::remove(retiring, ec);
                op.state = PeerOperationState::Committed;
                journal_.update_operation(op);
            } else if (advice == PeerRecoveryAction::AbortUncommitted) {
                // Restore original from retiring file or recovery artifact
                std::error_code ec;
                if (!fs::exists(target)) {
                    fs::rename(retiring, target, ec);
                }
            } else if (advice == PeerRecoveryAction::ResumeCommit) {
                // Re-commit from staging file
                const auto stage_path = fs::u8path(op.staging_artifact);
                if (fs::exists(stage_path)) {
                    try {
                        std::error_code ec;
                        fs::rename(stage_path, target);
                        fs::remove(retiring, ec);
                        op.state = PeerOperationState::Committed;
                        journal_.update_operation(op);
                    } catch (...) {}
                }
            }
        }
    }

    if (advice == PeerRecoveryAction::AbortUncommitted) {
        if (!local.local_commit_verified) {
            rollback_operations(session_id, local.plan_hash, options);
        }
    } else if (advice == PeerRecoveryAction::ResumeCommit) {
        commit_local(session_id, local.plan_hash, options);
    } else if (advice == PeerRecoveryAction::CompleteCommit) {
        if (!local.peer_commit_verified) {
            journal_.acknowledge_peer_commit(session_id, remote.peer_id, remote.plan_hash, remote.final_root);
        }
    } else if (advice == PeerRecoveryAction::ManualRecovery) {
        if (local.state != PeerSessionState::RecoveryRequired && !terminal(local.state)) {
            journal_.mark_recovery_required(session_id, "manual recovery required due to inconsistent state");
        }
    }
    return advice;
}

PeerReconciliationReport PeerTransactionCoordinator::reconcile_interrupted_session(
    const std::string& session_id,
    bool resume_commit,
    const PeerExecutorOptions& options) {
    (void)options;
    PeerReconciliationReport report;
    report.session_id = session_id;

    PeerSessionRecord session;
    try {
        session = journal_.load(session_id);
    } catch (const std::exception& e) {
        report.manual_recovery_required = true;
        report.diagnostic = "failed to load session: " + std::string(e.what());
        return report;
    }

    auto operations = journal_.load_operations(session_id);
    bool all_clean = true;

    for (auto& op : operations) {
        const auto target = sync_root_ / fs::u8path(op.relative_path);
        fs::path retiring = target;
        retiring += ".mc-retiring-" + op.operation_id.substr(0, 16);
        const auto stage_path = fs::u8path(op.staging_artifact);
        const auto recovery_path = fs::u8path(op.recovery_artifact);

        // Crash Point 3: Interrupted mid-replacement (retiring exists)
        if (fs::exists(retiring)) {
            if (fs::exists(target) && sha256_file(target) == op.expected_new_hash) {
                // New file was already installed before crash! Retiring file was lingering.
                std::error_code ec;
                fs::remove(retiring, ec);
                ++report.lingering_retiring_cleaned;
                op.state = PeerOperationState::Committed;
                journal_.update_operation(op);
            } else if (resume_commit && fs::exists(stage_path) && sha256_file(stage_path) == op.expected_new_hash) {
                // Resume commit: install new file from staging, remove retiring
                std::error_code ec;
                fs::rename(stage_path, target, ec);
                if (ec || !fs::exists(target) || sha256_file(target) != op.expected_new_hash) {
                    report.manual_recovery_required = true;
                    report.diagnostic = "failed to install new file from staging for " + op.relative_path;
                    all_clean = false;
                    continue;
                }
                fs::remove(retiring, ec);
                ++report.files_committed_from_staging;
                op.state = PeerOperationState::Committed;
                journal_.update_operation(op);
            } else {
                // Rollback / restore original: restore retiring back to target
                std::error_code ec;
                if (!fs::exists(target)) {
                    fs::rename(retiring, target, ec);
                } else {
                    fs::remove(target, ec);
                    fs::rename(retiring, target, ec);
                }
                if (ec || !fs::exists(target) || sha256_file(target) != op.prior_content_hash) {
                    // Try restoring from recovery artifact if retiring rename failed
                    if (fs::exists(recovery_path) && sha256_file(recovery_path) == op.prior_content_hash) {
                        fs::copy_file(recovery_path, target, fs::copy_options::overwrite_existing, ec);
                        if (!ec && sha256_file(target) == op.prior_content_hash) {
                            fs::remove(retiring, ec);
                            ++report.files_restored_from_recovery;
                            op.state = PeerOperationState::RolledBack;
                            journal_.update_operation(op);
                            continue;
                        }
                    }
                    report.manual_recovery_required = true;
                    report.diagnostic = "failed to restore destination from retiring/recovery for " + op.relative_path;
                    all_clean = false;
                    continue;
                }
                ++report.files_restored_from_retiring;
                if (fs::exists(stage_path)) {
                    fs::remove(stage_path, ec);
                    ++report.orphaned_staging_cleaned;
                }
                op.state = PeerOperationState::RolledBack;
                journal_.update_operation(op);
            }
        } else if (fs::exists(stage_path) && op.state != PeerOperationState::Committed && op.state != PeerOperationState::Finalized) {
            // Crash Point 2: Staged before commit
            if (!resume_commit || session.state == PeerSessionState::Aborted) {
                std::error_code ec;
                fs::remove(stage_path, ec);
                ++report.orphaned_staging_cleaned;
                if (op.state < PeerOperationState::Committed) {
                    op.state = PeerOperationState::RolledBack;
                    journal_.update_operation(op);
                }
            }
        }

        // Check recovery artifact health for any op that touched target
        if (op.action == PeerPlanAction::UpdateLocal || op.action == PeerPlanAction::DeleteLocal) {
            if (session.recovery_material_retained &&
                (!fs::exists(recovery_path) || sha256_file(recovery_path) != op.prior_content_hash)) {
                // If destination is not in expected committed state, missing backup is dangerous
                if (!fs::exists(target) || sha256_file(target) != op.expected_new_hash) {
                    report.manual_recovery_required = true;
                    report.diagnostic = "recovery artifact missing or corrupt for " + op.relative_path;
                    all_clean = false;
                }
            }
        }
    }

    if (all_clean && !report.manual_recovery_required) {
        report.reconciled = true;
        report.diagnostic = "session reconciled cleanly";
    }
    return report;
}

} // namespace mc::peer
