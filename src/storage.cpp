#include "merklechain/storage.hpp"
#include <sqlite3.h>
#include <stdexcept>

namespace mc {
struct ActivityStore::Impl { sqlite3* db{}; };

namespace {
void exec(sqlite3* db, const char* sql) {
    char* error=nullptr;
    if(sqlite3_exec(db,sql,nullptr,nullptr,&error)!=SQLITE_OK){std::string message=error?error:sqlite3_errmsg(db);sqlite3_free(error);throw std::runtime_error(message);}
}
bool has_column(sqlite3* db,const char* name) {
    sqlite3_stmt* statement=nullptr;
    if(sqlite3_prepare_v2(db,"PRAGMA table_info(file_activity)",-1,&statement,nullptr)!=SQLITE_OK)throw std::runtime_error(sqlite3_errmsg(db));
    bool found=false;
    while(sqlite3_step(statement)==SQLITE_ROW){const auto* column=reinterpret_cast<const char*>(sqlite3_column_text(statement,1));if(column&&std::string(column)==name){found=true;break;}}
    sqlite3_finalize(statement);return found;
}
void add_column(sqlite3* db,const char* name,const char* definition){if(!has_column(db,name)){std::string sql="ALTER TABLE file_activity ADD COLUMN ";sql+=definition;exec(db,sql.c_str());}}
std::int64_t now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
void reject_symlink(const fs::path& path){std::error_code ec;auto status=fs::symlink_status(path,ec);if(ec==std::errc::no_such_file_or_directory)return;if(ec)throw std::runtime_error("cannot inspect application storage path: "+ec.message());if(fs::is_symlink(status))throw std::runtime_error("application storage path cannot be a symbolic link: "+path.string());}
}

ActivityStore::ActivityStore(const fs::path& file):impl_(new Impl){
    if(!file.parent_path().empty()){reject_symlink(file.parent_path());fs::create_directories(file.parent_path());reject_symlink(file.parent_path());}
    reject_symlink(file);
    if(sqlite3_open(file.string().c_str(),&impl_->db)!=SQLITE_OK){std::string message=impl_->db?sqlite3_errmsg(impl_->db):"cannot allocate SQLite connection";if(impl_->db)sqlite3_close(impl_->db);delete impl_;impl_=nullptr;throw std::runtime_error("cannot open activity database: "+message);}
    try {
        exec(impl_->db,"PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;");
        exec(impl_->db,"CREATE TABLE IF NOT EXISTS file_activity(id INTEGER PRIMARY KEY,job_id TEXT NOT NULL,path TEXT NOT NULL,operation TEXT NOT NULL,source TEXT NOT NULL,destination TEXT NOT NULL,content_hash TEXT NOT NULL,bytes INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL,verified INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);");
        add_column(impl_->db,"started_at_ms","started_at_ms INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"completed_at_ms","completed_at_ms INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"bytes_transferred","bytes_transferred INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"verification_result","verification_result TEXT NOT NULL DEFAULT 'NOT_CHECKED'");
        add_column(impl_->db,"source_bytes_processed","source_bytes_processed INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"bytes_reused","bytes_reused INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"bytes_written","bytes_written INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"chunk_size_bytes","chunk_size_bytes INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"chunks_total","chunks_total INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"chunks_reused","chunks_reused INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"chunked_transfer","chunked_transfer INTEGER NOT NULL DEFAULT 0");
        add_column(impl_->db,"transfer_fallback_reason","transfer_fallback_reason TEXT NOT NULL DEFAULT ''");
        exec(impl_->db,"CREATE INDEX IF NOT EXISTS idx_file_activity_job_id ON file_activity(job_id);");
        sqlite3_stmt* version=nullptr;if(sqlite3_prepare_v2(impl_->db,"PRAGMA user_version",-1,&version,nullptr)!=SQLITE_OK)throw std::runtime_error(sqlite3_errmsg(impl_->db));int schema=sqlite3_step(version)==SQLITE_ROW?sqlite3_column_int(version,0):0;sqlite3_finalize(version);if(schema<3)exec(impl_->db,"PRAGMA user_version=3;");
        exec(impl_->db,"COMMIT");
    } catch(...) {try{exec(impl_->db,"ROLLBACK");}catch(...){}sqlite3_close(impl_->db);delete impl_;impl_=nullptr;throw;}
}
ActivityStore::~ActivityStore(){if(impl_){if(impl_->db)sqlite3_close(impl_->db);delete impl_;}}

std::string operation_name(Operation operation){switch(operation){case Operation::Add:return "ADD";case Operation::Modify:return "MODIFY";case Operation::Delete:return "DELETE";case Operation::Unchanged:return "UNCHANGED";case Operation::Preserve:return "PRESERVE";}return "UNKNOWN";}
std::string job_state_name(JobState state){switch(state){case JobState::Planned:return "PLANNED";case JobState::PendingApproval:return "PENDING_APPROVAL";case JobState::InProgress:return "IN_PROGRESS";case JobState::SucceededVerified:return "SUCCEEDED_VERIFIED";case JobState::Failed:return "FAILED";case JobState::Cancelled:return "CANCELLED";case JobState::Interrupted:return "INTERRUPTED";case JobState::Skipped:return "SKIPPED";}return "UNKNOWN";}

void ActivityStore::record(const SyncJob& job){
    exec(impl_->db,"BEGIN IMMEDIATE");sqlite3_stmt* statement=nullptr;
    const char* sql="INSERT INTO file_activity(job_id,path,operation,source,destination,content_hash,bytes,state,verified,error,started_at_ms,completed_at_ms,bytes_transferred,verification_result,source_bytes_processed,bytes_reused,bytes_written,chunk_size_bytes,chunks_total,chunks_reused,chunked_transfer,transfer_fallback_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    try {
        if(sqlite3_prepare_v2(impl_->db,sql,-1,&statement,nullptr)!=SQLITE_OK)throw std::runtime_error(sqlite3_errmsg(impl_->db));
        const auto bind_text=[&](int index,const std::string& value){sqlite3_bind_text(statement,index,value.c_str(),-1,SQLITE_TRANSIENT);};
        bind_text(1,job.id);bind_text(2,job.relative_path);bind_text(3,operation_name(job.operation));bind_text(4,job.source.string());bind_text(5,job.destination.string());bind_text(6,job.content_hash);
        const auto size=job.bytes_transferred?job.bytes_transferred:((job.operation!=Operation::Delete&&fs::exists(job.source))?fs::file_size(job.source):0);
        sqlite3_bind_int64(statement,7,static_cast<sqlite3_int64>(size));bind_text(8,job_state_name(job.state));sqlite3_bind_int(statement,9,job.verified?1:0);bind_text(10,job.error);
        sqlite3_bind_int64(statement,11,job.started_at_ms);sqlite3_bind_int64(statement,12,job.completed_at_ms?job.completed_at_ms:now_ms());sqlite3_bind_int64(statement,13,static_cast<sqlite3_int64>(job.bytes_transferred));
        bind_text(14,job.verified?"VERIFIED":(job.state==JobState::Failed?"FAILED":"NOT_CHECKED"));
        sqlite3_bind_int64(statement,15,static_cast<sqlite3_int64>(job.source_bytes_processed));
        sqlite3_bind_int64(statement,16,static_cast<sqlite3_int64>(job.bytes_reused));
        sqlite3_bind_int64(statement,17,static_cast<sqlite3_int64>(job.bytes_written));
        sqlite3_bind_int64(statement,18,static_cast<sqlite3_int64>(job.chunk_size_bytes));
        sqlite3_bind_int64(statement,19,static_cast<sqlite3_int64>(job.chunks_total));
        sqlite3_bind_int64(statement,20,static_cast<sqlite3_int64>(job.chunks_reused));
        sqlite3_bind_int(statement,21,job.chunked_transfer?1:0);
        bind_text(22,job.transfer_fallback_reason);
        if(sqlite3_step(statement)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));
        sqlite3_finalize(statement);statement=nullptr;exec(impl_->db,"COMMIT");
    } catch(...) {if(statement)sqlite3_finalize(statement);try{exec(impl_->db,"ROLLBACK");}catch(...){}throw;}
}
}
