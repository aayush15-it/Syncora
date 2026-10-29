#include "merklechain/versioning.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/sync.hpp"
#include <sqlite3.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <map>
#include <limits>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>

namespace mc {
struct VersionStore::Impl { sqlite3* db{}; fs::path state,objects,recovery; };
#ifdef MERKLECHAIN_TESTING
namespace { RestoreFaultPointForTesting restore_fault_point=RestoreFaultPointForTesting::None; }
void set_restore_fault_point_for_testing(RestoreFaultPointForTesting point){restore_fault_point=point;}
#endif
namespace {
void sql_exec(sqlite3* db,const char* sql){char* error=nullptr;if(sqlite3_exec(db,sql,nullptr,nullptr,&error)!=SQLITE_OK){std::string message=error?error:sqlite3_errmsg(db);sqlite3_free(error);throw std::runtime_error(message);}}
struct Statement {sqlite3_stmt* value{};sqlite3* db{};Statement(sqlite3* d,const char* query):db(d){if(sqlite3_prepare_v2(db,query,-1,&value,nullptr)!=SQLITE_OK)throw std::runtime_error(sqlite3_errmsg(db));}~Statement(){if(value)sqlite3_finalize(value);}Statement(const Statement&)=delete;Statement& operator=(const Statement&)=delete;};
std::int64_t now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
std::string id(){static std::mt19937_64 generator(std::random_device{}());std::ostringstream out;out<<std::hex<<now_ms()<<generator();return out.str();}
void bind(sqlite3_stmt* s,int index,const std::string& value){
    if(value.size()>static_cast<std::size_t>(std::numeric_limits<int>::max()))throw std::length_error("SQLite text value exceeds supported size");
    const int result=sqlite3_bind_text(s,index,value.data(),static_cast<int>(value.size()),SQLITE_TRANSIENT);
    if(result!=SQLITE_OK)throw std::runtime_error(std::string("SQLite text binding failed: ")+sqlite3_errmsg(sqlite3_db_handle(s)));
}
std::string column(sqlite3_stmt* s,int index){const auto* value=reinterpret_cast<const char*>(sqlite3_column_text(s,index));return value?value:"";}
fs::path object_path(const fs::path& objects,const std::string& hash){if(hash.size()!=64||!std::all_of(hash.begin(),hash.end(),[](unsigned char c){return std::isxdigit(c)!=0;}))throw std::runtime_error("invalid content hash in version metadata");return objects/hash.substr(0,2)/hash.substr(2);}
void reject_symlink_if_present(const fs::path& path){std::error_code ec;auto status=fs::symlink_status(path,ec);if(ec==std::errc::no_such_file_or_directory)return;if(ec)throw std::runtime_error("cannot inspect content-store path: "+ec.message());if(fs::is_symlink(status))throw std::runtime_error("content-store path cannot be a symbolic link: "+path.string());}
void ensure_no_symlink(const fs::path& root,const std::string& relative){
    if(!safe_relative_path(relative))throw std::runtime_error("unsafe relative path in version");
    fs::path current=root;
    for(const auto& part:fs::u8path(relative)){current/=part;std::error_code ec;auto status=fs::symlink_status(current,ec);if(ec&&ec!=std::errc::no_such_file_or_directory)throw std::runtime_error("cannot inspect restore path: "+ec.message());if(!ec&&fs::is_symlink(status))throw std::runtime_error("restore path crosses a symbolic link");}
}
}

VersionStore::VersionStore(const fs::path& database_file,const fs::path& state_directory):impl_(new Impl){
    impl_->state=state_directory;impl_->objects=state_directory/"objects";impl_->recovery=state_directory/"recovery";
    reject_symlink_if_present(state_directory);fs::create_directories(state_directory);reject_symlink_if_present(state_directory);reject_symlink_if_present(database_file);
    if(sqlite3_open(database_file.string().c_str(),&impl_->db)!=SQLITE_OK){std::string message=impl_->db?sqlite3_errmsg(impl_->db):"cannot allocate SQLite connection";if(impl_->db)sqlite3_close(impl_->db);delete impl_;impl_=nullptr;throw std::runtime_error("cannot open version database: "+message);}
    try {
        sql_exec(impl_->db,"PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;");
        sql_exec(impl_->db,"CREATE TABLE IF NOT EXISTS content_objects(hash TEXT PRIMARY KEY,size INTEGER NOT NULL,ref_count INTEGER NOT NULL DEFAULT 0 CHECK(ref_count>=0)); CREATE TABLE IF NOT EXISTS version_records(id TEXT PRIMARY KEY,parent_id TEXT REFERENCES version_records(id),label TEXT NOT NULL,created_at_ms INTEGER NOT NULL,merkle_root TEXT NOT NULL,file_count INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS version_files(version_id TEXT NOT NULL REFERENCES version_records(id) ON DELETE CASCADE,path TEXT NOT NULL,content_hash TEXT NOT NULL REFERENCES content_objects(hash),size INTEGER NOT NULL,modified_ticks INTEGER NOT NULL,PRIMARY KEY(version_id,path)); CREATE TRIGGER IF NOT EXISTS version_file_ref_insert AFTER INSERT ON version_files BEGIN UPDATE content_objects SET ref_count=ref_count+1 WHERE hash=NEW.content_hash; END; CREATE TRIGGER IF NOT EXISTS version_file_ref_delete AFTER DELETE ON version_files BEGIN UPDATE content_objects SET ref_count=ref_count-1 WHERE hash=OLD.content_hash; END; CREATE TABLE IF NOT EXISTS restore_journal(id TEXT PRIMARY KEY,folder TEXT NOT NULL,rollback_version TEXT NOT NULL,status TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',updated_at_ms INTEGER NOT NULL);");
        sqlite3_stmt* version=nullptr;if(sqlite3_prepare_v2(impl_->db,"PRAGMA user_version",-1,&version,nullptr)!=SQLITE_OK)throw std::runtime_error(sqlite3_errmsg(impl_->db));int schema=sqlite3_step(version)==SQLITE_ROW?sqlite3_column_int(version,0):0;sqlite3_finalize(version);if(schema<3)sql_exec(impl_->db,"PRAGMA user_version=3;");
        sql_exec(impl_->db,"UPDATE content_objects SET ref_count=(SELECT COUNT(*) FROM version_files WHERE version_files.content_hash=content_objects.hash);");
        sql_exec(impl_->db,"COMMIT");
    } catch(...) {try{sql_exec(impl_->db,"ROLLBACK");}catch(...){}sqlite3_close(impl_->db);delete impl_;impl_=nullptr;throw;}
}
VersionStore::~VersionStore(){if(impl_){if(impl_->db)sqlite3_close(impl_->db);delete impl_;}}

std::string VersionStore::create_snapshot(const fs::path& folder,const std::string& label,const std::string& parent_id){
    auto manifest=scan_folder(folder);if(!manifest.complete)throw std::runtime_error("cannot snapshot an incomplete folder scan");
    sql_exec(impl_->db,"BEGIN IMMEDIATE");
    try {
        std::string parent=parent_id;
        if(parent.empty()){Statement latest(impl_->db,"SELECT id FROM version_records ORDER BY rowid DESC LIMIT 1");const int latest_result=sqlite3_step(latest.value);if(latest_result==SQLITE_ROW)parent=column(latest.value,0);else if(latest_result!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));}
        if(!parent.empty()){Statement check(impl_->db,"SELECT 1 FROM version_records WHERE id=?");const int parent_bind=sqlite3_bind_text(check.value,1,parent.data(),static_cast<int>(parent.size()),SQLITE_TRANSIENT);if(parent_bind!=SQLITE_OK)throw std::runtime_error(std::string("cannot bind snapshot parent ID: ")+sqlite3_errmsg(impl_->db));if(sqlite3_step(check.value)!=SQLITE_ROW)throw std::runtime_error("snapshot parent version does not exist: "+parent);}
        // Hold the SQLite write lock while object bytes are checked/installed and their
        // references are committed. Garbage collection cannot remove an object between
        // installation and reference insertion.
        for(const auto& file:manifest.files){
            const auto source=folder/fs::u8path(file.relative_path);const auto object=object_path(impl_->objects,file.sha256);reject_symlink_if_present(impl_->objects);fs::create_directories(impl_->objects);reject_symlink_if_present(impl_->objects);reject_symlink_if_present(object.parent_path());fs::create_directories(object.parent_path());reject_symlink_if_present(object.parent_path());reject_symlink_if_present(object);
            if(fs::exists(object)){if(sha256_file(object)!=file.sha256)throw std::runtime_error("content object failed integrity check: "+file.sha256);}
            else {auto temp=object;temp += ".tmp-"+id();fs::copy_file(source,temp,fs::copy_options::none);if(sha256_file(temp)!=file.sha256){fs::remove(temp);throw std::runtime_error("source changed while snapshotting: "+file.relative_path);}try{fs::rename(temp,object);}catch(...){std::error_code ec;fs::remove(temp,ec);if(!fs::exists(object))throw;if(sha256_file(object)!=file.sha256)throw;}}
        }
        auto verification=scan_folder(folder);if(!verification.complete||verification.files.size()!=manifest.files.size()||verification.merkle_root!=manifest.merkle_root)throw std::runtime_error("folder changed while snapshot was being created");
        for(std::size_t i=0;i<manifest.files.size();++i)if(verification.files[i].relative_path!=manifest.files[i].relative_path||verification.files[i].modified_ticks!=manifest.files[i].modified_ticks||verification.files[i].size!=manifest.files[i].size)throw std::runtime_error("file metadata changed while snapshot was being created: "+manifest.files[i].relative_path);
        if(manifest.merkle_root.empty())throw std::runtime_error("cannot persist version snapshot: computed manifest Merkle root is empty");
        const auto version_id=id();const auto created=now_ms();
        Statement version(impl_->db,"INSERT INTO version_records(id,parent_id,label,created_at_ms,merkle_root,file_count) VALUES(?,?,?,?,?,?)");
        if(sqlite3_bind_parameter_count(version.value)!=6)throw std::runtime_error("version-record insert parameter count does not match its schema");
        bind(version.value,1,version_id);if(parent.empty())sqlite3_bind_null(version.value,2);else {const int parent_insert_bind=sqlite3_bind_text(version.value,2,parent.data(),static_cast<int>(parent.size()),SQLITE_TRANSIENT);if(parent_insert_bind!=SQLITE_OK)throw std::runtime_error(std::string("cannot bind snapshot parent ID: ")+sqlite3_errmsg(impl_->db));}bind(version.value,3,label);sqlite3_bind_int64(version.value,4,created);
        const int root_bind=sqlite3_bind_text(version.value,5,manifest.merkle_root.data(),static_cast<int>(manifest.merkle_root.size()),SQLITE_TRANSIENT);
        if(root_bind!=SQLITE_OK)throw std::runtime_error(std::string("cannot bind snapshot Merkle root: ")+sqlite3_errmsg(impl_->db));
        sqlite3_bind_int64(version.value,6,static_cast<sqlite3_int64>(manifest.files.size()));
        if(sqlite3_step(version.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));
        for(const auto& file:manifest.files){Statement object(impl_->db,"INSERT INTO content_objects(hash,size,ref_count) VALUES(?,?,0) ON CONFLICT(hash) DO NOTHING");bind(object.value,1,file.sha256);sqlite3_bind_int64(object.value,2,static_cast<sqlite3_int64>(file.size));if(sqlite3_step(object.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));Statement verify(impl_->db,"SELECT size FROM content_objects WHERE hash=?");bind(verify.value,1,file.sha256);if(sqlite3_step(verify.value)!=SQLITE_ROW||sqlite3_column_int64(verify.value,0)!=static_cast<sqlite3_int64>(file.size))throw std::runtime_error("content object metadata mismatch");Statement entry(impl_->db,"INSERT INTO version_files(version_id,path,content_hash,size,modified_ticks) VALUES(?,?,?,?,?)");bind(entry.value,1,version_id);bind(entry.value,2,file.relative_path);bind(entry.value,3,file.sha256);sqlite3_bind_int64(entry.value,4,static_cast<sqlite3_int64>(file.size));sqlite3_bind_int64(entry.value,5,file.modified_ticks);if(sqlite3_step(entry.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));}
        sql_exec(impl_->db,"COMMIT");return version_id;
    }catch(...){try{sql_exec(impl_->db,"ROLLBACK");}catch(...){}throw;}
}

std::vector<StoredVersion> VersionStore::list_versions() const {
    Statement query(impl_->db,"SELECT id,COALESCE(parent_id,''),label,created_at_ms,merkle_root,file_count FROM version_records ORDER BY rowid");std::vector<StoredVersion> result;
    while(sqlite3_step(query.value)==SQLITE_ROW){StoredVersion v;v.record.id=column(query.value,0);v.record.parent_id=column(query.value,1);v.label=column(query.value,2);v.record.timestamp=sqlite3_column_int64(query.value,3);v.record.integrity_hash=column(query.value,4);v.record.snapshot_reference="full:"+v.record.id;v.file_count=static_cast<std::uint64_t>(sqlite3_column_int64(query.value,5));result.push_back(std::move(v));}return result;
}

bool VersionStore::restore(const std::string& version_id,const fs::path& folder,bool approved){
    if(!approved)throw std::runtime_error("restore requires explicit approval");
    if(!safe_relative_path(version_id)||version_id.find('/')!=std::string::npos)throw std::runtime_error("invalid version identifier");
    if(!fs::is_directory(folder))throw std::runtime_error("restore target folder must already exist");
    // A process crash can leave a pending journal. Before starting another restore,
    // restore the prior manifest first. The guard prevents recursive journal replay.
    static thread_local bool replaying_journal=false;
    const auto normalized_folder=fs::weakly_canonical(folder).string();
    if(!replaying_journal){
        Statement pending(impl_->db,"SELECT id,rollback_version FROM restore_journal WHERE folder=? AND status IN ('PENDING','RECOVERY_REQUIRED') ORDER BY updated_at_ms");bind(pending.value,1,normalized_folder);
        std::vector<std::pair<std::string,std::string>> journals;while(sqlite3_step(pending.value)==SQLITE_ROW)journals.emplace_back(column(pending.value,0),column(pending.value,1));
        for(const auto& journal:journals){
            replaying_journal=true;bool recovered=false;std::string failure;
            try{recovered=restore(journal.second,folder,true);}catch(const std::exception& e){failure=e.what();}catch(...){failure="unknown error while replaying restore journal";}
            replaying_journal=false;
            if(!recovered){if(failure.empty())failure="rollback restore returned an incomplete result";Statement blocked(impl_->db,"UPDATE restore_journal SET status='RECOVERY_REQUIRED',error=?,updated_at_ms=? WHERE id=?");
                const int error_bind=sqlite3_bind_text(blocked.value,1,failure.data(),static_cast<int>(failure.size()),SQLITE_TRANSIENT);if(error_bind!=SQLITE_OK)throw std::runtime_error(std::string("cannot bind recovery diagnostic: ")+sqlite3_errmsg(impl_->db));
                sqlite3_bind_int64(blocked.value,2,now_ms());
                const int journal_id_bind=sqlite3_bind_text(blocked.value,3,journal.first.data(),static_cast<int>(journal.first.size()),SQLITE_TRANSIENT);if(journal_id_bind!=SQLITE_OK)throw std::runtime_error(std::string("cannot bind restore journal ID: ")+sqlite3_errmsg(impl_->db));
                if(sqlite3_step(blocked.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));
                if(sqlite3_changes(impl_->db)!=1)throw std::runtime_error("failed to mark pending restore journal RECOVERY_REQUIRED: "+journal.first);
                throw std::runtime_error("pending restore could not be recovered; see restore journal "+journal.first+": "+failure);
            }
            Statement resolved(impl_->db,"UPDATE restore_journal SET status='RECOVERED',error='',updated_at_ms=? WHERE id=?");sqlite3_bind_int64(resolved.value,1,now_ms());bind(resolved.value,2,journal.first);if(sqlite3_step(resolved.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));
        }
    }
    // Replay is subordinate to the original pending entry. Creating a second
    // journal here would leave a stale rollback point if this replay crashed.
    const bool owns_journal=!replaying_journal;
    FileManifest desired;std::string expected_root;
    {Statement version(impl_->db,"SELECT merkle_root FROM version_records WHERE id=?");bind(version.value,1,version_id);if(sqlite3_step(version.value)!=SQLITE_ROW)throw std::runtime_error("version was not found");expected_root=column(version.value,0);}
    {Statement rows(impl_->db,"SELECT path,content_hash,size,modified_ticks FROM version_files WHERE version_id=? ORDER BY path");bind(rows.value,1,version_id);while(sqlite3_step(rows.value)==SQLITE_ROW){FileMetadata f;f.relative_path=column(rows.value,0);f.sha256=column(rows.value,1);f.size=static_cast<std::uintmax_t>(sqlite3_column_int64(rows.value,2));f.modified_ticks=sqlite3_column_int64(rows.value,3);if(!safe_relative_path(f.relative_path))throw std::runtime_error("unsafe path in saved version");desired.files.push_back(std::move(f));}}
    desired.merkle_root=merkle_root(desired.files);if(desired.merkle_root!=expected_root)throw std::runtime_error("saved version manifest integrity check failed");
    for(const auto& file:desired.files){const auto object=object_path(impl_->objects,file.sha256);reject_symlink_if_present(impl_->objects);reject_symlink_if_present(object.parent_path());reject_symlink_if_present(object);if(!fs::is_regular_file(object)||sha256_file(object)!=file.sha256)throw std::runtime_error("saved content is missing or corrupt: "+file.relative_path);}
    auto current=scan_folder(folder);if(!current.complete)throw std::runtime_error("restore refused: target scan is incomplete");
    const auto rollback_version=create_snapshot(folder,"automatic pre-restore recovery");
    std::map<std::string,FileMetadata> have,want;for(const auto& f:current.files)have.emplace(f.relative_path,f);for(const auto& f:desired.files)want.emplace(f.relative_path,f);
    const auto restore_id=id();
    if(owns_journal){Statement journal(impl_->db,"INSERT INTO restore_journal(id,folder,rollback_version,status,error,updated_at_ms) VALUES(?,?,?,'PENDING','',?)");bind(journal.value,1,restore_id);bind(journal.value,2,normalized_folder);bind(journal.value,3,rollback_version);sqlite3_bind_int64(journal.value,4,now_ms());if(sqlite3_step(journal.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));}
    std::vector<SyncJob> jobs;
    for(const auto& [path,file]:want){auto found=have.find(path);if(found!=have.end()&&found->second.sha256==file.sha256)continue;SyncJob job;job.id=restore_id+"-"+std::to_string(jobs.size());job.operation=found==have.end()?Operation::Add:Operation::Modify;job.source=object_path(impl_->objects,file.sha256);job.destination=folder/fs::u8path(path);job.relative_path=path;job.content_hash=file.sha256;if(found!=have.end())job.expected_destination_hash=found->second.sha256;jobs.push_back(std::move(job));}
    ActivityStore activity(impl_->state/"activity.sqlite3");
    const auto removed_root=impl_->recovery/restore_id/"removed";
    std::vector<std::pair<fs::path,fs::path>> moved;std::vector<SyncJob> deletion_events;
    const auto rollback=[&](){
        std::string errors;
        for(auto it=moved.rbegin();it!=moved.rend();++it){std::error_code ec;if(fs::exists(it->first,ec)){if(errors.empty())errors="cannot return removed path "+it->first.string();continue;}fs::rename(it->second,it->first,ec);if(ec&&errors.empty())errors="cannot return removed path "+it->first.string()+": "+ec.message();}
        for(auto it=jobs.rbegin();it!=jobs.rend();++it)if(it->state==JobState::SucceededVerified){try{ensure_no_symlink(folder,it->relative_path);const auto target=folder/fs::u8path(it->relative_path);if(!fs::is_regular_file(target)||sha256_file(target)!=it->content_hash)throw std::runtime_error("target changed before rollback");if(it->operation==Operation::Add){fs::remove(target);continue;}const auto previous=have.find(it->relative_path);if(previous==have.end())throw std::runtime_error("original file metadata is unavailable");auto backup=impl_->recovery/restore_id/fs::u8path(it->relative_path);if(!fs::exists(backup)||sha256_file(backup)!=previous->second.sha256)throw std::runtime_error("verified per-file recovery copy is unavailable");
#ifdef MERKLECHAIN_TESTING
                if(restore_fault_point==RestoreFaultPointForTesting::FailBeforeRollbackRestore){restore_fault_point=RestoreFaultPointForTesting::None;throw std::runtime_error("injected rollback failure before restoring verified backup");}
#endif
                auto staged_backup=impl_->recovery/restore_id/"rollback-staging"/fs::u8path(it->relative_path);fs::create_directories(staged_backup.parent_path());reject_symlink_if_present(staged_backup.parent_path());reject_symlink_if_present(staged_backup);
                if(fs::exists(staged_backup)&&sha256_file(staged_backup)!=previous->second.sha256)fs::remove(staged_backup);
                if(!fs::exists(staged_backup))fs::copy_file(backup,staged_backup,fs::copy_options::none);
                if(sha256_file(staged_backup)!=previous->second.sha256)throw std::runtime_error("staged rollback copy failed verification");
                fs::remove(target);fs::rename(staged_backup,target);}
            catch(const std::exception& e){if(errors.empty())errors="rollback failed for "+it->relative_path+": "+e.what();}}
        for(const auto& [path,file]:have){try{ensure_no_symlink(folder,path);const auto target=folder/fs::u8path(path);if(fs::is_regular_file(target)&&sha256_file(target)==file.sha256){std::error_code ec;fs::last_write_time(target,fs::file_time_type(fs::file_time_type::duration(file.modified_ticks)),ec);if(ec&&errors.empty())errors="cannot restore original timestamp for "+path+": "+ec.message();}}catch(const std::exception& e){if(errors.empty())errors="cannot restore original timestamp for "+path+": "+e.what();}}
        auto check=scan_folder(folder);if((!check.complete||check.merkle_root!=current.merkle_root)&&errors.empty())errors="rollback Merkle root does not match the pre-restore snapshot";
        return errors;
    };
    const auto journal_status=[&](const std::string& state,const std::string& error){if(!owns_journal)return;Statement update(impl_->db,"UPDATE restore_journal SET status=?,error=?,updated_at_ms=? WHERE id=?");bind(update.value,1,state);bind(update.value,2,error);sqlite3_bind_int64(update.value,3,now_ms());bind(update.value,4,restore_id);if(sqlite3_step(update.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));};
    try {
        std::size_t verified_jobs=0;const auto after_verified=[&](const SyncJob&){
#ifdef MERKLECHAIN_TESTING
            ++verified_jobs;if(restore_fault_point==RestoreFaultPointForTesting::CrashAfterFirstAppliedFile&&verified_jobs==1)std::_Exit(86);
#else
            (void)verified_jobs;
#endif
        };
        SyncExecutionOptions restore_options;restore_options.authorization={true,false};restore_options.use_chunking=false;
        const bool copied=execute_plan(jobs,folder,impl_->recovery/restore_id,after_verified,restore_options);for(const auto& job:jobs)activity.record(job);if(!copied){const auto rollback_error=rollback();journal_status(rollback_error.empty()?"ROLLED_BACK":"RECOVERY_REQUIRED",rollback_error);return false;}
        for(const auto& file:desired.files){const auto path=folder/fs::u8path(file.relative_path);ensure_no_symlink(folder,file.relative_path);std::error_code ec;fs::last_write_time(path,fs::file_time_type(fs::file_time_type::duration(file.modified_ticks)),ec);if(ec)throw std::runtime_error("cannot restore modification time for "+file.relative_path+": "+ec.message());}
        for(const auto& [path,file]:have)if(want.find(path)==want.end()){
            ensure_no_symlink(folder,path);auto source=folder/fs::u8path(path);if(!fs::is_regular_file(source)||sha256_file(source)!=file.sha256)throw std::runtime_error("target changed during restore: "+path);
            auto saved=removed_root/fs::u8path(path);fs::create_directories(saved.parent_path());if(fs::exists(saved))saved += "."+id();fs::rename(source,saved);moved.emplace_back(source,saved);
            SyncJob deletion;deletion.id=restore_id+"-delete-"+std::to_string(moved.size());deletion.operation=Operation::Delete;deletion.source=source;deletion.destination=saved;deletion.relative_path=path;deletion.content_hash=file.sha256;deletion.state=JobState::SucceededVerified;deletion.verified=true;deletion.bytes_transferred=file.size;deletion.started_at_ms=now_ms();deletion.completed_at_ms=deletion.started_at_ms;deletion_events.push_back(std::move(deletion));
        }
        auto result=scan_folder(folder);if(!result.complete||result.merkle_root!=desired.merkle_root)throw std::runtime_error("restored folder Merkle root does not match the saved version");
        for(const auto& event:deletion_events)activity.record(event);
        journal_status("COMMITTED","");
    } catch(const std::exception& failure) {
        const auto rollback_error=rollback();for(auto& event:deletion_events){event.state=JobState::Failed;event.verified=false;event.error="restore rolled back after failure";activity.record(event);}
        const std::string detail=rollback_error.empty()?failure.what():std::string(failure.what())+"; "+rollback_error;journal_status(rollback_error.empty()?"ROLLED_BACK":"RECOVERY_REQUIRED",detail);throw std::runtime_error(detail);
    }
    return true;
}

void VersionStore::delete_version(const std::string& version_id,bool approved){
    if(!approved)throw std::runtime_error("deleting a version requires explicit approval");
    sql_exec(impl_->db,"BEGIN IMMEDIATE");
    try {
        Statement exists(impl_->db,"SELECT 1 FROM version_records WHERE id=?");bind(exists.value,1,version_id);if(sqlite3_step(exists.value)!=SQLITE_ROW)throw std::runtime_error("version was not found");
        Statement journal(impl_->db,"SELECT 1 FROM restore_journal WHERE rollback_version=? AND status IN ('PENDING','RECOVERY_REQUIRED') LIMIT 1");bind(journal.value,1,version_id);if(sqlite3_step(journal.value)==SQLITE_ROW)throw std::runtime_error("cannot delete a version referenced by an unfinished restore journal");
        Statement child(impl_->db,"SELECT 1 FROM version_records WHERE parent_id=? LIMIT 1");bind(child.value,1,version_id);if(sqlite3_step(child.value)==SQLITE_ROW)throw std::runtime_error("cannot delete a version that has child versions");
        Statement remove(impl_->db,"DELETE FROM version_records WHERE id=?");bind(remove.value,1,version_id);if(sqlite3_step(remove.value)!=SQLITE_DONE||sqlite3_changes(impl_->db)!=1)throw std::runtime_error(sqlite3_errmsg(impl_->db));
        sql_exec(impl_->db,"COMMIT");
    } catch(...) {try{sql_exec(impl_->db,"ROLLBACK");}catch(...){}throw;}
}

std::size_t VersionStore::collect_unreferenced_objects(){
    sql_exec(impl_->db,"BEGIN IMMEDIATE");std::size_t removed=0;
    try {std::vector<std::string> hashes;{Statement rows(impl_->db,"SELECT hash FROM content_objects WHERE ref_count=0");while(sqlite3_step(rows.value)==SQLITE_ROW)hashes.push_back(column(rows.value,0));}for(const auto& hash:hashes){auto object=object_path(impl_->objects,hash);reject_symlink_if_present(impl_->objects);reject_symlink_if_present(object.parent_path());reject_symlink_if_present(object);if(fs::exists(object)){if(sha256_file(object)!=hash)continue;fs::remove(object);}Statement erase(impl_->db,"DELETE FROM content_objects WHERE hash=? AND ref_count=0");bind(erase.value,1,hash);if(sqlite3_step(erase.value)!=SQLITE_DONE)throw std::runtime_error(sqlite3_errmsg(impl_->db));removed+=static_cast<std::size_t>(sqlite3_changes(impl_->db));}sql_exec(impl_->db,"COMMIT");return removed;}
    catch(...){try{sql_exec(impl_->db,"ROLLBACK");}catch(...){}throw;}
}
}
