#include "merklechain/sync.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/staging_file.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <cctype>
#include <unordered_map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <memory>

namespace mc {
static std::string make_id(){static std::mt19937_64 gen(std::random_device{}());std::ostringstream s;s<<std::hex<<gen();return s.str();}
static void reject_symlink_path(const fs::path& root,const std::string& relative){
    fs::path current=root;
    for(const auto& part:fs::u8path(relative)){current/=part;std::error_code ec;auto status=fs::symlink_status(current,ec);if(ec==std::errc::no_such_file_or_directory)continue;if(ec)throw std::runtime_error("cannot inspect destination path: "+ec.message());if(fs::is_symlink(status))throw std::runtime_error("destination path crosses a symbolic link");}
}
std::vector<SyncJob> compare_manifests(const FileManifest& a,const FileManifest& b,const fs::path& ra,const fs::path& rb,const SyncScope& scope){
    if(!a.complete||!b.complete) throw std::runtime_error("Cannot create a trusted plan from an incomplete scan");
    std::map<std::string,FileMetadata> left,right;for(auto& f:a.files)left.emplace(f.relative_path,f);for(auto& f:b.files)right.emplace(f.relative_path,f);
    std::vector<SyncJob> jobs;
    for(const auto& [path,f]:left){
        if(!scope.is_in_scope(path)) continue;
        auto found=right.find(path);Operation op=found==right.end()?Operation::Add:(found->second.sha256==f.sha256?Operation::Unchanged:Operation::Modify);if(op==Operation::Unchanged)continue;
        SyncJob j;j.id=make_id();j.operation=op;j.source=ra/path;j.destination=rb/path;j.relative_path=path;j.content_hash=f.sha256;if(found!=right.end())j.expected_destination_hash=found->second.sha256;jobs.push_back(std::move(j));
    }
    // B-only files are not deleted automatically. Keep them intact and make direction explicit.
    for(const auto& [path,f]:right)if(left.find(path)==left.end()){
        SyncJob j;j.id=make_id();j.operation=Operation::Preserve;j.source=rb/path;j.destination=rb/path;j.relative_path=path;j.content_hash=f.sha256;
        j.error=scope.is_in_scope(path)?"Destination-only file preserved; no deletion scheduled":"Excluded from selection scope; preserved untouched";
        jobs.push_back(std::move(j));
    }
    return jobs;
}
namespace {
bool mutates(Operation operation){return operation==Operation::Add||operation==Operation::Modify||operation==Operation::Delete;}
bool authorized(Operation operation,const SchedulerAuthorization& authorization){
    if(operation==Operation::Add||operation==Operation::Modify)return authorization.changes_approved;
    if(operation==Operation::Delete)return authorization.changes_approved&&authorization.deletions_confirmed;
    return true;
}
}
bool execute_plan(std::vector<SyncJob>& jobs,const fs::path& destination_root,const fs::path& backup_root,const std::function<void(const SyncJob&)>& after_verified_job,SyncExecutionOptions options){
    bool all=true;
    std::set<std::string> planned_paths;
    for(auto& job:jobs)if(mutates(job.operation)){
        if(!safe_relative_path(job.relative_path)){job.state=JobState::Failed;job.error="unsafe relative path";all=false;continue;}
        if(!authorized(job.operation,options.authorization)){
            job.state=JobState::PendingApproval;
            job.error=job.operation==Operation::Delete?"delete requires change approval and explicit deletion confirmation":"mutation requires change approval";
            all=false;continue;
        }
        std::string folded=job.relative_path;
        std::transform(folded.begin(),folded.end(),folded.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
        bool conflict=!planned_paths.insert(folded).second;
        for(auto slash=folded.find('/');!conflict&&slash!=std::string::npos;slash=folded.find('/',slash+1))conflict=planned_paths.find(folded.substr(0,slash))!=planned_paths.end();
        const auto descendant=planned_paths.lower_bound(folded+"/");
        if(!conflict&&descendant!=planned_paths.end()&&descendant->compare(0,folded.size()+1,folded+"/")==0)conflict=true;
        if(conflict){job.state=JobState::Failed;job.error="plan contains conflicting mutations for the same path or file/directory dependency";all=false;}
    }
    if(!all)return false;

    std::vector<std::size_t> execution_order;
    if(options.use_scheduler){
        BinaryHeapScheduler scheduler(options.scheduler_weights);
        std::unordered_map<std::string,std::size_t> index_by_token;
        for(std::size_t index=0;index<jobs.size();++index){
            auto& job=jobs[index];if(!mutates(job.operation))continue;
            FileMetadata metadata;metadata.relative_path=job.relative_path;
            const auto measured_path=job.operation==Operation::Delete?job.destination:job.source;
            std::error_code ec;metadata.size=fs::file_size(measured_path,ec);if(ec)metadata.size=0;
            ec.clear();const auto modified=fs::last_write_time(measured_path,ec);
            metadata.modified_ticks=ec?0:static_cast<std::int64_t>(modified.time_since_epoch().count());
            auto queued=job;const auto token="mc-queue-"+std::to_string(index);queued.id=token;
            index_by_token.emplace(token,index);
            scheduler.enqueue(std::move(queued),metadata,job.enqueued_at,options.file_clock_now);
        }
        while(auto selected=scheduler.try_dequeue(options.scheduler_now,options.authorization)){
            const auto found=index_by_token.find(selected->id);
            if(found==index_by_token.end())throw std::logic_error("scheduler returned an unknown synchronization job");
            jobs[found->second].priority=selected->priority;
            execution_order.push_back(found->second);
        }
        if(execution_order.size()!=index_by_token.size()){
            for(std::size_t index=0;index<jobs.size();++index)if(mutates(jobs[index].operation)&&jobs[index].state==JobState::Planned){jobs[index].state=JobState::PendingApproval;jobs[index].error="scheduler did not dispatch the approved mutation";}
            return false;
        }
    }else{
        for(std::size_t index=0;index<jobs.size();++index)if(mutates(jobs[index].operation))execution_order.push_back(index);
    }

    fs::create_directories(backup_root);
    for(const auto index:execution_order){auto& j=jobs[index];
        // Recheck at the execution boundary; selecting a job never grants consent.
        if(!authorized(j.operation,options.authorization)){j.state=JobState::PendingApproval;j.error="mutation authorization is missing";all=false;continue;}
        j.state=JobState::InProgress;
        j.started_at_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        fs::path staged,backup;std::unique_ptr<StagingFile> staged_file;bool backed_up=false,committed=false;
        try{
            if(!safe_relative_path(j.relative_path))throw std::runtime_error("unsafe relative path");
            reject_symlink_path(destination_root,j.relative_path);auto target=destination_root/fs::u8path(j.relative_path);fs::create_directories(target.parent_path());
            backup=backup_root/fs::path(j.relative_path);fs::create_directories(backup.parent_path());if(fs::exists(backup))backup += "."+j.id;
            if(j.operation==Operation::Delete){
                const auto expected=j.expected_destination_hash.empty()?j.content_hash:j.expected_destination_hash;
                if(!fs::is_regular_file(target)||expected.empty()||sha256_file(target)!=expected)throw std::runtime_error("destination changed after preview");
                fs::rename(target,backup);backed_up=true;committed=true;
                j.verified=sha256_file(backup)==expected;if(!j.verified)throw std::runtime_error("recovery copy verification failed");
            }else{
                if(sha256_file(j.source)!=j.content_hash)throw std::runtime_error("source changed after preview");
                if(j.operation==Operation::Add&&fs::exists(target))throw std::runtime_error("destination path appeared after preview");
                if(j.operation==Operation::Modify&&(!fs::exists(target)||sha256_file(target)!=j.expected_destination_hash))throw std::runtime_error("destination changed after preview");
                staged=target;staged += ".merklechain-tmp-"+j.id;
                staged_file=std::make_unique<StagingFile>(staged);
                if(options.use_chunking){
                    const auto transfer=copy_file_chunked_or_fallback(j.source,target,*staged_file,j.content_hash,
                        j.operation==Operation::Modify?j.expected_destination_hash:std::string{},options.chunk_size_bytes);
                    j.bytes_transferred=transfer.bytes_transferred;
                    j.source_bytes_processed=transfer.source_bytes_processed;
                    j.bytes_reused=transfer.reused_bytes;
                    j.bytes_written=transfer.bytes_written;
                    j.chunk_size_bytes=transfer.used_chunks?options.chunk_size_bytes:0;
                    j.chunks_total=transfer.chunk_count;
                    j.chunks_reused=transfer.reused_chunks;
                    j.chunked_transfer=transfer.used_chunks;
                    j.transfer_fallback_reason=transfer.fallback_reason;
                }else{
                    copy_file_to_staging(j.source,*staged_file,j.content_hash,&j.source_bytes_processed);
                    j.bytes_transferred=staged_file->size();
                    j.bytes_written=staged_file->bytes_written();
                }
                if(staged_file->sha256()!=j.content_hash)throw std::runtime_error("staged hash mismatch");
                if(sha256_file(j.source)!=j.content_hash)throw std::runtime_error("source changed after preview");
                if(j.operation==Operation::Add&&fs::exists(target))throw std::runtime_error("destination path appeared after preview");
                if(j.operation==Operation::Modify&&(!fs::exists(target)||sha256_file(target)!=j.expected_destination_hash))throw std::runtime_error("destination changed after preview");
                if(fs::exists(target)){if(fs::exists(backup))backup += "."+j.id;fs::rename(target,backup);backed_up=true;}
                staged_file->commit_to(target,j.content_hash);committed=true;
                j.verified=staged_file->sha256()==j.content_hash;if(!j.verified)throw std::runtime_error("post-commit verification failed");
            }
            j.state=JobState::SucceededVerified;
        }catch(const std::exception& e){
            std::error_code ignored;
            std::string failure_message=e.what();
            auto target=destination_root/fs::u8path(j.relative_path);
            if(staged_file){
                if(committed){
                    auto quarantine=staged;quarantine += ".failed-"+j.id;
                    try{staged_file->move_failed_commit_to(quarantine);if(!staged_file->discard())failure_message += "; failed to remove quarantined staging file";}
                    catch(const std::exception& cleanup_error){failure_message += "; rollback staging quarantine failed: "+std::string(cleanup_error.what());}
                }else if(!staged_file->discard())failure_message += "; failed to remove incomplete staging file";
                staged_file.reset();
            }
            if(backed_up&&fs::exists(backup,ignored)&&!fs::exists(target,ignored))fs::rename(backup,target,ignored);
            j.state=JobState::Failed;j.error=std::move(failure_message);all=false;
        }
        j.completed_at_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if(j.state==JobState::SucceededVerified&&after_verified_job)after_verified_job(j);
    }
    return all;
}
}
