#pragma once
#include "merklechain/types.hpp"
namespace mc {
class ActivityStore {
public:
    explicit ActivityStore(const fs::path& file);
    ~ActivityStore();
    ActivityStore(const ActivityStore&) = delete;
    ActivityStore& operator=(const ActivityStore&) = delete;
    void record(const SyncJob& job);
private: struct Impl; Impl* impl_;
};
std::string operation_name(Operation operation);
std::string job_state_name(JobState state);
}
