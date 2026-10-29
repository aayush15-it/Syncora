#pragma once
#include "merklechain/types.hpp"
#include <optional>

namespace mc {
#ifdef MERKLECHAIN_TESTING
enum class RestoreFaultPointForTesting { None, CrashAfterFirstAppliedFile, FailBeforeRollbackRestore };
void set_restore_fault_point_for_testing(RestoreFaultPointForTesting point);
#endif
struct StoredVersion {
    VersionRecord record;
    std::string label;
    std::uint64_t file_count{};
};

class VersionStore {
public:
    VersionStore(const fs::path& database_file,const fs::path& state_directory);
    ~VersionStore();
    VersionStore(const VersionStore&)=delete;
    VersionStore& operator=(const VersionStore&)=delete;
    std::string create_snapshot(const fs::path& folder,const std::string& label,const std::string& parent_id={});
    std::vector<StoredVersion> list_versions() const;
    bool restore(const std::string& version_id,const fs::path& folder,bool approved);
    void delete_version(const std::string& version_id,bool approved);
    std::size_t collect_unreferenced_objects();
private:
    struct Impl; Impl* impl_;
};
}
