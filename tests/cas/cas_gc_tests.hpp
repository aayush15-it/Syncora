#pragma once

#include "merklechain/collab_store.hpp"
#include <filesystem>

namespace mc::cas {

void run_cas_gc_tests(const mc::fs::path& fixture_root, void (*check)(bool, const char*));

} // namespace mc::cas
