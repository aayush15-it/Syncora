#pragma once

#include "merklechain/types.hpp"

namespace mc::cas {

void run_cas_tests(const mc::fs::path& fixture_root, void (*check)(bool, const char*));
void run_cas_collab_integration_tests(const mc::fs::path& fixture_root, void (*check)(bool, const char*));

} // namespace mc::cas

