#pragma once
#include <cstdint>

namespace mc {
// Runs a single-threaded HTTP service bound only to IPv4 loopback.
void run_web_server(std::uint16_t port = 47831);
}
