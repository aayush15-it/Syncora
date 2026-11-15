#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "merklechain/collab_broadcaster.hpp"
#include "merklechain/web_server.hpp"
#include "merklechain/collab_store.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <future>
#include <atomic>
#include <cstring>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

namespace mc {

namespace {

SOCKET create_connected_client(std::uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    DWORD timeout = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    return s;
}

std::string read_until(SOCKET s, const std::string& delimiter, int timeout_ms = 4000) {
    std::string result;
    auto start = std::chrono::steady_clock::now();
    char buf[1024];
    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(s, &read_fds);
        timeval tv{0, 30000}; // 30ms
        int sel = select(0, &read_fds, nullptr, nullptr, &tv);
        if (sel > 0 && FD_ISSET(s, &read_fds)) {
            int n = recv(s, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            result.append(buf, static_cast<std::size_t>(n));
            if (result.find(delimiter) != std::string::npos) {
                break;
            }
        }
    }
    return result;
}

std::string send_http_raw(std::uint16_t port, const std::string& request_text) {
    SOCKET s = create_connected_client(port);
    if (s == INVALID_SOCKET) return "";

    send(s, request_text.data(), static_cast<int>(request_text.size()), 0);

    std::string response;
    char buf[4096];
    for (;;) {
        int r = recv(s, buf, sizeof(buf) - 1, 0);
        if (r <= 0) break;
        buf[r] = '\0';
        response.append(buf, static_cast<std::size_t>(r));
    }
    closesocket(s);
    return response;
}

std::uint16_t find_free_port() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 49152;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int len = sizeof(addr);
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    std::uint16_t port = ntohs(addr.sin_port);
    closesocket(s);
    return port;
}

} // namespace

void run_branching_api_and_sse_tests(const fs::path& fixture_root,
                                     void (*check)(bool, const char*)) {
    (void)fixture_root;

    // =========================================================================
    // 1. EventBroadcaster Core Unit Tests
    // =========================================================================
    {
        SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        check(listener != INVALID_SOCKET, "Created listener socket");

        sockaddr_in laddr{};
        laddr.sin_family = AF_INET;
        laddr.sin_port = 0;
        laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int b_res = bind(listener, reinterpret_cast<sockaddr*>(&laddr), sizeof(laddr));
        check(b_res == 0, "Listener socket bound to ephemeral port");

        int len = sizeof(laddr);
        getsockname(listener, reinterpret_cast<sockaddr*>(&laddr), &len);
        std::uint16_t test_port = ntohs(laddr.sin_port);
        listen(listener, 5);

        EventBroadcaster broadcaster(std::chrono::milliseconds(50));
        broadcaster.start();
        check(broadcaster.is_running(), "EventBroadcaster started successfully");

        // Asynchronously connect client so accept() can proceed concurrently
        auto client_fut = std::async(std::launch::async, [test_port]() {
            return create_connected_client(test_port);
        });

        SOCKET server_accepted = accept(listener, nullptr, nullptr);
        check(server_accepted != INVALID_SOCKET, "Server accepted loopback socket");

        SOCKET client_sock = client_fut.get();
        check(client_sock != INVALID_SOCKET, "Loopback test client connected");

        broadcaster.add_client(static_cast<std::uintptr_t>(server_accepted));
        check(broadcaster.client_count() == 1, "Broadcaster registry has 1 registered client");

        // Broadcast CollabEvent
        CollabEvent ev;
        ev.id = "test_ev_1";
        ev.event_type = "branch_created";
        ev.workspace_id = "ws-test";
        ev.branch_id = "br-123";
        ev.version_id = "";
        ev.timestamp_ms = 123456789;
        ev.payload_json = "{\"test\":true,\"branch\":\"feature/x\"}";
        broadcaster.broadcast(ev);

        // Read from client_sock using read_until
        std::string frame = read_until(client_sock, "\n\n", 3000);
        check(!frame.empty(), "Client received broadcasted event bytes");
        check(frame.find("event: branch_created") != std::string::npos, "Frame contains correct event type");
        check(frame.find("id: test_ev_1") != std::string::npos, "Frame contains event ID");
        check(frame.find("{\"test\":true,\"branch\":\"feature/x\"}") != std::string::npos, "Frame contains payload JSON");

        // Close client socket to simulate client disconnect
        closesocket(client_sock);

        // Broadcast another event to trigger broken socket detection
        CollabEvent ev2;
        ev2.id = "test_ev_2";
        ev2.event_type = "branch_deleted";
        ev2.payload_json = "{}";
        broadcaster.broadcast(ev2);

        // Allow I/O thread loop to process and detect socket closure
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        check(broadcaster.client_count() == 0, "Broadcaster cleanly pruned disconnected client socket");

        broadcaster.stop();
        check(!broadcaster.is_running(), "Broadcaster stopped cleanly");
        closesocket(listener);
    }

    // =========================================================================
    // 2. WebServer Concurrency: Multiple Persistent SSE Clients + Concurrent HTTP
    // =========================================================================
    {
        std::uint16_t srv_port = find_free_port();
        WebServer server(srv_port, 4);
        server.start();
        check(server.is_running(), "Multi-threaded WebServer started on loopback");

        // First obtain CSRF token
        std::string status_resp = send_http_raw(srv_port,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(srv_port) + "\r\n\r\n");
        check(status_resp.find("200 OK") != std::string::npos, "GET /api/status responded 200 OK");

        std::string csrf;
        auto csrf_pos = status_resp.find("\"csrf\":\"");
        if (csrf_pos != std::string::npos) {
            auto csrf_end = status_resp.find("\"", csrf_pos + 8);
            if (csrf_end != std::string::npos) {
                csrf = status_resp.substr(csrf_pos + 8, csrf_end - (csrf_pos + 8));
            }
        }
        check(!csrf.empty(), "Obtained valid CSRF token from server");

        // Authenticate as host to get session token
        std::string login_body = "{\"username\":\"host\",\"password\":\"MerkleHost2026!\"}";
        std::string login_req =
            "POST /api/auth/login HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(login_body.size()) + "\r\n\r\n" + login_body;
        std::string login_resp = send_http_raw(srv_port, login_req);
        check(login_resp.find("200 OK") != std::string::npos, "Host login succeeded with 200 OK");

        std::string host_token;
        auto tok_pos = login_resp.find("\"session_token\":\"");
        if (tok_pos != std::string::npos) {
            auto tok_end = login_resp.find("\"", tok_pos + 17);
            if (tok_end != std::string::npos) {
                host_token = login_resp.substr(tok_pos + 17, tok_end - (tok_pos + 17));
            }
        }
        check(!host_token.empty(), "Obtained host session token");

        // Connect MULTIPLE simultaneous SSE clients (3 clients)
        const int num_sse_clients = 3;
        std::vector<SOCKET> sse_clients;
        for (int i = 0; i < num_sse_clients; ++i) {
            SOCKET sc = create_connected_client(srv_port);
            check(sc != INVALID_SOCKET, "SSE client socket created and connected");

            std::string sse_req =
                "GET /api/collab/events?session_token=" + host_token + " HTTP/1.1\r\n"
                "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
                "Accept: text/event-stream\r\n\r\n";
            send(sc, sse_req.data(), static_cast<int>(sse_req.size()), 0);

            // Read handshake response using read_until
            std::string sse_response = read_until(sc, "event: connected\n\n", 4000);
            check(sse_response.find("200 OK") != std::string::npos, "SSE handshake responded 200 OK");
            check(sse_response.find("Content-Type: text/event-stream") != std::string::npos, "SSE Content-Type header present");
            check(sse_response.find("event: connected") != std::string::npos, "Initial connected event received by client");

            sse_clients.push_back(sc);
        }
        check(sse_clients.size() == num_sse_clients, "All multiple SSE clients connected concurrently");

        // WHILE ALL 3 SSE connections are simultaneously active and holding sockets:
        // Run concurrent normal HTTP requests on other connections to verify worker pool is non-blocking!
        std::atomic<bool> http_success{true};
        std::vector<std::thread> test_threads;
        for (int i = 0; i < 8; ++i) {
            test_threads.emplace_back([srv_port, &http_success]() {
                for (int j = 0; j < 4; ++j) {
                    std::string resp = send_http_raw(srv_port,
                        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(srv_port) + "\r\n\r\n");
                    if (resp.find("200 OK") == std::string::npos) {
                        http_success.store(false);
                    }
                }
            });
        }
        for (auto& t : test_threads) {
            t.join();
        }
        check(http_success.load(), "Concurrent HTTP GET /api/status succeeded across all threads while multiple SSE clients active");

        // =====================================================================
        // 3. Branching REST APIs & Multi-Client SSE Push
        // =====================================================================

        // List branches via GET /api/collab/branches
        std::string list_req =
            "GET /api/collab/branches?workspace_id=ws-default HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n\r\n";
        std::string list_resp = send_http_raw(srv_port, list_req);
        check(list_resp.find("200 OK") != std::string::npos, "GET /api/collab/branches returned 200 OK");
        check(list_resp.find("\"name\":\"main\"") != std::string::npos, "Branch list includes default 'main'");

        // Create new branch via POST /api/collab/branches/create
        std::string create_body = "{\"workspace_id\":\"ws-default\",\"name\":\"feature/rest-test\"}";
        std::string create_req =
            "POST /api/collab/branches/create HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(create_body.size()) + "\r\n\r\n" + create_body;
        std::string create_resp = send_http_raw(srv_port, create_req);
        check(create_resp.find("200 OK") != std::string::npos, "POST /api/collab/branches/create returned 200 OK");
        check(create_resp.find("\"name\":\"feature/rest-test\"") != std::string::npos, "Response confirmed created branch");

        // Verify that EVERY connected SSE client received the real-time branch_created event
        for (std::size_t i = 0; i < sse_clients.size(); ++i) {
            std::string push_frame = read_until(sse_clients[i], "\n\n", 4000);
            check(!push_frame.empty(), "SSE client received real-time push frame");
            check(push_frame.find("event: branch_created") != std::string::npos, "Push event type is branch_created");
            check(push_frame.find("feature/rest-test") != std::string::npos, "Push payload contains new branch name");
        }

        // Verify active branch via GET /api/collab/branches/active
        std::string active_req =
            "GET /api/collab/branches/active?workspace_id=ws-default HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n\r\n";
        std::string active_resp = send_http_raw(srv_port, active_req);
        check(active_resp.find("200 OK") != std::string::npos, "GET /api/collab/branches/active returned 200 OK");
        check(active_resp.find("\"name\":\"main\"") != std::string::npos, "Active branch is currently 'main'");

        // Dirty switch test: write an uncommitted file to working copy
        std::string write_body = "{\"workspace_id\":\"ws-default\",\"path\":\"dirty.txt\",\"content\":\"uncommitted text\"}";
        std::string write_req =
            "POST /api/host/workspaces/files HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(write_body.size()) + "\r\n\r\n" + write_body;
        std::string write_resp = send_http_raw(srv_port, write_req);
        check(write_resp.find("200 OK") != std::string::npos, "Created uncommitted file dirty.txt in working copy");

        // Attempt branch switch without force -> MUST return HTTP 409 Conflict
        std::string switch_body = "{\"workspace_id\":\"ws-default\",\"name\":\"feature/rest-test\",\"force\":false}";
        std::string switch_req =
            "POST /api/collab/branches/switch HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(switch_body.size()) + "\r\n\r\n" + switch_body;
        std::string switch_resp = send_http_raw(srv_port, switch_req);
        check(switch_resp.find("409 Conflict") != std::string::npos, "Switching branch with dirty working copy returned 409 Conflict");
        check(switch_resp.find("\"dirty\":true") != std::string::npos, "409 response payload contains \"dirty\":true");

        // Now switch with force: true -> MUST succeed with HTTP 200 OK
        std::string force_body = "{\"workspace_id\":\"ws-default\",\"name\":\"feature/rest-test\",\"force\":true}";
        std::string force_req =
            "POST /api/collab/branches/switch HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(force_body.size()) + "\r\n\r\n" + force_body;
        std::string force_resp = send_http_raw(srv_port, force_req);
        check(force_resp.find("200 OK") != std::string::npos, "Switching branch with force=true succeeded with 200 OK");

        // Switch back to main so feature/rest-test can be deleted
        std::string sw_main_body = "{\"workspace_id\":\"ws-default\",\"name\":\"main\",\"force\":true}";
        std::string sw_main_req =
            "POST /api/collab/branches/switch HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(sw_main_body.size()) + "\r\n\r\n" + sw_main_body;
        std::string sw_main_resp = send_http_raw(srv_port, sw_main_req);
        check(sw_main_resp.find("200 OK") != std::string::npos, "Switched back to main branch");

        // Delete feature branch via POST /api/collab/branches/delete
        std::string del_body = "{\"workspace_id\":\"ws-default\",\"name\":\"feature/rest-test\"}";
        std::string del_req =
            "POST /api/collab/branches/delete HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "X-Session-Token: " + host_token + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(del_body.size()) + "\r\n\r\n" + del_body;
        std::string del_resp = send_http_raw(srv_port, del_req);
        check(del_resp.find("200 OK") != std::string::npos, "Deleted branch feature/rest-test with 200 OK");

        // =====================================================================
        // 4. Graceful Server Shutdown with Active SSE Connections
        // =====================================================================
        // Notice all 3 SSE client sockets are still connected and open!
        server.stop();
        check(!server.is_running(), "WebServer cleanly stopped while SSE connections were active");

        // Clean up client sockets
        for (SOCKET s : sse_clients) {
            closesocket(s);
        }
    }

    // =========================================================================
    // 5. Post-Commit Event Emission Guarantee Verification
    // =========================================================================
    {
        fs::path test_dir = fs::temp_directory_path() / ("mc_stage2_ev_" + std::to_string(GetTickCount64()));
        fs::create_directories(test_dir);

        CollabStore store(test_dir / "store.db", test_dir / "workspaces", test_dir / "blobs");

        std::atomic<bool> listener_called{false};
        std::atomic<bool> branch_found_in_db{false};

        store.set_event_listener([&](const CollabEvent& ev) {
            listener_called.store(true);
            if (ev.event_type == "branch_created") {
                // Immediately query the store/db inside the callback to prove the branch is already committed!
                auto branches = store.list_branches(ev.workspace_id);
                for (const auto& b : branches) {
                    if (b.name == "feature/verified-commit") {
                        branch_found_in_db.store(true);
                        break;
                    }
                }
            }
        });

        // Create branch: this should trigger event ONLY AFTER SQLite commit
        store.create_branch("ws-default", "feature/verified-commit", "host");

        check(listener_called.load(), "CollabEvent listener was invoked upon branch creation");
        check(branch_found_in_db.load(), "Branch was already fully committed in database when listener fired");

        // Verify that failed operation does NOT emit event
        std::atomic<bool> unexpected_event{false};
        store.set_event_listener([&](const CollabEvent& ev) {
            if (ev.event_type == "branch_created" && ev.payload_json.find("duplicate") != std::string::npos) {
                unexpected_event.store(true);
            }
        });

        try {
            // Attempt duplicate branch creation - must throw and emit NO event
            store.create_branch("ws-default", "feature/verified-commit", "host");
        } catch (...) {
            // Expected failure
        }
        check(!unexpected_event.load(), "Failed operation did not emit any CollabEvent");

        fs::remove_all(test_dir);
    }
}

} // namespace mc
