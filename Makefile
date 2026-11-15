SHELL := /usr/bin/sh
CXX := C:/msys64/ucrt64/bin/g++.exe
PKG_CONFIG := C:/msys64/ucrt64/bin/pkg-config.exe
export PATH := /ucrt64/bin:/usr/bin:$(PATH)
CPPFLAGS := -Iinclude $(shell "$(PKG_CONFIG)" --cflags openssl sqlite3)
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -O2
LDLIBS := $(shell "$(PKG_CONFIG)" --libs openssl sqlite3) -lws2_32 -lshell32 -luuid -lpsapi
PEER_SOURCES := src/peer/peer_protocol.cpp src/peer/peer_config.cpp src/peer/peer_auth.cpp src/peer/peer_transport.cpp src/peer/peer_sync.cpp src/peer/peer_session.cpp src/peer/peer_service.cpp src/peer/peer_controller.cpp src/peer/peer_cas_helpers.cpp
CAS_SOURCES := src/cas/chunker.cpp src/cas/file_manifest.cpp src/cas/manifest_serializer.cpp src/cas/object_store.cpp src/cas/object_verifier.cpp
BASE_SOURCES := src/main.cpp src/hash.cpp src/scanner.cpp src/chunk_sync.cpp src/sync.cpp src/storage.cpp src/versioning.cpp src/scheduler.cpp src/staging_file.cpp src/folder_picker.cpp src/collab_store.cpp src/collab_broadcaster.cpp src/web_server.cpp
SOURCES := $(BASE_SOURCES) $(PEER_SOURCES) $(CAS_SOURCES)
HEADERS := $(wildcard include/merklechain/*.hpp include/merklechain/peer/*.hpp include/merklechain/cas/*.hpp)
OBJECTS := $(patsubst src/%.cpp,build/%.o,$(BASE_SOURCES)) build/peer_protocol.o build/peer_config.o build/peer_auth.o build/peer_transport.o build/peer_sync.o build/peer_session.o build/peer_service.o build/peer_controller.o build/peer_cas_helpers.o
TARGET := build/merklechain.exe
DASHBOARD_PORT ?= 47831
# Optional Authenticode code signing thumbprint (disabled by default)
SIGNING_THUMBPRINT ?=
TEST_SOURCES := tests/test_main.cpp tests/branching_tests.cpp tests/branching_api_and_sse_tests.cpp tests/peer_cas_helpers_tests.cpp tests/peer_sync_cas_delta_tests.cpp tests/cas/cas_tests.cpp tests/cas/cas_collab_integration_tests.cpp tests/cas/cas_gc_tests.cpp tests/collab_store_tests.cpp tests/peer_transport_tests.cpp tests/peer_sync_tests.cpp tests/peer_session_tests.cpp tests/peer_service_tests.cpp src/hash.cpp src/scanner.cpp src/chunk_sync.cpp src/sync.cpp src/storage.cpp src/versioning.cpp src/scheduler.cpp src/staging_file.cpp src/folder_picker.cpp src/collab_store.cpp src/collab_broadcaster.cpp src/web_server.cpp $(PEER_SOURCES) $(CAS_SOURCES)
BENCH_SOURCES := benchmarks/chunk_benchmark.cpp src/chunk_sync.cpp src/hash.cpp src/staging_file.cpp
CAS_BENCH_SOURCES := benchmarks/cas_benchmark.cpp $(CAS_SOURCES) src/hash.cpp
CAS_NET_BENCH_SOURCES := benchmarks/cas_network_benchmark.cpp src/hash.cpp src/scanner.cpp src/chunk_sync.cpp src/sync.cpp src/storage.cpp src/versioning.cpp src/scheduler.cpp src/staging_file.cpp src/collab_store.cpp $(PEER_SOURCES) $(CAS_SOURCES)

.PHONY: all test benchmark cas-benchmark cas-net-benchmark dashboard-test clean run-local run-dashboard help sign
all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING $(SOURCES) -o $@ $(LDLIBS)
	@if [ -n "$(SIGNING_THUMBPRINT)" ]; then \
		powershell -Command "if (Test-Path 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)') { Set-AuthenticodeSignature -Certificate (Get-Item 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)') -FilePath $@ | Out-Null }"; \
	fi

build/%.o: src/%.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_protocol.o: src/peer/peer_protocol.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_config.o: src/peer/peer_config.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_auth.o: src/peer/peer_auth.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_transport.o: src/peer/peer_transport.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_sync.o: src/peer/peer_sync.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_session.o: src/peer/peer_session.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_service.o: src/peer/peer_service.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_controller.o: src/peer/peer_controller.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

build/peer_cas_helpers.o: src/peer/peer_cas_helpers.cpp $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING -c $< -o $@

TEST_LDLIBS := $(shell "$(PKG_CONFIG)" --libs openssl sqlite3) -lws2_32 -lshell32 -luuid -lpsapi

build/tests.exe: $(TEST_SOURCES) $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DMERKLECHAIN_TESTING $(TEST_SOURCES) -o $@ $(TEST_LDLIBS)
	@if [ -n "$(SIGNING_THUMBPRINT)" ]; then \
		powershell -Command "if (Test-Path 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)') { Set-AuthenticodeSignature -Certificate (Get-Item 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)') -FilePath $@ | Out-Null }"; \
	fi

build/chunk_benchmark.exe: $(BENCH_SOURCES) $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING $(BENCH_SOURCES) -o $@ $(TEST_LDLIBS)

build/cas_benchmark.exe: $(CAS_BENCH_SOURCES) $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING $(CAS_BENCH_SOURCES) -o $@ $(TEST_LDLIBS)

build/cas_network_benchmark.exe: $(CAS_NET_BENCH_SOURCES) $(HEADERS)
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -UMERKLECHAIN_TESTING $(CAS_NET_BENCH_SOURCES) -o $@ $(TEST_LDLIBS)
	@if [ -n "$(SIGNING_THUMBPRINT)" ]; then \
		powershell -Command "if (Test-Path 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)') { Set-AuthenticodeSignature -Certificate (Get-Item 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)') -FilePath $@ | Out-Null }"; \
	fi

test: build/tests.exe
	build/tests.exe

benchmark: build/chunk_benchmark.exe
	build/chunk_benchmark.exe

cas-benchmark: build/cas_benchmark.exe
	build/cas_benchmark.exe

cas-net-benchmark: build/cas_network_benchmark.exe
	build/cas_network_benchmark.exe

run-local: $(TARGET)
	$(TARGET) --local

run-dashboard: $(TARGET)
	$(TARGET) --dashboard $(DASHBOARD_PORT)

dashboard-test: $(TARGET)
	powershell.exe -NoProfile -File tests/dashboard_smoke.ps1 -ExecutablePath "$(TARGET)"

help: $(TARGET)
	$(TARGET) --help

sign: $(TARGET)
	@powershell -Command "if ('$(SIGNING_THUMBPRINT)' -ne '' -and (Test-Path 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)')) { Set-AuthenticodeSignature -Certificate (Get-Item 'Cert:\CurrentUser\My\$(SIGNING_THUMBPRINT)') -FilePath $(TARGET); Write-Host 'Signed $(TARGET) with certificate $(SIGNING_THUMBPRINT)' } else { Write-Error 'Signing requires valid SIGNING_THUMBPRINT environment variable or parameter.' }"

clean:
	rm -rf build
