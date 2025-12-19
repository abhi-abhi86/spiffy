cmake_minimum_required(VERSION 3.20)
project(spiffy_omega VERSION 29.0 LANGUAGES CXX)

# C++20 Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")

# Find dependencies
find_package(Boost 1.70 REQUIRED COMPONENTS system thread)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${SQLite3_INCLUDE_DIRS}
)

# Source files
set(SOURCES
    src/core/watchdog.cpp
    src/core/token_system.cpp
    src/core/vault.cpp
    src/bifrost/crypto.cpp
    src/bifrost/p2p_server.cpp
    src/bifrost/p2p_client.cpp
    src/recon/wifi_radar.cpp
    src/recon/fingerprint.cpp
    src/offensive/auto_fuzzer.cpp
    src/offensive/stressor.cpp
    src/defensive/mitm_sentinel.cpp
    src/defensive/ssl_probe.cpp
)

# Main executable
add_executable(spiffy_omega
    spiffy_omega.cpp
    ${SOURCES}
)

# Link libraries
target_link_libraries(spiffy_omega
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    Threads::Threads
)

# Installation
install(TARGETS spiffy_omega DESTINATION bin)

message(STATUS "Spiffy Omega-Infinity v29.0 - C++20 Kernel")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Boost Version: ${Boost_VERSION}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
