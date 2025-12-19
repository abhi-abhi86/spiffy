cmake_minimum_required(VERSION 3.15)
project(spiffy_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimization flags
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -DNDEBUG")
endif()

# Find Python
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# Find pybind11 using Python
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -m pybind11 --cmakedir
    OUTPUT_VARIABLE pybind11_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
find_package(pybind11 CONFIG REQUIRED)

# Find OpenSSL for crypto acceleration
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

# Source files
set(SOURCES
    network_scanner.cpp
    crypto_accelerator.cpp
    data_processor.cpp
    bindings.cpp
)

# Create Python module
pybind11_add_module(spiffy_cpp ${SOURCES})

# Link libraries
target_link_libraries(spiffy_cpp PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Platform-specific settings
if(APPLE)
    target_link_libraries(spiffy_cpp PRIVATE "-framework CoreFoundation")
endif()

# Installation
install(TARGETS spiffy_cpp LIBRARY DESTINATION .)
