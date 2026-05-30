# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

target_sources(statusbar-crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/sha256.cpp
                                        ${CMAKE_CURRENT_LIST_DIR}/sha512.cpp)

# Hardware-accelerated implementations (platform-specific). See the note in
# aes/CMakeLists.txt — march flags come from STATUSBAR_CRYPTO_ARCH_FLAGS.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
  target_sources(
    statusbar-crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/sha256_hw_arm64.cpp
                             ${CMAKE_CURRENT_LIST_DIR}/sha512_hw_arm64.cpp)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  target_sources(
    statusbar-crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/sha256_hw_amd64.cpp
                             ${CMAKE_CURRENT_LIST_DIR}/sha512_hw_amd64.cpp)
endif()

add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/sha256_fuzzer.cpp)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_TEST_FILES
           ${CMAKE_CURRENT_LIST_DIR}/sha256_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/sha256_hw_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/sha512_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/sha512_hw_test.cpp)
