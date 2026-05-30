# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

target_sources(statusbar-crypto
               PRIVATE ${CMAKE_CURRENT_LIST_DIR}/polyval_sw.cpp)

# Hardware-accelerated implementation (platform-specific). See the note in
# aes/CMakeLists.txt — march flags come from STATUSBAR_CRYPTO_ARCH_FLAGS.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
  target_sources(statusbar-crypto
                 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/polyval_hw_arm64.cpp)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  target_sources(statusbar-crypto
                 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/polyval_hw_amd64.cpp)
endif()
add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/polyval_fuzzer.cpp)

set_property(
  GLOBAL APPEND PROPERTY STATUSBAR_TEST_FILES
                         ${CMAKE_CURRENT_LIST_DIR}/polyval_hw_test.cpp)
