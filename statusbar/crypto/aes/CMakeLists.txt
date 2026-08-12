# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

target_sources(
  statusbar-crypto
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/aes_common_internal.cpp
          ${CMAKE_CURRENT_LIST_DIR}/aes_ct_internal.cpp
          ${CMAKE_CURRENT_LIST_DIR}/aes128.cpp
          ${CMAKE_CURRENT_LIST_DIR}/aes256.cpp)

# Hardware-accelerated implementations (platform-specific). The march flags
# enabling the crypto extensions are applied module-wide in ../CMakeLists.txt
# (STATUSBAR_CRYPTO_ARCH_FLAGS); each file also self-gates on the feature
# macros, so building on a CPU without the extensions is harmless.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
  target_sources(
    statusbar-crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/aes128_hw_arm64.cpp
                             ${CMAKE_CURRENT_LIST_DIR}/aes256_hw_arm64.cpp)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  target_sources(
    statusbar-crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/aes128_hw_amd64.cpp
                             ${CMAKE_CURRENT_LIST_DIR}/aes256_hw_amd64.cpp)
endif()

add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/aes_fuzzer.cpp)
add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/aes_cmac_fuzzer.cpp)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_TEST_FILES
           ${CMAKE_CURRENT_LIST_DIR}/aes_common_internal_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes_ct_internal_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes128_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes256_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes128_hw_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes256_hw_test.cpp)
