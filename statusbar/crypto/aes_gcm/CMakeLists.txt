# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

target_sources(
  statusbar-crypto
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ghash_internal.cpp
          ${CMAKE_CURRENT_LIST_DIR}/aes128_gcm.cpp
          ${CMAKE_CURRENT_LIST_DIR}/aes256_gcm.cpp)

add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/aes_gcm_fuzzer.cpp)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_TEST_FILES
           ${CMAKE_CURRENT_LIST_DIR}/ghash_internal_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes128_gcm_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes256_gcm_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/aes_gcm_test.cpp)
