# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

target_sources(
  statusbar-crypto
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ecies.cpp
          ${CMAKE_CURRENT_LIST_DIR}/ecies_hl32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/x25519_ecies.cpp)

add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/ecies_fuzzer.cpp)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_TEST_FILES ${CMAKE_CURRENT_LIST_DIR}/ecies_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/x25519_ecies_test.cpp)
