# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Every source is compiled unconditionally; curve25519 / ed25519 / x25519
# self-gate on STATUSBAR_CRYPTO_HAS_INT128 and become empty translation units on
# a 32-bit ALU, where the reduced-radix *32 implementations take over.
target_sources(
  statusbar-crypto
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/curve25519.cpp
          ${CMAKE_CURRENT_LIST_DIR}/ed25519_scalar.cpp
          ${CMAKE_CURRENT_LIST_DIR}/curve25519_fe32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/x25519_32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/ed25519_ge32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/ed25519.cpp
          ${CMAKE_CURRENT_LIST_DIR}/x25519.cpp
          ${CMAKE_CURRENT_LIST_DIR}/x25519_hl32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/ed25519_hl32.cpp)

add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/ed25519_fuzzer.cpp)
add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/x25519_fuzzer.cpp)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_TEST_FILES
           ${CMAKE_CURRENT_LIST_DIR}/curve25519_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/curve25519_fe32_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/x25519_32_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/ed25519_ge32_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/ed25519_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/x25519_test.cpp)
