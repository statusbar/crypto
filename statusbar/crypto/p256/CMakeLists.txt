# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Every source is compiled unconditionally; p256 / p256_ecdsa / p256_ecdh
# self-gate on STATUSBAR_CRYPTO_HAS_INT128 and become empty translation units on
# a 32-bit ALU, where the reduced-radix *32 implementations take over.
target_sources(
  statusbar-crypto
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/p256.cpp
          ${CMAKE_CURRENT_LIST_DIR}/p256_fe32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/p256_sc32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/p256_jac32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/p256_ecdsa.cpp
          ${CMAKE_CURRENT_LIST_DIR}/p256_ecdh.cpp
          ${CMAKE_CURRENT_LIST_DIR}/p256_ecdh_hl32.cpp
          ${CMAKE_CURRENT_LIST_DIR}/p256_ecdsa_hl32.cpp)

add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/p256_ecdsa_fuzzer.cpp)
add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/p256_ecdh_fuzzer.cpp)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_TEST_FILES
           ${CMAKE_CURRENT_LIST_DIR}/p256_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/p256_fe32_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/p256_sc32_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/p256_jac32_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/p256_ecdsa_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/p256_ecdh_test.cpp)
