# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

target_sources(statusbar-crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/kdf2.cpp)
add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/kdf2_fuzzer.cpp)

set_property(GLOBAL APPEND PROPERTY STATUSBAR_TEST_FILES
                                    ${CMAKE_CURRENT_LIST_DIR}/kdf2_test.cpp)
