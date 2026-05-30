# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

target_sources(statusbar-crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/aes_cbc.cpp)
add_crypto_fuzzer(${CMAKE_CURRENT_LIST_DIR}/aes_cbc_fuzzer.cpp)

set_property(GLOBAL APPEND PROPERTY STATUSBAR_TEST_FILES
                                    ${CMAKE_CURRENT_LIST_DIR}/aes_cbc_test.cpp)
