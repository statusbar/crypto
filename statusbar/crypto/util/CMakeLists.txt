# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# util is header-only (secure_array, crypto_util_internal, concepts); no sources
# to add to statusbar-crypto. Register its unit tests only.
set_property(GLOBAL APPEND PROPERTY STATUSBAR_TEST_FILES
                                    ${CMAKE_CURRENT_LIST_DIR}/util_test.cpp)
