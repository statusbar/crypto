# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Mostly header-only (secure_array, crypto_util_internal, crypto_cpu, concepts);
# crypto_backend.cpp provides the backend report + fail-closed handler.
target_sources(statusbar-crypto
               PRIVATE ${CMAKE_CURRENT_LIST_DIR}/crypto_backend.cpp)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_TEST_FILES ${CMAKE_CURRENT_LIST_DIR}/util_test.cpp
           ${CMAKE_CURRENT_LIST_DIR}/crypto_backend_test.cpp)
