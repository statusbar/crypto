# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Package INTERFACE library, include path and the global accumulation properties
# (statusbar_package_module_init in cmake/module.cmake).
statusbar_package_module_init()

# Module subdirectories — dependency order.
add_subdirectory(crypto)

# Populate the package INTERFACE library — skipped under the outer aggregate
# build, which populates a single shared `statusbar` itself.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  target_link_libraries(
    statusbar
    INTERFACE statusbar-crypto
              statusbar::args
              statusbar::benchmark
              statusbar::bpf
              statusbar::buffer
              statusbar::colbin
              statusbar::config
              statusbar::container
              statusbar::csv
              statusbar::ieee
              statusbar::ip
              statusbar::itc
              statusbar::net
              statusbar::pcap
              statusbar::realtime
              statusbar::sm
              statusbar::stats
              statusbar::status
              statusbar::test
              statusbar::toml
              statusbar::tsn
              statusbar::tui)
endif()

# Standalone per-package test binary (statusbar_package_test_binary in
# cmake/module.cmake); the outer aggregate build builds one combined
# statusbar_test from every aggregated package instead.
statusbar_package_test_binary()
