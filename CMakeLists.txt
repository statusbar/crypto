# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.31)
project(
  statusbar-crypto
  VERSION 2.1.0
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
enable_testing()

# Modules register bench tools into this aggregate target. The outer aggregate
# build supplies a single shared target instead.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  add_custom_target(run-all-benches)
endif()

# Dependency packages — must be installed and discoverable.
find_package(statusbar-core REQUIRED)

add_subdirectory(statusbar)

# Python cross-validation target lives in python-crypto-tests, registered at end
# of configure so that avtp_crypto_tool from a sibling add_subdirectory(avb) has
# been declared. For the standalone-crypto build, it's registered here
# (avtp_crypto_tool will never be available, so only the self-tests run). For
# the outer aggregate build, it's registered after all add_subdirectory() calls.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  find_program(UV uv)
  if(UV AND EXISTS
            ${CMAKE_CURRENT_SOURCE_DIR}/python/crypto/statusbar_crypto_test.py)
    add_custom_target(
      python-crypto-tests
      COMMAND ${UV} run
              ${CMAKE_CURRENT_SOURCE_DIR}/python/crypto/statusbar_crypto_test.py
      COMMENT
        "Python crypto self-tests (no avtp_crypto_tool — cross-check skipped)"
      VERBATIM USES_TERMINAL)
  endif()
endif()

# Export each module target under the short statusbar::<name> form, so dependent
# packages find_package() them as statusbar::<module>.
set_target_properties(statusbar-crypto PROPERTIES EXPORT_NAME crypto)

# Uniform statusbar- prefixed on-disk names for installed executables
# (statusbar_prefix_tool_names in cmake/module.cmake).
statusbar_prefix_tool_names()

# ---- install + export ----
# Standalone install/export boilerplate lives in
# statusbar_package_install_export (cmake/module.cmake); no-op under an outer
# aggregate build.
statusbar_package_install_export(NAME crypto)

if(NOT STATUSBAR_AGGREGATE_BUILD)

  # ---- Python helpers (runtime component) ----
  # statusbar_crypto.py is the flat library mirroring the C++ API; install it as
  # the package's __init__.py so `import statusbar_crypto as sc` works
  # regardless of the in-tree flat-script layout. Absolute path: dist-packages
  # is outside CMAKE_INSTALL_PREFIX (which is typically /usr/local) but Python
  # only scans /usr/lib/python3/dist-packages by default.
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/python/crypto/statusbar_crypto.py)
    install(
      FILES python/crypto/statusbar_crypto.py
      DESTINATION /usr/lib/python3/dist-packages/statusbar_crypto
      RENAME __init__.py
      COMPONENT runtime)
    install(
      FILES python/crypto/avtp_crypto_vectors.py
            python/crypto/avtp_crypto_cross_check.py
            python/crypto/statusbar_crypto_test.py
      DESTINATION /usr/lib/python3/dist-packages/statusbar_crypto
      COMPONENT runtime)
    install(
      PROGRAMS python/crypto/avtp_crypto_cross_check.py
      DESTINATION ${CMAKE_INSTALL_BINDIR}
      RENAME statusbar-avtp-crypto-cross-check
      COMPONENT runtime)
  endif()
endif()

# ---- packaging (CPack: TGZ + ZIP, plus DEB/RPM on Linux) ----
# Standalone builds only — run `cpack` from the build directory to produce this
# package's archives.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  statusbar_package_cpack_defaults(
    NAME
    crypto
    DESCRIPTION
    "Cryptography toolkit — AES (block, CBC, GCM-SIV, SIV, CMAC), SHA-2, POLYVAL, HKDF/KDF2, Curve25519 (X25519/Ed25519) and NIST P-256 (ECDH/ECDSA), ECIES, and PKCS#8."
  )
  # Python runtime deps. Auto-shlibdeps still runs and adds C++ runtime libs.
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_DEPENDS
      "python3, python3-cryptography (>= 43.0), python3-pycryptodome (>= 3.20)")
  # -dev pulls its own runtime so its cmake config's IMPORTED targets resolve.
  # >= (not =) so an auto-incremented Debian revision (<version>-<rev>) still
  # satisfies the cross-dependencies. Floors track the versions this build was
  # actually made against (find_package sets statusbar-core_VERSION), never a
  # hardcoded literal that goes stale on the next release.
  set(CPACK_DEBIAN_DEVEL_PACKAGE_DEPENDS
      "statusbar-crypto (>= ${PROJECT_VERSION}), statusbar-core-dev (>= ${statusbar-core_VERSION})"
  )
  set(CPACK_RPM_DEVEL_PACKAGE_REQUIRES
      "statusbar-core-devel >= ${statusbar-core_VERSION}")
  set(CPACK_COMPONENT_DEVEL_DESCRIPTION
      "C++ headers, static libraries and CMake package config")
  include(CPack)
endif()

# Auto-discovering fuzz-smoke / fuzz-all targets (no-op unless ENABLE_FUZZING).
statusbar_register_fuzz_targets()

# clang-tidy aggregate target (no-op unless clang-tidy is on PATH).
statusbar_register_clang_tidy_target()
