# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.31)
project(
  statusbar-crypto
  VERSION 1.6.1
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

# Give every installed executable a statusbar- prefixed on-disk name, so the
# bin/ directory is uniform (tools that set no OUTPUT_NAME, and examples, would
# otherwise install unprefixed).
get_property(_exe_targets GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS)
foreach(_t ${_exe_targets})
  if(NOT TARGET ${_t})
    continue()
  endif()
  get_target_property(_t_type ${_t} TYPE)
  if(NOT _t_type STREQUAL "EXECUTABLE")
    continue()
  endif()
  get_target_property(_t_name ${_t} OUTPUT_NAME)
  if(NOT _t_name)
    set(_t_name "${_t}")
  endif()
  if(NOT _t_name MATCHES "^statusbar-")
    string(REPLACE "_" "-" _t_name "${_t_name}")
    set_target_properties(${_t} PROPERTIES OUTPUT_NAME "statusbar-${_t_name}")
  endif()
endforeach()

# ---- install + export ----
# Skipped under the outer aggregate build, which builds, not installs. Install
# rules are split into runtime (tools / shared libs) and devel (static libs,
# headers, CMake config) components for CPack.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  get_property(_install_targets GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS)
  install(
    TARGETS ${_install_targets}
    EXPORT statusbar-cryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT devel
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime)
  install(
    EXPORT statusbar-cryptoTargets
    FILE statusbar-cryptoTargets.cmake
    NAMESPACE statusbar::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-crypto
    COMPONENT devel)
  # Also export the build tree, so a sibling package can find this one without
  # an install step: pass -Dstatusbar-crypto_DIR=<build-dir>.
  export(
    EXPORT statusbar-cryptoTargets
    FILE statusbar-cryptoTargets.cmake
    NAMESPACE statusbar::)
  install(
    DIRECTORY statusbar/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/statusbar
    COMPONENT devel
    FILES_MATCHING
    PATTERN "*.hpp"
    PATTERN "*.h")
  configure_package_config_file(
    cmake/statusbar-cryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/statusbar-cryptoConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-crypto)
  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/statusbar-cryptoConfigVersion.cmake
    VERSION 1.6.1
    COMPATIBILITY AnyNewerVersion)
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/statusbar-cryptoConfig.cmake
          ${CMAKE_CURRENT_BINARY_DIR}/statusbar-cryptoConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-crypto
    COMPONENT devel)
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/docs)
    install(
      DIRECTORY docs/
      DESTINATION ${CMAKE_INSTALL_DOCDIR}
      COMPONENT devel
      FILES_MATCHING
      PATTERN "*.md"
      PATTERN "*.svg"
      PATTERN "*.png")
  endif()

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
  set(CPACK_PACKAGE_NAME "statusbar-crypto")
  set(CPACK_PACKAGE_VENDOR "Jeff Koftinoff")
  set(CPACK_PACKAGE_VERSION "1.6.1")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
      "Cryptography toolkit — AES (block, CBC, GCM-SIV, SIV, CMAC), SHA-2, POLYVAL, HKDF/KDF2, Curve25519 (X25519/Ed25519) and NIST P-256 (ECDH/ECDSA), ECIES, and PKCS#8."
  )
  set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER
      "Jeff Koftinoff <jeff.koftinoff@statusbar.com>")
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_RPM_PACKAGE_LICENSE "MIT")
  set(CPACK_RPM_PACKAGE_GROUP "Development/Libraries")
  set(CPACK_RPM_PACKAGE_AUTOREQ ON)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
  endif()
  set(CPACK_DEB_COMPONENT_INSTALL ON)
  set(CPACK_RPM_COMPONENT_INSTALL ON)
  set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
  # Name DEB/RPM files the package-manager-conventional way
  # (<name>_<version>_<arch>.deb), so dependent builds and the orchestrator
  # locate them by package name.
  set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
  set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "statusbar-crypto")
  set(CPACK_RPM_RUNTIME_PACKAGE_NAME "statusbar-crypto")
  set(CPACK_COMPONENT_RUNTIME_DESCRIPTION "Command-line tools and executables")
  set(CPACK_COMPONENTS_ALL runtime devel)
  set(CPACK_DEBIAN_DEVEL_PACKAGE_NAME "statusbar-crypto-dev")
  set(CPACK_RPM_DEVEL_PACKAGE_NAME "statusbar-crypto-devel")
  # Python runtime deps. Auto-shlibdeps still runs and adds C++ runtime libs.
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_DEPENDS
      "python3, python3-cryptography (>= 43.0), python3-pycryptodome (>= 3.20)")
  # -dev pulls its own runtime so its cmake config's IMPORTED targets resolve.
  # >= (not =) so an auto-incremented Debian revision (1.3.0-<rev>) still
  # satisfies the cross-dependencies.
  set(CPACK_DEBIAN_DEVEL_PACKAGE_DEPENDS
      "statusbar-crypto (>= 1.3.0), statusbar-core-dev (>= 1.3.0)")
  set(CPACK_RPM_DEVEL_PACKAGE_REQUIRES "statusbar-core-devel >= 1.3.0")
  set(CPACK_COMPONENT_DEVEL_DESCRIPTION
      "C++ headers, static libraries and CMake package config")
  set(CPACK_GENERATOR "TGZ;ZIP")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND CPACK_GENERATOR "DEB")
    find_program(_rpmbuild rpmbuild)
    if(_rpmbuild)
      list(APPEND CPACK_GENERATOR "RPM")
    endif()
  endif()
  include(CPack)
endif()

# Auto-discovering fuzz-smoke / fuzz-all targets (no-op unless ENABLE_FUZZING).
statusbar_register_fuzz_targets()

# clang-tidy aggregate target (no-op unless clang-tidy is on PATH).
statusbar_register_clang_tidy_target()
