# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Create the crypto library target. Subdirectories add their sources to it.
add_library(statusbar-crypto STATIC)
add_library(statusbar::crypto ALIAS statusbar-crypto)
target_compile_features(statusbar-crypto PUBLIC cxx_std_23)
set_target_properties(statusbar-crypto PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(
  statusbar-crypto PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
                          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# crypto's internal headers include statusbar/buffer span helpers.
target_link_libraries(statusbar-crypto PUBLIC statusbar::buffer)
set_property(GLOBAL APPEND PROPERTY STATUSBAR_INSTALL_TARGETS statusbar-crypto)

# CPU crypto acceleration (AES / SHA / POLYVAL). The hardware-accelerated
# implementations self-gate on the compiler's feature macros (__ARM_FEATURE_AES,
# __AES__, ...); these flags define those macros so the accelerated code paths
# are compiled in rather than left as empty TUs. Native by default on arm64 /
# x86_64 — the end user can override STATUSBAR_CRYPTO_ARCH_FLAGS (set it to ""
# for a CPU without the crypto extensions, or to a specific -mcpu/-march for a
# cross build).
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
  # "native" is a host-CPU query and rejects when the compiler driver is running
  # on a different arch (e.g. cross-compile from x86_64). Fall back to a
  # portable armv8+crypto baseline that covers Cortex-A72/A76 (Pi 4/5), Apple
  # Silicon, Graviton, etc. Native builds keep -mcpu=native for the last-mile
  # micro-arch tuning.
  if(CMAKE_CROSSCOMPILING)
    set(_statusbar_crypto_default "-march=armv8-a+crypto")
  else()
    set(_statusbar_crypto_default "-mcpu=native+aes+sha2+sha3")
  endif()
  set(STATUSBAR_CRYPTO_ARCH_FLAGS
      "${_statusbar_crypto_default}"
      CACHE
        STRING
        "Compiler flags enabling CPU crypto acceleration in statusbar-crypto")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  set(STATUSBAR_CRYPTO_ARCH_FLAGS
      "-maes;-mpclmul;-msha;-msse4.1"
      CACHE
        STRING
        "Compiler flags enabling CPU crypto acceleration in statusbar-crypto")
else()
  set(STATUSBAR_CRYPTO_ARCH_FLAGS
      ""
      CACHE
        STRING
        "Compiler flags enabling CPU crypto acceleration in statusbar-crypto")
endif()
target_compile_options(statusbar-crypto PRIVATE ${STATUSBAR_CRYPTO_ARCH_FLAGS})

# Fail-closed hardware policy: when ON, the *_hw dispatchers abort the process
# instead of silently falling back to the software implementations when the
# running CPU lacks the crypto instructions (and the build errors out if the
# arch flags above don't even compile the hardware paths). For deployments on
# known-capable hardware, this turns a silent downgrade — masked CPUID in a VM,
# wrong arch flags, emulation — into an immediate, visible failure. SHA-512 is
# exempt (it has no hardware backend yet). See docs/HARDWARE_ACCELERATION.md
# ("Downgrade resistance").
option(
  STATUSBAR_CRYPTO_REQUIRE_HW
  "Abort instead of falling back to software when CPU crypto acceleration is unavailable"
  OFF)
if(STATUSBAR_CRYPTO_REQUIRE_HW)
  target_compile_definitions(statusbar-crypto
                             PRIVATE STATUSBAR_CRYPTO_REQUIRE_HW=1)
endif()

# Detect a compiler-provided 128-bit integer type. The 5x51 / 4x64-bit
# elliptic-curve code uses __uint128_t; a 32-bit ALU lacks that type, so on such
# targets only the reduced-radix *32 implementations are built. The high-level
# EC wrappers (curve25519/p256, ed25519/x25519, ECIES, PKCS#8, the benchmark)
# are gated on STATUSBAR_HAS_INT128 below.
include(CheckCXXSourceCompiles)
check_cxx_source_compiles(
  "int main() { __int128 v = 1; return static_cast<int>(v); }"
  STATUSBAR_HAS_INT128)

# Helper function: create a crypto fuzzer executable (platform-aware)
function(add_crypto_fuzzer source_file)
  if(NOT ENABLE_FUZZING)
    return()
  endif()

  get_filename_component(FUZZ_NAME ${source_file} NAME_WE)

  if(APPLE)
    # macOS: use standalone driver (libFuzzer runtime has ABI issues with
    # Homebrew LLVM)
    add_executable(
      ${FUZZ_NAME}
      ${source_file}
      ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/util/standalone_driver.cpp)
    target_link_libraries(${FUZZ_NAME} PRIVATE statusbar)
    target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=address,undefined
                                                -fno-omit-frame-pointer)
    target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=address,undefined)
  else()
    # Linux: use libFuzzer via -fsanitize=fuzzer
    add_executable(${FUZZ_NAME} ${source_file})
    target_link_libraries(${FUZZ_NAME} PRIVATE statusbar)
    target_compile_options(
      ${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined
                           -fno-omit-frame-pointer)
    target_link_options(
      ${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined
      ${FUZZER_EXTRA_LINK_OPTIONS})
  endif()
endfunction()

# The crypto benchmark compares the 64-bit and 32-bit implementations, so it is
# built only where the 128-bit-integer implementations exist.
if(STATUSBAR_HAS_INT128)
  add_executable(crypto_bench_tool
                 ${CMAKE_CURRENT_LIST_DIR}/crypto_bench_tool.cpp)
  target_link_libraries(crypto_bench_tool PRIVATE statusbar)
  set_target_properties(crypto_bench_tool PROPERTIES OUTPUT_NAME
                                                     statusbar-crypto-bench)

  # Runnable target for invoking the benchmark from the Makefile.
  add_custom_target(
    run-crypto-bench
    COMMAND $<TARGET_FILE:crypto_bench_tool>
    DEPENDS crypto_bench_tool
    USES_TERMINAL VERBATIM)
  add_dependencies(run-all-benches run-crypto-bench)
endif()

# Crypto subdirectories (each adds sources + tests + fuzzers)
add_subdirectory(25519)
add_subdirectory(aes)
add_subdirectory(aes_cbc)
add_subdirectory(aes_gcm_siv)
add_subdirectory(aes_siv)
add_subdirectory(hkdf)
add_subdirectory(kdf2)
add_subdirectory(p256)
add_subdirectory(polyval)
add_subdirectory(sha)
add_subdirectory(util)

# ECIES and PKCS#8 are built entirely on the elliptic-curve API, so they are
# included only where the 128-bit-integer implementations exist.
if(STATUSBAR_HAS_INT128)
  add_subdirectory(ecies)
  add_subdirectory(pkcs8)
endif()

# SECURITY INVARIANT: crypto dispatch must never be influenced by environment
# variables (downgrade-attack surface — cf. OpenSSL's OPENSSL_ia32cap, which
# masks CPUID bits from the environment to silently divert traffic onto the
# software paths). Enforced by grepping every source in this module for getenv:
# grep exits non-zero when nothing matches, and WILL_FAIL inverts that, so the
# test PASSES only when no getenv call exists anywhere. When a match is found,
# grep prints the offending file:line and exits 0, which WILL_FAIL turns into a
# test failure. See docs/HARDWARE_ACCELERATION.md.
add_test(NAME statusbar_crypto/no_env_knobs
         COMMAND grep -rn "getenv" "--include=*.cpp" "--include=*.hpp"
                 ${CMAKE_CURRENT_SOURCE_DIR})
set_tests_properties(statusbar_crypto/no_env_knobs PROPERTIES WILL_FAIL TRUE)

# Python cross-validation test (requires uv and the python/crypto tree, which
# ships with the crypto export package — see the crypto package in
# exports.toml).
set(_crypto_xcheck
    "${CMAKE_CURRENT_SOURCE_DIR}/../../python/crypto/avtp_crypto_cross_check.py"
)
find_program(UV_EXECUTABLE uv)
if(UV_EXECUTABLE AND EXISTS "${_crypto_xcheck}")
  add_test(NAME statusbar_crypto/python_cross_check
           COMMAND ${UV_EXECUTABLE} run "${_crypto_xcheck}" --build-dir
                   ${CMAKE_BINARY_DIR})
  # avtp_crypto_cross_check.py exits 77 when the avtp_crypto CLI tool is absent
  # (a standalone crypto build cannot produce it — it ships in the avb package);
  # treat that as a skipped test rather than a failure.
  set_tests_properties(statusbar_crypto/python_cross_check
                       PROPERTIES SKIP_RETURN_CODE 77)
elseif(NOT UV_EXECUTABLE)
  message(STATUS "uv not found — crypto Python cross-validation skipped")
endif()
