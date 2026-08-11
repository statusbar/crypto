// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Centralized detection of CPU crypto acceleration — the single source of
// truth for every *_hw dispatcher and for crypto_backend_report().
//
// Two layers per primitive family:
//
//  - cpu_*_hw_probe(): the raw answer — true iff the accelerated code path
//    was compiled in (arch feature macros from STATUSBAR_CRYPTO_ARCH_FLAGS)
//    AND the running CPU implements the instructions (CPUID on x86-64,
//    HWCAP / sysctl via crypto_cpu_arm.hpp on aarch64). Never aborts; this
//    is what crypto_backend_report() uses, so a report can be produced even
//    on a machine where the policy below would refuse to run.
//
//  - cpu_*_hw_active(): what the dispatchers call. Identical to the probe
//    unless the build defines STATUSBAR_CRYPTO_REQUIRE_HW, in which case a
//    false probe aborts the process (fail closed) instead of permitting a
//    silent fallback to the software implementation.
//
// SECURITY INVARIANT — no override knobs: the result of these probes must
// depend only on the CPU and the compile-time feature macros. No environment
// variable, config file, or other runtime input may influence dispatch; such
// knobs are downgrade-attack surface (cf. OpenSSL's OPENSSL_ia32cap, which
// lets anyone who controls the environment mask CPUID bits and force the
// side-channel-prone software paths). Enforced by the
// statusbar_crypto/no_env_knobs ctest and documented in
// docs/HARDWARE_ACCELERATION.md.

#pragma once

#include "statusbar/crypto/util/crypto_cpu_arm.hpp"

#if defined(__x86_64__) && (defined(__AES__) || defined(__SHA__) || defined(__PCLMUL__))
#    include <cpuid.h>
#endif

// Fail closed at build time: if the policy is "hardware or nothing", a build
// whose arch flags don't even compile the hardware paths can never satisfy it.
#if defined(STATUSBAR_CRYPTO_REQUIRE_HW)
#    if !((defined(__x86_64__) && defined(__AES__)) || (defined(__aarch64__) && defined(__ARM_FEATURE_AES)))
#        error "STATUSBAR_CRYPTO_REQUIRE_HW: AES hardware path not compiled in — check STATUSBAR_CRYPTO_ARCH_FLAGS"
#    endif
#    if !((defined(__x86_64__) && defined(__SHA__)) || (defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)))
#        error "STATUSBAR_CRYPTO_REQUIRE_HW: SHA-256 hardware path not compiled in — check STATUSBAR_CRYPTO_ARCH_FLAGS"
#    endif
#    if !((defined(__x86_64__) && defined(__PCLMUL__)) || (defined(__aarch64__) && defined(__ARM_FEATURE_AES)))
#        error "STATUSBAR_CRYPTO_REQUIRE_HW: POLYVAL hardware path not compiled in — check STATUSBAR_CRYPTO_ARCH_FLAGS"
#    endif
#endif

namespace statusbar::crypto::internal {

/// Fail-closed handler for STATUSBAR_CRYPTO_REQUIRE_HW builds: prints the
/// primitive family that lacks hardware support and aborts. Defined in
/// crypto_backend.cpp.
[[noreturn]] void require_hw_violation(char const* primitive) noexcept;

/// True iff the AES hardware path (AES-NI / FEAT_AES) is compiled in and the
/// running CPU implements it. Covers AES-128/256 block, x4 pipeline, and CMAC.
inline auto cpu_aes_hw_probe() -> bool
{
#if defined(__x86_64__) && defined(__AES__)
    // CPUID leaf 1, ECX bit 25 = AES-NI. Probed once, cached.
    static bool const has = [] {
        unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
        __cpuid(1, eax, ebx, ecx, edx);
        return (ecx & (1u << 25)) != 0;
    }();
    return has;
#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)
    return arm_has_aes();
#else
    return false;
#endif
}

/// True iff the SHA-256 hardware path (SHA-NI / FEAT_SHA256) is compiled in
/// and the running CPU implements it.
inline auto cpu_sha256_hw_probe() -> bool
{
#if defined(__x86_64__) && defined(__SHA__)
    // CPUID leaf 7, subleaf 0, EBX bit 29 = SHA-NI. Probed once, cached.
    static bool const has = [] {
        unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1u << 29)) != 0;
    }();
    return has;
#elif defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)
    return arm_has_sha2();
#else
    return false;
#endif
}

/// SHA-512 has no active hardware backend yet: the ARMv8.2 SHA-512 code is
/// pending validation and x86-64 has no SHA-512 ISA, so both _hw files
/// delegate to software. Constant false keeps crypto_backend_report() honest;
/// STATUSBAR_CRYPTO_REQUIRE_HW deliberately does not gate SHA-512 because
/// there is no hardware alternative to require.
constexpr auto cpu_sha512_hw_probe() -> bool
{
    return false;
}

/// True iff the POLYVAL carry-less-multiply hardware path (PCLMULQDQ /
/// FEAT_PMULL) is compiled in and the running CPU implements it.
inline auto cpu_polyval_hw_probe() -> bool
{
#if defined(__x86_64__) && defined(__PCLMUL__)
    // CPUID leaf 1, ECX bit 1 = PCLMULQDQ. Probed once, cached.
    static bool const has = [] {
        unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
        __cpuid(1, eax, ebx, ecx, edx);
        return (ecx & (1u << 1)) != 0;
    }();
    return has;
#elif defined(__aarch64__) && defined(__ARM_FEATURE_AES)
    // PMULL/PMULL2 are part of the ARMv8 AES feature set, but Linux reports
    // them as a distinct hwcap — check the PMULL bit, not the AES bit.
    return arm_has_pmull();
#else
    return false;
#endif
}

inline auto cpu_aes_hw_active() -> bool
{
#if defined(STATUSBAR_CRYPTO_REQUIRE_HW)
    if (!cpu_aes_hw_probe()) {
        require_hw_violation("aes");
    }
    return true;
#else
    return cpu_aes_hw_probe();
#endif
}

inline auto cpu_sha256_hw_active() -> bool
{
#if defined(STATUSBAR_CRYPTO_REQUIRE_HW)
    if (!cpu_sha256_hw_probe()) {
        require_hw_violation("sha256");
    }
    return true;
#else
    return cpu_sha256_hw_probe();
#endif
}

inline auto cpu_polyval_hw_active() -> bool
{
#if defined(STATUSBAR_CRYPTO_REQUIRE_HW)
    if (!cpu_polyval_hw_probe()) {
        require_hw_violation("polyval");
    }
    return true;
#else
    return cpu_polyval_hw_probe();
#endif
}

}  // namespace statusbar::crypto::internal
