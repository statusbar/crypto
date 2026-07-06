// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Runtime detection of ARMv8 crypto extensions (FEAT_AES, FEAT_SHA256,
// FEAT_PMULL). The *_hw_arm64 backends are compiled with the crypto
// intrinsics enabled, but the intrinsics are only legal on cores that
// actually implement the feature — executing them elsewhere raises SIGILL.
// Unlike x86-64 (which probes CPUID), the ARM backends previously had no
// runtime check, so a binary built `+crypto` crashed on a core without the
// extension instead of falling back to software. These helpers give the
// dispatchers a runtime gate, mirroring the x86-64 CPUID approach.
//
// aarch64 only; the whole header is a no-op on other architectures.

#pragma once

#if defined(__aarch64__)

#    if defined(__linux__)
#        include <asm/hwcap.h>
#        include <sys/auxv.h>
#    elif defined(__APPLE__)
#        include <cstddef>
#        include <sys/sysctl.h>
#    endif

namespace statusbar::crypto::internal {

#    if defined(__APPLE__)
// sysctlbyname("hw.optional.arm.FEAT_*") returns 1 when the feature is present.
inline auto apple_arm_feature(char const* name) -> bool
{
    int value = 0;
    std::size_t size = sizeof(value);
    if (sysctlbyname(name, &value, &size, nullptr, 0) != 0) {
        return false;
    }
    return value != 0;
}
#    endif

// True when the CPU implements the AES extension (AESE/AESD/AESMC/AESIMC).
// The result is probed once and cached (function-local static).
inline auto arm_has_aes() -> bool
{
#    if defined(__linux__)
    static bool const has = (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#    elif defined(__APPLE__)
    static bool const has = apple_arm_feature("hw.optional.arm.FEAT_AES");
#    else
    static bool const has = true;  // other aarch64 OSes: assume present (prior behavior)
#    endif
    return has;
}

// True when the CPU implements the SHA-256 extension (SHA256H/SHA256SU*).
inline auto arm_has_sha2() -> bool
{
#    if defined(__linux__)
    static bool const has = (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#    elif defined(__APPLE__)
    static bool const has = apple_arm_feature("hw.optional.arm.FEAT_SHA256");
#    else
    static bool const has = true;
#    endif
    return has;
}

// True when the CPU implements the polynomial-multiply extension (PMULL/PMULL2).
inline auto arm_has_pmull() -> bool
{
#    if defined(__linux__)
    static bool const has = (getauxval(AT_HWCAP) & HWCAP_PMULL) != 0;
#    elif defined(__APPLE__)
    static bool const has = apple_arm_feature("hw.optional.arm.FEAT_PMULL");
#    else
    static bool const has = true;
#    endif
    return has;
}

}  // namespace statusbar::crypto::internal

#endif  // __aarch64__
