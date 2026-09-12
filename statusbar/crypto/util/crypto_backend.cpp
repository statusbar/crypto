// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/crypto/util/crypto_backend.hpp"

#include "statusbar/crypto/util/crypto_cpu.hpp"
#include "statusbar/crypto/util/crypto_cpu_arm.hpp"

#if defined(__x86_64__) && (defined(__AES__) || defined(__SHA__) || defined(__PCLMUL__))
#    include <cpuid.h>
#endif

#include <array>
#include <cstdlib>
#include <format>
#include <print>

namespace statusbar::crypto {

namespace internal {

void require_hw_violation(char const* primitive) noexcept
{
    std::println(
        stderr,
        "statusbar-crypto: fatal: no hardware acceleration for {} on this CPU and this build "
        "was configured with STATUSBAR_CRYPTO_REQUIRE_HW (software fallback not permitted)",
        primitive);
    std::abort();
}

// The probes live here, out of line, rather than inline in crypto_cpu.hpp:
// this TU belongs to statusbar-crypto and so is compiled with
// STATUSBAR_CRYPTO_ARCH_FLAGS, which is what defines the feature macros below.
// Those flags are PRIVATE to the target, so an inline body would select the
// real probe here and a constant `false` in any other TU including the header.
// See the ODR note at the top of crypto_cpu.hpp.

auto cpu_aes_hw_probe() -> bool
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

auto cpu_sha256_hw_probe() -> bool
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

auto cpu_polyval_hw_probe() -> bool
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

}  // namespace internal

auto crypto_backend_report() noexcept -> CryptoBackendReport
{
    auto const backend = [](bool hw) { return hw ? CryptoBackend::hardware : CryptoBackend::software; };
    return CryptoBackendReport{
        .aes = backend(internal::cpu_aes_hw_probe()),
        .sha256 = backend(internal::cpu_sha256_hw_probe()),
        .sha512 = backend(internal::cpu_sha512_hw_probe()),
        .polyval = backend(internal::cpu_polyval_hw_probe()),
    };
}

auto crypto_backend_summary() noexcept -> std::string_view
{
    static std::array<char, 64> const buffer = [] {
        std::array<char, 64> b{};
        auto const r = crypto_backend_report();
        auto const out = std::format_to_n(
            b.data(),
            b.size() - 1,
            "aes={} sha256={} sha512={} polyval={}",
            to_string(r.aes),
            to_string(r.sha256),
            to_string(r.sha512),
            to_string(r.polyval));
        *out.out = '\0';
        return b;
    }();
    return {buffer.data()};
}

}  // namespace statusbar::crypto
