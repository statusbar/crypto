// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/crypto/util/crypto_backend.hpp"

#include "statusbar/crypto/util/crypto_cpu.hpp"

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
