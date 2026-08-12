// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Runtime report of which implementation each hardware-dispatched primitive
// family resolves to in this process.
//
// The *_hw entry points silently fall back to software when the CPU lacks the
// relevant instructions. The software AES fallback is a constant-time
// bitsliced core (aes/aes_ct_internal.hpp), so a downgrade no longer opens a
// cache-timing side channel — but it is still a large performance change and
// a signal that the platform is hiding CPU features (hypervisor masking
// CPUID, mis-set STATUSBAR_CRYPTO_ARCH_FLAGS, emulation), so it must never
// be *invisible*. Long-running daemons should log crypto_backend_summary()
// once at startup so a downgrade shows up as a one-line anomaly instead of
// going unnoticed for the life of the deployment.
//
// See docs/HARDWARE_ACCELERATION.md ("Downgrade resistance") and
// STATUSBAR_CRYPTO_REQUIRE_HW for the fail-closed alternative.

#pragma once

#include <cstdint>
#include <string_view>

namespace statusbar::crypto {

/// Which implementation a hardware-dispatched primitive family resolves to.
enum class CryptoBackend : uint8_t
{
    software,
    hardware,
};

/// "hw" / "sw" — whole literals, safe for deferred logging (StaticStr).
[[nodiscard]] constexpr auto to_string(CryptoBackend b) noexcept -> std::string_view
{
    return b == CryptoBackend::hardware ? "hw" : "sw";
}

/// Resolved backend per primitive family, as the *_hw dispatchers will
/// actually behave in this process (compile-time arch flags AND runtime CPU
/// feature probe).
struct CryptoBackendReport
{
    CryptoBackend aes;      ///< AES-128/256 block, x4 pipeline, CMAC (AES-NI / FEAT_AES)
    CryptoBackend sha256;   ///< SHA-256 hash + HMAC (SHA-NI / FEAT_SHA256)
    CryptoBackend sha512;   ///< SHA-512 (no hardware backend yet — always software)
    CryptoBackend polyval;  ///< POLYVAL carry-less multiply (PCLMULQDQ / FEAT_PMULL)

    auto operator==(CryptoBackendReport const&) const noexcept -> bool = default;
};

/// Probe (once) and report the resolved backends. Never aborts, even in
/// STATUSBAR_CRYPTO_REQUIRE_HW builds — usable for diagnostics before the
/// fail-closed policy would trip.
[[nodiscard]] auto crypto_backend_report() noexcept -> CryptoBackendReport;

/// One-line summary for startup logging, e.g.
/// "aes=hw sha256=hw sha512=sw polyval=hw".
/// Points at a process-lifetime static buffer (built on first call); the view
/// is NUL-terminated and safe to retain.
[[nodiscard]] auto crypto_backend_summary() noexcept -> std::string_view;

}  // namespace statusbar::crypto
