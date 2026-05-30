// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 (RFC 7748) Montgomery ladder — 32-bit reduced-radix implementation.
//
// A portable counterpart of curve25519_scalar_mult that runs the ladder over
// the 32-bit field arithmetic in curve25519_fe32, so X25519 key agreement
// works on a 32-bit ALU. The ladder itself is pure field arithmetic — no
// Edwards points — so this is the whole of X25519. Always compiled and
// cross-checked against the 5x51-bit implementation by x25519_32_test.cpp.

#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief X25519 scalar multiplication on the 32-bit reduced-radix field.
///
/// Computes the u-coordinate of [scalar]P via the Montgomery ladder, with the
/// scalar clamped per RFC 7748 Section 5. Constant-time. Produces the same
/// result as curve25519_scalar_mult.
/// @param scalar 32-byte little-endian scalar (clamped internally).
/// @param point_u 32-byte little-endian u-coordinate of the input point.
/// @return 32-byte little-endian u-coordinate of the result.
auto curve25519x32_scalar_mult(std::span<uint8_t const, 32> scalar, std::span<uint8_t const, 32> point_u)
    -> std::array<uint8_t, 32>;

}  // namespace statusbar::crypto
