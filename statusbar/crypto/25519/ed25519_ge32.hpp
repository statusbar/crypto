// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Ed25519 Edwards-group operations — 32-bit reduced-radix implementation.
//
// A portable counterpart of the GeP3 / ge_* group layer in curve25519.cpp,
// running over the 32-bit field arithmetic in curve25519_fe32 so the Ed25519
// group operations work on a 32-bit ALU. (Ed25519's scalar arithmetic —
// sc_reduce / sc_mul_add — already uses only 64-bit integers and needs no
// 32-bit variant.)
//
// Always compiled and cross-checked against the 5x51-bit group layer by
// ed25519_ge32_test.cpp.

#pragma once

#include "statusbar/crypto/25519/curve25519_fe32.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// @brief Point on the twisted Edwards curve in extended coordinates,
/// over the 32-bit field. The 32-bit counterpart of GeP3.
///
/// (X, Y, Z, T) with x = X/Z, y = Y/Z, T = X*Y/Z. Each field-element member
/// zeroes itself on destruction.
struct GeP3x32
{
    Fe25519x32 X;
    Fe25519x32 Y;
    Fe25519x32 Z;
    Fe25519x32 T;
};

//
// Group operations. Semantics match the ge_* functions in curve25519.hpp.
//

/// @brief The neutral element (identity point) — (0, 1, 1, 0).
auto ge32_p3_identity() -> GeP3x32;

/// @brief Encode an extended point to 32 bytes (RFC 8032 Section 5.1.2).
auto ge32_p3_to_bytes(GeP3x32 const& p) -> std::array<uint8_t, 32>;

/// @brief Decode a 32-byte compressed point, or nullopt if it is invalid.
auto ge32_from_bytes(std::span<uint8_t const, 32> s) -> std::optional<GeP3x32>;

/// @brief Unified twisted-Edwards point addition (a = -1).
auto ge32_p3_add(GeP3x32 const& P, GeP3x32 const& Q) -> GeP3x32;

/// @brief Dedicated twisted-Edwards point doubling (a = -1).
auto ge32_p3_dbl(GeP3x32 const& P) -> GeP3x32;

/// @brief Negate a point: (-X, Y, Z, -T).
auto ge32_p3_neg(GeP3x32 const& P) -> GeP3x32;

/// @brief Constant-time fixed-base scalar multiplication [scalar]B.
auto ge32_scalar_mult_base(std::span<uint8_t const, 32> scalar) -> GeP3x32;

/// @brief Compute [a]A + [b]B (Straus's trick, variable-time — for verify).
auto ge32_double_scalar_mult_vartime(std::span<uint8_t const, 32> a, GeP3x32 const& A, std::span<uint8_t const, 32> b) -> GeP3x32;

}  // namespace statusbar::crypto
