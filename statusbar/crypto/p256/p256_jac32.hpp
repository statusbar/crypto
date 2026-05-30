// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 Jacobian-group operations — 32-bit reduced-radix implementation.
//
// A portable counterpart of the P256JacobianPoint / p256_point_* group layer
// in p256.cpp, running over the 32-bit field and scalar arithmetic in
// p256_fe32 / p256_sc32 so the whole P-256 group machinery — point
// arithmetic, scalar multiplication, key generation, point encoding — works
// on a 32-bit ALU.
//
// Always compiled and cross-checked against the 4x64-bit group layer by
// p256_jac32_test.cpp.

#pragma once

#include "statusbar/crypto/p256/p256_fe32.hpp"
#include "statusbar/crypto/p256/p256_sc32.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace statusbar::crypto {

/// @brief P-256 point in Jacobian projective coordinates (32-bit field).
/// x = X/Z^2, y = Y/Z^3; the identity is Z = 0.
struct P256JacobianPoint32
{
    P256FieldElement32 X;
    P256FieldElement32 Y;
    P256FieldElement32 Z;
};

/// @brief P-256 affine point (x, y) over the 32-bit field.
struct P256AffinePoint32
{
    P256FieldElement32 x;
    P256FieldElement32 y;
};

//
// Group operations. Semantics match the p256_* functions in p256.hpp.
//

/// @brief The generator point G in affine coordinates.
auto p256x32_generator() -> P256AffinePoint32;

/// @brief The identity point (point at infinity).
auto p256x32_point_identity() -> P256JacobianPoint32;

/// @brief Return true if P is the identity (Z == 0).
auto p256x32_point_is_identity(P256JacobianPoint32 const& P) -> bool;

/// @brief Jacobian point doubling (a = -3 optimization).
auto p256x32_point_double(P256JacobianPoint32 const& P) -> P256JacobianPoint32;

/// @brief Jacobian + affine mixed addition.
auto p256x32_point_add_affine(P256JacobianPoint32 const& P, P256AffinePoint32 const& Q) -> P256JacobianPoint32;

/// @brief Full Jacobian point addition.
auto p256x32_point_add(P256JacobianPoint32 const& P, P256JacobianPoint32 const& Q) -> P256JacobianPoint32;

/// @brief Negate a point: (X, -Y, Z).
auto p256x32_point_neg(P256JacobianPoint32 const& P) -> P256JacobianPoint32;

/// @brief Convert Jacobian to affine (one field inversion).
auto p256x32_point_to_affine(P256JacobianPoint32 const& P) -> P256AffinePoint32;

/// @brief Convert affine to Jacobian (Z = 1).
auto p256x32_affine_to_jacobian(P256AffinePoint32 const& P) -> P256JacobianPoint32;

/// @brief Check that an affine point satisfies y^2 = x^3 - 3x + b.
auto p256x32_point_on_curve(P256AffinePoint32 const& P) -> bool;

/// @brief Variable-base scalar multiplication [scalar]P (constant-time).
auto p256x32_scalar_mult(P256Scalar32 const& scalar, P256AffinePoint32 const& P) -> P256JacobianPoint32;

/// @brief Fixed-base scalar multiplication [scalar]G.
auto p256x32_scalar_mult_base(P256Scalar32 const& scalar) -> P256JacobianPoint32;

/// @brief Double scalar multiplication [a]G + [b]Q (Shamir's trick).
auto p256x32_double_scalar_mult(P256Scalar32 const& a, P256Scalar32 const& b, P256AffinePoint32 const& Q) -> P256JacobianPoint32;

/// @brief Generate a keypair from a 32-byte seed: (private scalar, public point).
auto p256x32_keypair_from_seed(std::span<uint8_t const, 32> seed) -> std::pair<P256Scalar32, P256AffinePoint32>;

//
// Point encoding / decoding
//

/// @brief EC2OSP-X: encode as 0x01 || x (33 bytes).
auto p256x32_encode_point_x(P256AffinePoint32 const& P) -> std::array<uint8_t, 33>;

/// @brief OS2ECP-X: decode an 0x01 || x encoding, picking the even y.
auto p256x32_decode_point_x(std::span<uint8_t const, 33> encoded) -> std::optional<P256AffinePoint32>;

/// @brief Encode as uncompressed x || y (64 bytes).
auto p256x32_encode_point_uncompressed(P256AffinePoint32 const& P) -> std::array<uint8_t, 64>;

/// @brief Decode an uncompressed x || y encoding.
auto p256x32_decode_point_uncompressed(std::span<uint8_t const, 64> encoded) -> std::optional<P256AffinePoint32>;

}  // namespace statusbar::crypto
