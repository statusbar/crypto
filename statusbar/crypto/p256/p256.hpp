// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 (secp256r1) elliptic curve field arithmetic and group operations
//
// References:
// - FIPS 186-4: Digital Signature Standard (DSS)
// - SEC 2: Recommended Elliptic Curve Domain Parameters (secp256r1)
// - NIST SP 800-186: Recommendations for Discrete Logarithm-based Cryptography
//
// Curve: y^2 = x^3 - 3x + b over F_p
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (Solinas prime)
// n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
// G = (6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
//      4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace statusbar::crypto {

/// @brief Field element in F_p (4 x 64-bit limbs, little-endian).
///
/// Represents an integer modulo the P-256 field prime p.
/// Automatically zeroed on destruction to protect sensitive intermediate values.
struct P256FieldElement
{
    std::array<uint64_t, 4> limbs{};

    constexpr ~P256FieldElement()
    {
        if !consteval {
            internal::secure_zero(*this);
        }
    }
};

/// @brief Scalar in Z_n (4 x 64-bit limbs, little-endian).
///
/// Represents an integer modulo the P-256 group order n.
/// Automatically zeroed on destruction to protect private key material.
struct P256Scalar
{
    std::array<uint64_t, 4> limbs{};

    constexpr ~P256Scalar()
    {
        if !consteval {
            internal::secure_zero(*this);
        }
    }
};

/// @brief Point in Jacobian projective coordinates: x = X/Z^2, y = Y/Z^3.
///
/// The identity (point at infinity) is represented by Z = 0.
struct P256JacobianPoint
{
    P256FieldElement X;
    P256FieldElement Y;
    P256FieldElement Z;
};

/// @brief Affine point (x, y) on the P-256 curve.
///
/// Used for external point representation (key encoding/decoding, ECDH input).
struct P256AffinePoint
{
    P256FieldElement x;
    P256FieldElement y;
};

//
// Constants
//

inline constexpr size_t p256_field_element_size = 32;
inline constexpr size_t p256_scalar_size = 32;
inline constexpr size_t p256_compressed_point_size = 33;
inline constexpr size_t p256_uncompressed_point_size = 64;

//
// Field operations (all constant-time)
//

/// @brief Compute a + b (mod p).
/// @param a First operand.
/// @param b Second operand.
/// @return a + b reduced mod p.
auto p256_fe_add(P256FieldElement const& a, P256FieldElement const& b) -> P256FieldElement;

/// @brief Compute a - b (mod p).
/// @param a First operand.
/// @param b Second operand.
/// @return a - b reduced mod p.
auto p256_fe_sub(P256FieldElement const& a, P256FieldElement const& b) -> P256FieldElement;

/// @brief Compute a * b (mod p).
/// @param a First operand.
/// @param b Second operand.
/// @return a * b reduced mod p.
auto p256_fe_mul(P256FieldElement const& a, P256FieldElement const& b) -> P256FieldElement;

/// @brief Compute a^2 (mod p).
/// @param a The field element to square.
/// @return a^2 reduced mod p.
auto p256_fe_sqr(P256FieldElement const& a) -> P256FieldElement;

/// @brief Compute -a (mod p).
/// @param a The field element to negate.
/// @return p - a.
auto p256_fe_neg(P256FieldElement const& a) -> P256FieldElement;

/// @brief Compute a^{-1} (mod p) via Fermat's little theorem: a^{p-2}.
/// @param a The field element to invert (must be nonzero).
/// @return a^{-1} mod p.
auto p256_fe_inv(P256FieldElement const& a) -> P256FieldElement;

/// @brief Compute the square root of a (mod p), if it exists.
///
/// Uses exponentiation a^{(p+1)/4} which is valid since p = 3 (mod 4).
/// The exponent (p+1)/4 is a public constant, so timing does not leak information
/// about the input value a. Used only in point decompression where the input
/// is derived from public data (x-coordinate).
///
/// @param a The field element to take the square root of.
/// @return The square root, or std::nullopt if a is not a quadratic residue.
auto p256_fe_sqrt(P256FieldElement const& a) -> std::optional<P256FieldElement>;

/// @brief Deserialize a 32-byte big-endian encoding to a field element.
/// @param bytes 32-byte big-endian encoding.
/// @return The decoded field element.
auto p256_fe_from_bytes(std::span<uint8_t const, p256_field_element_size> bytes) -> P256FieldElement;

/// @brief Serialize a field element to 32-byte big-endian encoding.
/// @param a The field element to serialize.
/// @return 32-byte big-endian encoding.
auto p256_fe_to_bytes(P256FieldElement const& a) -> std::array<uint8_t, p256_field_element_size>;

/// @brief Return true if a == 0 (mod p).
/// @param a The field element to test.
/// @return true if a is zero mod p.
auto p256_fe_is_zero(P256FieldElement const& a) -> bool;

/// @brief Return true if a == b (mod p).
/// @param a First operand.
/// @param b Second operand.
/// @return true if a and b represent the same field element.
auto p256_fe_equal(P256FieldElement const& a, P256FieldElement const& b) -> bool;

/// @brief Constant-time conditional move: f = (b != 0) ? g : f.
/// @param f Destination field element, overwritten if b is nonzero.
/// @param g Source field element.
/// @param b Selector, must be 0 or 1.
void p256_fe_cmov(P256FieldElement& f, P256FieldElement const& g, uint64_t b);

/// @brief Return the field element 1.
/// @return The multiplicative identity in F_p.
auto p256_fe_one() -> P256FieldElement;

//
// Scalar field operations (mod n, all constant-time)
//

/// @brief Compute a + b (mod n).
/// @param a First operand.
/// @param b Second operand.
/// @return a + b reduced mod n.
auto p256_sc_add(P256Scalar const& a, P256Scalar const& b) -> P256Scalar;

/// @brief Compute a - b (mod n).
/// @param a First operand.
/// @param b Second operand.
/// @return a - b reduced mod n.
auto p256_sc_sub(P256Scalar const& a, P256Scalar const& b) -> P256Scalar;

/// @brief Compute a * b (mod n).
/// @param a First operand.
/// @param b Second operand.
/// @return a * b reduced mod n.
auto p256_sc_mul(P256Scalar const& a, P256Scalar const& b) -> P256Scalar;

/// @brief Compute a^{-1} (mod n) via Fermat's little theorem: a^{n-2}.
///
/// The exponent n-2 is a public constant, so timing does not leak information
/// about the input scalar a. Used in ECDSA signing (to invert k) where k is
/// an ephemeral secret, but the fixed exponent ensures constant-time behavior.
///
/// @param a The scalar to invert (must be nonzero).
/// @return a^{-1} mod n.
auto p256_sc_inv(P256Scalar const& a) -> P256Scalar;

/// @brief Compute -a (mod n).
/// @param a The scalar to negate.
/// @return n - a.
auto p256_sc_negate(P256Scalar const& a) -> P256Scalar;

/// @brief Deserialize a 32-byte big-endian encoding to a scalar.
/// Note: This does NOT reduce mod n. The caller must reduce if needed.
/// @param bytes 32-byte big-endian encoding.
/// @return The decoded scalar (may be >= n).
auto p256_sc_from_bytes(std::span<uint8_t const, p256_scalar_size> bytes) -> P256Scalar;

/// @brief Serialize a scalar to 32-byte big-endian encoding.
/// @param a The scalar to serialize.
/// @return 32-byte big-endian encoding.
auto p256_sc_to_bytes(P256Scalar const& a) -> std::array<uint8_t, p256_scalar_size>;

/// @brief Return true if a == 0 (mod n).
/// @param a The scalar to test.
/// @return true if a is zero mod n.
auto p256_sc_is_zero(P256Scalar const& a) -> bool;

/// @brief Reduce a wide (64-byte) value mod n.
/// @param wide 64-byte big-endian value to reduce.
/// @return The value reduced mod n.
auto p256_sc_reduce_wide(std::span<uint8_t const, 2 * p256_scalar_size> wide) -> P256Scalar;

//
// Group operations
//

/// @brief Return the identity point (point at infinity).
/// @return The identity element with Z = 0.
auto p256_point_identity() -> P256JacobianPoint;

/// @brief Check if a Jacobian point is the identity (Z == 0).
/// @param P The point to test.
/// @return true if P is the point at infinity.
auto p256_point_is_identity(P256JacobianPoint const& P) -> bool;

/// @brief Jacobian point doubling (optimized for a = -3).
/// @param P The point to double.
/// @return 2 * P in Jacobian coordinates.
auto p256_point_double(P256JacobianPoint const& P) -> P256JacobianPoint;

/// @brief Jacobian point addition (complete: handles all edge cases).
/// @param P First point.
/// @param Q Second point.
/// @return P + Q in Jacobian coordinates.
auto p256_point_add(P256JacobianPoint const& P, P256JacobianPoint const& Q) -> P256JacobianPoint;

/// @brief Add a Jacobian point and an affine point (Z_Q = 1 optimization).
/// @param P Jacobian point.
/// @param Q Affine point (implicitly Z = 1).
/// @return P + Q in Jacobian coordinates.
auto p256_point_add_affine(P256JacobianPoint const& P, P256AffinePoint const& Q) -> P256JacobianPoint;

/// @brief Negate a point: (X, Y, Z) -> (X, -Y, Z).
/// @param P The point to negate.
/// @return -P in Jacobian coordinates.
auto p256_point_neg(P256JacobianPoint const& P) -> P256JacobianPoint;

/// @brief Convert Jacobian to affine coordinates (requires one field inversion).
/// @param P The Jacobian point to convert (must not be the identity).
/// @return The equivalent affine point (x, y).
auto p256_point_to_affine(P256JacobianPoint const& P) -> P256AffinePoint;

/// @brief Convert affine to Jacobian (Z = 1).
/// @param P The affine point to convert.
/// @return The equivalent Jacobian point with Z = 1.
auto p256_affine_to_jacobian(P256AffinePoint const& P) -> P256JacobianPoint;

/// @brief Check if an affine point is on the curve y^2 = x^3 - 3x + b.
/// @param P The affine point to test.
/// @return true if P satisfies the curve equation.
auto p256_point_on_curve(P256AffinePoint const& P) -> bool;

/// @brief Fixed-base scalar multiplication: [scalar] * G.
/// @param scalar The scalar multiplier.
/// @return scalar * G in Jacobian coordinates.
auto p256_scalar_mult_base(P256Scalar const& scalar) -> P256JacobianPoint;

/// @brief Variable-base scalar multiplication: [scalar] * P.
/// @param scalar The scalar multiplier.
/// @param P The base point in affine coordinates.
/// @return scalar * P in Jacobian coordinates.
auto p256_scalar_mult(P256Scalar const& scalar, P256AffinePoint const& P) -> P256JacobianPoint;

/// Double scalar multiplication: [a]*G + [b]*Q (Shamir's trick for ECDSA verify).
///
/// This function is used exclusively in ECDSA verification (RFC 6979 / FIPS 186-4
/// Section 4.7) where both scalars a, b and the point Q are derived from public
/// data (the message hash, signature components, and signer's public key).
/// No secret values are processed, so variable-time optimizations would be safe.
/// However, constant-time table lookup with p256_fe_cmov is used to prevent
/// leaking information about the verifier's state.
/// @param a Scalar multiplier for the generator G.
/// @param b Scalar multiplier for Q.
/// @param Q Variable base point in affine coordinates.
/// @return a*G + b*Q in Jacobian coordinates.
auto p256_double_scalar_mult(P256Scalar const& a, P256Scalar const& b, P256AffinePoint const& Q) -> P256JacobianPoint;

//
// Key generation
//

/// @brief Return the generator point G in affine coordinates.
/// @return The standard P-256 base point G.
auto p256_generator() -> P256AffinePoint;

/// @brief Generate a P-256 keypair from a 32-byte seed.
/// The seed is hashed with SHA-256, reduced mod n, and used as the private scalar.
/// @param seed 32-byte random seed.
/// @return (private_scalar, public_point) where public_point = scalar * G.
auto p256_keypair_from_seed(std::span<uint8_t const, p256_scalar_size> seed) -> std::pair<P256Scalar, P256AffinePoint>;

//
// Point encoding/decoding
//

/// @brief EC2OSP-X: Encode a point as x-coordinate only (0x01 || x), 33 bytes.
/// @param P The affine point to encode.
/// @return 33-byte encoding: 0x01 prefix followed by 32-byte big-endian x.
auto p256_encode_point_x(P256AffinePoint const& P) -> std::array<uint8_t, p256_compressed_point_size>;

/// @brief OS2ECP-X: Decode x-coordinate only encoding.
/// Since y is ambiguous, picks the even y. For ECDH this doesn't matter.
/// @param encoded 33-byte encoding (0x01 || x).
/// @return The decoded point, or std::nullopt if x is not on the curve.
auto p256_decode_point_x(std::span<uint8_t const, p256_compressed_point_size> encoded) -> std::optional<P256AffinePoint>;

/// @brief Encode as uncompressed (x || y), 64 bytes (no 0x04 prefix).
/// @param P The affine point to encode.
/// @return 64-byte encoding: x (32 bytes) || y (32 bytes), big-endian.
auto p256_encode_point_uncompressed(P256AffinePoint const& P) -> std::array<uint8_t, p256_uncompressed_point_size>;

/// @brief Decode uncompressed (x || y), 64 bytes.
/// @param encoded 64-byte encoding: x (32 bytes) || y (32 bytes), big-endian.
/// @return The decoded point, or std::nullopt if the point is not on the curve.
auto p256_decode_point_uncompressed(std::span<uint8_t const, p256_uncompressed_point_size> encoded)
    -> std::optional<P256AffinePoint>;

}  // namespace statusbar::crypto
