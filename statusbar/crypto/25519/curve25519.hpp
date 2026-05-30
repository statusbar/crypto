// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Curve25519 field arithmetic and group operations
// References:
// - RFC 7748 (X25519): https://www.rfc-editor.org/rfc/rfc7748
// - RFC 8032 (Ed25519): https://www.rfc-editor.org/rfc/rfc8032

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// @brief Curve25519 scalar size in bytes (32).
inline constexpr size_t curve25519_scalar_size = 32;

/// @brief Curve25519 compressed point size in bytes (32).
inline constexpr size_t curve25519_point_size = 32;

/// @brief Wide scalar size in bytes (64), used for unreduced SHA-512 outputs.
inline constexpr size_t curve25519_wide_scalar_size = 64;

/// Field element in GF(2^255-19), stored as 5 x 51-bit limbs (radix 2^51)
struct Fe25519
{
    std::array<uint64_t, 5> limbs{};

    /// Securely zero field element limbs on destruction to prevent
    /// intermediate values from lingering on the stack.
    /// constexpr so Fe25519 remains a literal type for constexpr constants.
    constexpr ~Fe25519()
    {
        if !consteval {
            internal::secure_zero(limbs);
        }
    }
};

/// Extended coordinates point on the twisted Edwards curve
/// -x^2 + y^2 = 1 + d*x^2*y^2 where d = -121665/121666
/// (X, Y, Z, T) where x = X/Z, y = Y/Z, T = X*Y/Z
struct GeP3
{
    Fe25519 X;
    Fe25519 Y;
    Fe25519 Z;
    Fe25519 T;
};

//
// Field operations (constant-time)
//

/// @brief Add two field elements in GF(2^255-19).
/// @param a First operand.
/// @param b Second operand.
/// @return a + b mod p, not fully reduced (may exceed p).
auto fe25519_add(Fe25519 const& a, Fe25519 const& b) -> Fe25519;

/// @brief Subtract two field elements in GF(2^255-19).
/// @param a Minuend.
/// @param b Subtrahend.
/// @return a - b mod p, not fully reduced.
auto fe25519_sub(Fe25519 const& a, Fe25519 const& b) -> Fe25519;

/// @brief Multiply two field elements in GF(2^255-19).
///
/// Uses 128-bit unsigned integers for 64x64->128-bit intermediate products and reduces
/// mod p = 2^255-19 by folding high limbs with factor 19.
/// @param a First operand.
/// @param b Second operand.
/// @return a * b mod p, partially reduced.
auto fe25519_mul(Fe25519 const& a, Fe25519 const& b) -> Fe25519;

/// @brief Square a field element in GF(2^255-19).
///
/// Optimized specialization of multiply that exploits symmetry in the
/// schoolbook expansion to reduce the number of 64x64 multiplications.
/// @param a Operand to square.
/// @return a^2 mod p, partially reduced.
auto fe25519_sq(Fe25519 const& a) -> Fe25519;

/// @brief Compute the multiplicative inverse of a field element.
///
/// Computes z^(p-2) mod p using an addition chain, which yields the
/// inverse by Fermat's little theorem since p is prime.
/// @param z Field element to invert. Must be nonzero.
/// @return z^(-1) mod p.
auto fe25519_invert(Fe25519 const& z) -> Fe25519;

/// @brief Negate a field element in GF(2^255-19).
/// @param a Field element to negate.
/// @return p - a mod p.
auto fe25519_neg(Fe25519 const& a) -> Fe25519;

/// @brief Constant-time conditional move.
///
/// If b is 1, sets f to g. If b is 0, leaves f unchanged.
/// Runs in constant time regardless of b to avoid side-channel leakage.
/// @param f Destination field element (modified in place).
/// @param g Source field element.
/// @param b Condition flag, must be 0 or 1.
void fe25519_cmov(Fe25519& f, Fe25519 const& g, uint64_t b);

/// @brief Deserialize 32 bytes (little-endian) into a field element.
///
/// Unpacks a 256-bit little-endian integer into 5x51-bit limbs,
/// masking the top bit (bit 255) to stay within the field.
/// @param s 32-byte little-endian encoding.
/// @return Field element representing the decoded value.
auto fe25519_from_bytes(std::span<uint8_t const, curve25519_point_size> s) -> Fe25519;

/// @brief Serialize a field element to canonical 32-byte little-endian form.
///
/// Fully reduces the field element mod p before encoding, ensuring a
/// unique canonical representation in [0, p).
/// @param h Field element to serialize.
/// @return 32-byte little-endian encoding of the canonical representative.
auto fe25519_to_bytes(Fe25519 const& h) -> std::array<uint8_t, curve25519_point_size>;

/// @brief Return the low bit of the canonical encoding of a field element.
///
/// Determines the "sign" of the field element as defined by RFC 8032:
/// the least significant bit of the canonical byte encoding.
/// @param f Field element to test.
/// @return 0 or 1, the least significant bit of the canonical form.
auto fe25519_is_negative(Fe25519 const& f) -> uint64_t;

/// @brief Test whether a field element is zero mod p.
/// @param f Field element to test.
/// @return 1 if f == 0 mod p, 0 otherwise.
auto fe25519_is_zero(Fe25519 const& f) -> uint64_t;

/// @brief Compute z^((p-5)/8) = z^(2^252 - 3) in GF(2^255-19).
///
/// Used during point decompression to recover the x-coordinate from y.
/// The exponent (p-5)/8 arises from the square root formula for p = 5 mod 8.
/// @param z Field element to exponentiate.
/// @return z^(2^252 - 3) mod p.
auto fe25519_pow22523(Fe25519 const& z) -> Fe25519;

/// @brief Return the zero field element (additive identity).
/// @return Field element with all limbs set to zero.
auto fe25519_zero() -> Fe25519;

/// @brief Return the multiplicative identity (one) in GF(2^255-19).
/// @return Field element representing 1.
auto fe25519_one() -> Fe25519;

/// @brief Multiply a field element by a small integer.
///
/// Multiplies each limb by a single-word value and propagates carries.
/// More efficient than full fe25519_mul when one operand fits in a limb.
/// @param a Field element operand.
/// @param b Small integer multiplier (single limb).
/// @return a * b mod p, partially reduced.
auto fe25519_mul_small(Fe25519 const& a, uint64_t b) -> Fe25519;

//
// Edwards group operations
//

/// @brief Return the neutral element (identity point) on the Edwards curve.
/// @return Point (0, 1, 1, 0) in extended coordinates.
auto ge_p3_identity() -> GeP3;

/// @brief Encode an extended coordinates point to 32 bytes per RFC 8032.
///
/// The lower 255 bits encode the y-coordinate and bit 255 encodes the
/// sign of the x-coordinate (its least significant bit in canonical form).
/// @param p Point to encode.
/// @return 32-byte compressed point encoding.
auto ge_p3_to_bytes(GeP3 const& p) -> std::array<uint8_t, curve25519_point_size>;

/// @brief Decode a 32-byte compressed point on the Edwards curve.
///
/// Recovers the x-coordinate from y using the curve equation and the sign
/// bit. Validates that the point lies on the curve.
/// @param s 32-byte compressed point encoding.
/// @return The decoded point, or std::nullopt if the input does not represent a valid curve point.
auto ge_from_bytes(std::span<uint8_t const, curve25519_point_size> s) -> std::optional<GeP3>;

/// @brief Compute [scalar]B where B is the Ed25519 base point.
///
/// Uses a constant-time double-and-add algorithm to prevent timing
/// side-channel attacks on the secret scalar.
/// @param scalar 32-byte little-endian scalar.
/// @return The resulting point in extended coordinates.
auto ge_scalar_mult_base(std::span<uint8_t const, curve25519_scalar_size> scalar) -> GeP3;

/// @brief Add two points on the twisted Edwards curve (a = -1).
///
/// Implements the add-2008-hwcd-3 unified addition formula for extended
/// coordinates, which handles all input cases without exceptions.
/// @param P First point.
/// @param Q Second point.
/// @return P + Q in extended coordinates.
auto ge_p3_add(GeP3 const& P, GeP3 const& Q) -> GeP3;

/// @brief Compute [a]A + [b]B using Straus/Shamir's trick (variable-time).
///
/// Performs a double scalar multiplication using simultaneous multi-scalar
/// techniques. Variable-time: safe only when both scalars and the point A
/// are public (e.g., signature verification).
/// @param a 32-byte little-endian scalar for point A.
/// @param A Public point on the curve.
/// @param b 32-byte little-endian scalar for the base point B.
/// @return [a]A + [b]B in extended coordinates.
auto ge_double_scalar_mult_vartime(
    std::span<uint8_t const, curve25519_scalar_size> a, GeP3 const& A, std::span<uint8_t const, curve25519_scalar_size> b) -> GeP3;

/// @brief Negate a point on the Edwards curve.
/// @param P Point to negate.
/// @return (-X, Y, Z, -T), the additive inverse of P.
auto ge_p3_neg(GeP3 const& P) -> GeP3;

/// @brief Double a point on the twisted Edwards curve (a = -1).
///
/// Uses a dedicated doubling formula that is more efficient than
/// general addition when both inputs are the same point.
/// @param P Point to double.
/// @return 2P in extended coordinates.
auto ge_p3_dbl(GeP3 const& P) -> GeP3;

//
// Scalar operations mod L (group order)
// L = 2^252 + 27742317777372353535851937790883648493
//

/// @brief Reduce a 64-byte (512-bit) scalar mod L (the group order).
///
/// L = 2^252 + 27742317777372353535851937790883648493. Typically used to
/// reduce SHA-512 hash outputs into valid Ed25519 scalars.
/// @param in 64-byte little-endian scalar (e.g., SHA-512 output).
/// @return 32-byte little-endian scalar in [0, L).
auto sc_reduce(std::span<uint8_t const, curve25519_wide_scalar_size> in) -> std::array<uint8_t, curve25519_scalar_size>;

/// @brief Compute (a * b + c) mod L using schoolbook multiplication in 21-bit limbs.
///
/// Performs modular multiply-add in the scalar field of Ed25519. Used in
/// signature generation to compute S = (r + H(R,A,M) * a) mod L.
/// @param a First multiplicand (32-byte little-endian scalar).
/// @param b Second multiplicand (32-byte little-endian scalar).
/// @param c Addend (32-byte little-endian scalar).
/// @return (a * b + c) mod L as a 32-byte little-endian scalar.
auto sc_mul_add(
    std::span<uint8_t const, curve25519_scalar_size> a,
    std::span<uint8_t const, curve25519_scalar_size> b,
    std::span<uint8_t const, curve25519_scalar_size> c) -> std::array<uint8_t, curve25519_scalar_size>;

/// @brief Reduce a 64-byte scalar mod L, returning a SecureArray that zeroes on destruction.
///
/// Same computation as sc_reduce, but the result is securely zeroed when it
/// goes out of scope. Use this when the reduced scalar is secret (e.g. signing nonce).
/// @param s 64-byte little-endian scalar.
/// @return SecureArray<32> containing the reduced scalar in [0, L).
auto sc_reduce_secure(std::span<uint8_t const, curve25519_wide_scalar_size> s) -> SecureArray<curve25519_scalar_size>;

/// @brief Compute (a * b + c) mod L, returning a SecureArray that zeroes on destruction.
///
/// Same computation as sc_mul_add, but the result is securely zeroed when it
/// goes out of scope. Use this when the result is secret (e.g. signature scalar S).
/// @param a First multiplicand (32-byte little-endian scalar).
/// @param b Second multiplicand (32-byte little-endian scalar).
/// @param c Addend (32-byte little-endian scalar).
/// @return SecureArray<32> containing (a * b + c) mod L.
auto sc_mul_add_secure(
    std::span<uint8_t const, curve25519_scalar_size> a,
    std::span<uint8_t const, curve25519_scalar_size> b,
    std::span<uint8_t const, curve25519_scalar_size> c) -> SecureArray<curve25519_scalar_size>;

//
// Montgomery ladder (for X25519)
//

/// @brief Perform X25519 scalar multiplication on the Montgomery curve.
///
/// Computes the u-coordinate of [scalar]P using the Montgomery ladder,
/// where P is specified by its u-coordinate. The scalar is clamped per
/// RFC 7748 Section 5 (clear low 3 bits, clear bit 255, set bit 254).
/// @param scalar 32-byte little-endian scalar (clamped internally).
/// @param point_u 32-byte little-endian u-coordinate of the input point.
/// @return 32-byte little-endian u-coordinate of the resulting point.
auto curve25519_scalar_mult(
    std::span<uint8_t const, curve25519_scalar_size> scalar, std::span<uint8_t const, curve25519_point_size> point_u)
    -> std::array<uint8_t, curve25519_point_size>;

}  // namespace statusbar::crypto
