// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Curve25519 / Ed25519 constants
// Field element constants, base points, and masks used by curve25519.cpp,
// ed25519.cpp, and x25519.cpp.

#pragma once

#include "statusbar/crypto/25519/curve25519.hpp"

#include <array>
#include <cstdint>

namespace statusbar::crypto {
namespace constants {

// Bit mask for the lower 51 bits of a limb
inline constexpr uint64_t MASK51 = (uint64_t{1} << 51) - 1;

// Ed25519 curve constant d = -121665/121666 mod p
inline constexpr Fe25519 ED25519_D = {
    {929955233495203ULL, 466365720129213ULL, 1662059464998953ULL, 2033849074728123ULL, 1442794654840575ULL}};

// 2*d, precomputed for addition formulas
inline constexpr Fe25519 ED25519_2D = {
    {1859910466990425ULL, 932731440258426ULL, 1072319116312658ULL, 1815898335770999ULL, 633789495995903ULL}};

// sqrt(-1) mod p = 2^((p-1)/4) mod p. Used in ge_from_bytes when v*x^2 == -u
inline constexpr Fe25519 SQRT_M1 = {
    {1718705420411056ULL, 234908883556509ULL, 2233514472574048ULL, 2117202627021982ULL, 765476049583133ULL}};

// Ed25519 base point (compressed)
inline constexpr std::array<uint8_t, curve25519_point_size> BASE_POINT_COMPRESSED = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

// X25519/Montgomery curve base point: u-coordinate 9 (little-endian).
// Shared by x25519.cpp (as BASEPOINT_9) and ed25519.cpp (as x25519_basepoint).
inline constexpr std::array<uint8_t, curve25519_point_size> X25519_BASEPOINT = {9};

// 2*p in 5x51-bit limb form, used as bias in fe25519_sub to prevent underflow.
// p = 2^255 - 19, so 2p limbs are {2*(2^51-19), 2*(2^51-1), ..., 2*(2^51-1)}.
inline constexpr Fe25519 FE25519_2P = {
    {0xFFFFFFFFFFFDAULL, 0xFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFEULL}};

// Scalar reduction coefficients for mod L arithmetic.
// L = 2^252 + 27742317777372353535851937790883648493 (Ed25519 group order).
// These are the 6 signed balanced radix-2^21 limbs of -(L - 2^252),
// encoding 2^252 ≡ L0 + L1·2^21 + L2·2^42 + L3·2^63 + L4·2^84 + L5·2^105 (mod L).
// Used by sc_reduce and sc_mul_add to fold high limbs into low limbs.
inline constexpr int64_t SC_L0 = 666643;  // limb 0: positive
inline constexpr int64_t SC_L1 = 470296;  // limb 1: positive
inline constexpr int64_t SC_L2 = 654183;  // limb 2: positive
inline constexpr int64_t SC_L3 = 997805;  // limb 3: used with -= (negative in signed balanced form)
inline constexpr int64_t SC_L4 = 136657;  // limb 4: positive
inline constexpr int64_t SC_L5 = 683901;  // limb 5: used with -= (negative in signed balanced form)

}  // namespace constants
}  // namespace statusbar::crypto
