// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// POLYVAL constants
// Reduction constant for GF(2^128) multiplication used by POLYVAL (RFC 8452 Section 3).

#pragma once

#include <cstdint>

namespace statusbar::crypto {
namespace constants {

// POLYVAL reduction constant for right-shift multiplication in the reflected
// GF(2^128) representation.
//
// The POLYVAL field uses the irreducible polynomial:
//   p(x) = x^128 + x^127 + x^126 + x^121 + 1
//
// This constant encodes x^{-1} mod p = x^127 + x^126 + x^125 + x^120,
// which corresponds to the bit pattern 0xe100000000000000 in the high 64 bits.
//
// @see https://www.rfc-editor.org/rfc/rfc8452#section-3
inline constexpr uint64_t POLYVAL_REDUCTION = 0xe100000000000000ULL;

}  // namespace constants
}  // namespace statusbar::crypto
