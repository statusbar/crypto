// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128 constants
// Round constants from FIPS 197 Section 5.2.

#pragma once

#include <cstdint>

namespace statusbar::crypto {
namespace constants {

// Round constants (FIPS 197 Section 5.2):
// rcon[i] = x^(i+1) in GF(2^8), used in key schedule RotWord/SubWord step.
inline constexpr uint8_t aes128_rcon[10] = {
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1b,
    0x36,
};

}  // namespace constants
}  // namespace statusbar::crypto
