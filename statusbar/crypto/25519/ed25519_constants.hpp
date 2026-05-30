// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Ed25519 constants
// Group order L used for canonical scalar checks during verification.

#pragma once

#include "statusbar/crypto/25519/curve25519.hpp"

#include <array>
#include <cstdint>

namespace statusbar::crypto {
namespace constants {

// L = 2^252 + 27742317777372353535851937790883648493 in little-endian byte order.
// Used for canonical S check during verification.
inline constexpr std::array<uint8_t, curve25519_scalar_size> group_order_L = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,  //
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,  //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,  //
};

}  // namespace constants
}  // namespace statusbar::crypto
