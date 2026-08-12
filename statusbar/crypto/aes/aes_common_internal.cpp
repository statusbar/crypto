// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/crypto/aes/aes_common_internal.hpp"

namespace statusbar::crypto::internal {

void left_shift_one(std::array<uint8_t, aes_block_size>& block)
{
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t const next_carry = block[i] >> 7;
        block[i] = static_cast<uint8_t>((block[i] << 1) | carry);
        carry = next_carry;
    }
}

auto constant_time_equal(std::span<uint8_t const, aes_block_size> a, std::span<uint8_t const, aes_block_size> b) -> bool
{
    uint8_t diff = 0;
    for (size_t i = 0; i < aes_block_size; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

auto cmac_derive_subkeys(std::array<uint8_t, aes_block_size> const& L) -> CmacSubkeys
{
    constexpr uint8_t rb = 0x87;
    CmacSubkeys sk;

    // K1 = (L << 1) ^ (msb(L) ? Rb : 0)
    sk.K1 = L;
    uint8_t msb = sk.K1[0] >> 7;
    left_shift_one(sk.K1);
    sk.K1[15] ^= static_cast<uint8_t>(rb & static_cast<uint8_t>(~msb + 1));

    // K2 = (K1 << 1) ^ (msb(K1) ? Rb : 0)
    sk.K2 = sk.K1;
    msb = sk.K2[0] >> 7;
    left_shift_one(sk.K2);
    sk.K2[15] ^= static_cast<uint8_t>(rb & static_cast<uint8_t>(~msb + 1));

    return sk;
}

}  // namespace statusbar::crypto::internal
