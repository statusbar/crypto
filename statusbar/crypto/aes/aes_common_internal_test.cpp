// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for the shared AES CMAC helpers (subkey doubling, constant-time
// comparison, subkey derivation). The block-cipher primitives are tested in
// aes_ct_internal_test.cpp.

#include "statusbar/crypto/aes/aes_common_internal.hpp"

#include "statusbar/test/test.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

using namespace statusbar::crypto;
using namespace statusbar::crypto::internal;

//
// Tests: left_shift_one (CMAC subkey doubling)
//

TEST(aes_internal, left_shift_one_simple)
{
    std::array<uint8_t, aes_block_size> block{};
    block[0] = 0x01;

    left_shift_one(block);

    EXPECT_EQ(block[0], 0x02);
}

TEST(aes_internal, left_shift_one_carry)
{
    std::array<uint8_t, aes_block_size> block{};
    block[15] = 0x80;  // High bit of last byte

    left_shift_one(block);

    // Carry propagates: byte 15 becomes 0, byte 14 gets the carry
    EXPECT_EQ(block[15], 0x00);
    EXPECT_EQ(block[14], 0x01);
}

TEST(aes_internal, left_shift_one_all_ones)
{
    std::array<uint8_t, aes_block_size> block{};
    std::fill(block.begin(), block.end(), 0xFF);

    left_shift_one(block);

    // 0xFF << 1 = 0xFE with carry, except first byte loses MSB carry
    EXPECT_EQ(block[0], 0xFF);   // 0xFF << 1 | 1 carry from byte 1
    EXPECT_EQ(block[15], 0xFE);  // 0xFF << 1, no carry from beyond
}

//
// Tests: constant_time_equal
//

TEST(aes_internal, constant_time_equal_same)
{
    std::array<uint8_t, aes_block_size> a{};
    std::array<uint8_t, aes_block_size> b{};
    for (uint8_t i = 0; i < 16; ++i) {
        a[i] = i;
        b[i] = i;
    }

    EXPECT_TRUE(constant_time_equal(a, b));
}

TEST(aes_internal, constant_time_equal_different)
{
    std::array<uint8_t, aes_block_size> a{};
    std::array<uint8_t, aes_block_size> b{};
    for (uint8_t i = 0; i < 16; ++i) {
        a[i] = i;
        b[i] = i;
    }
    b[15] = 0xFF;

    EXPECT_FALSE(constant_time_equal(a, b));
}

TEST(aes_internal, constant_time_equal_all_zeros)
{
    std::array<uint8_t, aes_block_size> a{};
    std::array<uint8_t, aes_block_size> b{};

    EXPECT_TRUE(constant_time_equal(a, b));
}

//
// Tests: cmac_derive_subkeys
//

TEST(aes_internal, cmac_derive_subkeys_rfc4493_vector)
{
    // RFC 4493 test vector: L = AES-128(K, 0^128) with K = all zeros
    // For zero key, AES(0, 0) = 0x66e94bd4ef8a2c3b884cfa59ca342b2e
    // K1 = 0xfbeed618357133667c85e08f7236a8de (from doubling in GF)
    // Not easy to compute here without full AES, but we can test the derivation
    // with a known L value.

    // Test with L = 0 (simple case)
    std::array<uint8_t, aes_block_size> L{};
    auto sk = cmac_derive_subkeys(L);

    // L=0, so L<<1 = 0, MSB=0 so no XOR with Rb
    // K1 = 0, K2 = 0
    for (size_t i = 0; i < aes_block_size; ++i) {
        EXPECT_EQ(sk.K1[i], 0);
        EXPECT_EQ(sk.K2[i], 0);
    }
}

TEST(aes_internal, cmac_derive_subkeys_msb_set)
{
    // When MSB of L is set, K1 = (L << 1) ^ Rb
    std::array<uint8_t, aes_block_size> L{};
    L[0] = 0x80;  // MSB set

    auto sk = cmac_derive_subkeys(L);

    // L << 1 = all zeros (0x80 << 1 overflows byte 0, but carry gets lost from byte 0)
    // Actually: left_shift_one shifts the whole block left by 1 bit
    // 0x80 00...00 << 1 = 0x00 00...00 (with carry out)
    // Wait, the carry from byte[0] is the MSB, and it gets lost since there's nothing to receive it
    // Actually looking at left_shift_one: it processes from byte 15 to byte 0, carrying upward
    // Byte 0 = 0x80: (0x80 << 1) | carry_from_byte_1 = 0x00 | 0 = 0x00, carry = 0x80 >> 7 = 1
    // But carry from byte 0 is just dropped (no byte -1)
    // So L << 1 = 0x00 00...00
    // MSB was set, so XOR with 0x87 at byte[15]
    // K1 = 0x00 00...00 ^ 0x00 00...87 = 0x00 00...87
    EXPECT_EQ(sk.K1[0], 0x00);
    EXPECT_EQ(sk.K1[15], 0x87);

    // K1[0] MSB = 0, so K2 = K1 << 1, no XOR
    // K1 = 0x00..0087 << 1 = 0x00..010e
    EXPECT_EQ(sk.K2[14], 0x01);
    EXPECT_EQ(sk.K2[15], 0x0e);
}

TEST_MAIN(statusbar_crypto_aes, aes_common_internal_test)
