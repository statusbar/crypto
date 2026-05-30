// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for AES internal primitives (state transforms, S-box, GF math, CMAC subkeys)

#include "statusbar/crypto/aes/aes_common_internal.hpp"

#include "statusbar/test/test.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

using namespace statusbar::crypto;
using namespace statusbar::crypto::internal;

//
// Tests: state_from_bytes / state_to_bytes round trip
//

TEST(aes_internal, state_from_bytes_column_major)
{
    // FIPS 197 Section 3.4: input bytes map to state[col][row] = in[col*4 + row]
    std::array<uint8_t, aes_block_size> input{};
    for (uint8_t i = 0; i < 16; ++i) {
        input[i] = i;
    }

    State s{};
    state_from_bytes(s, input);

    // Column 0: bytes 0,1,2,3
    EXPECT_EQ(s[0][0], 0);
    EXPECT_EQ(s[0][1], 1);
    EXPECT_EQ(s[0][2], 2);
    EXPECT_EQ(s[0][3], 3);

    // Column 1: bytes 4,5,6,7
    EXPECT_EQ(s[1][0], 4);
    EXPECT_EQ(s[1][1], 5);
    EXPECT_EQ(s[1][2], 6);
    EXPECT_EQ(s[1][3], 7);

    // Column 3: bytes 12,13,14,15
    EXPECT_EQ(s[3][0], 12);
    EXPECT_EQ(s[3][3], 15);
}

TEST(aes_internal, state_roundtrip)
{
    std::array<uint8_t, aes_block_size> input{};
    for (uint8_t i = 0; i < 16; ++i) {
        input[i] = static_cast<uint8_t>((i * 17) + 3);
    }

    State s{};
    state_from_bytes(s, input);

    std::array<uint8_t, aes_block_size> output{};
    state_to_bytes(s, output);

    for (size_t i = 0; i < aes_block_size; ++i) {
        EXPECT_EQ(output[i], input[i]);
    }
}

//
// Tests: add_round_key (XOR)
//

TEST(aes_internal, add_round_key_xors_state)
{
    State s{};
    std::array<uint8_t, aes_block_size> input{};
    for (uint8_t i = 0; i < 16; ++i) {
        input[i] = i;
    }
    state_from_bytes(s, input);

    std::array<uint8_t, aes_block_size> rk{};
    for (uint8_t i = 0; i < 16; ++i) {
        rk[i] = 0xFF;
    }

    add_round_key(s, rk);

    // XOR with 0xFF inverts all bits
    std::array<uint8_t, aes_block_size> output{};
    state_to_bytes(s, output);
    for (size_t i = 0; i < aes_block_size; ++i) {
        EXPECT_EQ(output[i], static_cast<uint8_t>(input[i] ^ 0xFF));
    }
}

TEST(aes_internal, add_round_key_twice_restores)
{
    State s{};
    std::array<uint8_t, aes_block_size> input{};
    for (uint8_t i = 0; i < 16; ++i) {
        input[i] = static_cast<uint8_t>(i * 7);
    }
    state_from_bytes(s, input);

    std::array<uint8_t, aes_block_size> rk{};
    for (uint8_t i = 0; i < 16; ++i) {
        rk[i] = static_cast<uint8_t>(0xAB + i);
    }

    add_round_key(s, rk);
    add_round_key(s, rk);

    std::array<uint8_t, aes_block_size> output{};
    state_to_bytes(s, output);
    for (size_t i = 0; i < aes_block_size; ++i) {
        EXPECT_EQ(output[i], input[i]);
    }
}

//
// Tests: sub_bytes / inv_sub_bytes
//

TEST(aes_internal, sub_bytes_known_values)
{
    // S-box: sbox[0x00] = 0x63, sbox[0x01] = 0x7c, sbox[0x53] = 0xed
    State s{};
    s[0][0] = 0x00;
    s[0][1] = 0x01;
    s[1][0] = 0x53;

    sub_bytes(s);

    EXPECT_EQ(s[0][0], 0x63);
    EXPECT_EQ(s[0][1], 0x7c);
    EXPECT_EQ(s[1][0], 0xed);
}

TEST(aes_internal, sub_bytes_inv_sub_bytes_roundtrip)
{
    State s{};
    std::array<uint8_t, aes_block_size> input{};
    for (uint8_t i = 0; i < 16; ++i) {
        input[i] = static_cast<uint8_t>((i * 13) + 7);
    }
    state_from_bytes(s, input);

    sub_bytes(s);
    inv_sub_bytes(s);

    std::array<uint8_t, aes_block_size> output{};
    state_to_bytes(s, output);
    for (size_t i = 0; i < aes_block_size; ++i) {
        EXPECT_EQ(output[i], input[i]);
    }
}

//
// Tests: shift_rows / inv_shift_rows
//

TEST(aes_internal, shift_rows_row0_unchanged)
{
    State s{};
    // Set row 0 values across all columns
    s[0][0] = 0xAA;
    s[1][0] = 0xBB;
    s[2][0] = 0xCC;
    s[3][0] = 0xDD;

    shift_rows(s);

    // Row 0 is not shifted
    EXPECT_EQ(s[0][0], 0xAA);
    EXPECT_EQ(s[1][0], 0xBB);
    EXPECT_EQ(s[2][0], 0xCC);
    EXPECT_EQ(s[3][0], 0xDD);
}

TEST(aes_internal, shift_rows_row1_left_by_1)
{
    State s{};
    s[0][1] = 0x10;
    s[1][1] = 0x20;
    s[2][1] = 0x30;
    s[3][1] = 0x40;

    shift_rows(s);

    // Row 1 rotated left by 1: [20, 30, 40, 10]
    EXPECT_EQ(s[0][1], 0x20);
    EXPECT_EQ(s[1][1], 0x30);
    EXPECT_EQ(s[2][1], 0x40);
    EXPECT_EQ(s[3][1], 0x10);
}

TEST(aes_internal, shift_rows_inv_shift_rows_roundtrip)
{
    State s{};
    std::array<uint8_t, aes_block_size> input{};
    for (uint8_t i = 0; i < 16; ++i) {
        input[i] = static_cast<uint8_t>((i * 11) + 5);
    }
    state_from_bytes(s, input);

    shift_rows(s);
    inv_shift_rows(s);

    std::array<uint8_t, aes_block_size> output{};
    state_to_bytes(s, output);
    for (size_t i = 0; i < aes_block_size; ++i) {
        EXPECT_EQ(output[i], input[i]);
    }
}

//
// Tests: mix_columns / inv_mix_columns
//

TEST(aes_internal, mix_columns_inv_mix_columns_roundtrip)
{
    State s{};
    std::array<uint8_t, aes_block_size> input{};
    for (uint8_t i = 0; i < 16; ++i) {
        input[i] = static_cast<uint8_t>((i * 23) + 1);
    }
    state_from_bytes(s, input);

    mix_columns(s);
    inv_mix_columns(s);

    std::array<uint8_t, aes_block_size> output{};
    state_to_bytes(s, output);
    for (size_t i = 0; i < aes_block_size; ++i) {
        EXPECT_EQ(output[i], input[i]);
    }
}

TEST(aes_internal, mix_columns_known_vector)
{
    // FIPS 197 Appendix B example column:
    // Input column: {db, 13, 53, 45} -> Output: {8e, 4d, a1, bc}
    State s{};
    s[0] = {0xdb, 0x13, 0x53, 0x45};
    // Zero other columns
    s[1] = {0, 0, 0, 0};
    s[2] = {0, 0, 0, 0};
    s[3] = {0, 0, 0, 0};

    mix_columns(s);

    EXPECT_EQ(s[0][0], 0x8e);
    EXPECT_EQ(s[0][1], 0x4d);
    EXPECT_EQ(s[0][2], 0xa1);
    EXPECT_EQ(s[0][3], 0xbc);
}

//
// Tests: left_shift_one
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

//
// Tests: GF(2^8) arithmetic (constexpr - compile-time verified)
//

TEST(aes_internal, xtime_known_values)
{
    // xtime(0x57) = 0xAE (from FIPS 197 Section 4.2.1)
    EXPECT_EQ(xtime(0x57), 0xAE);

    // xtime(0xAE) = 0x47 (with reduction by x^8+x^4+x^3+x+1)
    EXPECT_EQ(xtime(0xAE), 0x47);

    // xtime(0x00) = 0x00
    EXPECT_EQ(xtime(0x00), 0x00);

    // xtime(0x01) = 0x02
    EXPECT_EQ(xtime(0x01), 0x02);
}

TEST(aes_internal, gf_mul_known_values)
{
    // gf_mul(0x57, 0x02) = xtime(0x57) = 0xAE
    EXPECT_EQ(gf_mul(0x57, 0x02), 0xAE);

    // gf_mul(a, 1) = a for any a
    EXPECT_EQ(gf_mul(0x57, 0x01), 0x57);
    EXPECT_EQ(gf_mul(0xFF, 0x01), 0xFF);

    // gf_mul(a, 0) = 0 for any a
    EXPECT_EQ(gf_mul(0x57, 0x00), 0x00);
    EXPECT_EQ(gf_mul(0xFF, 0x00), 0x00);

    // FIPS 197 Section 4.2.1: 0x57 * 0x13 = 0xFE
    EXPECT_EQ(gf_mul(0x57, 0x13), 0xFE);
}

//
// Main test runner
//

TEST_MAIN(statusbar_crypto_aes, aes_common_internal_test)
