// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the constant-time bitsliced AES core. The S-box circuit is
// checked exhaustively — all 256 inputs, forward and inverse — against the
// FIPS 197 tables (kept here, in the test, as the reference; the production
// code deliberately contains no tables at all). The permutation and
// MixColumns plane networks are checked against a plain byte-wise model and
// the FIPS 197 known vector.

#include "statusbar/crypto/aes/aes_ct_internal.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <span>

using namespace statusbar::crypto;
using namespace statusbar::crypto::internal;

namespace {

/// FIPS 197 Section 5.1.1 S-box — reference for exhaustive verification.
// clang-format off
constexpr uint8_t REF_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
// clang-format on

/// Apply a plane transform to a 16-byte block through pack/unpack.
template <typename Fn>
auto via_planes(std::array<uint8_t, 16> const& in, Fn fn) -> std::array<uint8_t, 16>
{
    auto q = aes_ct_pack(in);
    fn(q);
    std::array<uint8_t, 16> out{};
    aes_ct_unpack(q, out);
    return out;
}

}  // namespace

TEST(aes_ct, pack_unpack_roundtrip)
{
    std::array<uint8_t, 16> block{};
    for (size_t i = 0; i < 16; ++i) {
        block[i] = static_cast<uint8_t>((i * 17) + 3);
    }
    auto const out = via_planes(block, [](AesBitPlanes&) {});
    EXPECT_EQ(out, block);
}

TEST(aes_ct, sbox_matches_fips_table_exhaustive)
{
    // 16 blocks of 16 consecutive byte values cover all 256 inputs.
    for (unsigned base = 0; base < 256; base += 16) {
        std::array<uint8_t, 16> block{};
        for (unsigned j = 0; j < 16; ++j) {
            block[j] = static_cast<uint8_t>(base + j);
        }
        auto const out = via_planes(block, [](AesBitPlanes& q) { aes_ct_sub_bytes(q); });
        for (unsigned j = 0; j < 16; ++j) {
            EXPECT_EQ(out[j], REF_SBOX[base + j]);
        }
    }
}

TEST(aes_ct, inv_sbox_matches_fips_table_exhaustive)
{
    for (unsigned base = 0; base < 256; base += 16) {
        std::array<uint8_t, 16> block{};
        for (unsigned j = 0; j < 16; ++j) {
            block[j] = REF_SBOX[base + j];
        }
        auto const out = via_planes(block, [](AesBitPlanes& q) { aes_ct_inv_sub_bytes(q); });
        for (unsigned j = 0; j < 16; ++j) {
            EXPECT_EQ(out[j], static_cast<uint8_t>(base + j));
        }
    }
}

TEST(aes_ct, shift_rows_matches_byte_model)
{
    std::array<uint8_t, 16> block{};
    for (size_t i = 0; i < 16; ++i) {
        block[i] = static_cast<uint8_t>(i);
    }
    auto const out = via_planes(block, [](AesBitPlanes& q) { aes_ct_shift_rows(q); });
    // state[c][r] = byte 4c+r; ShiftRows: row r rotates left by r columns,
    // so out[4c+r] = in[4*((c+r)%4)+r].
    for (size_t c = 0; c < 4; ++c) {
        for (size_t r = 0; r < 4; ++r) {
            EXPECT_EQ(out[(4 * c) + r], block[(4 * ((c + r) % 4)) + r]);
        }
    }
}

TEST(aes_ct, shift_rows_roundtrip)
{
    std::array<uint8_t, 16> block{};
    for (size_t i = 0; i < 16; ++i) {
        block[i] = static_cast<uint8_t>(0xA0 + i);
    }
    auto const out = via_planes(block, [](AesBitPlanes& q) {
        aes_ct_shift_rows(q);
        aes_ct_inv_shift_rows(q);
    });
    EXPECT_EQ(out, block);
}

TEST(aes_ct, mix_columns_fips_known_vector)
{
    // FIPS 197 / classic MixColumns test column {db,13,53,45} -> {8e,4d,a1,bc},
    // replicated across all four columns.
    std::array<uint8_t, 16> block{};
    for (size_t c = 0; c < 4; ++c) {
        block[(4 * c) + 0] = 0xdb;
        block[(4 * c) + 1] = 0x13;
        block[(4 * c) + 2] = 0x53;
        block[(4 * c) + 3] = 0x45;
    }
    auto const out = via_planes(block, [](AesBitPlanes& q) { aes_ct_mix_columns(q); });
    for (size_t c = 0; c < 4; ++c) {
        EXPECT_EQ(out[(4 * c) + 0], 0x8e);
        EXPECT_EQ(out[(4 * c) + 1], 0x4d);
        EXPECT_EQ(out[(4 * c) + 2], 0xa1);
        EXPECT_EQ(out[(4 * c) + 3], 0xbc);
    }
}

TEST(aes_ct, mix_columns_roundtrip)
{
    std::array<uint8_t, 16> block{};
    for (size_t i = 0; i < 16; ++i) {
        block[i] = static_cast<uint8_t>((i * 73) ^ 0x5c);
    }
    auto const out = via_planes(block, [](AesBitPlanes& q) {
        aes_ct_mix_columns(q);
        aes_ct_inv_mix_columns(q);
    });
    EXPECT_EQ(out, block);
}

TEST(aes_ct, sub_word_matches_table)
{
    auto const out = aes_ct_sub_word({0x00, 0x53, 0xcf, 0xff});
    EXPECT_EQ(out[0], REF_SBOX[0x00]);
    EXPECT_EQ(out[1], REF_SBOX[0x53]);
    EXPECT_EQ(out[2], REF_SBOX[0xcf]);
    EXPECT_EQ(out[3], REF_SBOX[0xff]);
}

TEST(aes_ct, encrypt_decrypt_roundtrip)
{
    // Deterministic dummy round keys; correctness against FIPS 197 / CAVP
    // vectors is covered end-to-end by aes128_test / aes256_test.
    std::array<std::array<uint8_t, 16>, 11> rks{};
    for (size_t k = 0; k < rks.size(); ++k) {
        for (size_t i = 0; i < 16; ++i) {
            rks[k][i] = static_cast<uint8_t>((k * 31) + (i * 7) + 1);
        }
    }
    std::array<uint8_t, 16> block{};
    for (size_t i = 0; i < 16; ++i) {
        block[i] = static_cast<uint8_t>(i * 11);
    }
    auto const original = block;
    aes_ct_encrypt_block(rks, block);
    EXPECT_TRUE(block != original);
    aes_ct_decrypt_block(rks, block);
    EXPECT_EQ(block, original);
}

TEST_MAIN(statusbar_crypto_aes, aes_ct_internal_test)
