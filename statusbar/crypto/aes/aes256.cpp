// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256 block cipher (FIPS 197)
// Reference: https://csrc.nist.gov/publications/detail/fips/197/final
//
// Implements:
// - Key expansion (Section 5.2): 256-bit key -> 15 round keys (Nk=8, Nr=14, 60 words)
// - Encryption (Section 5.1): 14 rounds of SubBytes/ShiftRows/MixColumns/AddRoundKey
// - Decryption (Section 5.3): Inverse cipher with InvSubBytes/InvShiftRows/InvMixColumns
// - CMAC (NIST SP 800-38B): CBC-MAC with subkey derivation for message authentication
//
// Internal representation:
// - State is a 4x4 byte matrix stored column-major [col][row] per FIPS 197 Section 3.4
// - GF(2^8) arithmetic uses the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1

#include "statusbar/crypto/aes/aes256.hpp"

#include "statusbar/crypto/aes/aes256_constants.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/aes/aes_ct_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

namespace statusbar::crypto {

using namespace internal;
using std::span;

namespace {

constexpr auto& rcon = constants::aes256_rcon;

// Access a 4-byte word within the flat round keys array.
// The 60 key schedule words are stored across 15 round key arrays (4 words each).
// Word i is at round_keys[i/4], bytes [(i%4)*4 .. (i%4)*4+3].
struct WordView
{
    std::array<std::array<uint8_t, aes_block_size>, aes256_num_rounds + 1>& keys;

    auto get(size_t i) const -> std::array<uint8_t, 4>
    {
        auto const& rk = keys[i / 4];
        size_t const off = (i % 4) * 4;
        return {rk[off], rk[off + 1], rk[off + 2], rk[off + 3]};
    }

    void set(size_t i, std::array<uint8_t, 4> const& w)
    {
        auto& rk = keys[i / 4];
        size_t const off = (i % 4) * 4;
        rk[off] = w[0];
        rk[off + 1] = w[1];
        rk[off + 2] = w[2];
        rk[off + 3] = w[3];
    }
};

}  // anonymous namespace

//
// Key expansion (FIPS 197 Section 5.2)
//

// AES-256 key schedule: expands an 8-word (256-bit) key into 60 words (15 round keys).
// Differs from AES-128 in two ways:
//   1. The key is 8 words (Nk=8) instead of 4, so the first two round keys come
//      directly from the key material.
//   2. An extra SubWord transform is applied when (i mod Nk) == 4, providing
//      additional non-linearity in the longer key schedule.
auto aes256_expand_key_sw(Aes256Key const& key) -> Aes256RoundKeys
{
    Aes256RoundKeys rk;

    // First 8 words (32 bytes) are the key itself
    span_copy(rk.round_keys[0], span<uint8_t const>(key.data).first<16>());
    span_copy(rk.round_keys[1], span<uint8_t const>(key.data).last<16>());

    WordView wv{rk.round_keys};

    for (size_t i = 8; i < 60; ++i) {
        auto temp = wv.get(i - 1);

        if (i % 8 == 0) {
            // RotWord + SubWord + Rcon
            auto const sw = aes_ct_sub_word({temp[1], temp[2], temp[3], temp[0]});
            temp = {
                static_cast<uint8_t>(sw[0] ^ rcon[(i / 8) - 1]),
                sw[1],
                sw[2],
                sw[3],
            };
        } else if (i % 8 == 4) {
            // SubWord only (AES-256 specific)
            temp = aes_ct_sub_word(temp);
        }

        auto prev = wv.get(i - 8);
        wv.set(
            i,
            {
                static_cast<uint8_t>(prev[0] ^ temp[0]),
                static_cast<uint8_t>(prev[1] ^ temp[1]),
                static_cast<uint8_t>(prev[2] ^ temp[2]),
                static_cast<uint8_t>(prev[3] ^ temp[3]),
            });
    }

    return rk;
}

//
// Block encrypt / decrypt (FIPS 197 Sections 5.1, 5.3)
//

// AES-256 encryption: 14 rounds via the constant-time bitsliced core
// (aes_ct_internal.hpp) — no table lookups, no secret-dependent timing.
void aes256_encrypt_block_sw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    aes_ct_encrypt_block(rk.round_keys, block);
}

// AES-256 decryption: inverse cipher, 14 rounds, same constant-time core.
void aes256_decrypt_block_sw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    aes_ct_decrypt_block(rk.round_keys, block);
}

//
// CMAC (NIST SP 800-38B)
//

auto aes256_cmac_sw(Aes256RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes256_block_size>
{
    return internal::cmac_core([&rk](auto block) { aes256_encrypt_block_sw(rk, block); }, message);
}

auto aes256_cmac_xorend_sw(Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> xor_end)
    -> std::array<uint8_t, aes256_block_size>
{
    return internal::cmac_xorend_core([&rk](auto block) { aes256_encrypt_block_sw(rk, block); }, message, xor_end);
}

auto aes256_cmac_verify_sw(
    Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> expected_tag) -> bool
{
    return internal::cmac_verify_core([&rk](auto block) { aes256_encrypt_block_sw(rk, block); }, message, expected_tag);
}

}  // namespace statusbar::crypto
