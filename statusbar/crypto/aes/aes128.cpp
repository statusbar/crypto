// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128 block cipher (FIPS 197)
// Reference: https://csrc.nist.gov/publications/detail/fips/197/final
//
// Implements:
// - Key expansion (Section 5.2): 128-bit key -> 11 round keys
// - Encryption (Section 5.1): 10 rounds of SubBytes/ShiftRows/MixColumns/AddRoundKey
// - Decryption (Section 5.3): Inverse cipher with InvSubBytes/InvShiftRows/InvMixColumns
// - CMAC (RFC 4493): CBC-MAC with subkey derivation for message authentication
//
// Internal representation:
// - State is a 4x4 byte matrix stored column-major [col][row] per FIPS 197 Section 3.4
// - GF(2^8) arithmetic uses the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1

#include "statusbar/crypto/aes/aes128.hpp"

#include "statusbar/crypto/aes/aes128_constants.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

namespace statusbar::crypto {

using namespace internal;
using std::span;

namespace {

constexpr auto& rcon = constants::aes128_rcon;

}  // anonymous namespace

//
// Key expansion (FIPS 197 Section 5.2)
//

// AES-128 key schedule: expands a 4-word (128-bit) key into 44 words (11 round keys).
// Each round key[i] is derived from key[i-1] with a RotWord+SubWord+Rcon transform
// applied to the last word, then XORed through all 4 words.
auto aes128_expand_key_sw(Aes128Key const& key) -> Aes128RoundKeys
{
    Aes128RoundKeys rk;

    // Round key 0 is the key itself
    span_copy(rk.round_keys[0], key.data);

    for (size_t round = 1; round <= aes128_num_rounds; ++round) {
        auto const& prev = rk.round_keys[round - 1];
        auto& curr = rk.round_keys[round];

        // RotWord + SubWord + Rcon on the last word of the previous round key
        uint8_t const temp[4] = {
            static_cast<uint8_t>(sbox[prev[13]] ^ rcon[round - 1]),
            sbox[prev[14]],
            sbox[prev[15]],
            sbox[prev[12]],
        };

        // Word 0
        for (int b = 0; b < 4; ++b) {
            curr[b] = prev[b] ^ temp[b];
        }

        // Words 1-3
        for (int w = 1; w < 4; ++w) {
            for (int b = 0; b < 4; ++b) {
                curr[(w * 4) + b] = prev[(w * 4) + b] ^ curr[((w - 1) * 4) + b];
            }
        }
    }

    return rk;
}

//
// Block encrypt / decrypt (FIPS 197 Sections 5.1, 5.3)
//

// AES-128 encryption: 10 rounds.
// Round structure: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
// Final round omits MixColumns per the standard.
void aes128_encrypt_block_sw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    State s;
    state_from_bytes(s, block);

    add_round_key(s, rk.round_keys[0]);

    for (size_t r = 1; r < aes128_num_rounds; ++r) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, rk.round_keys[r]);
    }

    // Final round (no MixColumns)
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, rk.round_keys[aes128_num_rounds]);

    state_to_bytes(s, block);
}

// AES-128 decryption: inverse cipher, 10 rounds.
// Round structure: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
// Final round omits InvMixColumns. Rounds applied in reverse order.
void aes128_decrypt_block_sw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    State s;
    state_from_bytes(s, block);

    add_round_key(s, rk.round_keys[aes128_num_rounds]);

    for (size_t r = aes128_num_rounds - 1; r >= 1; --r) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, rk.round_keys[r]);
        inv_mix_columns(s);
    }

    // Final round (no InvMixColumns)
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, rk.round_keys[0]);

    state_to_bytes(s, block);
}

//
// CMAC (RFC 4493 / NIST SP 800-38B)
//

auto aes128_cmac_sw(Aes128RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes128_block_size>
{
    return internal::cmac_core([&rk](auto block) { aes128_encrypt_block_sw(rk, block); }, message);
}

auto aes128_cmac_xorend_sw(Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> xor_end)
    -> std::array<uint8_t, aes128_block_size>
{
    return internal::cmac_xorend_core([&rk](auto block) { aes128_encrypt_block_sw(rk, block); }, message, xor_end);
}

auto aes128_cmac_verify_sw(
    Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> expected_tag) -> bool
{
    return internal::cmac_verify_core([&rk](auto block) { aes128_encrypt_block_sw(rk, block); }, message, expected_tag);
}

}  // namespace statusbar::crypto
