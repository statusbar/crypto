// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128 hardware-accelerated implementation using ARMv8 Crypto Extensions
//
// Uses AESE/AESMC for encryption and AESD/AESIMC for decryption.
// ARMv8 AES instructions operate on the AES state differently from the textbook
// description: AESE performs AddRoundKey then SubBytes+ShiftRows, and AESMC
// performs MixColumns. This means the round key ordering is shifted by one
// compared to the software implementation.

#include "statusbar/crypto/aes/aes128_hw.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <cstring>

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)
#    include <arm_neon.h>
#endif

namespace statusbar::crypto {

using namespace internal;
using std::span;

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)

namespace {

auto load_block(span<uint8_t const, aes_block_size> in) -> uint8x16_t
{
    return vld1q_u8(in.data());
}

auto load_block(std::array<uint8_t, aes_block_size> const& in) -> uint8x16_t
{
    return vld1q_u8(in.data());
}

void store_block(span<uint8_t, aes_block_size> out, uint8x16_t v)
{
    vst1q_u8(out.data(), v);
}

}  // anonymous namespace

auto aes128_expand_key_hw(Aes128Key const& key) -> Aes128RoundKeys
{
    // Key expansion uses the same algorithm as software — the round keys
    // are just byte arrays regardless of how they're consumed by AESE/AESD.
    return aes128_expand_key_sw(key);
}

void aes128_encrypt_block_hw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    // ARMv8 AESE instruction: AddRoundKey(state, key) then SubBytes+ShiftRows
    // ARMv8 AESMC instruction: MixColumns
    //
    // Standard AES round: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    // With ARM instructions: AESE(state, rk[i]) performs XOR then SubBytes+ShiftRows
    // followed by AESMC for MixColumns.
    //
    // The key ordering is: AESE with rk[0], AESMC, AESE with rk[1], AESMC, ...
    // AESE with rk[9] (no AESMC), then XOR with rk[10].

    uint8x16_t state = load_block(block);

    // Rounds 0-8: AESE + AESMC
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[0])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[1])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[2])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[3])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[4])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[5])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[6])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[7])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[8])));

    // Final round: AESE (no AESMC) + XOR with last round key
    state = vaeseq_u8(state, load_block(rk.round_keys[9]));
    state = veorq_u8(state, load_block(rk.round_keys[10]));

    store_block(block, state);
}

void aes128_encrypt_blocks_x4_hw(Aes128RoundKeys const& rk, span<uint8_t, 4 * aes128_block_size> blocks)
{
    // Interleave 4 independent AES encryptions across the 10 rounds so the
    // CPU's AES pipeline stays full. Each round loads one round key, then
    // applies AESE+AESMC to all 4 states before moving on — so round-key
    // loads are amortized and consecutive AESE/AESMC pairs on different
    // states keep the AES unit busy.

    uint8_t* const p0 = blocks.data();
    uint8_t* const p1 = blocks.data() + aes128_block_size;
    uint8_t* const p2 = blocks.data() + (2 * aes128_block_size);
    uint8_t* const p3 = blocks.data() + (3 * aes128_block_size);

    uint8x16_t s0 = vld1q_u8(p0);
    uint8x16_t s1 = vld1q_u8(p1);
    uint8x16_t s2 = vld1q_u8(p2);
    uint8x16_t s3 = vld1q_u8(p3);

    for (int r = 0; r < 9; ++r) {
        uint8x16_t const rk_r = load_block(rk.round_keys[r]);
        s0 = vaesmcq_u8(vaeseq_u8(s0, rk_r));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rk_r));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rk_r));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rk_r));
    }

    uint8x16_t const rk9 = load_block(rk.round_keys[9]);
    s0 = vaeseq_u8(s0, rk9);
    s1 = vaeseq_u8(s1, rk9);
    s2 = vaeseq_u8(s2, rk9);
    s3 = vaeseq_u8(s3, rk9);

    uint8x16_t const rk10 = load_block(rk.round_keys[10]);
    s0 = veorq_u8(s0, rk10);
    s1 = veorq_u8(s1, rk10);
    s2 = veorq_u8(s2, rk10);
    s3 = veorq_u8(s3, rk10);

    vst1q_u8(p0, s0);
    vst1q_u8(p1, s1);
    vst1q_u8(p2, s2);
    vst1q_u8(p3, s3);
}

void aes128_decrypt_block_hw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    // ARMv8 AESD: XOR round key then InvSubBytes+InvShiftRows
    // ARMv8 AESIMC: InvMixColumns
    //
    // Uses the Equivalent Inverse Cipher: round keys 1-9 must have
    // InvMixColumns applied (via AESIMC). Keys 0 and 10 are used as-is.

    uint8x16_t state = load_block(block);

    // First AESD: use rk[10] as-is, then AESIMC on state
    state = vaesimcq_u8(vaesdq_u8(state, load_block(rk.round_keys[10])));
    // Middle rounds: use AESIMC(rk[i]) for i=9..2, then AESIMC on state
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[9]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[8]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[7]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[6]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[5]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[4]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[3]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[2]))));

    // Final round: AESD with AESIMC(rk[1]), no AESIMC on state, then XOR rk[0]
    state = vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[1])));
    state = veorq_u8(state, load_block(rk.round_keys[0]));

    store_block(block, state);
}

auto aes128_cmac_hw(Aes128RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes128_block_size>
{
    return internal::cmac_core([&rk](auto block) { aes128_encrypt_block_hw(rk, block); }, message);
}

auto aes128_cmac_xorend_hw(Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> xor_end)
    -> std::array<uint8_t, aes128_block_size>
{
    return internal::cmac_xorend_core([&rk](auto block) { aes128_encrypt_block_hw(rk, block); }, message, xor_end);
}

auto aes128_cmac_verify_hw(
    Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> expected_tag) -> bool
{
    return internal::cmac_verify_core([&rk](auto block) { aes128_encrypt_block_hw(rk, block); }, message, expected_tag);
}

#else  // No ARM64 AES support — fall back to software

auto aes128_expand_key_hw(Aes128Key const& key) -> Aes128RoundKeys
{
    return aes128_expand_key_sw(key);
}
void aes128_encrypt_block_hw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    aes128_encrypt_block_sw(rk, block);
}
void aes128_decrypt_block_hw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    aes128_decrypt_block_sw(rk, block);
}
void aes128_encrypt_blocks_x4_hw(Aes128RoundKeys const& rk, span<uint8_t, 4 * aes128_block_size> blocks)
{
    for (size_t i = 0; i < 4; ++i) {
        aes128_encrypt_block_sw(rk, blocks.subspan(i * aes128_block_size).first<aes128_block_size>());
    }
}
auto aes128_cmac_hw(Aes128RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes128_block_size>
{
    return aes128_cmac_sw(rk, message);
}
auto aes128_cmac_xorend_hw(Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> xor_end)
    -> std::array<uint8_t, aes128_block_size>
{
    return aes128_cmac_xorend_sw(rk, message, xor_end);
}
auto aes128_cmac_verify_hw(
    Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> expected_tag) -> bool
{
    return aes128_cmac_verify_sw(rk, message, expected_tag);
}

#endif

}  // namespace statusbar::crypto
