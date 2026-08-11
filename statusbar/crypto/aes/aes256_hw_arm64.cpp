// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256 hardware-accelerated implementation using ARMv8 Crypto Extensions
//
// Uses AESE/AESMC for encryption and AESD/AESIMC for decryption.
// AES-256 uses 14 rounds (vs AES-128's 10).

#include "statusbar/crypto/aes/aes256_hw.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/util/crypto_cpu.hpp"
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

auto aes256_expand_key_hw(Aes256Key const& key) -> Aes256RoundKeys
{
    return aes256_expand_key_sw(key);
}

void aes256_encrypt_block_hw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    if (!internal::cpu_aes_hw_active()) {
        aes256_encrypt_block_sw(rk, block);
        return;
    }
    uint8x16_t state = load_block(block);

    // Rounds 0-12: AESE + AESMC
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[0])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[1])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[2])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[3])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[4])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[5])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[6])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[7])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[8])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[9])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[10])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[11])));
    state = vaesmcq_u8(vaeseq_u8(state, load_block(rk.round_keys[12])));

    // Final round: AESE (no AESMC) + XOR with last round key
    state = vaeseq_u8(state, load_block(rk.round_keys[13]));
    state = veorq_u8(state, load_block(rk.round_keys[14]));

    store_block(block, state);
}

void aes256_decrypt_block_hw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    if (!internal::cpu_aes_hw_active()) {
        aes256_decrypt_block_sw(rk, block);
        return;
    }
    // Equivalent Inverse Cipher: round keys 1-13 need AESIMC applied.
    // Keys 0 and 14 are used as-is.

    uint8x16_t state = load_block(block);

    // First AESD: rk[14] as-is
    state = vaesimcq_u8(vaesdq_u8(state, load_block(rk.round_keys[14])));
    // Middle rounds: AESIMC(rk[i]) for i=13..2
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[13]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[12]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[11]))));
    state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(load_block(rk.round_keys[10]))));
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

auto aes256_cmac_hw(Aes256RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes256_block_size>
{
    if (!internal::cpu_aes_hw_active()) {
        return aes256_cmac_sw(rk, message);
    }
    return internal::cmac_core([&rk](auto block) { aes256_encrypt_block_hw(rk, block); }, message);
}

auto aes256_cmac_xorend_hw(Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> xor_end)
    -> std::array<uint8_t, aes256_block_size>
{
    if (!internal::cpu_aes_hw_active()) {
        return aes256_cmac_xorend_sw(rk, message, xor_end);
    }
    return internal::cmac_xorend_core([&rk](auto block) { aes256_encrypt_block_hw(rk, block); }, message, xor_end);
}

auto aes256_cmac_verify_hw(
    Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> expected_tag) -> bool
{
    if (!internal::cpu_aes_hw_active()) {
        return aes256_cmac_verify_sw(rk, message, expected_tag);
    }
    return internal::cmac_verify_core([&rk](auto block) { aes256_encrypt_block_hw(rk, block); }, message, expected_tag);
}

#else  // No ARM64 AES support — fall back to software

auto aes256_expand_key_hw(Aes256Key const& key) -> Aes256RoundKeys
{
    return aes256_expand_key_sw(key);
}
void aes256_encrypt_block_hw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    aes256_encrypt_block_sw(rk, block);
}
void aes256_decrypt_block_hw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    aes256_decrypt_block_sw(rk, block);
}
auto aes256_cmac_hw(Aes256RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes256_block_size>
{
    return aes256_cmac_sw(rk, message);
}
auto aes256_cmac_xorend_hw(Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> xor_end)
    -> std::array<uint8_t, aes256_block_size>
{
    return aes256_cmac_xorend_sw(rk, message, xor_end);
}
auto aes256_cmac_verify_hw(
    Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> expected_tag) -> bool
{
    return aes256_cmac_verify_sw(rk, message, expected_tag);
}

#endif

}  // namespace statusbar::crypto
