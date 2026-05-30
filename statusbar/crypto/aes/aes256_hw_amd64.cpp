// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256 hardware-accelerated implementation using x86-64 AES-NI
//
// Uses AESENC/AESENCLAST for encryption and AESDEC/AESDECLAST for decryption.
// AES-256 uses 14 rounds. Decryption requires Equivalent Inverse Cipher
// round keys (InvMixColumns applied to encryption round keys 1..Nr-1).
//
// Runtime CPUID detection: checks for AES-NI at runtime (CPUID leaf 1, ECX bit 25)
// and falls back to software if not available.

#include "statusbar/crypto/aes/aes256_hw.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <cstring>

#if defined(__x86_64__) && defined(__AES__)
#    include <cpuid.h>
#    include <immintrin.h>
#    include <wmmintrin.h>
#endif

namespace statusbar::crypto {

using namespace internal;
using std::span;

#if defined(__x86_64__) && defined(__AES__)

namespace {

auto cpu_has_aes_ni() -> bool
{
    static bool const result = [] {
        unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
        __cpuid(1, eax, ebx, ecx, edx);
        return (ecx & (1u << 25)) != 0;
    }();
    return result;
}

// The 3 helpers below wrap _mm_loadu_si128 / _mm_storeu_si128, which
// require __m128i pointer casts from our byte spans.
// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
auto load_block(span<uint8_t const, aes_block_size> in) -> __m128i
{
    return _mm_loadu_si128(reinterpret_cast<__m128i const*>(in.data()));
}

auto load_block(std::array<uint8_t, aes_block_size> const& in) -> __m128i
{
    return _mm_loadu_si128(reinterpret_cast<__m128i const*>(in.data()));
}

void store_block(span<uint8_t, aes_block_size> out, __m128i v)
{
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data()), v);
}
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

void aes256_encrypt_block_ni(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    __m128i state = load_block(block);

    state = _mm_xor_si128(state, load_block(rk.round_keys[0]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[1]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[2]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[3]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[4]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[5]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[6]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[7]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[8]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[9]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[10]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[11]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[12]));
    state = _mm_aesenc_si128(state, load_block(rk.round_keys[13]));
    state = _mm_aesenclast_si128(state, load_block(rk.round_keys[14]));

    store_block(block, state);
}

void aes256_decrypt_block_ni(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    // AES-NI decryption: Equivalent Inverse Cipher requires InvMixColumns
    // on round keys 1..13 (not 0 or 14).
    __m128i dk[15];
    dk[0] = load_block(rk.round_keys[14]);
    for (int i = 1; i < 14; ++i) {
        dk[i] = _mm_aesimc_si128(load_block(rk.round_keys[14 - i]));
    }
    dk[14] = load_block(rk.round_keys[0]);

    __m128i state = load_block(block);

    state = _mm_xor_si128(state, dk[0]);
    state = _mm_aesdec_si128(state, dk[1]);
    state = _mm_aesdec_si128(state, dk[2]);
    state = _mm_aesdec_si128(state, dk[3]);
    state = _mm_aesdec_si128(state, dk[4]);
    state = _mm_aesdec_si128(state, dk[5]);
    state = _mm_aesdec_si128(state, dk[6]);
    state = _mm_aesdec_si128(state, dk[7]);
    state = _mm_aesdec_si128(state, dk[8]);
    state = _mm_aesdec_si128(state, dk[9]);
    state = _mm_aesdec_si128(state, dk[10]);
    state = _mm_aesdec_si128(state, dk[11]);
    state = _mm_aesdec_si128(state, dk[12]);
    state = _mm_aesdec_si128(state, dk[13]);
    state = _mm_aesdeclast_si128(state, dk[14]);

    store_block(block, state);
}

auto aes256_cmac_ni(Aes256RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes256_block_size>
{
    return internal::cmac_core([&rk](auto block) { aes256_encrypt_block_ni(rk, block); }, message);
}

auto aes256_cmac_xorend_ni(Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> xor_end)
    -> std::array<uint8_t, aes256_block_size>
{
    return internal::cmac_xorend_core([&rk](auto block) { aes256_encrypt_block_ni(rk, block); }, message, xor_end);
}

auto aes256_cmac_verify_ni(
    Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> expected_tag) -> bool
{
    return internal::cmac_verify_core([&rk](auto block) { aes256_encrypt_block_ni(rk, block); }, message, expected_tag);
}

}  // anonymous namespace

// Public API: runtime dispatch based on CPUID AES-NI detection

auto aes256_expand_key_hw(Aes256Key const& key) -> Aes256RoundKeys
{
    return aes256_expand_key_sw(key);
}

void aes256_encrypt_block_hw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    if (cpu_has_aes_ni()) {
        aes256_encrypt_block_ni(rk, block);
    } else {
        aes256_encrypt_block_sw(rk, block);
    }
}

void aes256_decrypt_block_hw(Aes256RoundKeys const& rk, span<uint8_t, aes256_block_size> block)
{
    if (cpu_has_aes_ni()) {
        aes256_decrypt_block_ni(rk, block);
    } else {
        aes256_decrypt_block_sw(rk, block);
    }
}

auto aes256_cmac_hw(Aes256RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes256_block_size>
{
    if (cpu_has_aes_ni()) {
        return aes256_cmac_ni(rk, message);
    }
    return aes256_cmac_sw(rk, message);
}

auto aes256_cmac_xorend_hw(Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> xor_end)
    -> std::array<uint8_t, aes256_block_size>
{
    if (cpu_has_aes_ni()) {
        return aes256_cmac_xorend_ni(rk, message, xor_end);
    }
    return aes256_cmac_xorend_sw(rk, message, xor_end);
}

auto aes256_cmac_verify_hw(
    Aes256RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes256_block_size> expected_tag) -> bool
{
    if (cpu_has_aes_ni()) {
        return aes256_cmac_verify_ni(rk, message, expected_tag);
    }
    return aes256_cmac_verify_sw(rk, message, expected_tag);
}

#else  // No x86-64 AES-NI compile support — fall back to software

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
