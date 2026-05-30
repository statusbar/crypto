// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128 hardware-accelerated implementation using x86-64 AES-NI
//
// Uses AESENC/AESENCLAST for encryption and AESDEC/AESDECLAST for decryption.
// AES-NI decryption requires Equivalent Inverse Cipher round keys (InvMixColumns
// applied to encryption round keys 1..Nr-1).
//
// Runtime CPUID detection: checks for AES-NI at runtime (CPUID leaf 1, ECX bit 25)
// and falls back to software if not available.

#include "statusbar/crypto/aes/aes128_hw.hpp"
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

void aes128_encrypt_block_ni(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
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
    state = _mm_aesenclast_si128(state, load_block(rk.round_keys[10]));

    store_block(block, state);
}

void aes128_encrypt_blocks_x4_ni(Aes128RoundKeys const& rk, span<uint8_t, 4 * aes128_block_size> blocks)
{
    // Interleave 4 independent AES encryptions across the 10 rounds so the
    // AES-NI execution unit stays fed. AESENC has 3-4 cycle latency but
    // 1-cycle throughput on modern Intel/AMD — pipelining 4 blocks hides
    // the latency chain.

    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    auto* const p0 = reinterpret_cast<__m128i*>(blocks.data());
    auto* const p1 = reinterpret_cast<__m128i*>(blocks.data() + aes128_block_size);
    auto* const p2 = reinterpret_cast<__m128i*>(blocks.data() + (2 * aes128_block_size));
    auto* const p3 = reinterpret_cast<__m128i*>(blocks.data() + (3 * aes128_block_size));

    __m128i s0 = _mm_loadu_si128(p0);
    __m128i s1 = _mm_loadu_si128(p1);
    __m128i s2 = _mm_loadu_si128(p2);
    __m128i s3 = _mm_loadu_si128(p3);
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)

    __m128i const rk0 = load_block(rk.round_keys[0]);
    s0 = _mm_xor_si128(s0, rk0);
    s1 = _mm_xor_si128(s1, rk0);
    s2 = _mm_xor_si128(s2, rk0);
    s3 = _mm_xor_si128(s3, rk0);

    for (int r = 1; r < 10; ++r) {
        __m128i const rk_r = load_block(rk.round_keys[r]);
        s0 = _mm_aesenc_si128(s0, rk_r);
        s1 = _mm_aesenc_si128(s1, rk_r);
        s2 = _mm_aesenc_si128(s2, rk_r);
        s3 = _mm_aesenc_si128(s3, rk_r);
    }

    __m128i const rk10 = load_block(rk.round_keys[10]);
    s0 = _mm_aesenclast_si128(s0, rk10);
    s1 = _mm_aesenclast_si128(s1, rk10);
    s2 = _mm_aesenclast_si128(s2, rk10);
    s3 = _mm_aesenclast_si128(s3, rk10);

    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    _mm_storeu_si128(p0, s0);
    _mm_storeu_si128(p1, s1);
    _mm_storeu_si128(p2, s2);
    _mm_storeu_si128(p3, s3);
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
}

void aes128_decrypt_block_ni(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    // AES-NI decryption uses the Equivalent Inverse Cipher which requires
    // InvMixColumns applied to round keys 1..9 (not 0 or 10).
    __m128i dk[11];
    dk[0] = load_block(rk.round_keys[10]);
    for (int i = 1; i < 10; ++i) {
        dk[i] = _mm_aesimc_si128(load_block(rk.round_keys[10 - i]));
    }
    dk[10] = load_block(rk.round_keys[0]);

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
    state = _mm_aesdeclast_si128(state, dk[10]);

    store_block(block, state);
}

auto aes128_cmac_ni(Aes128RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes128_block_size>
{
    return internal::cmac_core([&rk](auto block) { aes128_encrypt_block_ni(rk, block); }, message);
}

auto aes128_cmac_xorend_ni(Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> xor_end)
    -> std::array<uint8_t, aes128_block_size>
{
    return internal::cmac_xorend_core([&rk](auto block) { aes128_encrypt_block_ni(rk, block); }, message, xor_end);
}

auto aes128_cmac_verify_ni(
    Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> expected_tag) -> bool
{
    return internal::cmac_verify_core([&rk](auto block) { aes128_encrypt_block_ni(rk, block); }, message, expected_tag);
}

}  // anonymous namespace

// Public API: runtime dispatch based on CPUID AES-NI detection

auto aes128_expand_key_hw(Aes128Key const& key) -> Aes128RoundKeys
{
    return aes128_expand_key_sw(key);
}

void aes128_encrypt_block_hw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    if (cpu_has_aes_ni()) {
        aes128_encrypt_block_ni(rk, block);
    } else {
        aes128_encrypt_block_sw(rk, block);
    }
}

void aes128_decrypt_block_hw(Aes128RoundKeys const& rk, span<uint8_t, aes128_block_size> block)
{
    if (cpu_has_aes_ni()) {
        aes128_decrypt_block_ni(rk, block);
    } else {
        aes128_decrypt_block_sw(rk, block);
    }
}

void aes128_encrypt_blocks_x4_hw(Aes128RoundKeys const& rk, span<uint8_t, 4 * aes128_block_size> blocks)
{
    if (cpu_has_aes_ni()) {
        aes128_encrypt_blocks_x4_ni(rk, blocks);
        return;
    }
    for (size_t i = 0; i < 4; ++i) {
        aes128_encrypt_block_sw(rk, blocks.subspan(i * aes128_block_size).first<aes128_block_size>());
    }
}

auto aes128_cmac_hw(Aes128RoundKeys const& rk, span<uint8_t const> message) -> std::array<uint8_t, aes128_block_size>
{
    if (cpu_has_aes_ni()) {
        return aes128_cmac_ni(rk, message);
    }
    return aes128_cmac_sw(rk, message);
}

auto aes128_cmac_xorend_hw(Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> xor_end)
    -> std::array<uint8_t, aes128_block_size>
{
    if (cpu_has_aes_ni()) {
        return aes128_cmac_xorend_ni(rk, message, xor_end);
    }
    return aes128_cmac_xorend_sw(rk, message, xor_end);
}

auto aes128_cmac_verify_hw(
    Aes128RoundKeys const& rk, span<uint8_t const> message, span<uint8_t const, aes128_block_size> expected_tag) -> bool
{
    if (cpu_has_aes_ni()) {
        return aes128_cmac_verify_ni(rk, message, expected_tag);
    }
    return aes128_cmac_verify_sw(rk, message, expected_tag);
}

#else  // No x86-64 AES-NI compile support — fall back to software

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
