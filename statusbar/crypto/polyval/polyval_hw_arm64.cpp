// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// POLYVAL hardware-accelerated implementation using ARMv8 PMULL/PMULL2
//
// Uses carry-less multiplication (PMULL/PMULL2) for GF(2^128) dot product.
// POLYVAL operates over GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1.

#include "statusbar/crypto/polyval/polyval_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/status/statusbar_assert.hpp"

#include <cstring>

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)
// PMULL is part of the AES crypto extension feature set
#    include <arm_neon.h>
#endif

namespace statusbar::crypto {

using std::span;

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)

namespace {

/// @brief GF(2^128) multiplication with POLYVAL reduction using ARMv8 PMULL.
///
/// POLYVAL uses the polynomial p(x) = x^128 + x^127 + x^126 + x^121 + 1
/// in a reflected (little-endian) bit ordering.
///
/// Uses Karatsuba decomposition for the 128x128 -> 256 bit product,
/// then reduces the 256-bit result modulo p(x) via Montgomery reduction.
/// @param a First 128-bit operand.
/// @param b Second 128-bit operand.
/// @return a * b mod p(x) as a 128-bit NEON vector.
auto polyval_dot_hw(uint8x16_t a, uint8x16_t b) -> uint8x16_t
{
    // Karatsuba decomposition:
    // lo = a_lo * b_lo, hi = a_hi * b_hi, mid = a_lo*b_hi + a_hi*b_lo
    poly64_t const a_lo = vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
    poly64_t const a_hi = vgetq_lane_u64(vreinterpretq_u64_u8(a), 1);
    poly64_t const b_lo = vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
    poly64_t const b_hi = vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);

    uint8x16_t lo = vreinterpretq_u8_p128(vmull_p64(a_lo, b_lo));
    uint8x16_t hi = vreinterpretq_u8_p128(vmull_p64(a_hi, b_hi));
    uint8x16_t const mid = veorq_u8(vreinterpretq_u8_p128(vmull_p64(a_lo, b_hi)), vreinterpretq_u8_p128(vmull_p64(a_hi, b_lo)));

    // Fold middle term: lo[127:64] ^= mid[63:0], hi[63:0] ^= mid[127:64]
    lo = veorq_u8(lo, vextq_u8(vdupq_n_u8(0), mid, 8));
    hi = veorq_u8(hi, vextq_u8(mid, vdupq_n_u8(0), 8));

    // Montgomery reduction modulo x^128 + C*x^64 + 1 where C = 0xc200000000000000
    // Matches the Linux kernel pattern: reduce the lo part, keep hi as addend.
    //
    // Step 1: r1 = clmul(lo[63:0], C); lo = swap(lo) ^ r1
    // Step 2: r2 = clmul(lo[127:64]_updated, C); lo = swap(lo) ^ r2
    // Result: lo ^ hi

    // Step 1
    uint8x16_t const r1 =
        vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(lo), 0), static_cast<poly64_t>(0xc200000000000000ULL)));
    lo = veorq_u8(vextq_u8(lo, lo, 8), r1);

    // Step 2: after step 1, lane 0 has the value we need for the second PMULL
    uint8x16_t const r2 =
        vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(lo), 0), static_cast<poly64_t>(0xc200000000000000ULL)));
    lo = veorq_u8(vextq_u8(lo, lo, 8), r2);

    return veorq_u8(lo, hi);
}

}  // anonymous namespace

auto polyval_hw(PolyvalKey const& H, span<uint8_t const> input) -> std::array<uint8_t, polyval_block_size>
{
    std::array<uint8_t, polyval_block_size> result{};
    polyval_update_hw(H, input, result);
    return result;
}

void polyval_update_hw(PolyvalKey const& H, span<uint8_t const> input, span<uint8_t, polyval_block_size> accumulator)
{
    auto const can_update = polyval_can_update(input);
    STATUSBAR_ASSERT(can_update);
    uint8x16_t const h = vld1q_u8(H.data.data());
    uint8x16_t s = vld1q_u8(accumulator.data());

    size_t const num_blocks = input.size() / polyval_block_size;
    for (size_t i = 0; i < num_blocks; ++i) {
        uint8x16_t const x = vld1q_u8(input.data() + (i * polyval_block_size));
        s = veorq_u8(s, x);
        s = polyval_dot_hw(s, h);
    }

    vst1q_u8(accumulator.data(), s);
}

#else  // No ARM64 PMULL support — fall back to software

auto polyval_hw(PolyvalKey const& H, span<uint8_t const> input) -> std::array<uint8_t, polyval_block_size>
{
    return polyval_sw(H, input);
}

void polyval_update_hw(PolyvalKey const& H, span<uint8_t const> input, span<uint8_t, polyval_block_size> accumulator)
{
    polyval_update_sw(H, input, accumulator);
}

#endif

}  // namespace statusbar::crypto
