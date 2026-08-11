// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// POLYVAL hardware-accelerated implementation using x86-64 PCLMULQDQ
//
// Uses carry-less multiplication (PCLMULQDQ) for GF(2^128) dot product.
// POLYVAL operates over GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1.
//
// Runtime dispatch via internal::cpu_polyval_hw_active() (util/crypto_cpu.hpp):
// PCLMULQDQ when the CPU has it, software fallback otherwise.

#include "statusbar/crypto/polyval/polyval_hw.hpp"
#include "statusbar/crypto/util/crypto_cpu.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/status/statusbar_assert.hpp"

#include <cstring>

#if defined(__x86_64__) && defined(__PCLMUL__)
#    include <immintrin.h>
#    include <wmmintrin.h>
#endif

namespace statusbar::crypto {

using internal::load_le64;
using internal::make_const_span;
using internal::store_le64;
using std::span;

#if defined(__x86_64__) && defined(__PCLMUL__)

namespace {

/// @brief GF(2^128) multiplication with POLYVAL reduction using x86-64 PCLMULQDQ.
///
/// Uses Karatsuba decomposition for 128x128->256 bit carry-less multiply,
/// then reduces modulo the POLYVAL polynomial x^128 + x^127 + x^126 + x^121 + 1.
///
/// Montgomery reduction: reduces `lo` (not `hi`) using swap-halves and two
/// rounds of clmul with the reduction constant, matching the Linux kernel /
/// BoringSSL pattern used in the ARM64 implementation.
/// @param a First 128-bit operand.
/// @param b Second 128-bit operand.
/// @return a * b mod p(x) as a 128-bit SSE vector.
auto polyval_dot_ni(__m128i a, __m128i b) -> __m128i
{
    // Karatsuba decomposition:
    // lo = a_lo * b_lo (bits 0-127 of product)
    // hi = a_hi * b_hi (bits 128-255 of product)
    // mid = a_lo * b_hi XOR a_hi * b_lo (cross terms)
    __m128i lo = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i hi = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i mid1 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i mid2 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i mid = _mm_xor_si128(mid1, mid2);

    // Add middle term: lo[127:64] ^= mid[63:0], hi[63:0] ^= mid[127:64]
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    // Montgomery reduction modulo x^128 + x^127 + x^126 + x^121 + 1.
    // Reduction constant C = 0xc200000000000000 (= x^127 + x^126 + x^121).
    //
    // Step 1: r1 = clmul(lo[63:0], C); lo = swap_halves(lo) ^ r1
    // Step 2: r2 = clmul(lo[63:0], C); lo = swap_halves(lo) ^ r2
    // Result: lo ^ hi
    __m128i C = _mm_set_epi64x(0, static_cast<long long>(0xc200000000000000ULL));

    // Step 1
    __m128i r1 = _mm_clmulepi64_si128(lo, C, 0x00);
    lo = _mm_xor_si128(_mm_shuffle_epi32(lo, 0x4E), r1);  // 0x4E swaps 64-bit halves

    // Step 2
    __m128i r2 = _mm_clmulepi64_si128(lo, C, 0x00);
    lo = _mm_xor_si128(_mm_shuffle_epi32(lo, 0x4E), r2);

    return _mm_xor_si128(lo, hi);
}

/// @brief POLYVAL update using PCLMULQDQ hardware acceleration.
/// @param H The POLYVAL hash key.
/// @param input Input data (processed in 16-byte blocks).
/// @param accumulator Running POLYVAL accumulator, updated in place.
// polyval_update_ni below uses CLMUL intrinsics with __m128i pointer
// casts for _mm_loadu_si128 / _mm_storeu_si128 on byte buffers.
// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
void polyval_update_ni(PolyvalKey const& H, span<uint8_t const> input, span<uint8_t, polyval_block_size> accumulator)
{
    auto const can_update = polyval_can_update(input);
    STATUSBAR_ASSERT(can_update);
    __m128i h = _mm_loadu_si128(reinterpret_cast<__m128i const*>(H.data.data()));
    __m128i s = _mm_loadu_si128(reinterpret_cast<__m128i const*>(accumulator.data()));

    size_t num_blocks = input.size() / polyval_block_size;
    for (size_t i = 0; i < num_blocks; ++i) {
        __m128i x = _mm_loadu_si128(reinterpret_cast<__m128i const*>(input.data() + i * polyval_block_size));
        s = _mm_xor_si128(s, x);
        s = polyval_dot_ni(s, h);
    }

    _mm_storeu_si128(reinterpret_cast<__m128i*>(accumulator.data()), s);
}
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

}  // anonymous namespace

// Public API: runtime dispatch based on CPUID PCLMULQDQ detection

auto polyval_hw(PolyvalKey const& H, span<uint8_t const> input) -> std::array<uint8_t, polyval_block_size>
{
    std::array<uint8_t, polyval_block_size> result{};
    polyval_update_hw(H, input, result);
    return result;
}

void polyval_update_hw(PolyvalKey const& H, span<uint8_t const> input, span<uint8_t, polyval_block_size> accumulator)
{
    if (cpu_polyval_hw_active()) {
        polyval_update_ni(H, input, accumulator);
    } else {
        polyval_update_sw(H, input, accumulator);
    }
}

#else  // No x86-64 PCLMULQDQ compile support — fall back to software

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
