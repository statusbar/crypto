// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-256 hardware-accelerated implementation using ARMv8 SHA-2 Crypto Extensions
//
// Uses SHA256H/SHA256H2 for hash rounds and SHA256SU0/SHA256SU1 for message schedule.
// ARM SHA-2 instructions process two rounds at a time using 128-bit NEON registers.

#include "statusbar/crypto/sha/sha256_constants.hpp"
#include "statusbar/crypto/sha/sha256_hmac.hpp"
#include "statusbar/crypto/sha/sha256_hw.hpp"
#include "statusbar/crypto/util/crypto_cpu_arm.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>
#include <cstring>

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)
#    include <arm_neon.h>
#endif

namespace statusbar::crypto {

using internal::make_const_span;
using internal::secure_zero;
using internal::span_copy;
using internal::span_zero;
using internal::store_be32;
using std::span;

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)

namespace {

constexpr auto& K = constants::SHA256_K;

/// @brief SHA-256 compression using ARM SHA-2 instructions.
///
/// Processes one 64-byte block using vsha256hq/vsha256h2q for rounds
/// and vsha256su0q/vsha256su1q for message schedule.
/// @param state The running 8-word (256-bit) hash state, updated in place.
/// @param block A 64-byte message block to compress.
void sha256_compress_hw(std::array<uint32_t, 8>& state, span<uint8_t const, sha256_block_size> block)
{
    // Load state into two 128-bit registers: ABCD and EFGH
    uint32x4_t ABCD = vld1q_u32(&state[0]);
    uint32x4_t EFGH = vld1q_u32(&state[4]);

    uint32x4_t const ABCD_saved = ABCD;
    uint32x4_t const EFGH_saved = EFGH;

    // Load message block as four 128-bit vectors (big-endian to host)
    uint32x4_t MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.data())));
    uint32x4_t MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.data() + 16)));
    uint32x4_t MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.data() + 32)));
    uint32x4_t MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.data() + 48)));

    uint32x4_t TMP;

    // vsha256hq_u32(ABCD, EFGH, wk) -> new ABCD
    // vsha256h2q_u32(EFGH, old_ABCD, wk) -> new EFGH

    // Rounds 0-3
    TMP = vaddq_u32(MSG0, vld1q_u32(&K[0]));
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_saved, TMP);
    MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

    // Rounds 4-7
    TMP = vaddq_u32(MSG1, vld1q_u32(&K[4]));
    uint32x4_t ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

    // Rounds 8-11
    TMP = vaddq_u32(MSG2, vld1q_u32(&K[8]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

    // Rounds 12-15
    TMP = vaddq_u32(MSG3, vld1q_u32(&K[12]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

    // Rounds 16-19
    TMP = vaddq_u32(MSG0, vld1q_u32(&K[16]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

    // Rounds 20-23
    TMP = vaddq_u32(MSG1, vld1q_u32(&K[20]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

    // Rounds 24-27
    TMP = vaddq_u32(MSG2, vld1q_u32(&K[24]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

    // Rounds 28-31
    TMP = vaddq_u32(MSG3, vld1q_u32(&K[28]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

    // Rounds 32-35
    TMP = vaddq_u32(MSG0, vld1q_u32(&K[32]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

    // Rounds 36-39
    TMP = vaddq_u32(MSG1, vld1q_u32(&K[36]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

    // Rounds 40-43
    TMP = vaddq_u32(MSG2, vld1q_u32(&K[40]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

    // Rounds 44-47
    TMP = vaddq_u32(MSG3, vld1q_u32(&K[44]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
    MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

    // Rounds 48-51
    TMP = vaddq_u32(MSG0, vld1q_u32(&K[48]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

    // Rounds 52-55
    TMP = vaddq_u32(MSG1, vld1q_u32(&K[52]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

    // Rounds 56-59
    TMP = vaddq_u32(MSG2, vld1q_u32(&K[56]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

    // Rounds 60-63
    TMP = vaddq_u32(MSG3, vld1q_u32(&K[60]));
    ABCD_prev = ABCD;
    ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
    EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

    // Add back to running state
    ABCD = vaddq_u32(ABCD, ABCD_saved);
    EFGH = vaddq_u32(EFGH, EFGH_saved);

    vst1q_u32(&state[0], ABCD);
    vst1q_u32(&state[4], EFGH);
}

struct Sha256HwCtx
{
    std::array<uint32_t, 8> state{};
    std::array<uint8_t, sha256_block_size> buffer{};
    size_t buffer_len{};
    uint64_t total_len{};

    ~Sha256HwCtx() { secure_zero(*this); }
};

void sha256_hw_init(Sha256HwCtx& ctx)
{
    ctx.state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    ctx.buffer = {};
    ctx.buffer_len = 0;
    ctx.total_len = 0;
}

void sha256_hw_update(Sha256HwCtx& ctx, span<uint8_t const> data)
{
    size_t offset = 0;
    ctx.total_len += data.size();

    if (ctx.buffer_len > 0) {
        size_t const fill = std::min(sha256_block_size - ctx.buffer_len, data.size());
        span_copy(span(ctx.buffer).subspan(ctx.buffer_len, fill), data.first(fill));
        ctx.buffer_len += fill;
        offset += fill;

        if (ctx.buffer_len == sha256_block_size) {
            sha256_compress_hw(ctx.state, make_const_span(ctx.buffer));
            ctx.buffer_len = 0;
        }
    }

    while (offset + sha256_block_size <= data.size()) {
        sha256_compress_hw(ctx.state, data.subspan(offset).first<sha256_block_size>());
        offset += sha256_block_size;
    }

    if (offset < data.size()) {
        size_t const remaining = data.size() - offset;
        span_copy(span(ctx.buffer).first(remaining), data.subspan(offset, remaining));
        ctx.buffer_len = remaining;
    }
}

auto sha256_hw_final(Sha256HwCtx& ctx) -> std::array<uint8_t, sha256_digest_size>
{
    uint64_t const bit_len = ctx.total_len * 8;

    ctx.buffer[ctx.buffer_len++] = 0x80;

    if (ctx.buffer_len > 56) {
        span_zero(span(ctx.buffer).subspan(ctx.buffer_len));
        sha256_compress_hw(ctx.state, make_const_span(ctx.buffer));
        ctx.buffer_len = 0;
    }

    auto buf = span(ctx.buffer);
    span_zero(buf.subspan(ctx.buffer_len, 56 - ctx.buffer_len));
    store_be32(buf.subspan<56, 4>(), static_cast<uint32_t>(bit_len >> 32));
    store_be32(buf.subspan<60, 4>(), static_cast<uint32_t>(bit_len));
    sha256_compress_hw(ctx.state, make_const_span(ctx.buffer));

    std::array<uint8_t, sha256_digest_size> digest{};
    for (int i = 0; i < 8; ++i) {
        store_be32(span(digest).subspan(static_cast<size_t>(i) * 4).first<4>(), ctx.state[static_cast<size_t>(i)]);
    }
    return digest;
}

}  // anonymous namespace

auto sha256_hw(span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    if (!internal::arm_has_sha2()) {
        return sha256_sw(message);
    }
    Sha256HwCtx ctx;
    sha256_hw_init(ctx);
    sha256_hw_update(ctx, message);
    return sha256_hw_final(ctx);
}

auto sha256_hmac_hw(span<uint8_t const> key, span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    if (!internal::arm_has_sha2()) {
        return sha256_hmac_sw(key, message);
    }
    return internal::sha256_hmac_generic<Sha256HwCtx>(
        key, message, {}, sha256_hw, sha256_hw_init, sha256_hw_update, sha256_hw_final);
}

auto sha256_hmac_hw(span<uint8_t const> key, span<uint8_t const> message1, span<uint8_t const> message2)
    -> std::array<uint8_t, sha256_digest_size>
{
    if (!internal::arm_has_sha2()) {
        return sha256_hmac_sw(key, message1, message2);
    }
    return internal::sha256_hmac_generic<Sha256HwCtx>(
        key, message1, message2, sha256_hw, sha256_hw_init, sha256_hw_update, sha256_hw_final);
}

auto sha256_secure_hw(span<uint8_t const> message) -> SecureArray<sha256_digest_size>
{
    return SecureArray<sha256_digest_size>(sha256_hw(message));
}

#else  // No ARM64 SHA-2 support — fall back to software

auto sha256_hw(span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    return sha256_sw(message);
}
auto sha256_hmac_hw(span<uint8_t const> key, span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    return sha256_hmac_sw(key, message);
}
auto sha256_hmac_hw(span<uint8_t const> key, span<uint8_t const> message1, span<uint8_t const> message2)
    -> std::array<uint8_t, sha256_digest_size>
{
    return sha256_hmac_sw(key, message1, message2);
}
auto sha256_secure_hw(span<uint8_t const> message) -> SecureArray<sha256_digest_size>
{
    return sha256_secure_sw(message);
}

#endif

}  // namespace statusbar::crypto
