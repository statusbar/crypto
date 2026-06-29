// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-256 hardware-accelerated implementation using x86-64 SHA-NI
//
// Uses SHA256RNDS2 for hash rounds and SHA256MSG1/SHA256MSG2 for message schedule.
// SHA-NI processes two rounds at a time. Requires SSE4.1 + SHA extensions.
//
// Runtime CPUID detection: SHA-NI is not available on all x86-64 CPUs (notably
// absent on Intel before Ice Lake client / Goldmont Atom). The _hw functions
// check at runtime and fall back to software if SHA-NI is missing.

#include "statusbar/crypto/sha/sha256_constants.hpp"
#include "statusbar/crypto/sha/sha256_hmac.hpp"
#include "statusbar/crypto/sha/sha256_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>
#include <cstring>

#if defined(__x86_64__) && defined(__SHA__)
#    include <cpuid.h>
#    include <immintrin.h>
#endif

namespace statusbar::crypto {

using internal::make_const_span;
using internal::secure_zero;
using internal::span_copy;
using internal::span_zero;
using internal::store_be32;
using std::span;

#if defined(__x86_64__) && defined(__SHA__)

namespace {

/// @brief Check CPUID leaf 7, subleaf 0, EBX bit 29 for SHA-NI support.
///
/// Cached in a static local so the CPUID instruction executes only once.
/// @return true if the CPU supports SHA-NI instructions.
auto cpu_has_sha_ni() -> bool
{
    static bool const result = [] {
        unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1u << 29)) != 0;
    }();
    return result;
}

constexpr auto& K = constants::SHA256_K;

/// @brief SHA-256 compression using Intel SHA-NI instructions.
///
/// SHA256RNDS2 performs two SHA-256 rounds using the current state and message+K.
/// SHA256MSG1/SHA256MSG2 compute the next message schedule words.
/// @param state The running 8-word (256-bit) hash state, updated in place.
/// @param block A 64-byte message block to compress.
// sha256_compress_hw below uses SHA-NI intrinsics throughout and has 14
// __m128i pointer casts for _mm_loadu_si128 / _mm_storeu_si128.
// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
void sha256_compress_hw(std::array<uint32_t, 8>& state, span<uint8_t const, sha256_block_size> block)
{
    // SHA-NI uses a different state ordering than FIPS 180-4:
    // STATE0 = ABEF = (A, B, E, F), STATE1 = CDGH = (C, D, G, H) after shuffle.
    // rnds2(a=STATE1, b=STATE0) takes a=CDGH, b=ABEF per Intel docs.
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;

    // Load state: state[0..3] = A,B,C,D and state[4..7] = E,F,G,H
    TMP = _mm_loadu_si128(reinterpret_cast<__m128i const*>(&state[0]));
    STATE1 = _mm_loadu_si128(reinterpret_cast<__m128i const*>(&state[4]));

    // Shuffle to SHA-NI ordering: STATE0 = ABEF, STATE1 = CDGH
    TMP = _mm_shuffle_epi32(TMP, 0xB1);           // B,A,D,C
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);     // H,G,F,E
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);     // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);  // CDGH

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Load message words (big-endian byte swap)
    __m128i MASK = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<__m128i const*>(block.data())), MASK);
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<__m128i const*>(block.data() + 16)), MASK);
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<__m128i const*>(block.data() + 32)), MASK);
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<__m128i const*>(block.data() + 48)), MASK);

    // Rounds 0-3
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128(reinterpret_cast<__m128i const*>(&K[0])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 4-7
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128(reinterpret_cast<__m128i const*>(&K[4])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 8-11
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128(reinterpret_cast<__m128i const*>(&K[8])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 12-15. The alignr below must read MSG2 while it still holds the
    // original message words W8..11, so the MSG2 msg1 update is issued *after* it.
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128(reinterpret_cast<__m128i const*>(&K[12])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

// Rounds 16-63 follow the same rotating pattern. Each group: rnds2 consumes the
// already-finalized schedule words m0; msg2 finalizes m1 (adds the W[t-7] term
// via alignr(m0, m3, 4) then sigma1), needed through the group that produces
// W60..63 (r < 60); msg1 seeds m3 (sigma0 + W[t-16]) for a later msg2, needed
// only while future words remain (r < 52). msg1 on m3 runs *after* the alignr
// that reads m3, so the schedule words are still the originals when consumed.
#    define SHA256_4ROUNDS(r, m0, m1, m2, m3)                                                                                      \
        MSG = _mm_add_epi32(m0, _mm_loadu_si128(reinterpret_cast<__m128i const*>(&K[r])));                                         \
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);                                                                       \
        if ((r) < 60) {                                                                                                            \
            TMP = _mm_alignr_epi8(m0, m3, 4);                                                                                      \
            m1 = _mm_add_epi32(m1, TMP);                                                                                           \
            m1 = _mm_sha256msg2_epu32(m1, m0);                                                                                     \
        }                                                                                                                          \
        MSG = _mm_shuffle_epi32(MSG, 0x0E);                                                                                        \
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);                                                                       \
        if ((r) < 52) {                                                                                                            \
            m3 = _mm_sha256msg1_epu32(m3, m0);                                                                                     \
        }

    SHA256_4ROUNDS(16, MSG0, MSG1, MSG2, MSG3)
    SHA256_4ROUNDS(20, MSG1, MSG2, MSG3, MSG0)
    SHA256_4ROUNDS(24, MSG2, MSG3, MSG0, MSG1)
    SHA256_4ROUNDS(28, MSG3, MSG0, MSG1, MSG2)
    SHA256_4ROUNDS(32, MSG0, MSG1, MSG2, MSG3)
    SHA256_4ROUNDS(36, MSG1, MSG2, MSG3, MSG0)
    SHA256_4ROUNDS(40, MSG2, MSG3, MSG0, MSG1)
    SHA256_4ROUNDS(44, MSG3, MSG0, MSG1, MSG2)
    SHA256_4ROUNDS(48, MSG0, MSG1, MSG2, MSG3)
    SHA256_4ROUNDS(52, MSG1, MSG2, MSG3, MSG0)
    SHA256_4ROUNDS(56, MSG2, MSG3, MSG0, MSG1)
    SHA256_4ROUNDS(60, MSG3, MSG0, MSG1, MSG2)

#    undef SHA256_4ROUNDS

    // Add back to running state
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    // Unshuffle back to FIPS ordering: A,B,C,D,E,F,G,H
    TMP = _mm_shuffle_epi32(STATE0, 0x1B);     // STATE0 was ABEF
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);  // STATE1 was CDGH

    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), STATE0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), STATE1);
}
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

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
        size_t fill = std::min(sha256_block_size - ctx.buffer_len, data.size());
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
        size_t remaining = data.size() - offset;
        span_copy(span(ctx.buffer).first(remaining), data.subspan(offset, remaining));
        ctx.buffer_len = remaining;
    }
}

auto sha256_hw_final(Sha256HwCtx& ctx) -> std::array<uint8_t, sha256_digest_size>
{
    uint64_t bit_len = ctx.total_len * 8;

    ctx.buffer[ctx.buffer_len++] = 0x80;

    if (ctx.buffer_len > 56) {
        span_zero(span(ctx.buffer).subspan(ctx.buffer_len));
        sha256_compress_hw(ctx.state, make_const_span(ctx.buffer));
        ctx.buffer_len = 0;
    }

    auto buf = span(ctx.buffer);
    span_zero(buf.subspan(ctx.buffer_len, 56 - ctx.buffer_len));
    store_be32(buf.subspan<56, 4>(), uint32_t(bit_len >> 32));
    store_be32(buf.subspan<60, 4>(), uint32_t(bit_len));
    sha256_compress_hw(ctx.state, make_const_span(ctx.buffer));

    std::array<uint8_t, sha256_digest_size> digest{};
    for (int i = 0; i < 8; ++i) {
        store_be32(span(digest).subspan(size_t(i) * 4).first<4>(), ctx.state[size_t(i)]);
    }
    return digest;
}

auto sha256_ni(span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    Sha256HwCtx ctx;
    sha256_hw_init(ctx);
    sha256_hw_update(ctx, message);
    return sha256_hw_final(ctx);
}

auto sha256_hmac_ni(span<uint8_t const> key, span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    return internal::sha256_hmac_generic<Sha256HwCtx>(
        key, message, {}, sha256_ni, sha256_hw_init, sha256_hw_update, sha256_hw_final);
}

auto sha256_hmac_ni(span<uint8_t const> key, span<uint8_t const> message1, span<uint8_t const> message2)
    -> std::array<uint8_t, sha256_digest_size>
{
    return internal::sha256_hmac_generic<Sha256HwCtx>(
        key, message1, message2, sha256_ni, sha256_hw_init, sha256_hw_update, sha256_hw_final);
}

}  // anonymous namespace

// Public API: runtime dispatch based on CPUID SHA-NI detection

auto sha256_hw(span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    if (cpu_has_sha_ni()) {
        return sha256_ni(message);
    }
    return sha256_sw(message);
}

auto sha256_hmac_hw(span<uint8_t const> key, span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    if (cpu_has_sha_ni()) {
        return sha256_hmac_ni(key, message);
    }
    return sha256_hmac_sw(key, message);
}

auto sha256_hmac_hw(span<uint8_t const> key, span<uint8_t const> message1, span<uint8_t const> message2)
    -> std::array<uint8_t, sha256_digest_size>
{
    if (cpu_has_sha_ni()) {
        return sha256_hmac_ni(key, message1, message2);
    }
    return sha256_hmac_sw(key, message1, message2);
}

auto sha256_secure_hw(span<uint8_t const> message) -> SecureArray<sha256_digest_size>
{
    if (cpu_has_sha_ni()) {
        return SecureArray<sha256_digest_size>(sha256_ni(message));
    }
    return sha256_secure_sw(message);
}

#else  // No x86-64 SHA-NI compile support — fall back to software

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
