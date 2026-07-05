// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-512 (FIPS 180-4 Section 6.4)
// Reference: https://csrc.nist.gov/publications/detail/fips/180/4/final

#include "statusbar/crypto/sha/sha512.hpp"

#include "statusbar/crypto/sha/sha512_constants.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>

namespace statusbar::crypto {

using internal::load_be64;
using internal::make_const_span;
using internal::span_copy;
using internal::span_zero;
using internal::store_be64;
using std::span;

namespace {

constexpr auto& K = constants::SHA512_K;
constexpr auto& H0 = constants::SHA512_H0;

/// @brief Circular right rotation for 64-bit words.
/// @param x The value to rotate.
/// @param n Number of bits to rotate right.
/// @return x rotated right by n bits.
auto rotr64(uint64_t x, unsigned n) -> uint64_t
{
    return (x >> n) | (x << (64 - n));
}

/// @brief FIPS 180-4 Section 4.1.3: Ch(x,y,z) = (x AND y) XOR (NOT x AND z).
///
/// "Choose" -- for each bit position, choose y if x=1, else z.
/// @param x Selector word.
/// @param y Value chosen when corresponding bit of x is 1.
/// @param z Value chosen when corresponding bit of x is 0.
/// @return The bitwise choice result.
auto Ch(uint64_t x, uint64_t y, uint64_t z) -> uint64_t
{
    return (x & y) ^ (~x & z);
}

/// @brief FIPS 180-4 Section 4.1.3: Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z).
///
/// "Majority" -- for each bit position, output the majority value of x, y, z.
/// @param x First input word.
/// @param y Second input word.
/// @param z Third input word.
/// @return The bitwise majority result.
auto Maj(uint64_t x, uint64_t y, uint64_t z) -> uint64_t
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/// @brief FIPS 180-4 Section 4.1.3: Sigma_0^{512}(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x).
///
/// Used in the round function on the "a" working variable.
/// @param x Input word.
/// @return The Sigma_0 transform of x.
auto Sigma0(uint64_t x) -> uint64_t
{
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

/// @brief FIPS 180-4 Section 4.1.3: Sigma_1^{512}(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x).
///
/// Used in the round function on the "e" working variable.
/// @param x Input word.
/// @return The Sigma_1 transform of x.
auto Sigma1(uint64_t x) -> uint64_t
{
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

/// @brief FIPS 180-4 Section 4.1.3: sigma_0^{512}(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x).
///
/// Used in the message schedule expansion (W[t] computation).
/// @param x Input word.
/// @return The sigma_0 transform of x.
auto sigma0(uint64_t x) -> uint64_t
{
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

/// @brief FIPS 180-4 Section 4.1.3: sigma_1^{512}(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x).
///
/// Used in the message schedule expansion (W[t] computation).
/// @param x Input word.
/// @return The sigma_1 transform of x.
auto sigma1(uint64_t x) -> uint64_t
{
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

/// @brief SHA-512 compression function (FIPS 180-4 Section 6.4.2).
///
/// Processes a single 1024-bit (128-byte) message block and updates the 64-bit hash state.
/// @param state The running 8-word (512-bit) hash state, updated in place.
/// @param block A 128-byte message block to compress.
void sha512_compress(std::array<uint64_t, 8>& state, span<uint8_t const, sha512_block_size> block)
{
    // Step 1: Message schedule expansion.
    // W[0..15] are loaded directly from the block in big-endian order (64-bit words).
    // W[16..79] are derived: W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
    SecureWorkArray<uint64_t, 80> W;
    for (int t = 0; t < 16; ++t) {
        W[t] = load_be64(block.subspan(static_cast<size_t>(t) * 8).first<8>());
    }
    for (int t = 16; t < 80; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    // Step 2: Initialize working variables a..h from current hash state.
    // Zero them on scope exit (matters when SHA-512 is used as an HMAC/HKDF
    // PRF over secret keys) — mirrors sha256_compress.
    uint64_t a = state[0];
    SecureZeroRef const zero_a{a};
    uint64_t b = state[1];
    SecureZeroRef const zero_b{b};
    uint64_t c = state[2];
    SecureZeroRef const zero_c{c};
    uint64_t d = state[3];
    SecureZeroRef const zero_d{d};
    uint64_t e = state[4];
    SecureZeroRef const zero_e{e};
    uint64_t f = state[5];
    SecureZeroRef const zero_f{f};
    uint64_t g = state[6];
    SecureZeroRef const zero_g{g};
    uint64_t h = state[7];
    SecureZeroRef const zero_h{h};

    // Step 3: 80 rounds of the compression function (SHA-512 uses 80 rounds vs. SHA-256's 64).
    // Each round: T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
    //             T2 = Sigma0(a) + Maj(a,b,c)
    // Then shift working variables and inject T1, T2.
    for (int t = 0; t < 80; ++t) {
        uint64_t const T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
        uint64_t const T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Step 4: Add compressed chunk to running hash state (Merkle-Damgard construction).
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

}  // anonymous namespace

//
// SHA-512 public API
//

/// @brief Initialize the SHA-512 context with the standard initial hash values.
/// @param ctx The context to initialize.
void sha512_init_sw(Sha512Context& ctx)
{
    ctx.state = {H0[0], H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7]};
    ctx.buffer = {};
    ctx.buffer_len = 0;
    ctx.total_len = 0;
}

/// @brief Feed data incrementally into the SHA-512 context.
///
/// Buffers partial blocks and compresses complete 128-byte blocks as they become available.
/// @param ctx The SHA-512 context.
/// @param data Input data to hash.
void sha512_update_sw(Sha512Context& ctx, span<uint8_t const> data)
{
    size_t offset = 0;
    ctx.total_len += data.size();

    // Fill any partial block left over from a previous update.
    if (ctx.buffer_len > 0) {
        size_t const fill = std::min(sha512_block_size - ctx.buffer_len, data.size());
        span_copy(span(ctx.buffer).subspan(ctx.buffer_len, fill), data.first(fill));
        ctx.buffer_len += fill;
        offset += fill;

        if (ctx.buffer_len == sha512_block_size) {
            sha512_compress(ctx.state, make_const_span(ctx.buffer));
            ctx.buffer_len = 0;
        }
    }

    // Process full 128-byte blocks directly from the input data.
    while (offset + sha512_block_size <= data.size()) {
        sha512_compress(ctx.state, data.subspan(offset).first<sha512_block_size>());
        offset += sha512_block_size;
    }

    // Buffer any remaining bytes (less than a full block).
    if (offset < data.size()) {
        size_t const remaining = data.size() - offset;
        span_copy(span(ctx.buffer).first(remaining), data.subspan(offset, remaining));
        ctx.buffer_len = remaining;
    }
}

/// @brief Finalize the SHA-512 hash and produce the 64-byte digest.
///
/// Applies FIPS 180-4 Section 5.1.2 padding: a 1-bit, then zero bits, then the
/// 128-bit big-endian message length in bits (not 64-bit as in SHA-256), such that
/// the total is a multiple of 1024 bits.
///
/// Message length limit: This implementation tracks total_len (bytes) as uint64_t.
/// We then compute bit_len = total_len * 8 and store it as the low 64 bits of the
/// 128-bit length field (high 64 bits are zero). Maximum addressable: 2^61 bytes.
/// @param ctx The SHA-512 context to finalize.
/// @return 64-byte SHA-512 digest.
auto sha512_final_sw(Sha512Context& ctx) -> std::array<uint8_t, sha512_digest_size>
{
    // Compute message length in bits for the final padding field.
    uint64_t const bit_len = ctx.total_len * 8;

    // Append the 0x80 byte (a 1-bit followed by seven 0-bits).
    ctx.buffer[ctx.buffer_len++] = 0x80;

    // If the partial block cannot fit the 16-byte (128-bit) length field
    // (need 112 bytes free), pad to the end and compress, then start a new block.
    if (ctx.buffer_len > 112) {
        span_zero(span(ctx.buffer).subspan(ctx.buffer_len));
        sha512_compress(ctx.state, make_const_span(ctx.buffer));
        ctx.buffer_len = 0;
    }

    // Pad with zeros up to byte 112, then write the 128-bit big-endian bit length.
    // The high 64 bits are zero because total_len fits in a uint64_t (messages < 2^64 bits).
    auto buf = span(ctx.buffer);
    span_zero(buf.subspan(ctx.buffer_len, 112 - ctx.buffer_len));
    store_be64(buf.subspan<112, 8>(), 0);
    store_be64(buf.subspan<120, 8>(), bit_len);
    sha512_compress(ctx.state, make_const_span(ctx.buffer));

    // Serialize the final hash state as 64 bytes in big-endian order.
    std::array<uint8_t, sha512_digest_size> digest{};
    for (int i = 0; i < 8; ++i) {
        store_be64(span(digest).subspan(static_cast<size_t>(i) * 8).first<8>(), ctx.state[static_cast<size_t>(i)]);
    }
    return digest;
}

/// @brief One-shot SHA-512: init, update with the full message, and finalize.
/// @param message The input message to hash.
/// @return 64-byte SHA-512 digest.
auto sha512_sw(span<uint8_t const> message) -> std::array<uint8_t, sha512_digest_size>
{
    Sha512Context ctx;
    sha512_init_sw(ctx);
    sha512_update_sw(ctx, message);
    return sha512_final_sw(ctx);
}

auto sha512_final_secure_sw(Sha512Context& ctx) -> SecureArray<sha512_digest_size>
{
    return SecureArray<sha512_digest_size>(sha512_final_sw(ctx));
}

auto sha512_secure_sw(span<uint8_t const> message) -> SecureArray<sha512_digest_size>
{
    return SecureArray<sha512_digest_size>(sha512_sw(message));
}

}  // namespace statusbar::crypto
