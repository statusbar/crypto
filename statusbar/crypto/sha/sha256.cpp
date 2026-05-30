// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-256 (FIPS 180-4 Section 6.2) and HMAC-SHA-256 (RFC 2104)
// References:
// - https://csrc.nist.gov/publications/detail/fips/180/4/final
// - https://www.rfc-editor.org/rfc/rfc2104

#include "statusbar/crypto/sha/sha256.hpp"

#include "statusbar/crypto/sha/sha256_constants.hpp"
#include "statusbar/crypto/sha/sha256_hmac.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>

namespace statusbar::crypto {

using internal::load_be32;
using internal::make_const_span;
using internal::secure_zero;
using internal::span_copy;
using internal::span_zero;
using internal::store_be32;
using std::span;

namespace {

constexpr auto& K = constants::SHA256_K;

// Circular right rotation for 32-bit words.
auto rotr32(uint32_t x, unsigned n) -> uint32_t
{
    return (x >> n) | (x << (32 - n));
}

// FIPS 180-4 Section 4.1.2: Ch(x,y,z) = (x AND y) XOR (NOT x AND z)
// "Choose" — for each bit position, choose y if x=1, else z.
auto Ch(uint32_t x, uint32_t y, uint32_t z) -> uint32_t
{
    return (x & y) ^ (~x & z);
}

// FIPS 180-4 Section 4.1.2: Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
// "Majority" — for each bit position, output the majority value of x, y, z.
auto Maj(uint32_t x, uint32_t y, uint32_t z) -> uint32_t
{
    return (x & y) ^ (x & z) ^ (y & z);
}

// FIPS 180-4 Section 4.1.2: upper-case Sigma_0^{256}(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
// Used in the round function on the "a" working variable.
auto Sigma0(uint32_t x) -> uint32_t
{
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

// FIPS 180-4 Section 4.1.2: upper-case Sigma_1^{256}(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
// Used in the round function on the "e" working variable.
auto Sigma1(uint32_t x) -> uint32_t
{
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

// FIPS 180-4 Section 4.1.2: lower-case sigma_0^{256}(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
// Used in the message schedule expansion (W[t] computation).
auto sigma0(uint32_t x) -> uint32_t
{
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

// FIPS 180-4 Section 4.1.2: lower-case sigma_1^{256}(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
// Used in the message schedule expansion (W[t] computation).
auto sigma1(uint32_t x) -> uint32_t
{
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

// SHA-256 compression function (FIPS 180-4 Section 6.2.2).
// Processes a single 512-bit (64-byte) message block and updates the hash state.
void sha256_compress(std::array<uint32_t, 8>& state, span<uint8_t const, sha256_block_size> block)
{
    // Step 1: Message schedule expansion.
    // W[0..15] are loaded directly from the block in big-endian order.
    // W[16..63] are derived: W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
    SecureWorkArray<uint32_t, 64> W;
    for (int t = 0; t < 16; ++t) {
        W[t] = load_be32(block.subspan(static_cast<size_t>(t) * 4).first<4>());
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    // Step 2: Initialize working variables a..h from current hash state.
    uint32_t a = state[0];
    SecureZeroRef const zero_a{a};  // Ensure "a" is securely zeroed on scope exit (important for HMAC with secret keys).
    uint32_t b = state[1];
    SecureZeroRef const zero_b{b};  // Ensure "b" is securely zeroed on scope exit (important for HMAC with secret keys).
    uint32_t c = state[2];
    SecureZeroRef const zero_c{c};  // Ensure "c" is securely zeroed on scope exit (important for HMAC with secret keys).
    uint32_t d = state[3];
    SecureZeroRef const zero_d{d};  // Ensure "d" is securely zeroed on scope exit (important for HMAC with secret keys).
    uint32_t e = state[4];
    SecureZeroRef const zero_e{e};  // Ensure "e" is securely zeroed on scope exit (important for HMAC with secret keys).
    uint32_t f = state[5];
    SecureZeroRef const zero_f{f};  // Ensure "f" is securely zeroed on scope exit (important for HMAC with secret keys).
    uint32_t g = state[6];
    SecureZeroRef const zero_g{g};  // Ensure "g" is securely zeroed on scope exit (important for HMAC with secret keys).
    uint32_t h = state[7];
    SecureZeroRef const zero_h{h};  // Ensure "h" is securely zeroed on scope exit (important for HMAC with secret keys).

    // Step 3: 64 rounds of the compression function.
    // Each round: T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
    //             T2 = Sigma0(a) + Maj(a,b,c)
    // Then shift working variables and inject T1, T2.
    for (int t = 0; t < 64; ++t) {
        uint32_t const T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
        uint32_t const T2 = Sigma0(a) + Maj(a, b, c);
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

// Internal incremental context (used by the one-shot API and HMAC construction).
// Destructor securely zeroes state and buffer to prevent key material from
// lingering on the stack after HMAC computations.
struct Sha256Ctx
{
    std::array<uint32_t, 8> state{};                  // Running hash state (H0..H7)
    std::array<uint8_t, sha256_block_size> buffer{};  // Partial block buffer (up to 64 bytes)
    size_t buffer_len{};                              // Number of bytes currently in the partial buffer
    uint64_t total_len{};                             // Total message length in bytes (for final padding)

    ~Sha256Ctx() { secure_zero(*this); }
};

// Initialize the SHA-256 context with the standard initial hash values.
// FIPS 180-4 Section 5.3.3: first 32 bits of the fractional parts of the
// square roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
void sha256_ctx_init(Sha256Ctx& ctx)
{
    ctx.state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    ctx.buffer = {};
    ctx.buffer_len = 0;
    ctx.total_len = 0;
}

// Feed data incrementally into the SHA-256 context.
// Buffers partial blocks and compresses complete 64-byte blocks as they become available.
void sha256_ctx_update(Sha256Ctx& ctx, span<uint8_t const> data)
{
    size_t offset = 0;
    ctx.total_len += data.size();

    // Fill any partial block left over from a previous update.
    if (ctx.buffer_len > 0) {
        size_t const fill = std::min(sha256_block_size - ctx.buffer_len, data.size());
        span_copy(span(ctx.buffer).subspan(ctx.buffer_len, fill), data.first(fill));
        ctx.buffer_len += fill;
        offset += fill;

        if (ctx.buffer_len == sha256_block_size) {
            sha256_compress(ctx.state, make_const_span(ctx.buffer));
            ctx.buffer_len = 0;
        }
    }

    // Process full 64-byte blocks directly from the input data.
    while (offset + sha256_block_size <= data.size()) {
        sha256_compress(ctx.state, data.subspan(offset).first<sha256_block_size>());
        offset += sha256_block_size;
    }

    // Buffer any remaining bytes (less than a full block).
    if (offset < data.size()) {
        size_t const remaining = data.size() - offset;
        span_copy(span(ctx.buffer).first(remaining), data.subspan(offset, remaining));
        ctx.buffer_len = remaining;
    }
}

// Finalize the SHA-256 hash and produce the 32-byte digest.
// Applies FIPS 180-4 Section 5.1.1 padding: a 1-bit, then zero bits, then the
// 64-bit big-endian message length in bits, such that the total is a multiple of 512 bits.
auto sha256_ctx_final(Sha256Ctx& ctx) -> std::array<uint8_t, sha256_digest_size>
{
    uint64_t const bit_len = ctx.total_len * 8;

    // Append the 0x80 byte (a 1-bit followed by seven 0-bits).
    ctx.buffer[ctx.buffer_len++] = 0x80;

    // If the partial block cannot fit the 8-byte length field (need 56 bytes free),
    // pad to the end and compress, then start a new block.
    if (ctx.buffer_len > 56) {
        span_zero(span(ctx.buffer).subspan(ctx.buffer_len));
        sha256_compress(ctx.state, make_const_span(ctx.buffer));
        ctx.buffer_len = 0;
    }

    // Pad with zeros up to byte 56, then write the 64-bit big-endian bit length.
    auto buf = span(ctx.buffer);
    span_zero(buf.subspan(ctx.buffer_len, 56 - ctx.buffer_len));
    store_be32(buf.subspan<56, 4>(), static_cast<uint32_t>(bit_len >> 32));
    store_be32(buf.subspan<60, 4>(), static_cast<uint32_t>(bit_len));
    sha256_compress(ctx.state, make_const_span(ctx.buffer));

    // Serialize the final hash state as 32 bytes in big-endian order.
    std::array<uint8_t, sha256_digest_size> digest{};
    for (int i = 0; i < 8; ++i) {
        store_be32(span(digest).subspan(static_cast<size_t>(i) * 4).first<4>(), ctx.state[static_cast<size_t>(i)]);
    }
    return digest;
}

}  // anonymous namespace

//
// SHA-256 public API
//

auto sha256_sw(span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    Sha256Ctx ctx;
    sha256_ctx_init(ctx);
    sha256_ctx_update(ctx, message);
    return sha256_ctx_final(ctx);
}

//
// HMAC-SHA-256 (RFC 2104)
//

// HMAC-SHA-256 (RFC 2104 Section 2).
// HMAC(K, text) = H((K XOR opad) || H((K XOR ipad) || text))
// where ipad = 0x36 repeated, opad = 0x5c repeated, and H = SHA-256.
auto sha256_hmac_sw(span<uint8_t const> key, span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>
{
    return internal::sha256_hmac_generic<Sha256Ctx>(
        key, message, {}, sha256_sw, sha256_ctx_init, sha256_ctx_update, sha256_ctx_final);
}

auto sha256_hmac_sw(span<uint8_t const> key, span<uint8_t const> message1, span<uint8_t const> message2)
    -> std::array<uint8_t, sha256_digest_size>
{
    return internal::sha256_hmac_generic<Sha256Ctx>(
        key, message1, message2, sha256_sw, sha256_ctx_init, sha256_ctx_update, sha256_ctx_final);
}

auto sha256_secure_sw(span<uint8_t const> message) -> SecureArray<sha256_digest_size>
{
    return SecureArray<sha256_digest_size>(sha256_sw(message));
}

}  // namespace statusbar::crypto
