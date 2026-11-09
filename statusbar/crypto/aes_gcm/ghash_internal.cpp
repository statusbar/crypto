// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file ghash_internal.cpp
/// @brief GHASH over POLYVAL (RFC 8452 Appendix A).

#include "statusbar/crypto/aes_gcm/ghash_internal.hpp"

#include "statusbar/crypto/polyval/polyval_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>

namespace statusbar::crypto::internal {

namespace {

using Block = std::array<uint8_t, ghash_block_size>;

auto byte_reverse(std::span<uint8_t const, ghash_block_size> in) -> Block
{
    Block out{};
    std::reverse_copy(in.begin(), in.end(), out.begin());
    return out;
}

// Multiply by x in POLYVAL's field representation (RFC 8452 Appendix A mulX_POLYVAL):
// POLYVAL reads the block as a little-endian integer whose bit i is the x^i
// coefficient, so x * a is a one-bit left shift of that integer with a dropped
// x^128 term reduced by x^128 = x^127 + x^126 + x^121 + 1, i.e. XOR 0xC2 into the
// last byte and 0x01 into the first. The RFC's example: mulX_POLYVAL of
// 9c98c04df9387ded828175a92ba652d8 is 3931819bf271fada0503eb52574ca572.
void mul_x_polyval(Block& b)
{
    uint8_t const carry = static_cast<uint8_t>(b[15] >> 7U);
    for (size_t i = ghash_block_size - 1; i > 0; --i) {
        b[i] = static_cast<uint8_t>((b[i] << 1U) | (b[i - 1] >> 7U));
    }
    b[0] = static_cast<uint8_t>(b[0] << 1U);
    b[0] ^= static_cast<uint8_t>(0x01U * carry);
    b[15] ^= static_cast<uint8_t>(0xC2U * carry);
}

// Blocks are byte-reversed into a stack buffer this many at a time before POLYVAL sees them.
constexpr size_t chunk_blocks = 16;
constexpr size_t chunk_size = chunk_blocks * ghash_block_size;

void absorb_chunk(GhashKey const& key, std::span<uint8_t const> blocks, std::span<uint8_t, ghash_block_size> accumulator)
{
    std::array<uint8_t, chunk_size> reversed{};
    for (size_t off = 0; off < blocks.size(); off += ghash_block_size) {
        auto const in = blocks.subspan(off).first<ghash_block_size>();
        std::reverse_copy(in.begin(), in.end(), reversed.begin() + static_cast<std::ptrdiff_t>(off));
    }
    polyval_update_hw(key.polyval, std::span<uint8_t const>(reversed).first(blocks.size()), accumulator);
}

}  // namespace

auto ghash_key(std::span<uint8_t const, ghash_block_size> h) -> GhashKey
{
    GhashKey key{};
    auto reversed = byte_reverse(h);
    mul_x_polyval(reversed);
    key.polyval.data = reversed;
    secure_zero(reversed);
    return key;
}

void ghash_update(GhashKey const& key, std::span<uint8_t const> blocks, std::span<uint8_t, ghash_block_size> accumulator)
{
    for (size_t off = 0; off < blocks.size(); off += chunk_size) {
        absorb_chunk(key, blocks.subspan(off, std::min(chunk_size, blocks.size() - off)), accumulator);
    }
}

void ghash_update_padded(GhashKey const& key, std::span<uint8_t const> data, std::span<uint8_t, ghash_block_size> accumulator)
{
    size_t const whole = data.size() - (data.size() % ghash_block_size);
    ghash_update(key, data.first(whole), accumulator);
    if (whole == data.size()) {
        return;
    }
    Block pad{};
    span_copy(std::span<uint8_t>(pad).first(data.size() - whole), data.subspan(whole));
    ghash_update(key, pad, accumulator);
}

void ghash_update_lengths(
    GhashKey const& key, uint64_t const aad_size, uint64_t const ciphertext_size, std::span<uint8_t, ghash_block_size> accumulator)
{
    Block lengths{};
    auto const bytes = std::span<uint8_t>(lengths);
    store_be64(bytes.first<8>(), aad_size * 8U);
    store_be64(bytes.last<8>(), ciphertext_size * 8U);
    ghash_update(key, lengths, accumulator);
}

auto ghash_final(std::span<uint8_t const, ghash_block_size> accumulator) -> Block
{
    return byte_reverse(accumulator);
}

auto ghash(std::span<uint8_t const, ghash_block_size> h, std::span<uint8_t const> blocks) -> Block
{
    auto const key = ghash_key(h);
    Block accumulator{};
    ghash_update(key, blocks, accumulator);
    return ghash_final(accumulator);
}

}  // namespace statusbar::crypto::internal
