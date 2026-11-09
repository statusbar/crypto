// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file ghash_internal.hpp
/// @brief GHASH (NIST SP 800-38D 6.4) computed with the POLYVAL module.
///
/// RFC 8452 Appendix A relates the two universal hashes:
///
///     GHASH_H(X_1, ..., X_n) = ByteReverse(POLYVAL_H'(ByteReverse(X_1), ..., ByteReverse(X_n)))
///     H' = mulX_POLYVAL(ByteReverse(H))
///
/// so GHASH is a byte-order adapter around POLYVAL, which carries the carry-less
/// multiplication (PMULL / PCLMULQDQ with a constant-time software fallback).
/// The accumulator is kept in POLYVAL byte order between updates; ghash_final()
/// converts it back to the GCM order.
///
/// @see https://www.rfc-editor.org/rfc/rfc8452#appendix-A

#pragma once

#include "statusbar/crypto/polyval/polyval_sw.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto::internal {

/// @brief GHASH block size in bytes (128 bits).
inline constexpr size_t ghash_block_size = 16;

/// @brief The POLYVAL form H' of a GHASH hash subkey H = E_K(0^128).
struct GhashKey
{
    PolyvalKey polyval{};
};

/// @brief Convert the hash subkey H to its POLYVAL key H' (RFC 8452 Appendix A).
auto ghash_key(std::span<uint8_t const, ghash_block_size> h) -> GhashKey;

/// @brief Absorb whole blocks into the POLYVAL-order accumulator.
/// @pre blocks.size() is a multiple of ghash_block_size.
void ghash_update(GhashKey const& key, std::span<uint8_t const> blocks, std::span<uint8_t, ghash_block_size> accumulator);

/// @brief Absorb data zero-padded to a block boundary (the pad() of SP 800-38D 7.1 step 5).
void ghash_update_padded(GhashKey const& key, std::span<uint8_t const> data, std::span<uint8_t, ghash_block_size> accumulator);

/// @brief Absorb the GCM length block [len(A)]64 || [len(C)]64: bit lengths, big-endian.
void ghash_update_lengths(
    GhashKey const& key, uint64_t aad_size, uint64_t ciphertext_size, std::span<uint8_t, ghash_block_size> accumulator);

/// @brief The GHASH value in GCM byte order from the POLYVAL-order accumulator.
auto ghash_final(std::span<uint8_t const, ghash_block_size> accumulator) -> std::array<uint8_t, ghash_block_size>;

/// @brief One-shot GHASH_H(blocks) in GCM byte order.
/// @pre blocks.size() is a multiple of ghash_block_size.
auto ghash(std::span<uint8_t const, ghash_block_size> h, std::span<uint8_t const> blocks) -> std::array<uint8_t, ghash_block_size>;

}  // namespace statusbar::crypto::internal
