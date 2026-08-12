// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes_ct_internal.hpp
/// @brief Constant-time bitsliced AES core shared by aes128.cpp and aes256.cpp.
///
/// The block state is held as eight 16-bit "bit planes": bit j of plane i is
/// bit i of state byte j (byte j = block[j], i.e. FIPS 197 state column j/4,
/// row j%4). In this representation every AES step is pure bit logic:
///
///   - SubBytes evaluates the S-box as a boolean circuit over the eight
///     planes — the 113-gate decomposition of Boyar and Peralta ("A new
///     combinational logic minimization technique with applications to
///     cryptology", 2009, https://eprint.iacr.org/2009/191) — computing all
///     16 byte substitutions at once with no table lookups.
///   - ShiftRows / MixColumns (and inverses) are fixed bit permutations and
///     XOR networks on the planes.
///
/// No secret-dependent memory addresses or branches exist anywhere in this
/// core, so execution time and cache behavior are independent of key and
/// data — immune to Prime+Probe / Flush+Reload style cache-timing recovery
/// that table-based AES is subject to. This matters doubly here because the
/// software path is the *production* path on CPUs without AES instructions
/// (e.g. Raspberry Pi's BCM2711/BCM2712, which lack the ARMv8 Crypto
/// Extensions).
///
/// Not part of the public API — used only by the AES software implementations
/// and their tests. The public entry points remain aes128_*_sw / aes256_*_sw.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto::internal {

/// Eight bit planes holding one 16-byte AES block (bit j of plane i = bit i
/// of block byte j).
using AesBitPlanes = std::array<uint16_t, 8>;

/// Pack a 16-byte block into bit planes.
[[nodiscard]] auto aes_ct_pack(std::span<uint8_t const, 16> in) -> AesBitPlanes;

/// Unpack bit planes back into a 16-byte block.
void aes_ct_unpack(AesBitPlanes const& q, std::span<uint8_t, 16> out);

/// SubBytes on all 16 bytes at once (Boyar–Peralta S-box circuit).
void aes_ct_sub_bytes(AesBitPlanes& q);

/// InvSubBytes on all 16 bytes at once (inverse affine, S-box core, inverse
/// affine — the inverse S-box shares the forward circuit's GF(2^8) inversion).
void aes_ct_inv_sub_bytes(AesBitPlanes& q);

/// ShiftRows / InvShiftRows as bit-plane rotations.
void aes_ct_shift_rows(AesBitPlanes& q);
void aes_ct_inv_shift_rows(AesBitPlanes& q);

/// MixColumns / InvMixColumns as bit-plane XOR networks.
void aes_ct_mix_columns(AesBitPlanes& q);
void aes_ct_inv_mix_columns(AesBitPlanes& q);

/// S-box applied to the 4 bytes of a key-schedule word, constant-time.
[[nodiscard]] auto aes_ct_sub_word(std::array<uint8_t, 4> const& w) -> std::array<uint8_t, 4>;

/// Full block encrypt with round_keys.size()-1 rounds (11 keys for AES-128,
/// 15 for AES-256). Round keys are in standard byte layout; they are packed
/// into planes internally.
void aes_ct_encrypt_block(std::span<std::array<uint8_t, 16> const> round_keys, std::span<uint8_t, 16> block);

/// Full block decrypt (inverse cipher), same round-key layout as encrypt.
void aes_ct_decrypt_block(std::span<std::array<uint8_t, 16> const> round_keys, std::span<uint8_t, 16> block);

}  // namespace statusbar::crypto::internal
