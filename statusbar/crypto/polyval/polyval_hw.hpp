// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file polyval_hw.hpp
/// @brief POLYVAL hardware-accelerated universal hash (RFC 8452 Section 3).
///
/// Mirrors the software API in aes_gcm_siv.hpp with @c _hw suffix on all function names.
/// Uses hardware acceleration when available, falls back to software otherwise.
///   - ARM64: PMULL/PMULL2 for carry-less multiplication in GF(2^128)
///   - x86-64: PCLMULQDQ for carry-less multiplication in GF(2^128)
///
/// @warning Timing: The software fallback for GF(2^128) multiplication uses shift-and-XOR
/// loops that are not compiler-guaranteed to be constant-time. While the algorithm has no
/// secret-dependent branches, compiler optimizations could theoretically introduce timing
/// variations. Hardware carry-less multiply (PCLMULQDQ/PMULL) is constant-time by design.
/// For security-critical deployments, verify hardware support is available at runtime.
///
/// @see polyval_sw.hpp for the software-only implementations and type definitions.

#pragma once

#include "statusbar/crypto/polyval/polyval_sw.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Compute the POLYVAL hash over the given input in a single call.
///
/// POLYVAL is a universal hash function defined in RFC 8452 Section 3.
/// It operates over GF(2^128) with the irreducible polynomial
/// x^128 + x^127 + x^126 + x^121 + 1, processing 16-byte blocks.
/// Uses hardware-accelerated carry-less multiplication when available.
/// @pre polyval_can_update(input) — input size must be a multiple of 16 bytes.
/// @param H     The 128-bit POLYVAL hash key.
/// @param input Data to hash. The caller is responsible for zero-padding partial blocks.
/// @return      The 16-byte POLYVAL hash result.
auto polyval_hw(PolyvalKey const& H, std::span<uint8_t const> input) -> std::array<uint8_t, polyval_block_size>;

/// @brief Incrementally update a POLYVAL accumulator with additional input blocks.
///
/// Processes one or more 16-byte blocks into an existing accumulator,
/// enabling streaming computation of POLYVAL across disjoint data
/// segments (e.g., AAD, plaintext, and length block separately).
/// Uses hardware-accelerated carry-less multiplication when available.
/// @pre polyval_can_update(input) — input size must be a multiple of 16 bytes.
/// @param H           The 128-bit POLYVAL hash key.
/// @param input       Data to absorb. The caller is responsible for zero-padding partial blocks.
/// @param accumulator The running POLYVAL state, updated in place. Must be
///                    zero-initialized for the first call in a new hash computation.
void polyval_update_hw(PolyvalKey const& H, std::span<uint8_t const> input, std::span<uint8_t, polyval_block_size> accumulator);

}  // namespace statusbar::crypto
