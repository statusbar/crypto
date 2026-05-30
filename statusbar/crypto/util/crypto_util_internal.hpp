// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Internal shared utilities for statusbar_crypto
// Not part of the public API — used only by implementation files.

#pragma once

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/crypto/util/crypto_has_int128.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace statusbar::crypto {
namespace internal {

/// @brief Portable typedefs for the compiler-provided 128-bit integer types.
///
/// Used by the 5x51 / 4x64-bit elliptic-curve code for 64x64->128-bit
/// multiplication intermediates. These types exist only where the compiler
/// provides __int128 (64-bit ALUs); 32-bit targets build the reduced-radix
/// implementations instead, so the typedefs are guarded.
#if STATUSBAR_CRYPTO_HAS_INT128
using Uint128 = __uint128_t;
using Int128 = __int128_t;
#endif

// Re-export common span utilities from statusbar namespace into internal namespace
// so that existing crypto callers (using internal::span_copy, etc.) continue to work.
using statusbar::can_span_copy;
using statusbar::make_const_span;
using statusbar::make_span;
using statusbar::span_compare;
using statusbar::span_compare_constant_time;
using statusbar::span_copy;
using statusbar::span_fill;
using statusbar::span_load;
using statusbar::span_store;
using statusbar::span_zero;

//
// SecureArray-specific overloads (template deduction doesn't work through derived-to-base conversion)
//

/// @brief Overload for SecureArray<N> — const byte span.
template <size_t N>
inline auto make_const_span(SecureArray<N> const& arr) -> std::span<uint8_t const, N>
{
    return std::span<uint8_t const, N>(arr.data(), N);
}

/// @brief Overload for SecureArray<N> — mutable span.
template <size_t N>
inline auto make_span(SecureArray<N>& arr) -> std::span<uint8_t, N>
{
    return std::span<uint8_t, N>(arr.data(), N);
}

/// @brief Copy a fixed-extent byte span into a SecureArray.
template <size_t N>
inline void span_copy(SecureArray<N>& dest, std::span<uint8_t const, N> src)
{
    span_copy(make_span(dest), src);
}

/// @brief Copy from a fixed-size array into a SecureArray.
template <size_t N>
inline void span_copy(SecureArray<N>& dest, std::array<uint8_t, N> const& src)
{
    span_copy(make_span(dest), make_const_span(src));
}

/// @brief Copy a fixed-extent byte span into a new SecureArray (zeroed on destruction).
template <size_t N>
inline auto span_copy(std::span<uint8_t const, N> src) -> SecureArray<N>
{
    SecureArray<N> result;
    span_copy(make_span(result), src);
    return result;
}

/// @brief Copy a dynamically-sized source span into a SecureArray.
template <size_t N>
inline void span_copy(SecureArray<N>& dest, std::span<uint8_t const> src)
{
    span_copy(make_span(dest), src);
}

/// @brief Check if a dynamically-sized source span can be copied into a SecureArray.
template <size_t N>
inline auto can_span_copy([[maybe_unused]] SecureArray<N>& dest, std::span<uint8_t const> src) -> bool
{
    return src.size() == N;
}

/// @brief Copy from a SecureArray to a std::array.
template <size_t N>
inline void span_copy(std::array<uint8_t, N>& dest, SecureArray<N> const& src)
{
    span_copy(make_span(dest), make_const_span(src));
}

/// @brief Copy from a SecureArray to a SecureArray.
template <size_t N>
inline void span_copy(SecureArray<N>& dest, SecureArray<N> const& src)
{
    span_copy(make_span(dest), make_const_span(src));
}

//
// Crypto-specific utilities
//

/// @brief Doubling in GF(2^128) per RFC 5297 Section 2.3.
///
/// Left-shift the 128-bit block by 1 bit. If the original MSB was set,
/// XOR with Rb = 0x87 (the reduction polynomial x^128 + x^7 + x^2 + x + 1).
/// @param block The 16-byte block to double in-place.
inline void dbl(std::array<uint8_t, 16>& block)
{
    uint8_t const carry = block[0] >> 7;
    for (int i = 0; i < 15; ++i) {
        block[i] = static_cast<uint8_t>((block[i] << 1) | (block[i + 1] >> 7));
    }
    block[15] = static_cast<uint8_t>((block[15] << 1) ^ (carry * 0x87));
}

/// @brief Legacy alias for constant-time 16-byte comparison.
inline auto span_compare_constant_time_16(std::array<uint8_t, 16> const& a, std::span<uint8_t const, 16> b) -> bool
{
    return span_compare_constant_time<16>(a, b);
}

//
// Endian-aware load/store
//

/// @brief Load a 32-bit value from memory in little-endian byte order.
inline auto load_le32(std::span<uint8_t const, 4> p) -> uint32_t
{
    uint32_t v;
    span_load(v, p);
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    return v;
}

/// @brief Store a 32-bit value to memory in little-endian byte order.
inline void store_le32(std::span<uint8_t, 4> p, uint32_t v)
{
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    span_store(p, v);
}

/// @brief Load a 64-bit value from memory in little-endian byte order.
inline auto load_le64(std::span<uint8_t const, 8> p) -> uint64_t
{
    uint64_t v;
    span_load(v, p);
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    return v;
}

/// @brief Store a 64-bit value to memory in little-endian byte order.
inline void store_le64(std::span<uint8_t, 8> p, uint64_t v)
{
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    span_store(p, v);
}

/// @brief Load a 32-bit big-endian word from a byte span.
inline auto load_be32(std::span<uint8_t const, 4> p) -> uint32_t
{
    uint32_t v;
    span_load(v, p);
    if constexpr (std::endian::native == std::endian::little) {
        v = std::byteswap(v);
    }
    return v;
}

/// @brief Store a 32-bit word as big-endian bytes.
inline void store_be32(std::span<uint8_t, 4> p, uint32_t v)
{
    if constexpr (std::endian::native == std::endian::little) {
        v = std::byteswap(v);
    }
    span_store(p, v);
}

/// @brief Load a 64-bit big-endian word from a byte span.
inline auto load_be64(std::span<uint8_t const, 8> p) -> uint64_t
{
    uint64_t v;
    span_load(v, p);
    if constexpr (std::endian::native == std::endian::little) {
        v = std::byteswap(v);
    }
    return v;
}

/// @brief Store a 64-bit word as big-endian bytes.
inline void store_be64(std::span<uint8_t, 8> p, uint64_t v)
{
    if constexpr (std::endian::native == std::endian::little) {
        v = std::byteswap(v);
    }
    span_store(p, v);
}

}  // namespace internal
}  // namespace statusbar::crypto
