// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// HKDF-SHA-256 (RFC 5869)
// Reference: https://www.rfc-editor.org/rfc/rfc5869

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Size of the pseudorandom key (PRK) produced by HKDF-Extract, in bytes.
///
/// Equal to the SHA-256 digest size (32 bytes / 256 bits).
inline constexpr size_t hkdf_sha256_prk_size = 32;

/// @brief Maximum size of the info parameter for HKDF-Expand, in bytes.
///
/// This is an implementation limit based on the fixed-size internal buffer.
/// For AVTP key derivation, use build_ed25519_transport_key_info() or
/// build_p256_transport_key_info() to construct properly sized info values.
inline constexpr size_t hkdf_sha256_max_info_size = 256;

/// @brief HKDF-SHA-256 Extract step (RFC 5869 Section 2.2).
///
/// Extracts a fixed-length pseudorandom key (PRK) from the input keying material (IKM)
/// and an optional salt. PRK = HMAC-SHA-256(salt, IKM). If salt is empty, a string
/// of HashLen (32) zero bytes is used as the salt per the RFC.
///
/// @param salt Optional salt value (a non-secret random value). May be empty.
/// @param ikm  Input keying material (the secret to extract from).
/// @return A 32-byte pseudorandom key (PRK).
auto hkdf_sha256_extract(std::span<uint8_t const> salt, std::span<uint8_t const> ikm) -> SecureArray<hkdf_sha256_prk_size>;

/// @brief HKDF-SHA-256 Expand step (RFC 5869 Section 2.3).
///
/// Expands the pseudorandom key (PRK) into output keying material (OKM) of the
/// requested length, using the optional context/info string for domain separation.
/// The expansion is computed as:
///   T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i), for i = 1..N
/// where N = ceil(L / HashLen) and T(0) is empty.
///
/// @precondition prk.size() == 32 (HKDF-SHA-256 PRK is exactly 32 bytes).
/// @precondition okm must be non-empty and at most 8160 bytes (= 255 * 32 byte blocks).
/// @precondition info must be at most 256 bytes (larger info is rejected to prevent misuse).
///               For AVTP key derivation with variable-length fields, use build_ed25519_transport_key_info()
///               or build_p256_transport_key_info() to create fixed-width info and prevent ambiguous concatenations.
/// @param prk  A 32-byte pseudorandom key (typically from hkdf_sha256_extract).
/// @param info Optional context and application-specific information (may be empty, max 256 bytes).
/// @param okm  Output buffer to receive the derived key material.
/// @return true on success, false if okm is empty, size exceeds 8160 bytes, or info exceeds 256 bytes.
auto hkdf_sha256_expand(std::span<uint8_t const, hkdf_sha256_prk_size> prk, std::span<uint8_t const> info, std::span<uint8_t> okm)
    -> bool;

/// @brief HKDF-SHA-256 one-shot: Extract-then-Expand (RFC 5869 Section 2.1).
///
/// Convenience function combining the extract and expand steps in a single call.
///
/// @param salt Optional salt for the extract step. May be empty.
/// @param ikm  Input keying material.
/// @param info Optional context for the expand step. May be empty.
/// @param okm  Output buffer for derived key material (max 8160 bytes).
/// @return true on success, false if okm size is invalid.
auto hkdf_sha256(std::span<uint8_t const> salt, std::span<uint8_t const> ikm, std::span<uint8_t const> info, std::span<uint8_t> okm)
    -> bool;

}  // namespace statusbar::crypto
