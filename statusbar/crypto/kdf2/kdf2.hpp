// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// KDF2 Key Derivation Function (IEEE 1363a-2004 Section 13.2)
//
// KDF2 with SHA-256: Hash_i = SHA-256(Z || I2OSP(counter, 4) || P)
// where counter starts at 1 (32-bit big-endian).
//
// References:
// - IEEE 1363a-2004 Section 13.2
// - IEEE 1722-2016 clause 17.3.1 (KDF2 with SHA-256)

#pragma once

#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief KDF2 key derivation with SHA-256 (IEEE 1363a-2004 Section 13.2).
///
/// Derives key material by iterating: Hash_i = SHA-256(Z || I2OSP(counter, 4) || P),
/// where the counter starts at 1 and increments for each 32-byte block needed.
/// The output buffer is filled with the concatenation of Hash_1 || Hash_2 || ...,
/// truncated to the requested length.
///
/// Used by IEEE 1722-2016 clause 17.3.1 for deriving symmetric keys from ECDH shared secrets.
///
/// @param shared_secret The shared secret Z (input keying material).
/// @param params Additional parameters P concatenated after the counter (may be empty).
/// @param output Output buffer to fill with derived key material. The number of bytes
///               derived equals output.size().
/// @return true on success, false if shared_secret.size() + 4 + params.size() exceeds
///         the internal 256-byte hash input buffer.
auto kdf2_sha256(std::span<uint8_t const> shared_secret, std::span<uint8_t const> params, std::span<uint8_t> output) -> bool;

}  // namespace statusbar::crypto
