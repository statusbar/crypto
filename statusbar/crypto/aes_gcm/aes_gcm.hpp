// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes_gcm.hpp
/// @brief AES-GCM constants shared by the AES-128 and AES-256 flavours (NIST SP 800-38D).
///
/// GCM here is the 96-bit-IV, 128-bit-tag profile that RFC 5116 registers as
/// AEAD_AES_128_GCM / AEAD_AES_256_GCM and that RFC 9180 (HPKE) uses as AEAD
/// ids 0x0001 / 0x0002. Other IV lengths and truncated tags are not offered.
///
/// @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
/// @see https://www.rfc-editor.org/rfc/rfc5116

#pragma once

#include <cstddef>
#include <cstdint>

namespace statusbar::crypto {

/// @brief Nonce (IV) size for AES-GCM: 12 bytes (96 bits), the SP 800-38D 8.2 recommended length.
inline constexpr size_t aes_gcm_nonce_size = 12;

/// @brief Authentication tag size for AES-GCM: 16 bytes (128 bits), untruncated.
inline constexpr size_t aes_gcm_tag_size = 16;

/// @brief Largest plaintext one (key, nonce) pair may encrypt: 2^39 - 256 bits
/// (SP 800-38D 5.2.1.1), i.e. 2^32 - 2 blocks, so the 32-bit block counter never
/// returns to the J0 block that masks the tag.
inline constexpr uint64_t aes_gcm_max_plaintext_size = (uint64_t{1} << 36U) - 32U;

}  // namespace statusbar::crypto
