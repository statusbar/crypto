// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes_gcm_siv.hpp
/// @brief AES-GCM-SIV constants and POLYVAL type re-exports (RFC 8452).
///
/// Defines AES-GCM-SIV specific constants (nonce size, tag size) and
/// re-exports POLYVAL types and software functions from polyval_sw.hpp
/// for backward compatibility.
///
/// @see https://www.rfc-editor.org/rfc/rfc8452

#pragma once

#include "statusbar/crypto/polyval/polyval_sw.hpp"

#include <cstddef>

namespace statusbar::crypto {

/// @brief Nonce size for AES-GCM-SIV: 12 bytes (96 bits) per RFC 8452.
inline constexpr size_t aes_gcm_siv_nonce_size = 12;

/// @brief Authentication tag size for AES-GCM-SIV: 16 bytes (128 bits) per RFC 8452.
inline constexpr size_t aes_gcm_siv_tag_size = 16;

}  // namespace statusbar::crypto
