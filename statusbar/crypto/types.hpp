// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Fixed-size byte array wrapper types for cryptographic operations.
//
// Provides semantic wrapper structs for common fixed-size byte arrays
// used across statusbar_crypto. Each struct follows the same pattern as the
// key types in keys.hpp: a static LENGTH constant and a data member.
//
// Key types (Aes128Key, Ed25519PublicKey, etc.) are in keys.hpp.
// These types cover non-key fixed-size byte arrays.

#pragma once

#include <array>
#include <cstdint>

namespace statusbar::crypto {

/// @brief 16-byte AES block (plaintext, ciphertext, CMAC tag, IV, counter, etc.).
struct AesBlock
{
    /// AES block size in bytes (128 bits). FIPS 197.
    static constexpr size_t LENGTH = 16;

    /// Raw block bytes (16 octets).
    std::array<uint8_t, LENGTH> data{};
};

/// @brief 8-byte AVTP stream identifier (EUI-64 based).
struct StreamId
{
    /// AVTP stream identifier size in bytes (64 bits).
    static constexpr size_t LENGTH = 8;

    /// Raw stream ID bytes (8 octets).
    std::array<uint8_t, LENGTH> data{};
};

/// @brief 32-byte P-256 field element (big-endian encoding of an element in GF(p)).
struct P256FieldElementBytes
{
    /// P-256 field element size in bytes (256 bits).
    static constexpr size_t LENGTH = 32;

    /// Big-endian encoding of the field element.
    std::array<uint8_t, LENGTH> data{};
};

}  // namespace statusbar::crypto
