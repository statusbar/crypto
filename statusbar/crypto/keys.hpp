// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Fundamental key type definitions for cryptographic operations.
//
// Defines the key structs used across all statusbar_crypto primitives:
// AES-128/256 symmetric keys, Ed25519 signing keys, X25519 ECDH keys,
// P-256 ECDSA/ECDH keys, and SIV combined keys.

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstdint>

namespace statusbar::crypto {

/// @brief A 64-byte Ed25519 signature consisting of the encoded point R (32 bytes)
///        followed by the scalar S (32 bytes).
struct Ed25519Signature
{
    /// Size of an Ed25519 signature in bytes (64). RFC 8032 Section 5.1.6.
    static constexpr size_t LENGTH = 64;

    /// The raw 64-byte signature data: R (bytes 0..31) || S (bytes 32..63).
    std::array<uint8_t, LENGTH> data{};
};

/// @brief 128-bit AES symmetric key.
struct Aes128Key
{
    /// AES-128 key size in bytes (128 bits). FIPS 197.
    static constexpr size_t LENGTH = 16;

    /// Raw key bytes (16 octets).
    std::array<uint8_t, LENGTH> data{};

    /// Securely zero key material on destruction.
    ~Aes128Key() { internal::secure_zero(data); }
};

/// @brief 256-bit AES symmetric key.
struct Aes256Key
{
    /// AES-256 key size in bytes (256 bits). FIPS 197.
    static constexpr size_t LENGTH = 32;

    /// Raw key bytes (32 octets).
    std::array<uint8_t, LENGTH> data{};

    /// Securely zero key material on destruction.
    ~Aes256Key() { internal::secure_zero(data); }
};

/// @brief Ed25519 public key (32-byte compressed Edwards point).
struct Ed25519PublicKey
{
    /// Ed25519 public key size in bytes (32-byte compressed Edwards point). RFC 8032 Section 5.1.5.
    static constexpr size_t LENGTH = 32;

    /// Compressed point encoding: y-coordinate with sign bit in byte 31.
    std::array<uint8_t, LENGTH> data{};
};

/// @brief Ed25519 private key (expanded form from SHA-512 of seed).
///
/// The first 32 bytes are the clamped scalar 'a', and the last 32 bytes
/// are the nonce prefix used during signing (RFC 8032 Section 5.1.5).
/// The embedded public key avoids recomputation during sign operations.
struct Ed25519PrivateKey
{
    /// Ed25519 private key size in bytes (SHA-512(seed): scalar + nonce prefix). RFC 8032 Section 5.1.5.
    static constexpr size_t LENGTH = 64;

    /// SHA-512(seed): bytes 0..31 = clamped scalar, bytes 32..63 = nonce prefix.
    std::array<uint8_t, LENGTH> data{};
    /// Precomputed public key A = [a]B.
    Ed25519PublicKey public_key{};

    /// Securely zero private key material on destruction.
    ~Ed25519PrivateKey() { internal::secure_zero(*this); }
};

/// @brief X25519 public key (32-byte Montgomery u-coordinate).
struct X25519PublicKey
{
    /// X25519 public key size in bytes (32-byte Montgomery u-coordinate). RFC 7748 Section 5.
    static constexpr size_t LENGTH = 32;

    /// Little-endian encoding of the u-coordinate on Curve25519.
    std::array<uint8_t, LENGTH> data{};
};

/// @brief X25519 private key (clamped 32-byte scalar).
///
/// The scalar is clamped per RFC 7748 Section 5: bits 0-2 cleared,
/// bit 254 set, bit 255 cleared. The embedded public key is
/// X25519(scalar, basepoint_9).
struct X25519PrivateKey
{
    /// X25519 private key size in bytes (32-byte clamped scalar). RFC 7748 Section 5.
    static constexpr size_t LENGTH = 32;

    /// Clamped scalar (clamping applied inside curve25519_scalar_mult).
    std::array<uint8_t, LENGTH> data{};
    /// Precomputed public key = X25519(scalar, 9).
    X25519PublicKey public_key{};

    /// Securely zero private key material on destruction.
    ~X25519PrivateKey() { internal::secure_zero(*this); }
};

/// @brief NIST P-256 public key (64-byte uncompressed: x || y, big-endian).
struct P256PublicKey
{
    /// P-256 public key size in bytes (x || y, uncompressed without 0x04 prefix). FIPS 186-4.
    static constexpr size_t LENGTH = 64;

    /// Uncompressed point encoding: x (32 bytes) || y (32 bytes), big-endian.
    std::array<uint8_t, LENGTH> data{};
};

/// @brief NIST P-256 private key (32-byte scalar d, big-endian).
///
/// The embedded public key avoids recomputation during sign/ECDH operations.
struct P256PrivateKey
{
    /// P-256 private key size in bytes (scalar d, big-endian). FIPS 186-4.
    static constexpr size_t LENGTH = 32;

    /// Private scalar d (32 bytes, big-endian).
    std::array<uint8_t, LENGTH> data{};
    /// Precomputed public key Q = d * G.
    P256PublicKey public_key{};

    /// Securely zero private key material on destruction.
    ~P256PrivateKey() { internal::secure_zero(*this); }
};

/// @brief P-256 ECDSA signature (64-byte: r || s, big-endian).
struct P256EcdsaSignature
{
    /// P-256 ECDSA signature size in bytes (r || s, big-endian). FIPS 186-4.
    static constexpr size_t LENGTH = 64;

    /// r (32 bytes) || s (32 bytes), each big-endian.
    std::array<uint8_t, LENGTH> data{};
};

/// @brief AES-128-SIV combined key (RFC 5297): 32 bytes split in half.
///
/// The first 16 bytes (K1) are used for S2V (CMAC-based authentication)
/// and the last 16 bytes (K2) are used for AES-CTR encryption.
struct Aes128SivKey
{
    /// AES-128-SIV combined key size in bytes (2 x 16). RFC 5297.
    static constexpr size_t LENGTH = 32;

    /// Combined key: bytes 0..15 = CMAC key, bytes 16..31 = CTR key.
    std::array<uint8_t, LENGTH> data{};

    /// Securely zero key material on destruction.
    ~Aes128SivKey() { internal::secure_zero(data); }
};

/// @brief AES-256-SIV combined key (RFC 5297): 64 bytes split in half.
///
/// The first 32 bytes (K1) are used for S2V (CMAC-based authentication)
/// and the last 32 bytes (K2) are used for AES-CTR encryption.
struct Aes256SivKey
{
    /// AES-256-SIV combined key size in bytes (2 x 32). RFC 5297.
    static constexpr size_t LENGTH = 64;

    /// Combined key: bytes 0..31 = CMAC key, bytes 32..63 = CTR key.
    std::array<uint8_t, LENGTH> data{};

    /// Securely zero key material on destruction.
    ~Aes256SivKey() { internal::secure_zero(data); }
};

}  // namespace statusbar::crypto
