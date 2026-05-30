// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// C++23 concepts for extensible cryptographic key operations.
//
// The software key types (Ed25519PrivateKey, X25519PrivateKey) satisfy
// these concepts via the free functions in ed25519.hpp and x25519.hpp.
//
// To add secure-enclave support, clients define their own key type in
// their own namespace and provide ADL-visible overloads of the required
// functions.  For example:
//
//   namespace my_enclave {
//
//   struct Ed25519EnclaveKey {
//       uint64_t slot_id;
//       statusbar::crypto::Ed25519PublicKey public_key;
//   };
//
//   auto ed25519_sign(Ed25519EnclaveKey const& k,
//                     std::span<uint8_t const> message)
//       -> statusbar::crypto::Ed25519Signature
//   {
//       return platform_enclave_sign(k.slot_id, message);
//   }
//
//   auto ed25519_public_key(Ed25519EnclaveKey const& k)
//       -> statusbar::crypto::Ed25519PublicKey
//   {
//       return k.public_key;
//   }
//
//   }  // namespace my_enclave
//
// my_enclave::Ed25519EnclaveKey then satisfies Ed25519SigningKey, and any
// template constrained with that concept accepts both the software key
// and the enclave key with no virtual dispatch overhead.

#pragma once

#include "statusbar/crypto/25519/ed25519.hpp"
#include "statusbar/crypto/25519/x25519.hpp"
#include "statusbar/crypto/p256/p256_ecdsa.hpp"

#include <concepts>
#include <span>

namespace statusbar::crypto {

/// @brief Concept for any type that can produce Ed25519 signatures.
///
/// Requires ADL-visible functions:
///   ed25519_sign(key, message) -> Ed25519Signature
///   ed25519_public_key(key)    -> Ed25519PublicKey
///
/// Satisfied by statusbar::crypto::Ed25519PrivateKey (software) and by any
/// client-defined enclave key type that provides the matching overloads.
template <typename K>
concept Ed25519SigningKey = requires(K const& k, std::span<uint8_t const> msg) {
    { ed25519_sign(k, msg) } -> std::same_as<Ed25519Signature>;
    { ed25519_public_key(k) } -> std::same_as<Ed25519PublicKey>;
};

/// @brief Concept for any type that can perform X25519 key agreement.
///
/// Requires an ADL-visible function:
///   x25519(private_key, public_key) -> std::array<uint8_t, 32>
///
/// Satisfied by statusbar::crypto::X25519PrivateKey (software) and by any
/// client-defined enclave key type that provides the matching overload.
template <typename K>
concept X25519KeyAgreement = requires(K const& sk, X25519PublicKey const& pk) {
    { x25519(sk, pk) } -> std::same_as<std::array<uint8_t, x25519_shared_secret_size>>;
};

/// @brief Concept for any type that can produce P-256 ECDSA signatures.
///
/// Requires ADL-visible functions:
///   p256_ecdsa_sign(key, message) -> P256EcdsaSignature
///   p256_public_key(key)          -> P256PublicKey
///
/// Satisfied by statusbar::crypto::P256PrivateKey (software) and by any
/// client-defined enclave key type that provides the matching overloads.
template <typename K>
concept P256SigningKey = requires(K const& k, std::span<uint8_t const> msg) {
    { p256_ecdsa_sign(k, msg) } -> std::same_as<P256EcdsaSignature>;
    { p256_public_key(k) } -> std::same_as<P256PublicKey>;
};

// Verify that the software key types satisfy the concepts.
static_assert(Ed25519SigningKey<Ed25519PrivateKey>);
static_assert(X25519KeyAgreement<X25519PrivateKey>);
static_assert(P256SigningKey<P256PrivateKey>);

}  // namespace statusbar::crypto
