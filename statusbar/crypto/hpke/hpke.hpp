// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file hpke.hpp
/// @brief Hybrid Public Key Encryption (RFC 9180) for one cipher suite family:
/// DHKEM(P-256, HKDF-SHA256) 0x0010 / HKDF-SHA256 0x0001 / AES-128-GCM 0x0001
/// or AES-256-GCM 0x0002, in all four modes (base, psk, auth, auth_psk).
///
/// HPKE is the IETF's standard hybrid encryption: a KEM encapsulates a fresh
/// shared secret to the recipient's public key, a key schedule turns it into an
/// AEAD key, nonce and exporter secret, and the resulting context seals any
/// number of messages with a sequence-numbered nonce. It is the only hybrid
/// scheme with published end-to-end known answers (the RFC's Appendix A and the
/// CFRG vector grid), which is what makes it a candidate for an IEEE 1722 EECF
/// enc value next to ECC1.
///
/// Sender:    auto s = hpke_setup_base_s(aead, pk_r, info, fresh_random_32_bytes);
///            auto tag = hpke_seal(s->context, aad, plaintext_to_ciphertext);  // send s->enc, ct, *tag
/// Recipient: auto c = hpke_setup_base_r(aead, enc, sk_r, info);
///            bool ok = hpke_open(*c, aad, ciphertext_to_plaintext, tag);
///
/// @see https://www.rfc-editor.org/rfc/rfc9180

#pragma once

#include "statusbar/crypto/aes_gcm/aes_gcm.hpp"
#include "statusbar/crypto/keys.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// @brief HPKE modes (RFC 9180 Table 1).
enum class HpkeMode : uint8_t
{
    base = 0x00,      ///< recipient public key only
    psk = 0x01,       ///< plus a pre-shared key the sender proves knowledge of
    auth = 0x02,      ///< plus the sender's static key pair (recipient learns who sent it)
    auth_psk = 0x03,  ///< both
};

/// @brief The AEADs this suite family offers (RFC 9180 Table 5).
enum class HpkeAead : uint16_t
{
    aes128_gcm = 0x0001,
    aes256_gcm = 0x0002,
};

inline constexpr uint16_t hpke_kem_id = 0x0010;  ///< DHKEM(P-256, HKDF-SHA256) (Table 2)
inline constexpr uint16_t hpke_kdf_id = 0x0001;  ///< HKDF-SHA256 (Table 3)

inline constexpr size_t hpke_p256_public_key_size = 65;               ///< Npk = Nenc: SEC1 uncompressed, 0x04 || x || y
inline constexpr size_t hpke_p256_private_key_size = 32;              ///< Nsk
inline constexpr size_t hpke_shared_secret_size = 32;                 ///< Nsecret
inline constexpr size_t hpke_hash_size = 32;                          ///< Nh (SHA-256)
inline constexpr size_t hpke_nonce_size = aes_gcm_nonce_size;         ///< Nn
inline constexpr size_t hpke_tag_size = aes_gcm_tag_size;             ///< Nt
inline constexpr size_t hpke_max_key_size = 32;                       ///< Nk of AES-256-GCM; AES-128-GCM uses 16
inline constexpr size_t hpke_min_psk_size = 32;                       ///< 5.1.2: a psk MUST carry at least 32 bytes of entropy
inline constexpr size_t hpke_min_ikm_size = 32;                       ///< 7.1.3: DeriveKeyPair ikm SHOULD carry at least Nsk bytes
inline constexpr size_t hpke_max_export_size = 255 * hpke_hash_size;  ///< 5.3: L <= 255 * Nh
/// @brief Implementation limit on an exporter_context: the HKDF module's 256-byte
/// info buffer less HPKE's labelling of it. info and psk_id are hashed and unbounded.
inline constexpr size_t hpke_max_exporter_context_size = 234;

/// @brief Nk: the AEAD key size in bytes.
[[nodiscard]] constexpr auto hpke_aead_key_size(HpkeAead const aead) -> size_t
{
    return aead == HpkeAead::aes128_gcm ? 16U : 32U;
}

// ---- DHKEM(P-256, HKDF-SHA256) (7.1) -----------------------------------------------------

/// @brief DeriveKeyPair (7.1.3): a P-256 key pair determined by @p ikm.
///
/// Pass at least hpke_min_ikm_size fresh random bytes for a sender's ephemeral
/// key; the RFC's ikmE / ikmR / ikmS vectors reproduce its key pairs exactly.
/// @return nullopt when ikm is too short or all 256 candidates were rejected
/// (probability about 2^-32 per candidate, so never in practice).
auto hpke_p256_derive_key_pair(std::span<uint8_t const> ikm) -> std::optional<P256PrivateKey>;

/// @brief SerializePublicKey (7.1.1): SEC1 uncompressed, 0x04 || x || y.
auto hpke_p256_serialize_public_key(P256PublicKey const& pk) -> std::array<uint8_t, hpke_p256_public_key_size>;

/// @brief DeserializePublicKey (7.1.1): nullopt unless 0x04-prefixed and a point on the curve.
auto hpke_p256_deserialize_public_key(std::span<uint8_t const, hpke_p256_public_key_size> encoded) -> std::optional<P256PublicKey>;

// ---- Contexts (5.1, 5.2, 5.3) --------------------------------------------------------------

/// @brief One side's encryption context: the key schedule output and the sequence number.
///
/// The fields are plain so a test can pin them against the RFC vectors and a
/// transport can resume a context at a given seq; treat key, base_nonce and
/// exporter_secret as secrets (they zero themselves on destruction).
struct HpkeContext
{
    HpkeAead aead{HpkeAead::aes128_gcm};
    SecureArray<hpke_max_key_size> key{};  ///< the first hpke_aead_key_size(aead) bytes are the key
    SecureArray<hpke_nonce_size> base_nonce{};
    SecureArray<hpke_hash_size> exporter_secret{};
    uint64_t seq{0};
};

/// @brief What a sender setup yields: the encapsulated key to transmit and the context.
struct HpkeSenderSetup
{
    std::array<uint8_t, hpke_p256_public_key_size> enc{};
    HpkeContext context{};
};

/// @brief ContextS.Seal (5.2): encrypt in place under nonce base_nonce XOR seq, then increment seq.
/// @return the tag; nullopt (nothing encrypted, seq unchanged) when the message
/// limit is reached or the plaintext exceeds aes_gcm_max_plaintext_size.
auto hpke_seal(HpkeContext& context, std::span<uint8_t const> aad, std::span<uint8_t> plaintext_to_ciphertext)
    -> std::optional<std::array<uint8_t, hpke_tag_size>>;

/// @brief ContextR.Open (5.2): verify, decrypt in place, then increment seq.
/// @return false (buffer zeroed, seq unchanged) when the tag does not verify.
auto hpke_open(
    HpkeContext& context,
    std::span<uint8_t const> aad,
    std::span<uint8_t> ciphertext_to_plaintext,
    std::span<uint8_t const, hpke_tag_size> tag) -> bool;

/// @brief Context.Export (5.3): LabeledExpand(exporter_secret, "sec", exporter_context, L).
/// @return false when out is empty or longer than hpke_max_export_size, or the
/// context longer than hpke_max_exporter_context_size.
auto hpke_export(HpkeContext const& context, std::span<uint8_t const> exporter_context, std::span<uint8_t> out) -> bool;

// ---- Setup (5.1.1 - 5.1.4) -----------------------------------------------------------------
//
// The *_s functions take the sender's ephemeral ikm (see hpke_p256_derive_key_pair)
// and return the enc to transmit with the context; the *_r functions take the
// received enc. PSK modes require psk (at least hpke_min_psk_size bytes) and
// psk_id both non-empty. Every function returns nullopt on an invalid public
// key, a degenerate ECDH result or inconsistent psk inputs.

auto hpke_setup_base_s(HpkeAead aead, P256PublicKey const& pk_r, std::span<uint8_t const> info, std::span<uint8_t const> ikm_e)
    -> std::optional<HpkeSenderSetup>;

auto hpke_setup_base_r(
    HpkeAead aead,
    std::span<uint8_t const, hpke_p256_public_key_size> enc,
    P256PrivateKey const& sk_r,
    std::span<uint8_t const> info) -> std::optional<HpkeContext>;

auto hpke_setup_psk_s(
    HpkeAead aead,
    P256PublicKey const& pk_r,
    std::span<uint8_t const> info,
    std::span<uint8_t const> psk,
    std::span<uint8_t const> psk_id,
    std::span<uint8_t const> ikm_e) -> std::optional<HpkeSenderSetup>;

auto hpke_setup_psk_r(
    HpkeAead aead,
    std::span<uint8_t const, hpke_p256_public_key_size> enc,
    P256PrivateKey const& sk_r,
    std::span<uint8_t const> info,
    std::span<uint8_t const> psk,
    std::span<uint8_t const> psk_id) -> std::optional<HpkeContext>;

auto hpke_setup_auth_s(
    HpkeAead aead,
    P256PublicKey const& pk_r,
    std::span<uint8_t const> info,
    P256PrivateKey const& sk_s,
    std::span<uint8_t const> ikm_e) -> std::optional<HpkeSenderSetup>;

auto hpke_setup_auth_r(
    HpkeAead aead,
    std::span<uint8_t const, hpke_p256_public_key_size> enc,
    P256PrivateKey const& sk_r,
    std::span<uint8_t const> info,
    P256PublicKey const& pk_s) -> std::optional<HpkeContext>;

auto hpke_setup_auth_psk_s(
    HpkeAead aead,
    P256PublicKey const& pk_r,
    std::span<uint8_t const> info,
    std::span<uint8_t const> psk,
    std::span<uint8_t const> psk_id,
    P256PrivateKey const& sk_s,
    std::span<uint8_t const> ikm_e) -> std::optional<HpkeSenderSetup>;

auto hpke_setup_auth_psk_r(
    HpkeAead aead,
    std::span<uint8_t const, hpke_p256_public_key_size> enc,
    P256PrivateKey const& sk_r,
    std::span<uint8_t const> info,
    std::span<uint8_t const> psk,
    std::span<uint8_t const> psk_id,
    P256PublicKey const& pk_s) -> std::optional<HpkeContext>;

}  // namespace statusbar::crypto
