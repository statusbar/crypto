// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes256_gcm_siv.cpp
/// @brief AES-256-GCM-SIV authenticated encryption (RFC 8452).
///
/// Implements the full AES-256-GCM-SIV AEAD algorithm. The structure is
/// identical to AES-128-GCM-SIV with the following differences for 256-bit keys:
///   1. Key derivation uses 6 AES blocks (instead of 4) to produce 48 bytes:
///      16 bytes for the authentication key + 32 bytes for the encryption key.
///   2. AES-256 is used throughout (key derivation, tag finalization, CTR mode).
///
/// Algorithm overview:
///   1. Key derivation (Section 4): Derive per-message authentication key
///      (message_auth_key, 128-bit) and encryption key (message_key, 256-bit)
///      from the master key and nonce.
///   2. POLYVAL tag computation (Section 3): Hash zero-padded AAD, zero-padded
///      plaintext, and a length block using the derived auth key.
///   3. AES-CTR encryption: Encrypt plaintext using the tag as the initial counter.
///
/// @see https://www.rfc-editor.org/rfc/rfc8452

#include "statusbar/crypto/aes_gcm_siv/aes256_gcm_siv.hpp"

#include "statusbar/crypto/aes/aes256_hw.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/polyval/polyval_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <algorithm>

namespace statusbar::crypto {

using namespace internal;
using std::span;

namespace {

//
// Key derivation (RFC 8452 Section 4)
//
// AES-256-GCM-SIV derives two per-message keys from the master key and nonce:
//   - message_auth_key (128-bit): used as the POLYVAL hash key H
//   - message_enc_key  (256-bit): used for AES-CTR encryption and tag finalization
//
// Unlike AES-128-GCM-SIV which uses 4 KDF blocks (32 bytes), AES-256-GCM-SIV
// uses 6 KDF blocks to produce 48 bytes total:
//   bytes  0-15 = message_auth_key (128-bit, same size as AES-128 variant)
//   bytes 16-47 = message_enc_key  (256-bit, double the AES-128 variant)
//
// Each KDF block is AES-256-encrypted (LE32(counter) || nonce), with only
// the first 8 bytes of each encrypted block kept.
//

// Per-message derived keys for AES-256-GCM-SIV.
struct DerivedKeys256
{
    PolyvalKey auth_key;     // 128-bit POLYVAL hash key H
    Aes256RoundKeys enc_rk;  // Expanded round keys for the 256-bit encryption key
};

// Derive per-message authentication and encryption keys from master key + nonce.
auto derive_keys(Aes256Key const& key, span<uint8_t const, aes_gcm_siv_nonce_size> nonce) -> DerivedKeys256
{
    // Expand the master key for use in the KDF AES encryptions
    auto kdf_rk = aes256_expand_key_hw(key);
    DerivedKeys256 dk{};

    // Generate 6 KDF blocks (counter 0-5), each contributing 8 bytes
    // Block format: LE32(counter) || nonce (4 + 12 = 16 bytes)
    // After AES encryption, only the first 8 bytes of each block are kept
    SecureArray<48> derived{};
    for (uint32_t ctr = 0; ctr < 6; ++ctr) {
        std::array<uint8_t, aes_block_size> block{};
        store_le32(span(block).first<4>(), ctr);
        span_copy(span(block).subspan(4, 12), nonce);
        aes256_encrypt_block_hw(kdf_rk, block);
        span_copy(span<uint8_t>(derived).subspan(static_cast<size_t>(ctr) * 8, 8), span<uint8_t const>(block).first(8));
    }

    // First 16 bytes (blocks 0-1) become the POLYVAL authentication key
    span_copy(dk.auth_key.data, span<uint8_t const>(derived).first<aes_block_size>());

    // Next 32 bytes (blocks 2-5) become the AES-256 encryption key
    Aes256Key enc_key;
    span_copy(enc_key.data, span<uint8_t const>(derived).subspan(16, 32));
    dk.enc_rk = aes256_expand_key_hw(enc_key);
    secure_zero(enc_key.data);

    return dk;
}

//
// Tag computation (RFC 8452 Section 4)
//
// Computes the authentication tag via POLYVAL and AES-256:
//   1. Hash the concatenation: pad(AAD) || pad(PT) || len_block
//      using POLYVAL with the derived auth_key.
//      - pad() zero-pads each segment to a 16-byte boundary.
//      - len_block = LE64(len(AAD) in bits) || LE64(len(PT) in bits)
//   2. XOR the 12-byte nonce into the first 12 bytes of the POLYVAL result.
//   3. Clear bit 127 (MSB of the last byte) — this reserves bit 127 for
//      the AES-CTR counter mode flag.
//   4. AES-256-encrypt the result to produce the final 16-byte tag.
//
// Note: The tag computation is identical to AES-128-GCM-SIV except that
// AES-256 is used for the final encryption step.
//

// Compute the authentication tag over AAD and plaintext.
auto compute_tag(
    DerivedKeys256 const& dk,
    span<uint8_t const, aes_gcm_siv_nonce_size> nonce,
    span<uint8_t const> plaintext,
    span<uint8_t const> aad) -> std::array<uint8_t, aes_gcm_siv_tag_size>
{
    // S is the POLYVAL accumulator, initialized to zero
    std::array<uint8_t, aes_block_size> S{};

    // Step 1a: Hash AAD full blocks through POLYVAL
    size_t const aad_full = aad.size() / aes_block_size;
    if (aad_full > 0) {
        polyval_update_hw(dk.auth_key, aad.subspan(0, aad_full * aes_block_size), S);
    }
    // Step 1b: Hash AAD partial block (zero-padded to 16 bytes)
    if (size_t const rem = aad.size() % aes_block_size; rem > 0) {
        std::array<uint8_t, aes_block_size> pad{};
        span_copy(span(pad).first(rem), aad.subspan(aad_full * aes_block_size, rem));
        polyval_update_hw(dk.auth_key, pad, S);
    }

    // Step 1c: Hash plaintext full blocks through POLYVAL
    size_t const pt_full = plaintext.size() / aes_block_size;
    if (pt_full > 0) {
        polyval_update_hw(dk.auth_key, plaintext.subspan(0, pt_full * aes_block_size), S);
    }
    // Step 1d: Hash plaintext partial block (zero-padded to 16 bytes)
    if (size_t const rem = plaintext.size() % aes_block_size; rem > 0) {
        std::array<uint8_t, aes_block_size> pad{};
        span_copy(span(pad).first(rem), plaintext.subspan(pt_full * aes_block_size, rem));
        polyval_update_hw(dk.auth_key, pad, S);
    }

    // Step 1e: Hash the length block — bit lengths of AAD and plaintext as LE64
    std::array<uint8_t, aes_block_size> len_block{};
    auto lb = span(len_block);
    store_le64(lb.first<8>(), static_cast<uint64_t>(aad.size()) * 8);
    store_le64(lb.last<8>(), static_cast<uint64_t>(plaintext.size()) * 8);
    polyval_update_hw(dk.auth_key, len_block, S);

    // Step 2: XOR the nonce into the first 12 bytes of S
    for (size_t i = 0; i < 12; ++i) {
        S[i] ^= nonce[i];
    }

    // Step 3: Clear bit 127 (MSB of last byte) — reserved for CTR mode flag
    S[15] &= 0x7F;

    // Step 4: AES-256-encrypt S with the derived encryption key to produce the tag
    aes256_encrypt_block_hw(dk.enc_rk, S);
    return S;
}

//
// AES-CTR counter mode (RFC 8452 Section 4)
//
// Encrypts or decrypts data using AES-256 in counter mode. The counter block
// is 16 bytes, with the LE32 counter occupying bytes 0-3. The counter is
// incremented by 1 after each 16-byte block of keystream is generated.
//
// In AES-GCM-SIV, the initial counter is the authentication tag with
// bit 127 set (byte 15 |= 0x80). This ensures the CTR keystream cannot
// collide with the tag computation (which clears bit 127).
//
// For the final partial block, only the needed keystream bytes are XORed.
//

// AES-CTR encrypt/decrypt: XOR data with AES-256-generated keystream blocks.
void aes_ctr(Aes256RoundKeys const& rk, std::array<uint8_t, aes_block_size> ctr, span<uint8_t> data)
{
    size_t off = 0;
    while (off < data.size()) {
        // Generate one block of keystream by encrypting the counter
        auto keystream = ctr;
        aes256_encrypt_block_hw(rk, keystream);

        // XOR keystream into data (handles partial final block)
        size_t const n = std::min(static_cast<size_t>(aes_block_size), data.size() - off);
        for (size_t j = 0; j < n; ++j) {
            data[off + j] ^= keystream[j];
        }

        // Increment the LE32 counter in bytes 0-3
        auto ctr_span = span(ctr);
        uint32_t const c = load_le32(ctr_span.first<4>());
        store_le32(ctr_span.first<4>(), c + 1);
        off += n;
    }
}

}  // anonymous namespace

//
// AES-256-GCM-SIV public API
//

// Encrypt: derive keys -> compute tag over plaintext -> AES-CTR encrypt.
// The tag is computed BEFORE encryption because the SIV construction
// authenticates the plaintext, not the ciphertext.
auto aes256_gcm_siv_encrypt(
    Aes256Key const& key,
    span<uint8_t const, aes_gcm_siv_nonce_size> nonce,
    span<uint8_t> plaintext_to_ciphertext,
    span<uint8_t const> aad) -> std::array<uint8_t, aes_gcm_siv_tag_size>
{
    // RFC 8452 §6: AAD and plaintext are each limited to 2^36 bytes.
    if (static_cast<uint64_t>(aad.size()) > (static_cast<uint64_t>(1) << 36)) {
        return {};
    }
    // Plaintext bound (2^36 bytes = 2^32 blocks); the 32-bit CTR counter also
    // caps it, so reject anything that would wrap the counter.
    if (plaintext_to_ciphertext.size() > static_cast<uint64_t>(0xFFFFFFFF) * 16) {
        return {};
    }

    // Step 1: Derive per-message authentication and encryption keys
    auto dk = derive_keys(key, nonce);

    // Step 2: Compute authentication tag over plaintext (before encryption)
    auto tag = compute_tag(dk, nonce, plaintext_to_ciphertext, aad);

    // Step 3: AES-CTR encrypt using the tag as initial counter (with bit 127 set)
    // Setting bit 127 distinguishes the CTR counter space from the tag space
    if (!plaintext_to_ciphertext.empty()) {
        auto ctr = tag;
        ctr[15] |= 0x80;
        aes_ctr(dk.enc_rk, ctr, plaintext_to_ciphertext);
    }

    return tag;
}

// Decrypt: derive keys -> AES-CTR decrypt -> recompute and verify tag.
// Decryption must happen before tag verification because the SIV tag
// is computed over plaintext, not ciphertext.
auto aes256_gcm_siv_decrypt(
    Aes256Key const& key,
    span<uint8_t const, aes_gcm_siv_nonce_size> nonce,
    span<uint8_t> ciphertext_to_plaintext,
    span<uint8_t const, aes_gcm_siv_tag_size> tag,
    span<uint8_t const> aad) -> bool
{
    // RFC 8452 §6: AAD and ciphertext are each limited to 2^36 bytes.
    if (static_cast<uint64_t>(aad.size()) > (static_cast<uint64_t>(1) << 36)) {
        return false;
    }
    // Ciphertext bound (2^36 bytes = 2^32 blocks); the 32-bit CTR counter also
    // caps it, so reject anything that would wrap the counter.
    if (ciphertext_to_plaintext.size() > static_cast<uint64_t>(0xFFFFFFFF) * 16) {
        return false;
    }

    // Step 1: Derive per-message authentication and encryption keys
    auto dk = derive_keys(key, nonce);

    // Step 2: AES-CTR decrypt using the tag as initial counter (with bit 127 set)
    if (!ciphertext_to_plaintext.empty()) {
        std::array<uint8_t, aes_block_size> ctr{};
        span_copy(ctr, span<uint8_t const, aes_block_size>(tag));
        ctr[15] |= 0x80;
        aes_ctr(dk.enc_rk, ctr, ciphertext_to_plaintext);
    }

    // Step 3: Recompute tag over the recovered plaintext and verify
    // Uses constant-time comparison to prevent timing side-channel attacks
    auto expected = compute_tag(dk, nonce, ciphertext_to_plaintext, aad);
    if (!span_compare_constant_time_16(expected, tag)) {
        // Authentication failed — zero the buffer to prevent use of
        // unauthenticated (potentially tampered) plaintext
        internal::secure_zero(ciphertext_to_plaintext);
        return false;
    }

    return true;
}

}  // namespace statusbar::crypto
