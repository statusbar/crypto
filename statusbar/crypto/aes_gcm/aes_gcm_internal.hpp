// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes_gcm_internal.hpp
/// @brief The GCM authenticated-encryption core shared by AES-128-GCM and
/// AES-256-GCM (NIST SP 800-38D clause 7), parameterised on the block cipher.
///
/// Decryption verifies the tag over the ciphertext before producing any
/// plaintext (7.2 steps 5-8 before step 4), so a forged message never
/// yields bytes to a caller; the buffer is zeroed on failure instead.

#pragma once

#include "statusbar/crypto/aes_gcm/aes_gcm.hpp"
#include "statusbar/crypto/aes_gcm/ghash_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto::internal {

using GcmBlock = std::array<uint8_t, ghash_block_size>;

/// @brief What GCM derives from (key, nonce): the hash subkey, J0 and E_K(J0).
struct GcmState
{
    GhashKey h{};
    GcmBlock j0{};
    GcmBlock encrypted_j0{};  // the tag mask; secret

    ~GcmState() { secure_zero(encrypted_j0); }
};

/// @brief J0 for a 96-bit IV: IV || 0^31 || 1 (SP 800-38D 7.1 step 2).
inline auto gcm_j0(std::span<uint8_t const, aes_gcm_nonce_size> nonce) -> GcmBlock
{
    GcmBlock j0{};
    span_copy(std::span<uint8_t>(j0).first<aes_gcm_nonce_size>(), nonce);
    j0[15] = 1;
    return j0;
}

/// @brief inc32: add one to the rightmost 32 bits, big-endian, mod 2^32 (SP 800-38D 6.2).
inline void gcm_inc32(GcmBlock& block)
{
    auto const tail = std::span<uint8_t>(block).last<4>();
    store_be32(tail, load_be32(tail) + 1U);
}

/// @brief XOR @p keystream into @p data (data.size() <= 16).
inline void gcm_xor_into(std::span<uint8_t> data, GcmBlock const& keystream)
{
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= keystream[i];
    }
}

/// @brief E_K(block) as a new block.
/// @tparam EncryptBlock void(std::span<uint8_t, 16>): encrypt one block in place under the key.
template <typename EncryptBlock>
auto gcm_encrypt_block(EncryptBlock encrypt_block, GcmBlock const& block) -> GcmBlock
{
    GcmBlock out = block;
    encrypt_block(std::span<uint8_t, ghash_block_size>(out));
    return out;
}

/// @brief The hash subkey H = E_K(0^128) in its POLYVAL form (SP 800-38D 7.1 step 1).
template <typename EncryptBlock>
auto gcm_hash_subkey(EncryptBlock encrypt_block) -> GhashKey
{
    GcmBlock const h = gcm_encrypt_block(encrypt_block, GcmBlock{});
    return ghash_key(h);
}

template <typename EncryptBlock>
auto gcm_state(EncryptBlock encrypt_block, std::span<uint8_t const, aes_gcm_nonce_size> nonce) -> GcmState
{
    auto const j0 = gcm_j0(nonce);
    return GcmState{gcm_hash_subkey(encrypt_block), j0, gcm_encrypt_block(encrypt_block, j0)};
}

/// @brief GCTR_K(inc32(J0), data) in place (SP 800-38D 6.5): block i is XORed with E_K(inc32^i(J0)), i >= 1.
template <typename EncryptBlock>
void gcm_ctr(EncryptBlock encrypt_block, GcmBlock counter, std::span<uint8_t> data)
{
    for (size_t off = 0; off < data.size(); off += ghash_block_size) {
        gcm_inc32(counter);
        auto const keystream = gcm_encrypt_block(encrypt_block, counter);
        gcm_xor_into(data.subspan(off, std::min(ghash_block_size, data.size() - off)), keystream);
    }
}

/// @brief S = GHASH_H(pad(A) || pad(C) || [len(A)]64 || [len(C)]64) (SP 800-38D 7.1 step 5).
inline auto gcm_ghash(GhashKey const& h, std::span<uint8_t const> ciphertext, std::span<uint8_t const> aad) -> GcmBlock
{
    GcmBlock accumulator{};
    ghash_update_padded(h, aad, accumulator);
    ghash_update_padded(h, ciphertext, accumulator);
    ghash_update_lengths(h, aad.size(), ciphertext.size(), accumulator);
    return ghash_final(accumulator);
}

/// @brief T = S XOR E_K(J0) (SP 800-38D 7.1 step 6).
inline auto gcm_tag(GcmState const& state, std::span<uint8_t const> ciphertext, std::span<uint8_t const> aad) -> GcmBlock
{
    auto tag = gcm_ghash(state.h, ciphertext, aad);
    gcm_xor_into(tag, state.encrypted_j0);
    return tag;
}

/// @brief GCM-AE (SP 800-38D 7.1): encrypt in place, return the tag.
/// @return The 16-byte tag; all zeros with nothing encrypted when the plaintext
/// exceeds aes_gcm_max_plaintext_size.
template <typename EncryptBlock>
auto gcm_encrypt(
    EncryptBlock encrypt_block,
    std::span<uint8_t const, aes_gcm_nonce_size> nonce,
    std::span<uint8_t> plaintext_to_ciphertext,
    std::span<uint8_t const> aad) -> GcmBlock
{
    if (plaintext_to_ciphertext.size() > aes_gcm_max_plaintext_size) {
        return {};
    }
    auto const state = gcm_state(encrypt_block, nonce);
    gcm_ctr(encrypt_block, state.j0, plaintext_to_ciphertext);
    return gcm_tag(state, plaintext_to_ciphertext, aad);
}

/// @brief GCM-AD (SP 800-38D 7.2): verify the tag over the ciphertext in constant
/// time, then decrypt in place. On any failure the buffer is zeroed and false returned.
template <typename EncryptBlock>
auto gcm_decrypt(
    EncryptBlock encrypt_block,
    std::span<uint8_t const, aes_gcm_nonce_size> nonce,
    std::span<uint8_t> ciphertext_to_plaintext,
    std::span<uint8_t const, aes_gcm_tag_size> tag,
    std::span<uint8_t const> aad) -> bool
{
    if (ciphertext_to_plaintext.size() > aes_gcm_max_plaintext_size) {
        secure_zero(ciphertext_to_plaintext);
        return false;
    }
    auto const state = gcm_state(encrypt_block, nonce);
    if (!span_compare_constant_time_16(gcm_tag(state, ciphertext_to_plaintext, aad), tag)) {
        secure_zero(ciphertext_to_plaintext);
        return false;
    }
    gcm_ctr(encrypt_block, state.j0, ciphertext_to_plaintext);
    return true;
}

}  // namespace statusbar::crypto::internal
