// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128-SIV authenticated encryption (RFC 5297)
// Reference: https://www.rfc-editor.org/rfc/rfc5297
//
// Implements:
// - S2V (Section 2.4): CMAC-based authentication using dbl and xorend
// - SIV-ENCRYPT (Section 2.6): S2V tag + AES-CTR with bits 31,63 cleared
// - SIV-DECRYPT (Section 2.7): AES-CTR decrypt + S2V tag verification
//
// Key structure: 32-byte combined key split in half
//   K1 (bytes 0..15)  = CMAC key for S2V authentication
//   K2 (bytes 16..31) = AES key for CTR encryption

#include "statusbar/crypto/aes_siv/aes128_siv.hpp"

#include "statusbar/crypto/aes/aes128_hw.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>

namespace statusbar::crypto {

using namespace internal;
using std::span;

namespace {

// S2V: String-to-Vector PRF (RFC 5297 Section 2.4).
//
// Computes the synthetic IV from one AD component and plaintext:
//   S2V(K, S1=AAD, S2=Plaintext) with n=2:
//     D = AES-CMAC(K, <zero>)
//     D = dbl(D) XOR AES-CMAC(K, AAD)
//     if len(PT) >= 128:
//       T = PT xorend D   (XOR D into last 16 bytes of PT copy)
//     else:
//       T = dbl(D) XOR pad(PT)  (10*-padding to 16 bytes)
//     return AES-CMAC(K, T)
auto s2v(Aes128RoundKeys const& rk, span<uint8_t const> aad, span<uint8_t const> plaintext)
    -> std::array<uint8_t, aes128_block_size>
{
    // D = AES-CMAC(K, <zero>)
    std::array<uint8_t, aes_block_size> zero{};
    auto D = aes128_cmac_hw(rk, zero);

    // D = dbl(D) XOR AES-CMAC(K, AAD)
    dbl(D);
    auto cmac_aad = aes128_cmac_hw(rk, aad);
    for (size_t i = 0; i < aes_block_size; ++i) {
        D[i] ^= cmac_aad[i];
    }

    // Handle the final component (plaintext)
    if (plaintext.size() >= aes_block_size) {
        return aes128_cmac_xorend_hw(rk, plaintext, D);
    }

    // Short plaintext: dbl(D) XOR pad(PT)
    // pad() appends 0x80 then zeros to fill 16 bytes
    dbl(D);
    std::array<uint8_t, aes_block_size> padded{};
    span_copy(span(padded).first(plaintext.size()), plaintext);
    padded[plaintext.size()] = 0x80;
    for (size_t i = 0; i < aes_block_size; ++i) {
        padded[i] ^= D[i];
    }
    return aes128_cmac_hw(rk, padded);
}

// AES-CTR with big-endian 32-bit counter in bytes 12-15 (RFC 5297 Section 2.5).
// This is standard NIST CTR mode, unlike GCM-SIV which uses LE32 in bytes 0-3.
void aes_ctr_siv(Aes128RoundKeys const& rk, std::array<uint8_t, aes128_block_size> ctr, span<uint8_t> data)
{
    size_t off = 0;
    while (off < data.size()) {
        auto keystream = ctr;
        aes128_encrypt_block_hw(rk, keystream);

        size_t const n = std::min(static_cast<size_t>(aes_block_size), data.size() - off);
        for (size_t j = 0; j < n; ++j) {
            data[off + j] ^= keystream[j];
        }

        // Increment big-endian 32-bit counter in bytes 12-15
        uint32_t c = (static_cast<uint32_t>(ctr[12]) << 24) | (static_cast<uint32_t>(ctr[13]) << 16) |
            (static_cast<uint32_t>(ctr[14]) << 8) | static_cast<uint32_t>(ctr[15]);
        c += 1;
        ctr[12] = static_cast<uint8_t>(c >> 24);
        ctr[13] = static_cast<uint8_t>(c >> 16);
        ctr[14] = static_cast<uint8_t>(c >> 8);
        ctr[15] = static_cast<uint8_t>(c);

        off += n;
    }
}

}  // anonymous namespace

//
// AES-128-SIV public API (RFC 5297 Sections 2.6, 2.7)
//

auto aes128_siv_encrypt(Aes128SivKey const& key, span<uint8_t> plaintext_to_ciphertext, span<uint8_t const> aad)
    -> std::array<uint8_t, aes128_block_size>
{
    // Reject inputs that would overflow the CTR counter. RFC 5297 clears bits 31 and 63
    // of the IV before CTR mode, limiting the counter space to 2^31 blocks (not 2^32).
    if (plaintext_to_ciphertext.size() > static_cast<uint64_t>(0x7FFFFFFF) * 16) {
        return {};
    }

    // Split key: K1 for CMAC (S2V), K2 for CTR
    Aes128Key k1, k2;
    span_copy(k1.data, span<uint8_t const>(key.data).first<Aes128Key::LENGTH>());
    span_copy(k2.data, span<uint8_t const>(key.data).last<Aes128Key::LENGTH>());

    auto rk1 = aes128_expand_key_hw(k1);
    auto rk2 = aes128_expand_key_hw(k2);

    // Compute SIV tag via S2V over AAD and plaintext
    auto siv = s2v(rk1, aad, plaintext_to_ciphertext);

    // CTR encrypt: clear bits 31 and 63 (counting from right) for counter
    if (!plaintext_to_ciphertext.empty()) {
        auto Q = siv;
        Q[8] &= 0x7F;   // clear bit 63
        Q[12] &= 0x7F;  // clear bit 31
        aes_ctr_siv(rk2, Q, plaintext_to_ciphertext);
    }

    return siv;
}

auto aes128_siv_decrypt(
    Aes128SivKey const& key,
    span<uint8_t> ciphertext_to_plaintext,
    span<uint8_t const, aes128_block_size> siv,
    span<uint8_t const> aad) -> bool
{
    // Reject inputs that would overflow the CTR counter. RFC 5297 clears bits 31 and 63
    // of the IV before CTR mode, limiting the counter space to 2^31 blocks (not 2^32).
    if (ciphertext_to_plaintext.size() > static_cast<uint64_t>(0x7FFFFFFF) * 16) {
        return false;
    }

    // Split key: K1 for CMAC (S2V), K2 for CTR
    Aes128Key k1, k2;
    span_copy(k1.data, span<uint8_t const>(key.data).first<Aes128Key::LENGTH>());
    span_copy(k2.data, span<uint8_t const>(key.data).last<Aes128Key::LENGTH>());

    auto rk1 = aes128_expand_key_hw(k1);
    auto rk2 = aes128_expand_key_hw(k2);

    // CTR decrypt
    if (!ciphertext_to_plaintext.empty()) {
        std::array<uint8_t, aes_block_size> Q{};
        span_copy(Q, span<uint8_t const, aes_block_size>(siv));
        Q[8] &= 0x7F;   // clear bit 63
        Q[12] &= 0x7F;  // clear bit 31
        aes_ctr_siv(rk2, Q, ciphertext_to_plaintext);
    }

    // Recompute SIV and verify
    auto expected = s2v(rk1, aad, ciphertext_to_plaintext);
    if (!span_compare_constant_time_16(expected, siv)) {
        internal::secure_zero(ciphertext_to_plaintext);
        return false;
    }

    return true;
}

}  // namespace statusbar::crypto
