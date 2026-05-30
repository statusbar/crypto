// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// DL/ECIES (IEEE 1363a-2004 Section 11.3) — 32-bit reduced-radix backend.
//
// The 32-bit-ALU counterpart of ecies.cpp: identical orchestration. Almost
// everything it calls is already backend-agnostic — the high-level p256_ecdh
// / p256_ecdsa_keypair_from_seed (byte API) and the symmetric KDF2 / AES-CBC
// / HMAC-SHA-256 primitives. Only the two P-256 point-encoding primitives
// differ between backends, so this file retargets them to p256x32_*.
// Provides the same ecies_* symbols; selected when __int128 is unavailable.

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if !STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/aes/aes_common_internal.hpp"
#    include "statusbar/crypto/aes_cbc/aes_cbc.hpp"
#    include "statusbar/crypto/ecies/ecies.hpp"
#    include "statusbar/crypto/kdf2/kdf2.hpp"
#    include "statusbar/crypto/p256/p256_ecdh.hpp"
#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
#    include "statusbar/crypto/p256/p256_jac32.hpp"
#    include "statusbar/crypto/sha/sha256_hw.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

namespace statusbar::crypto {

using internal::span_compare_constant_time;
using internal::span_copy;
using std::span;

//
// ECIES Encrypt (IEEE 1363a-2004 Section 11.3.2, DHAES mode)
//

auto ecies_encrypt(
    P256PublicKey const& recipient_pk,
    span<uint8_t const> plaintext,
    span<uint8_t> output,
    span<uint8_t const, p256_scalar_size> entropy) -> span<uint8_t const>
{
    size_t const needed = ecies_output_size(plaintext.size());
    if (output.size() < needed) {
        return {};
    }

    // Step 1: Generate ephemeral keypair from entropy
    auto eph_sk = p256_ecdsa_keypair_from_seed(entropy);

    // Step 2: Compute shared secret z = ECDH(ephemeral_sk, recipient_pk)
    auto z = p256_ecdh(eph_sk, recipient_pk);
    // Check for failure (all zeros = invalid peer key)
    {
        uint8_t acc = 0;
        for (auto b : z) {
            acc |= b;
        }
        if (acc == 0) {
            return {};
        }
    }

    // Step 3: Encode ephemeral public key as V = EC2OSP-X (0x01 || x, 33 bytes)
    // Extract x-coordinate from the uncompressed public key
    std::array<uint8_t, p256_compressed_point_size> V{};
    V[0] = 0x01;
    span_copy(
        span(V).subspan(1, p256_field_element_size), span<uint8_t const>(eph_sk.public_key.data).first<p256_field_element_size>());

    // Step 4: DHAES mode: VZ = V || Z (65 bytes)
    SecureArray<ecies_ephemeral_key_size + p256_field_element_size> VZ{};
    span_copy(span(VZ).first<ecies_ephemeral_key_size>(), V);
    span_copy(span(VZ).last<p256_field_element_size>(), z);

    // Step 5: Derive key material K = KDF2_SHA256(VZ, "", 64)
    SecureArray<Aes256SivKey::LENGTH> K{};
    span<uint8_t const> const empty_params{};
    if (!kdf2_sha256(VZ, empty_params, K)) {
        return {};
    }

    // Step 6: Split key (DHAES mode):
    //   K2 = K[0..31] (MAC key)
    //   K1 = K[32..63] (encryption key)
    Aes256Key K1{};
    span_copy(K1.data, span<uint8_t const>(K).last<Aes256Key::LENGTH>());
    SecureArray<Aes256Key::LENGTH> K2{};
    span_copy(K2, span<uint8_t const>(K).first<Aes256Key::LENGTH>());

    // Step 7: Encrypt C = AES-256-CBC-IV0(K1, plaintext)
    size_t const c_len = aes_cbc_iv0_ciphertext_size(plaintext.size());
    auto C_span = output.subspan(ecies_ephemeral_key_size, c_len);
    aes256_cbc_iv0_encrypt(K1, plaintext, C_span);

    // Step 8: MAC: T = HMAC-SHA-256(K2, C || I2OSP(0, 8))
    // P2 is empty, L2 = 8 zero bytes (big-endian encoding of 0)
    std::array<uint8_t, 8> const L2{};
    auto T = sha256_hmac_hw(K2, C_span, L2);

    // Step 9: Output V || C || T
    span_copy(output.first(V.size()), V);
    // C is already written at the right offset
    auto offset = ecies_ephemeral_key_size + c_len;
    span_copy(output.subspan(offset, T.size()), T);

    return output.first(ecies_ephemeral_key_size + c_len + ecies_mac_tag_size);
}

//
// ECIES Decrypt (IEEE 1363a-2004 Section 11.3.3)
//

auto ecies_decrypt(P256PrivateKey const& sk, span<uint8_t const> input, span<uint8_t> plaintext) -> span<uint8_t const>
{
    // Minimum size: V(33) + C(16, one block minimum) + T(32) = 81 bytes
    if (input.size() < ecies_fixed_overhead + aes_block_size) {
        return {};
    }

    // Step 1: Parse V (33 bytes), C (variable), T (32 bytes)
    // Ensure the input is large enough to extract T at the computed offset.
    auto V = input.subspan(0, ecies_ephemeral_key_size);
    size_t const c_len = input.size() - ecies_fixed_overhead;
    if ((c_len % aes_block_size) != 0) {
        return {};  // C must be block-aligned
    }
    // Explicit bounds check: verify we can safely extract T from the input.
    if (ecies_ephemeral_key_size + c_len + ecies_mac_tag_size != input.size()) {
        return {};  // Input size mismatch (shouldn't happen after checks above, but be explicit)
    }
    auto C = input.subspan(ecies_ephemeral_key_size, c_len);
    auto T = input.subspan(ecies_ephemeral_key_size + c_len, ecies_mac_tag_size);

    // Step 2: Recover ephemeral point from V (EC2OSP-X: 0x01 || x)
    if (V[0] != 0x01) {
        return {};
    }

    // Build a P256PublicKey from x-only: decode x, compute y, form uncompressed key
    std::array<uint8_t, p256_compressed_point_size> v_encoded{};
    span_copy(v_encoded, V);
    auto eph_point = p256x32_decode_point_x(v_encoded);
    if (!eph_point) {
        return {};  // Point not on curve (invalid x-coordinate)
    }
    // NOTE: P-256 has cofactor h=1, so there are no low-order points.
    // The recovered point is guaranteed to be valid and non-zero if it decoded successfully.
    // For completeness, explicit point-at-infinity check is not needed (infinity has no x-coordinate).

    P256PublicKey eph_pk{};
    auto eph_encoded = p256x32_encode_point_uncompressed(*eph_point);
    span_copy(eph_pk.data, eph_encoded);

    // Step 3: Compute shared secret z = ECDH(sk, ephemeral_pk)
    auto z = p256_ecdh(sk, eph_pk);
    {
        uint8_t acc = 0;
        for (auto b : z) {
            acc |= b;
        }
        if (acc == 0) {
            return {};
        }
    }

    // Step 4: VZ = V || Z, derive K, split into K2, K1
    SecureArray<ecies_ephemeral_key_size + p256_field_element_size> VZ{};
    span_copy(span(VZ).first<ecies_ephemeral_key_size>(), V);
    span_copy(span(VZ).last<p256_field_element_size>(), z);

    SecureArray<Aes256SivKey::LENGTH> K{};
    span<uint8_t const> const empty_params{};
    if (!kdf2_sha256(VZ, empty_params, K)) {
        return {};
    }

    Aes256Key K1{};
    span_copy(K1.data, span<uint8_t const>(K).last<Aes256Key::LENGTH>());
    SecureArray<Aes256Key::LENGTH> K2{};
    span_copy(K2, span<uint8_t const>(K).first<Aes256Key::LENGTH>());

    // Step 5: Verify T == HMAC-SHA-256(K2, C || I2OSP(0, 8))
    std::array<uint8_t, 8> const L2{};
    auto T_computed = sha256_hmac_hw(K2, C, L2);

    if (!span_compare_constant_time<ecies_mac_tag_size>(T_computed, T.first<ecies_mac_tag_size>())) {
        return {};
    }

    // Step 6: Decrypt M = AES-256-CBC-IV0_decrypt(K1, C)
    if (plaintext.size() < C.size()) {
        return {};  // Plaintext buffer too small
    }
    return aes256_cbc_iv0_decrypt(K1, C, plaintext);
}

}  // namespace statusbar::crypto

#endif  // !STATUSBAR_CRYPTO_HAS_INT128
