// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 ECIES implementation (IEEE 1722-2016 Clause 17, enc=1)

// X25519 ECIES calls only the high-level x25519* byte API and symmetric
// HKDF / AES-CBC / HMAC primitives — no field or point types cross any
// boundary — so this file is backend-agnostic and needs no __int128 gate.

#include "statusbar/crypto/ecies/x25519_ecies.hpp"

#include "statusbar/crypto/25519/x25519.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/aes_cbc/aes_cbc.hpp"
#include "statusbar/crypto/hkdf/hkdf.hpp"
#include "statusbar/crypto/sha/sha256_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

namespace statusbar::crypto {

using internal::span_compare_constant_time;
using internal::span_copy;
using std::span;

// HKDF info label: "X25519-ECIES" (12 bytes, no null terminator)
static constexpr uint8_t hkdf_label[] = {'X', '2', '5', '5', '1', '9', '-', 'E', 'C', 'I', 'E', 'S'};
static constexpr size_t hkdf_label_len = sizeof(hkdf_label);
static constexpr size_t hkdf_info_len = hkdf_label_len + x25519_ecies_ephemeral_key_size;  // 12 + 32 = 44

//
// X25519 ECIES Encrypt
//

auto x25519_ecies_encrypt(
    X25519PublicKey const& recipient_pk,
    span<uint8_t const> plaintext,
    span<uint8_t> output,
    span<uint8_t const, X25519PrivateKey::LENGTH> entropy) -> span<uint8_t const>
{
    size_t const needed = x25519_ecies_output_size(plaintext.size());
    if (output.size() < needed) {
        return {};
    }

    // Step 1: Generate ephemeral keypair from entropy
    auto eph_sk = x25519_keypair_from_seed(entropy);

    // Step 2: V = ephemeral public key (32 bytes, native format)
    auto const& V = eph_sk.public_key.data;

    // Step 3: Compute shared secret Z = X25519(ephemeral_sk, recipient_pk)
    // SecureArray so the raw DH secret is wiped from the stack on return
    // (matches the P-256 ECIES path, where p256_ecdh returns SecureArray).
    SecureArray<x25519_shared_secret_size> const Z = x25519(eph_sk, recipient_pk);
    if (!x25519_shared_secret_is_valid(Z)) {
        return {};
    }

    // Step 4: Derive K = HKDF-SHA-256(salt="", ikm=Z, info="X25519-ECIES"||V, 64)
    SecureArray<hkdf_info_len> info{};
    span_copy(span<uint8_t>(info).subspan(0, hkdf_label_len), span<uint8_t const>(hkdf_label, hkdf_label_len));
    span_copy(span<uint8_t>(info).subspan(hkdf_label_len, x25519_ecies_ephemeral_key_size), span<uint8_t const>(V));

    SecureArray<Aes256SivKey::LENGTH> K{};  // 64 bytes
    if (!hkdf_sha256({}, Z, info, K)) {
        return {};
    }

    // Step 5: Split key — K2 = K[0..31] (MAC), K1 = K[32..63] (encryption)
    Aes256Key K1{};
    span_copy(K1.data, span<uint8_t const>(K).last<Aes256Key::LENGTH>());
    SecureArray<Aes256Key::LENGTH> K2{};
    span_copy(K2, span<uint8_t const>(K).first<Aes256Key::LENGTH>());

    // Step 6: Encrypt C = AES-256-CBC-IV0(K1, plaintext)
    size_t const c_len = aes_cbc_iv0_ciphertext_size(plaintext.size());
    auto C_span = output.subspan(x25519_ecies_ephemeral_key_size, c_len);
    aes256_cbc_iv0_encrypt(K1, plaintext, C_span);

    // Step 7: MAC: T = HMAC-SHA-256(K2, C || L2) where L2 = 8 zero bytes
    std::array<uint8_t, 8> const L2{};
    auto T = sha256_hmac_hw(K2, C_span, L2);

    // Step 8: Output V || C || T
    span_copy(output.first(V.size()), span<uint8_t const>(V));
    // C is already written at the right offset
    auto offset = x25519_ecies_ephemeral_key_size + c_len;
    span_copy(output.subspan(offset, T.size()), T);

    return output.first(x25519_ecies_ephemeral_key_size + c_len + x25519_ecies_mac_tag_size);
}

//
// X25519 ECIES Decrypt
//

auto x25519_ecies_decrypt(X25519PrivateKey const& sk, span<uint8_t const> input, span<uint8_t> plaintext) -> span<uint8_t const>
{
    // Minimum size: V(32) + C(16, one block minimum) + T(32) = 80 bytes
    if (input.size() < x25519_ecies_fixed_overhead + aes_block_size) {
        return {};
    }

    // Step 1: Parse V (32 bytes), C (variable), T (32 bytes)
    auto V = input.subspan(0, x25519_ecies_ephemeral_key_size);
    size_t const c_len = input.size() - x25519_ecies_fixed_overhead;
    if ((c_len % aes_block_size) != 0) {
        return {};  // C must be block-aligned
    }
    if (x25519_ecies_ephemeral_key_size + c_len + x25519_ecies_mac_tag_size != input.size()) {
        return {};  // Input size mismatch
    }
    auto C = input.subspan(x25519_ecies_ephemeral_key_size, c_len);
    auto T = input.subspan(x25519_ecies_ephemeral_key_size + c_len, x25519_ecies_mac_tag_size);

    // Step 2: Reconstruct ephemeral public key from V (native 32-byte format)
    X25519PublicKey eph_pk{};
    span_copy(eph_pk.data, V);

    // Step 3: Compute shared secret Z = X25519(sk, ephemeral_pk)
    // SecureArray so the raw DH secret is wiped from the stack on return.
    SecureArray<x25519_shared_secret_size> const Z = x25519(sk, eph_pk);
    if (!x25519_shared_secret_is_valid(Z)) {
        return {};
    }

    // Step 4: Derive K = HKDF-SHA-256(salt="", ikm=Z, info="X25519-ECIES"||V, 64)
    SecureArray<hkdf_info_len> info{};
    span_copy(span<uint8_t>(info).subspan(0, hkdf_label_len), span<uint8_t const>(hkdf_label, hkdf_label_len));
    span_copy(span<uint8_t>(info).subspan(hkdf_label_len, x25519_ecies_ephemeral_key_size), V);

    SecureArray<Aes256SivKey::LENGTH> K{};
    if (!hkdf_sha256({}, Z, info, K)) {
        return {};
    }

    // Step 5: Split key — K2 = K[0..31] (MAC), K1 = K[32..63] (encryption)
    Aes256Key K1{};
    span_copy(K1.data, span<uint8_t const>(K).last<Aes256Key::LENGTH>());
    SecureArray<Aes256Key::LENGTH> K2{};
    span_copy(K2, span<uint8_t const>(K).first<Aes256Key::LENGTH>());

    // Step 6: Verify T == HMAC-SHA-256(K2, C || L2)
    std::array<uint8_t, 8> const L2{};
    auto T_computed = sha256_hmac_hw(K2, C, L2);

    if (!span_compare_constant_time<x25519_ecies_mac_tag_size>(T_computed, T.first<x25519_ecies_mac_tag_size>())) {
        return {};
    }

    // Step 7: Decrypt M = AES-256-CBC-IV0_decrypt(K1, C)
    if (plaintext.size() < C.size()) {
        return {};  // Plaintext buffer too small
    }
    return aes256_cbc_iv0_decrypt(K1, C, plaintext);
}

}  // namespace statusbar::crypto
