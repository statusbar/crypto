// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// ECDSA over NIST P-256 with SHA-256 implementation

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/aes/aes_common_internal.hpp"
#    include "statusbar/crypto/p256/p256.hpp"
#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
#    include "statusbar/crypto/p256/p256_wire_constants.hpp"
#    include "statusbar/crypto/sha/sha256_hw.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

#    include <cstring>

namespace statusbar::crypto {

using internal::span_compare;
using internal::span_copy;
using internal::span_fill;
using ::statusbar::crypto::p256_group_order_bytes;
using std::span;

//
// Public key extraction
//

auto p256_public_key(P256PrivateKey const& sk) -> P256PublicKey
{
    return sk.public_key;
}

//
// Key generation
//

auto p256_keypair_from_scalar(span<uint8_t const, p256_scalar_size> scalar_bytes) -> std::optional<P256PrivateKey>
{
    auto d = p256_sc_from_bytes(scalar_bytes);

    // Reject zero scalar
    if (p256_sc_is_zero(d)) {
        return std::nullopt;
    }

    // Reject scalar >= n: constant-time comparison against the P-256 order.
    // Scans all 32 bytes without early exit to avoid timing side-channels.
    {
        uint32_t gt = 0, lt = 0;
        for (int i = 0; i < 32; ++i) {
            uint32_t const a = scalar_bytes[static_cast<size_t>(i)];
            uint32_t const b = p256_group_order_bytes[i];
            uint32_t const decided = gt | lt;  // nonzero if already decided
            uint32_t not_decided = 1 -
                (decided | (decided >> 1) | (decided >> 2) | (decided >> 3) | (decided >> 4) | (decided >> 5) | (decided >> 6) |
                 (decided >> 7));
            not_decided &= 1;
            gt |= ((b - a) >> 8) & not_decided;  // a > b at this position
            lt |= ((a - b) >> 8) & not_decided;  // a < b at this position
        }
        if (lt == 0) {
            return std::nullopt;  // scalar >= n
        }
    }

    // Compute Q = d * G
    auto Q_jac = p256_scalar_mult_base(d);
    auto Q = p256_point_to_affine(Q_jac);
    auto Q_bytes = p256_encode_point_uncompressed(Q);

    P256PrivateKey sk{};
    span_copy(sk.data, scalar_bytes);
    span_copy(sk.public_key.data, Q_bytes);
    return sk;
}

auto p256_ecdsa_keypair_from_seed(span<uint8_t const, 32> seed) -> P256PrivateKey
{
    auto [d, Q] = p256_keypair_from_seed(seed);

    P256PrivateKey sk{};
    SecureArray<32> const d_bytes = p256_sc_to_bytes(d);
    span_copy(sk.data, d_bytes);

    auto q_encoded = p256_encode_point_uncompressed(Q);
    span_copy(sk.public_key.data, q_encoded);

    return sk;
}

//
// RFC 6979 deterministic nonce generation
//

// Generate deterministic k from private key and message hash per RFC 6979.
// Uses HMAC-SHA-256 as the internal HMAC_DRBG.
static auto rfc6979_generate_k(span<uint8_t const, p256_scalar_size> privkey_bytes, span<uint8_t const, p256_scalar_size> hash)
    -> P256Scalar
{
    // RFC 6979 Section 3.2:
    // a. h1 = H(m) -> hash (already computed)
    // b. V = 0x01 0x01 ... 0x01 (32 bytes)
    // c. K = 0x00 0x00 ... 0x00 (32 bytes)
    // d. K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    // e. V = HMAC_K(V)
    // f. K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    // g. V = HMAC_K(V)
    // h. loop: V = HMAC_K(V), k = bits2int(V), check 1 <= k < n

    // V, K, and all message buffers hold HMAC-DRBG state derived from the private key.
    // SecureArray ensures they are zeroed when leaving scope.
    SecureArray<32> V{};
    SecureArray<32> K{};
    span_fill(V, uint8_t{0x01});
    span_fill(K, uint8_t{0x00});

    // Step d: K = HMAC_K(V || 0x00 || x || h1)
    {
        SecureArray<32 + 1 + 32 + 32> msg{};
        span_copy(span(msg).first<32>(), V);
        msg[32] = 0x00;
        span_copy(span(msg).subspan<33, 32>(), privkey_bytes);
        span_copy(span(msg).last<32>(), hash);
        K = sha256_hmac_hw(K, msg);
    }

    // Step e: V = HMAC_K(V)
    V = sha256_hmac_hw(K, V);

    // Step f: K = HMAC_K(V || 0x01 || x || h1)
    {
        SecureArray<32 + 1 + 32 + 32> msg{};
        span_copy(span(msg).first<32>(), V);
        msg[32] = 0x01;
        span_copy(span(msg).subspan<33, 32>(), privkey_bytes);
        span_copy(span(msg).last<32>(), hash);
        K = sha256_hmac_hw(K, msg);
    }

    // Step g: V = HMAC_K(V)
    V = sha256_hmac_hw(K, V);

    // Step h: generate k
    for (int attempt = 0; attempt < 100; ++attempt) {
        V = sha256_hmac_hw(K, V);
        auto k = p256_sc_from_bytes(V);
        if (!p256_sc_is_zero(k)) {
            // Check k < n by converting back and comparing
            auto k_bytes = p256_sc_to_bytes(k);
            if (span_compare(V, k_bytes)) {
                return k;  // k was already < n (from_bytes didn't reduce)
            }
            // k was reduced, meaning original was >= n. Try again.
        }
        // Update K and V for retry
        SecureArray<33> retry_msg{};
        span_copy(span(retry_msg).first<32>(), V);
        retry_msg[32] = 0x00;
        K = sha256_hmac_hw(K, retry_msg);
        V = sha256_hmac_hw(K, V);
    }

    // Should never reach here with valid inputs
    return P256Scalar{};
}

//
// ECDSA Sign (ECSP-DSA)
//

auto p256_ecdsa_sign(P256PrivateKey const& sk, span<uint8_t const> message) -> P256EcdsaSignature
{
    // Step 1: Hash the message
    auto e_hash = sha256_hw(message);

    // Step 2: Convert hash to scalar (EMSA1: leftmost min(orderBits, hashBits) = 256 bits)
    auto e = p256_sc_from_bytes(e_hash);

    // Step 3: Generate deterministic nonce k via RFC 6979
    auto k = rfc6979_generate_k(span<uint8_t const, p256_scalar_size>{sk.data.data(), p256_scalar_size}, e_hash);

    // Step 4: R = k * G
    auto R_jac = p256_scalar_mult_base(k);
    auto R_aff = p256_point_to_affine(R_jac);

    // Step 5: r = R.x mod n
    auto r_bytes = p256_fe_to_bytes(R_aff.x);
    auto r = p256_sc_from_bytes(r_bytes);
    // Note: p256_sc_from_bytes doesn't reduce mod n. We need to check if R.x >= n
    // and reduce. Since p > n, R.x could be >= n. Use reduce_wide with zero-padded value.
    {
        std::array<uint8_t, 2 * p256_scalar_size> wide{};
        span_copy(span(wide).last<p256_scalar_size>(), r_bytes);
        r = p256_sc_reduce_wide(wide);
    }

    if (p256_sc_is_zero(r)) {
        return P256EcdsaSignature{};  // Should not happen with valid k
    }

    // Step 6: s = k^(-1) * (e + r * d) mod n
    auto d = p256_sc_from_bytes(sk.data);
    auto rd = p256_sc_mul(r, d);
    auto e_plus_rd = p256_sc_add(e, rd);
    auto k_inv = p256_sc_inv(k);
    auto s = p256_sc_mul(k_inv, e_plus_rd);

    if (p256_sc_is_zero(s)) {
        return P256EcdsaSignature{};  // Should not happen with valid k
    }

    // Step 7: Encode signature as r || s
    P256EcdsaSignature sig{};
    auto r_out = p256_sc_to_bytes(r);
    auto s_out = p256_sc_to_bytes(s);
    span_copy(span(sig.data).first<p256_scalar_size>(), r_out);
    span_copy(span(sig.data).last<p256_scalar_size>(), s_out);

    return sig;
}

//
// ECDSA Verify (ECVP-DSA)
//

auto p256_ecdsa_verify(P256PublicKey const& pk, span<uint8_t const> message, P256EcdsaSignature const& signature) -> bool
{
    // Step 1: Parse r, s from signature
    std::array<uint8_t, p256_scalar_size> r_bytes{};
    std::array<uint8_t, p256_scalar_size> s_bytes{};
    span_copy(r_bytes, span<uint8_t const>(signature.data).first<p256_scalar_size>());
    span_copy(s_bytes, span<uint8_t const>(signature.data).last<p256_scalar_size>());

    auto r = p256_sc_from_bytes(r_bytes);
    auto s = p256_sc_from_bytes(s_bytes);

    // Check r, s in [1, n-1]
    if (p256_sc_is_zero(r) || p256_sc_is_zero(s)) {
        return false;
    }

    // Check r < n and s < n (from_bytes doesn't reduce, so check roundtrip)
    {
        auto r_check = p256_sc_to_bytes(r);
        auto s_check = p256_sc_to_bytes(s);
        if (!span_compare(r_bytes, r_check)) {
            return false;
        }
        if (!span_compare(s_bytes, s_check)) {
            return false;
        }
    }

    // Step 2: Hash the message
    auto e_hash = sha256_hw(message);
    auto e = p256_sc_from_bytes(e_hash);

    // Step 3: w = s^(-1) mod n
    auto w = p256_sc_inv(s);

    // Step 4: u1 = e*w mod n, u2 = r*w mod n
    auto u1 = p256_sc_mul(e, w);
    auto u2 = p256_sc_mul(r, w);

    // Step 5: Decode public key
    auto Q_opt = p256_decode_point_uncompressed(pk.data);
    if (!Q_opt) {
        return false;
    }
    auto const& Q = *Q_opt;
    if (!p256_point_on_curve(Q)) {
        return false;
    }

    // Step 6: R = u1*G + u2*Q (double scalar multiplication)
    auto R_jac = p256_double_scalar_mult(u1, u2, Q);
    if (p256_point_is_identity(R_jac)) {
        return false;
    }

    auto R_aff = p256_point_to_affine(R_jac);

    // Step 7: v = R.x mod n
    auto v_bytes = p256_fe_to_bytes(R_aff.x);
    P256Scalar v{};
    {
        std::array<uint8_t, 2 * p256_scalar_size> wide{};
        span_copy(span(wide).last<p256_scalar_size>(), v_bytes);
        v = p256_sc_reduce_wide(wide);
    }

    // Step 8: Accept iff v == r
    auto v_out = p256_sc_to_bytes(v);
    auto r_out = p256_sc_to_bytes(r);
    return span_compare(v_out, r_out);
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
