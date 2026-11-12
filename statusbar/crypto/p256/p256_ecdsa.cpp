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

// Builds the key pair for a scalar already checked to lie in [1, n-1].
static auto keypair_from_checked_scalar(span<uint8_t const, p256_scalar_size> scalar_bytes, P256Scalar const& d) -> P256PrivateKey
{
    // Compute Q = d * G
    auto Q = p256_point_to_affine(p256_scalar_mult_base(d));
    auto Q_bytes = p256_encode_point_uncompressed(Q);

    P256PrivateKey sk{};
    span_copy(sk.data, scalar_bytes);
    span_copy(sk.public_key.data, Q_bytes);
    return sk;
}

auto p256_keypair_from_scalar(span<uint8_t const, p256_scalar_size> scalar_bytes) -> std::optional<P256PrivateKey>
{
    auto d = p256_sc_from_bytes(scalar_bytes);

    // Reject zero scalar
    if (p256_sc_is_zero(d)) {
        return std::nullopt;
    }

    // Reject scalar >= n (constant time).
    if (!p256_scalar_bytes_below_order(scalar_bytes)) {
        return std::nullopt;
    }

    return keypair_from_checked_scalar(scalar_bytes, d);
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

    // RFC 6979 §2.3.4 bits2octets(h1): the DRBG is seeded with the message
    // hash reduced mod n, not the raw hash. For H(m) < n this is a no-op.
    SecureArray<32> h1_octets{};
    {
        std::array<uint8_t, 2 * p256_scalar_size> wide{};
        span_copy(span(wide).last<32>(), hash);
        h1_octets = p256_sc_to_bytes(p256_sc_reduce_wide(wide));
    }

    // Step d: K = HMAC_K(V || 0x00 || x || bits2octets(h1))
    {
        SecureArray<32 + 1 + 32 + 32> msg{};
        span_copy(span(msg).first<32>(), V);
        msg[32] = 0x00;
        span_copy(span(msg).subspan<33, 32>(), privkey_bytes);
        span_copy(span(msg).last<32>(), h1_octets);
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
        span_copy(span(msg).last<32>(), h1_octets);
        K = sha256_hmac_hw(K, msg);
    }

    // Step g: V = HMAC_K(V)
    V = sha256_hmac_hw(K, V);

    // Step h: generate k by rejection sampling (RFC 6979 §3.2 step h.3).
    for (int attempt = 0; attempt < 100; ++attempt) {
        V = sha256_hmac_hw(K, V);
        // bits2int(V) == int(V) for P-256 (qlen == hlen == 256). Accept only
        // when int(V) is in [1, n-1]. p256_sc_from_bytes does NOT reduce, so
        // the old code's from->to round-trip always matched V and the >= n
        // branch never ran, realizing k = int(V) mod n — a modulo-biased
        // nonce. Reduce int(V) mod n and accept only when it is unchanged
        // (i.e. int(V) was already < n); otherwise reject and re-run the DRBG.
        std::array<uint8_t, 2 * p256_scalar_size> wide{};
        span_copy(span(wide).last<32>(), V);
        auto k = p256_sc_reduce_wide(wide);
        if (!p256_sc_is_zero(k)) {
            auto k_bytes = p256_sc_to_bytes(k);
            if (span_compare(V, k_bytes)) {
                return k;  // int(V) < n: in range, accept
            }
            // int(V) >= n: out of range, reject and continue the DRBG.
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

// Step 1: r and s, accepted only when both lie in [1, n-1].
static auto decode_signature_scalars(P256EcdsaSignature const& signature, P256Scalar& r, P256Scalar& s) -> bool
{
    auto const r_bytes = span<uint8_t const>(signature.data).first<p256_scalar_size>();
    auto const s_bytes = span<uint8_t const>(signature.data).last<p256_scalar_size>();

    // Check r < n and s < n against the group order itself: from_bytes does not
    // reduce, and a to-bytes round trip of an unreduced value never differs, so
    // without this a congruent s + n would verify like s.
    if (!p256_scalar_bytes_below_order(r_bytes) || !p256_scalar_bytes_below_order(s_bytes)) {
        return false;
    }

    r = p256_sc_from_bytes(r_bytes);
    s = p256_sc_from_bytes(s_bytes);
    return !p256_sc_is_zero(r) && !p256_sc_is_zero(s);
}

// Step 7: v = R.x mod n
static auto x_coordinate_mod_n(P256FieldElement const& x) -> P256Scalar
{
    std::array<uint8_t, 2 * p256_scalar_size> wide{};
    span_copy(span(wide).last<p256_scalar_size>(), p256_fe_to_bytes(x));
    return p256_sc_reduce_wide(wide);
}

// Steps 6 to 8: R = u1*G + u2*Q, accept iff R.x mod n == r.
static auto point_x_matches_r(P256Scalar const& u1, P256Scalar const& u2, P256AffinePoint const& Q, P256Scalar const& r) -> bool
{
    auto R_jac = p256_double_scalar_mult(u1, u2, Q);
    if (p256_point_is_identity(R_jac)) {
        return false;
    }

    auto v = x_coordinate_mod_n(p256_point_to_affine(R_jac).x);
    return span_compare(p256_sc_to_bytes(v), p256_sc_to_bytes(r));
}

// Steps 2 to 8 for a decoded, on-curve public key.
static auto verify_against_point(
    P256AffinePoint const& Q, span<uint8_t const, p256_scalar_size> e_hash, P256Scalar const& r, P256Scalar const& s) -> bool
{
    // Step 2: e from the hash (EMSA1: leftmost 256 bits)
    auto e = p256_sc_from_bytes(e_hash);

    // Step 3: w = s^(-1) mod n
    auto w = p256_sc_inv(s);

    // Step 4: u1 = e*w mod n, u2 = r*w mod n
    auto u1 = p256_sc_mul(e, w);
    auto u2 = p256_sc_mul(r, w);

    return point_x_matches_r(u1, u2, Q, r);
}

auto p256_ecdsa_verify(P256PublicKey const& pk, span<uint8_t const> message, P256EcdsaSignature const& signature) -> bool
{
    // Step 1: Parse r, s from signature, both in [1, n-1]
    P256Scalar r{}, s{};
    if (!decode_signature_scalars(signature, r, s)) {
        return false;
    }

    // Step 5: Decode public key
    auto Q_opt = p256_decode_point_uncompressed(pk.data);
    if (!Q_opt || !p256_point_on_curve(*Q_opt)) {
        return false;
    }

    return verify_against_point(*Q_opt, sha256_hw(message), r, s);
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
