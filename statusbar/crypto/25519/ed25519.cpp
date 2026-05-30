// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Ed25519 sign/verify (RFC 8032 Section 5.1)
// Reference: https://www.rfc-editor.org/rfc/rfc8032

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/curve25519.hpp"
#    include "statusbar/crypto/25519/curve25519_constants.hpp"
#    include "statusbar/crypto/25519/ed25519.hpp"
#    include "statusbar/crypto/25519/ed25519_constants.hpp"
#    include "statusbar/crypto/sha/sha512_hw.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

namespace statusbar::crypto {

using internal::make_const_span;
using internal::span_compare_constant_time;
using internal::span_copy;
using std::span;

namespace {

using constants::group_order_L;
using constants::X25519_BASEPOINT;

/// Check if a 32-byte scalar (little-endian) is less than group order L.
/// Returns true if s < L (i.e. s is canonical).
/// This is NOT constant-time, but that's fine -- it operates on the public
/// signature value S, which is not secret.
auto sc_is_canonical(span<uint8_t const, curve25519_scalar_size> s) -> bool
{
    // Compare bytes from MSB down to detect s >= L
    for (int i = 31; i >= 0; --i) {
        if (s[static_cast<size_t>(i)] < group_order_L[static_cast<size_t>(i)]) {
            return true;
        }
        if (s[static_cast<size_t>(i)] > group_order_L[static_cast<size_t>(i)]) {
            return false;
        }
    }
    // s == L, not canonical
    return false;
}

}  // anonymous namespace

//
// Ed25519 public API
//

auto ed25519_keypair_from_seed(span<uint8_t const, ed25519_seed_size> seed) -> Ed25519PrivateKey
{
    // RFC 8032 Section 5.1.5: Key generation

    // 1. Hash seed to get 64 bytes of deterministic keying material.
    //    Bytes 0..31 become the scalar; bytes 32..63 become the nonce prefix.
    auto hash = sha512_secure_hw(seed);

    // 2. Clamping: clear low 3 bits (divisible by cofactor 8), clear bit 255,
    //    set bit 254 (ensure fixed-length scalar). This prevents small-subgroup
    //    attacks and ensures the scalar has a predictable bit length.
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    // 3. Compute public key A = [a]B
    auto scalar = make_const_span(hash).first<curve25519_scalar_size>();
    auto A = ge_scalar_mult_base(scalar);

    // 4. Encode public key
    auto pk_bytes = ge_p3_to_bytes(A);

    // 5. Build private key: store full SHA-512 hash (clamped scalar + nonce prefix)
    Ed25519PrivateKey sk;
    span_copy(sk.data, hash);
    span_copy(sk.public_key.data, pk_bytes);

    return sk;
}

auto ed25519_public_key(Ed25519PrivateKey const& sk) -> Ed25519PublicKey
{
    return sk.public_key;
}

auto ed25519_sign(Ed25519PrivateKey const& sk, span<uint8_t const> message) -> Ed25519Signature
{
    // RFC 8032 Section 5.1.6: Sign
    // Deterministic signing: the nonce r is derived from the private key's
    // nonce prefix and the message, making signatures reproducible and immune
    // to bad randomness.

    // Extract scalar 'a' (first 32 bytes, already clamped) and nonce prefix (last 32 bytes)
    auto scalar_a = span_copy(make_const_span(sk.data).first<curve25519_scalar_size>());
    auto nonce_prefix = span_copy(make_const_span(sk.data).last<curve25519_scalar_size>());

    // 1. Compute nonce: r = SHA-512(nonce_prefix || message) mod L
    Sha512Context ctx;
    sha512_init_hw(ctx);
    sha512_update_hw(ctx, nonce_prefix);
    sha512_update_hw(ctx, message);
    auto nonce_hash = sha512_final_secure_hw(ctx);

    auto nonce_hash_span = make_const_span(nonce_hash);
    auto r = sc_reduce_secure(nonce_hash_span);

    // 2. Compute R = [r]B
    auto r_span = make_const_span(r);
    auto R_point = ge_scalar_mult_base(r_span);
    auto R_bytes = ge_p3_to_bytes(R_point);

    // 3. Compute H = SHA-512(R || pk || message) mod L
    sha512_init_hw(ctx);
    sha512_update_hw(ctx, R_bytes);
    sha512_update_hw(ctx, sk.public_key.data);
    sha512_update_hw(ctx, message);
    auto h_hash = sha512_final_secure_hw(ctx);

    auto h_hash_span = make_const_span(h_hash);
    auto h = sc_reduce_secure(h_hash_span);

    // 4. Compute S = (h * a + r) mod L
    auto h_span = make_const_span(h);
    auto a_span = make_const_span(scalar_a);
    auto S = sc_mul_add_secure(h_span, a_span, r_span);

    // 5. Signature = R || S
    // All sensitive locals (scalar_a, nonce_prefix, nonce_hash, r, h_hash, h, S)
    // are SecureArray — zeroed automatically by RAII on scope exit.
    Ed25519Signature sig;
    span_copy(span(sig.data).first<curve25519_point_size>(), make_const_span(R_bytes));
    span_copy(span(sig.data).last<curve25519_scalar_size>(), make_const_span(S));

    return sig;
}

auto ed25519_verify(Ed25519PublicKey const& pk, span<uint8_t const> message, Ed25519Signature const& signature) -> bool
{
    // RFC 8032 Section 5.1.7: Verify
    // Verification: check [S]B == R + [H]A by computing [H](-A) + [S]B and
    // comparing with R. The negation trick avoids computing [H]A separately.

    // 1. Decode public key A
    auto pk_span = make_const_span(pk.data);
    auto A_opt = ge_from_bytes(pk_span);
    if (!A_opt) {
        return false;
    }
    auto const& A = *A_opt;

    // 2. Extract R (first 32 bytes) and S (second 32 bytes) from signature
    auto R_bytes = span_copy(make_const_span(signature.data).first<curve25519_point_size>());
    auto S_bytes = span_copy(make_const_span(signature.data).last<curve25519_scalar_size>());

    // 3. Check S < L (reject non-canonical S)
    auto S_span = make_const_span(S_bytes);
    if (!sc_is_canonical(S_span)) {
        return false;
    }

    // 4. Compute H = SHA-512(R || pk || message) mod L
    Sha512Context ctx;
    sha512_init_hw(ctx);
    sha512_update_hw(ctx, R_bytes);
    sha512_update_hw(ctx, pk.data);
    sha512_update_hw(ctx, message);
    auto h_hash = sha512_final_hw(ctx);

    auto h_hash_span = make_const_span(h_hash);
    auto h = sc_reduce(h_hash_span);

    // 5. Verify: [S]B == R + [h]A
    //    Compute [S]B - [h]A = [h](-A) + [S]B via ge_double_scalar_mult_vartime
    //    Then compare encoding with R
    auto neg_A = ge_p3_neg(A);
    auto h_span = make_const_span(h);
    auto check_point = ge_double_scalar_mult_vartime(h_span, neg_A, S_span);
    auto check_bytes = ge_p3_to_bytes(check_point);

    // 6. Constant-time comparison of check_bytes with R_bytes
    return span_compare_constant_time(check_bytes, R_bytes);
}

auto ed25519_pk_to_x25519_pk(Ed25519PublicKey const& ed_pk) -> std::optional<X25519PublicKey>
{
    // Birational equivalence between twisted Edwards and Montgomery curves.
    // The Edwards point (x,y) corresponds to Montgomery u = (1+y)/(1-y).
    // We only need y (from the public key encoding) to compute u.

    // Decode y from Ed25519 public key (lower 255 bits, ignore sign bit)
    auto y_bytes = span_copy(make_const_span(ed_pk.data));
    y_bytes[31] &= 0x7F;  // Clear sign bit

    auto y_span = make_const_span(y_bytes);
    auto y = fe25519_from_bytes(y_span);

    auto one = fe25519_one();

    // denominator = 1 - y
    auto den = fe25519_sub(one, y);

    // Reject identity point: if y == 1, then den == 0 and the mapping is undefined.
    // fe25519_invert(0) returns 0, which would silently produce an all-zero X25519 key
    // (a low-order point that contributes nothing in ECDH).
    if (fe25519_is_zero(den) != 0) {
        return std::nullopt;
    }

    // numerator = 1 + y
    auto num = fe25519_add(one, y);

    // u = num * den^(-1)
    auto den_inv = fe25519_invert(den);
    auto u = fe25519_mul(num, den_inv);

    auto u_bytes = fe25519_to_bytes(u);

    X25519PublicKey x_pk;
    span_copy(x_pk.data, u_bytes);
    return x_pk;
}

auto ed25519_sk_to_x25519_sk(Ed25519PrivateKey const& ed_sk) -> X25519PrivateKey
{
    // The Ed25519 private key stores SHA-512(seed), where bytes 0..31 are the
    // clamped scalar. This same scalar works as an X25519 private key because
    // the Ed25519 and Curve25519 groups have the same order.

    X25519PrivateKey x_sk;
    span_copy(x_sk.data, make_const_span(ed_sk.data).first<X25519PrivateKey::LENGTH>());

    // Compute X25519 public key: [scalar] * basepoint(9)
    auto scalar_span = make_const_span(x_sk.data);
    auto bp_span = make_const_span(X25519_BASEPOINT);
    auto x_pk_bytes = curve25519_scalar_mult(scalar_span, bp_span);

    span_copy(x_sk.public_key.data, x_pk_bytes);
    return x_sk;
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
