// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 ECDH key agreement (RFC 7748 Section 5)
// Reference: https://www.rfc-editor.org/rfc/rfc7748

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/curve25519.hpp"
#    include "statusbar/crypto/25519/curve25519_constants.hpp"
#    include "statusbar/crypto/25519/x25519.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

#    include <cstdint>

namespace statusbar::crypto {

using internal::span_copy;
using std::span;

namespace {

using constants::X25519_BASEPOINT;

}  // anonymous namespace

auto x25519_keypair_from_seed(span<uint8_t const, X25519PrivateKey::LENGTH> seed) -> X25519PrivateKey
{
    // Generate X25519 keypair. The seed is used directly as the scalar --
    // clamping (clear bits 0-2, set bit 254, clear bit 255) is applied inside
    // curve25519_scalar_mult per RFC 7748 Section 5. Public key = scalar *
    // basepoint(9) on the Montgomery curve.
    X25519PrivateKey sk{};

    // Copy seed to private key scalar (clamping happens inside curve25519_scalar_mult)
    span_copy(sk.data, seed);

    // Compute public key = X25519(seed, basepoint_9)
    auto pub = curve25519_scalar_mult(seed, X25519_BASEPOINT);
    span_copy(sk.public_key.data, pub);

    return sk;
}

auto x25519(X25519PrivateKey const& sk, X25519PublicKey const& pk) -> std::array<uint8_t, x25519_shared_secret_size>
{
    // Compute shared_secret = X25519(sk.scalar, pk.u). The Montgomery ladder
    // in curve25519_scalar_mult handles clamping and the full ladder computation.
    return curve25519_scalar_mult(sk.data, pk.data);
}

auto x25519_shared_secret_is_valid(span<uint8_t const, x25519_shared_secret_size> shared_secret) -> bool
{
    // Constant-time all-zero check: OR all 32 bytes into a single accumulator.
    // If the result is zero, the peer used a small-order point and the shared
    // secret is invalid per RFC 7748.
    uint8_t acc = 0;
    for (auto b : shared_secret) {
        acc |= b;
    }
    return acc != 0;
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
