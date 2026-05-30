// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 ECDH key agreement (RFC 7748 Section 5) — 32-bit reduced-radix backend.
//
// The 32-bit-ALU counterpart of x25519.cpp: identical orchestration, but the
// Montgomery ladder runs over curve25519x32_scalar_mult (10-limb radix-2^25.5
// field) instead of the 5x51-bit __int128 implementation. Provides the same
// x25519* symbols; selected at compile time when __int128 is unavailable.

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if !STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/curve25519_constants.hpp"
#    include "statusbar/crypto/25519/x25519.hpp"
#    include "statusbar/crypto/25519/x25519_32.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

#    include <array>
#    include <cstdint>

namespace statusbar::crypto {

using internal::span_copy;
using std::span;

namespace {

using constants::X25519_BASEPOINT;

}  // anonymous namespace

auto x25519_keypair_from_seed(span<uint8_t const, X25519PrivateKey::LENGTH> seed) -> X25519PrivateKey
{
    // The seed is used directly as the scalar; clamping happens inside
    // curve25519x32_scalar_mult. Public key = [seed] * basepoint(9).
    X25519PrivateKey sk{};
    span_copy(sk.data, seed);

    auto pub = curve25519x32_scalar_mult(seed, X25519_BASEPOINT);
    span_copy(sk.public_key.data, pub);

    return sk;
}

auto x25519(X25519PrivateKey const& sk, X25519PublicKey const& pk) -> std::array<uint8_t, x25519_shared_secret_size>
{
    // shared_secret = X25519(sk.scalar, pk.u); the ladder handles clamping.
    return curve25519x32_scalar_mult(sk.data, pk.data);
}

auto x25519_shared_secret_is_valid(span<uint8_t const, x25519_shared_secret_size> shared_secret) -> bool
{
    // Constant-time all-zero check: a zero result means the peer used a
    // small-order point and the shared secret is invalid per RFC 7748.
    uint8_t acc = 0;
    for (auto b : shared_secret) {
        acc |= b;
    }
    return acc != 0;
}

}  // namespace statusbar::crypto

#endif  // !STATUSBAR_CRYPTO_HAS_INT128
