// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// ECDH over NIST P-256 (ECSVDP-DHC) — 32-bit reduced-radix backend.
//
// The 32-bit-ALU counterpart of p256_ecdh.cpp: identical orchestration, but
// over the p256x32 / p256_sc32 reduced-radix arithmetic instead of the
// 4x64-bit __int128 implementation. Provides the same p256_ecdh symbol;
// selected at compile time when __int128 is unavailable.

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if !STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/p256/p256_ecdh.hpp"
#    include "statusbar/crypto/p256/p256_jac32.hpp"
#    include "statusbar/crypto/p256/p256_sc32.hpp"

namespace statusbar::crypto {

auto p256_ecdh(P256PrivateKey const& sk, P256PublicKey const& peer_pk) -> SecureArray<p256_field_element_size>
{
    // Decode the peer public key (uncompressed x || y, 64 bytes).
    auto Q_opt = p256x32_decode_point_uncompressed(peer_pk.data);
    if (!Q_opt) {
        return {};
    }
    auto const& Q = *Q_opt;

    // Validate the peer key lies on the curve.
    if (!p256x32_point_on_curve(Q)) {
        return {};
    }

    // Load the private scalar d; reject d == 0.
    auto d = p256_sc32_from_bytes(sk.data);
    if (p256_sc32_is_zero(d)) {
        return {};
    }

    // Shared point S = [d]Q; reject the identity.
    auto S_jac = p256x32_scalar_mult(d, Q);
    if (p256x32_point_is_identity(S_jac)) {
        return {};
    }

    auto S_aff = p256x32_point_to_affine(S_jac);

    // Shared secret = the x-coordinate as 32-byte big-endian (FE2OSP).
    return p256_fe32_to_bytes(S_aff.x);
}

}  // namespace statusbar::crypto

#endif  // !STATUSBAR_CRYPTO_HAS_INT128
