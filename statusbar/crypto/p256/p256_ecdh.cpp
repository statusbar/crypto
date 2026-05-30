// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// ECDH over NIST P-256 implementation

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/p256/p256.hpp"
#    include "statusbar/crypto/p256/p256_ecdh.hpp"

#    include <cstring>

namespace statusbar::crypto {

auto p256_ecdh(P256PrivateKey const& sk, P256PublicKey const& peer_pk) -> SecureArray<p256_field_element_size>
{
    // Decode peer public key
    auto Q_opt = p256_decode_point_uncompressed(peer_pk.data);
    if (!Q_opt) {
        return {};
    }
    auto const& Q = *Q_opt;

    // Validate peer key is on curve
    if (!p256_point_on_curve(Q)) {
        return {};
    }

    // Load private scalar
    auto d = p256_sc_from_bytes(sk.data);
    if (p256_sc_is_zero(d)) {
        return {};
    }

    // Compute shared point: S = d * Q
    auto S_jac = p256_scalar_mult(d, Q);
    if (p256_point_is_identity(S_jac)) {
        return {};
    }

    auto S_aff = p256_point_to_affine(S_jac);

    // Return x-coordinate as 32-byte big-endian (FE2OSP)
    return p256_fe_to_bytes(S_aff.x);
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
