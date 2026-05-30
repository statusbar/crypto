// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// PKCS#8 and SPKI encoding for NIST P-256 keys

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/p256/p256.hpp"
#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
#    include "statusbar/crypto/pkcs8/der_internal.hpp"
#    include "statusbar/crypto/pkcs8/pkcs8_p256.hpp"
#    include "statusbar/crypto/pkcs8/pkcs8_p256_constants.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

#    include <cstring>

namespace statusbar::crypto {

using internal::der_read_length;
using internal::span_compare;
using internal::span_copy;
using std::span;

constexpr auto& p256_algorithm_id = constants::p256_algorithm_id;
constexpr auto& spki_p256_prefix = constants::spki_p256_prefix;
constexpr auto& pkcs8_p256_prefix = constants::pkcs8_p256_prefix;

//
// P-256 SPKI export
//

auto spki_export_p256(P256PublicKey const& pk) -> std::array<uint8_t, spki_p256_der_size>
{
    std::array<uint8_t, spki_p256_der_size> der{};
    span_copy(span(der).first(sizeof(spki_p256_prefix)), span<uint8_t const>(spki_p256_prefix, sizeof(spki_p256_prefix)));
    span_copy(span(der).subspan(sizeof(spki_p256_prefix), 64), span<uint8_t const>(pk.data));
    return der;
}

//
// P-256 SPKI import
//

auto spki_import_p256(span<uint8_t const> der) -> std::optional<P256PublicKey>
{
    if (der.size() < spki_p256_der_size) {
        return std::nullopt;
    }

    size_t pos = 0;

    // Outer SEQUENCE
    if (pos >= der.size() || der[pos] != 0x30) {
        return std::nullopt;
    }
    ++pos;
    auto seq_len = der_read_length(der, pos);
    if (seq_len == SIZE_MAX || pos + seq_len > der.size()) {
        return std::nullopt;
    }

    // AlgorithmIdentifier (21 bytes exact match)
    if (pos + sizeof(p256_algorithm_id) > der.size()) {
        return std::nullopt;
    }
    if (!span_compare(der.subspan(pos, sizeof(p256_algorithm_id)), p256_algorithm_id)) {
        return std::nullopt;
    }
    pos += sizeof(p256_algorithm_id);

    // BIT STRING
    if (pos >= der.size() || der[pos] != 0x03) {
        return std::nullopt;
    }
    ++pos;
    auto bs_len = der_read_length(der, pos);
    auto is_invalid_bitstring_length = [](size_t len, size_t min_len, size_t pos, size_t data_size) -> bool {
        return len == SIZE_MAX || len < min_len || pos + len > data_size;
    };
    if (is_invalid_bitstring_length(bs_len, 66, pos, der.size())) {
        return std::nullopt;
    }

    // Unused bits = 0, uncompressed point marker = 0x04
    if (pos + 2 > der.size() || der[pos] != 0x00 || der[pos + 1] != 0x04) {
        return std::nullopt;
    }
    pos += 2;

    // Extract x || y (64 bytes)
    if (pos + 64 > der.size()) {
        return std::nullopt;
    }

    P256PublicKey pk{};
    span_copy(pk.data, der.subspan(pos, 64));

    // Validate point is on curve
    auto point = p256_decode_point_uncompressed(pk.data);
    if (!point || !p256_point_on_curve(*point)) {
        return std::nullopt;
    }

    return pk;
}

//
// P-256 PKCS#8 export
//

auto pkcs8_export_p256(P256PrivateKey const& sk) -> std::array<uint8_t, pkcs8_p256_der_size>
{
    std::array<uint8_t, pkcs8_p256_der_size> der{};
    span_copy(span(der).first(sizeof(pkcs8_p256_prefix)), span<uint8_t const>(pkcs8_p256_prefix, sizeof(pkcs8_p256_prefix)));
    span_copy(span(der).subspan(sizeof(pkcs8_p256_prefix), 32), span<uint8_t const>(sk.data).first<32>());
    return der;
}

//
// P-256 PKCS#8 import
//

auto pkcs8_import_p256(span<uint8_t const> der) -> std::optional<P256PrivateKey>
{
    if (der.size() < pkcs8_p256_der_size) {
        return std::nullopt;
    }

    size_t pos = 0;

    // Outer SEQUENCE
    if (pos >= der.size() || der[pos] != 0x30) {
        return std::nullopt;
    }
    ++pos;
    auto outer_len = der_read_length(der, pos);
    if (outer_len == SIZE_MAX || pos + outer_len > der.size()) {
        return std::nullopt;
    }

    // Version INTEGER (accept 0 or 1)
    if (pos + 3 > der.size() || der[pos] != 0x02 || der[pos + 1] != 0x01 || der[pos + 2] > 0x01) {
        return std::nullopt;
    }
    pos += 3;

    // AlgorithmIdentifier (21 bytes exact match)
    if (pos + sizeof(p256_algorithm_id) > der.size()) {
        return std::nullopt;
    }
    if (!span_compare(der.subspan(pos, sizeof(p256_algorithm_id)), p256_algorithm_id)) {
        return std::nullopt;
    }
    pos += sizeof(p256_algorithm_id);

    // OCTET STRING (wrapping ECPrivateKey)
    if (pos >= der.size() || der[pos] != 0x04) {
        return std::nullopt;
    }
    ++pos;
    auto octet_len = der_read_length(der, pos);
    if (octet_len == SIZE_MAX || pos + octet_len > der.size()) {
        return std::nullopt;
    }

    // ECPrivateKey SEQUENCE
    if (pos >= der.size() || der[pos] != 0x30) {
        return std::nullopt;
    }
    ++pos;
    auto ec_len = der_read_length(der, pos);
    if (ec_len == SIZE_MAX || pos + ec_len > der.size()) {
        return std::nullopt;
    }

    // ECPrivateKey version (must be 1)
    if (pos + 3 > der.size() || der[pos] != 0x02 || der[pos + 1] != 0x01 || der[pos + 2] != 0x01) {
        return std::nullopt;
    }
    pos += 3;

    // OCTET STRING (private scalar)
    if (pos >= der.size() || der[pos] != 0x04) {
        return std::nullopt;
    }
    ++pos;
    auto scalar_len = der_read_length(der, pos);
    if (scalar_len == SIZE_MAX || pos + scalar_len > der.size()) {
        return std::nullopt;
    }

    // Handle scalar length variations (some implementations pad or strip leading zeros)
    SecureArray<32> scalar{};
    if (scalar_len == 32) {
        span_copy(scalar, der.subspan(pos, 32));
    } else if (scalar_len == 31) {
        // Left-pad with zero
        span_copy(span(scalar).subspan(1, 31), der.subspan(pos, 31));
    } else if (scalar_len == 33 && der[pos] == 0x00) {
        // Strip leading zero pad
        span_copy(scalar, der.subspan(pos + 1, 32));
    } else {
        return std::nullopt;
    }

    // Construct keypair from raw scalar (validates scalar in [1, n-1])
    return p256_keypair_from_scalar(scalar);
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
