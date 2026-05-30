// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// PKCS#8 and SPKI encoding for Ed25519 keys

// PKCS#8 / SPKI for Ed25519 is pure DER/ASN.1 byte work plus the high-level
// ed25519_keypair_from_seed (byte API) — no field or point type crosses any
// boundary — so this file is backend-agnostic and needs no __int128 gate.

#include "statusbar/crypto/pkcs8/pkcs8_ed25519.hpp"

#include "statusbar/crypto/25519/ed25519.hpp"
#include "statusbar/crypto/pkcs8/der_internal.hpp"
#include "statusbar/crypto/pkcs8/pkcs8_ed25519_constants.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <cstring>

namespace statusbar::crypto {

using internal::der_read_length;
using internal::span_compare;
using internal::span_copy;
using std::span;

constexpr auto& ed25519_algorithm_id = constants::ed25519_algorithm_id;
constexpr auto& spki_ed25519_prefix = constants::spki_ed25519_prefix;
constexpr auto& pkcs8_ed25519_prefix = constants::pkcs8_ed25519_prefix;

//
// Ed25519 SPKI export
//

auto spki_export_ed25519(Ed25519PublicKey const& pk) -> std::array<uint8_t, spki_ed25519_der_size>
{
    std::array<uint8_t, spki_ed25519_der_size> der{};
    span_copy(span(der).first(sizeof(spki_ed25519_prefix)), span<uint8_t const>(spki_ed25519_prefix, sizeof(spki_ed25519_prefix)));
    span_copy(span(der).subspan(sizeof(spki_ed25519_prefix), 32), span<uint8_t const>(pk.data).first<32>());
    return der;
}

//
// Ed25519 SPKI import
//

auto spki_import_ed25519(span<uint8_t const> der) -> std::optional<Ed25519PublicKey>
{
    if (der.size() < spki_ed25519_der_size) {
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

    // AlgorithmIdentifier (7 bytes exact match)
    if (pos + sizeof(ed25519_algorithm_id) > der.size()) {
        return std::nullopt;
    }
    if (!span_compare(der.subspan(pos, sizeof(ed25519_algorithm_id)), ed25519_algorithm_id)) {
        return std::nullopt;
    }
    pos += sizeof(ed25519_algorithm_id);

    // BIT STRING
    if (pos >= der.size() || der[pos] != 0x03) {
        return std::nullopt;
    }
    ++pos;
    auto bs_len = der_read_length(der, pos);
    auto is_invalid_bitstring_length = [](size_t len, size_t min_len, size_t pos, size_t data_size) -> bool {
        return len == SIZE_MAX || len < min_len || pos + len > data_size;
    };
    if (is_invalid_bitstring_length(bs_len, 33, pos, der.size())) {
        return std::nullopt;
    }

    // Unused bits = 0
    if (pos >= der.size() || der[pos] != 0x00) {
        return std::nullopt;
    }
    ++pos;

    // Extract 32-byte public key
    if (pos + 32 > der.size()) {
        return std::nullopt;
    }

    Ed25519PublicKey pk{};
    span_copy(span(pk.data).first<32>(), der.subspan(pos, 32));
    return pk;
}

//
// Ed25519 PKCS#8 export
//

auto pkcs8_export_ed25519(span<uint8_t const, 32> seed) -> std::array<uint8_t, pkcs8_ed25519_der_size>
{
    std::array<uint8_t, pkcs8_ed25519_der_size> der{};
    span_copy(
        span(der).first(sizeof(pkcs8_ed25519_prefix)), span<uint8_t const>(pkcs8_ed25519_prefix, sizeof(pkcs8_ed25519_prefix)));
    span_copy(span(der).subspan(sizeof(pkcs8_ed25519_prefix), 32), span<uint8_t const, 32>(seed));
    return der;
}

//
// Ed25519 PKCS#8 import
//

auto pkcs8_import_ed25519(span<uint8_t const> der) -> std::optional<Ed25519PrivateKey>
{
    if (der.size() < pkcs8_ed25519_der_size) {
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

    // AlgorithmIdentifier (7 bytes exact match)
    if (pos + sizeof(ed25519_algorithm_id) > der.size()) {
        return std::nullopt;
    }
    if (!span_compare(der.subspan(pos, sizeof(ed25519_algorithm_id)), ed25519_algorithm_id)) {
        return std::nullopt;
    }
    pos += sizeof(ed25519_algorithm_id);

    // Outer OCTET STRING (wrapping CurvePrivateKey)
    if (pos >= der.size() || der[pos] != 0x04) {
        return std::nullopt;
    }
    ++pos;
    auto outer_octet_len = der_read_length(der, pos);
    if (outer_octet_len == SIZE_MAX || pos + outer_octet_len > der.size()) {
        return std::nullopt;
    }

    // Inner OCTET STRING (the actual 32-byte seed)
    if (pos >= der.size() || der[pos] != 0x04) {
        return std::nullopt;
    }
    ++pos;
    auto seed_len = der_read_length(der, pos);
    if (seed_len != 32 || pos + 32 > der.size()) {
        return std::nullopt;
    }

    // Extract seed and generate keypair (SecureArray zeroes on destruction)
    SecureArray<32> seed{};
    span_copy(seed, der.subspan(pos, 32));

    auto sk = ed25519_keypair_from_seed(seed);
    return sk;
}

}  // namespace statusbar::crypto
