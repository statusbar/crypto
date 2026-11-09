// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file hpke.cpp
/// @brief RFC 9180 HPKE: DHKEM(P-256, HKDF-SHA256) and DHKEM(X25519, HKDF-SHA256),
/// the HKDF-SHA256 key schedule and the AES-GCM context operations.
///
/// Section numbers below are RFC 9180's. The two KEMs are a trait each (key
/// types, id, Npk, DH, (de)serialisation, DeriveKeyPair); Encap, Decap and the
/// setups are templates over the trait, and the key schedule and context
/// operations are shared. LabeledExtract is computed directly as
/// HMAC-SHA-256(salt, "HPKE-v1" || suite_id || label, ikm) through the two-part
/// HMAC, so info and psk_id are not size-limited; LabeledExpand goes through the
/// HKDF module and inherits its 256-byte info buffer, which bounds only an
/// exporter_context (hpke_max_exporter_context_size).

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/x25519.hpp"
#    include "statusbar/crypto/aes_gcm/aes128_gcm.hpp"
#    include "statusbar/crypto/aes_gcm/aes256_gcm.hpp"
#    include "statusbar/crypto/hkdf/hkdf.hpp"
#    include "statusbar/crypto/hpke/hpke.hpp"
#    include "statusbar/crypto/p256/p256.hpp"
#    include "statusbar/crypto/p256/p256_ecdh.hpp"
#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
#    include "statusbar/crypto/sha/sha256_hw.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

#    include <algorithm>
#    include <string_view>

namespace statusbar::crypto {

using namespace internal;
using std::span;

namespace {

using Prk = SecureArray<hpke_hash_size>;
using SharedSecret = SecureArray<hpke_shared_secret_size>;

constexpr std::string_view version_label = "HPKE-v1";
constexpr size_t suite_id_size = 10;   // "HPKE" || kem_id || kdf_id || aead_id; the KEM's "KEM" || kem_id is shorter
constexpr size_t max_label_size = 13;  // "shared_secret"
// LabeledExpand info is I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info; an
// exporter_context plus the "sec" labelling must fit the HKDF module's info buffer.
static_assert(hpke_max_exporter_context_size + 2 + version_label.size() + suite_id_size + 3 <= hkdf_sha256_max_info_size);

void put_u16(span<uint8_t, 2> out, uint16_t const value)
{
    out[0] = static_cast<uint8_t>(value >> 8U);
    out[1] = static_cast<uint8_t>(value & 0xFFU);
}

// suite_id for the KEM (7.1): "KEM" || I2OSP(kem_id, 2)
auto kem_suite_id(HpkeKem const kem) -> std::array<uint8_t, 5>
{
    std::array<uint8_t, 5> id{'K', 'E', 'M'};
    put_u16(span(id).last<2>(), static_cast<uint16_t>(kem));
    return id;
}

// suite_id for the key schedule (5.1): "HPKE" || kem_id || kdf_id || aead_id
auto hpke_suite_id(HpkeKem const kem, HpkeAead const aead) -> std::array<uint8_t, suite_id_size>
{
    std::array<uint8_t, suite_id_size> id{'H', 'P', 'K', 'E'};
    put_u16(span(id).subspan<4, 2>(), static_cast<uint16_t>(kem));
    put_u16(span(id).subspan<6, 2>(), hpke_kdf_id);
    put_u16(span(id).subspan<8, 2>(), static_cast<uint16_t>(aead));
    return id;
}

// A growable fixed-capacity byte string for the labelled inputs.
template <size_t Capacity>
struct Bytes
{
    std::array<uint8_t, Capacity> data{};
    size_t size{0};

    auto append(span<uint8_t const> const more) -> Bytes&
    {
        span_copy(span(data).subspan(size, more.size()), more);
        size += more.size();
        return *this;
    }

    auto append(std::string_view const text) -> Bytes&
    {
        return append(span<uint8_t const>(reinterpret_cast<uint8_t const*>(text.data()), text.size()));
    }

    [[nodiscard]] auto view() const -> span<uint8_t const> { return span<uint8_t const>(data).first(size); }
};

// LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm) (4),
// Extract being HMAC-SHA-256 keyed with the salt (32 zero bytes when empty).
auto labeled_extract(span<uint8_t const> suite_id, span<uint8_t const> salt, std::string_view label, span<uint8_t const> ikm) -> Prk
{
    Bytes<version_label.size() + suite_id_size + max_label_size> prefix{};
    prefix.append(version_label).append(suite_id).append(label);
    std::array<uint8_t, hpke_hash_size> const zero_salt{};
    return Prk{sha256_hmac_hw(salt.empty() ? span<uint8_t const>(zero_salt) : salt, prefix.view(), ikm)};
}

// LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L) (4)
auto labeled_expand(
    span<uint8_t const> suite_id, Prk const& prk, std::string_view label, span<uint8_t const> info, span<uint8_t> out) -> bool
{
    if (2 + version_label.size() + suite_id.size() + label.size() + info.size() > hkdf_sha256_max_info_size) {
        return false;
    }
    Bytes<hkdf_sha256_max_info_size> labeled{};
    put_u16(span(labeled.data).first<2>(), static_cast<uint16_t>(out.size()));
    labeled.size = 2;
    labeled.append(version_label).append(suite_id).append(label).append(info);
    return hkdf_sha256_expand(make_const_span(prk), labeled.view(), out);
}

// ---- The two DHKEMs (7.1) ----------------------------------------------------------------
//
// Each KEM is a trait: key types, RFC id and Npk, DH (with the 7.1.4 all-zero
// check), SerializePublicKey / DeserializePublicKey (7.1.1) and DeriveKeyPair
// (7.1.3). Encap, Decap and the setups below are templates over it.

auto is_all_zero(span<uint8_t const, hpke_shared_secret_size> bytes) -> bool
{
    std::array<uint8_t, hpke_shared_secret_size> const zero{};
    return span_compare(bytes, span<uint8_t const>(zero));
}

struct P256Kem
{
    using PrivateKey = P256PrivateKey;
    using PublicKey = P256PublicKey;
    static constexpr HpkeKem id = HpkeKem::p256;
    static constexpr size_t npk = hpke_p256_public_key_size;

    // DH(sk, pk): the x-coordinate of sk * pk. The P-256 module returns all zeros on
    // an invalid point or the identity, which HPKE must treat as a failure.
    static auto dh(PrivateKey const& sk, PublicKey const& pk) -> std::optional<SharedSecret>
    {
        auto const z = p256_ecdh(sk, pk);
        return is_all_zero(z) ? std::nullopt : std::optional{SharedSecret{z}};
    }
    static auto serialize(PublicKey const& pk) { return hpke_p256_serialize_public_key(pk); }
    static auto deserialize(span<uint8_t const, npk> enc) { return hpke_p256_deserialize_public_key(enc); }
    static auto derive_key_pair(span<uint8_t const> ikm) { return hpke_p256_derive_key_pair(ikm); }
};

struct X25519Kem
{
    using PrivateKey = X25519PrivateKey;
    using PublicKey = X25519PublicKey;
    static constexpr HpkeKem id = HpkeKem::x25519;
    static constexpr size_t npk = hpke_x25519_public_key_size;

    // DH(sk, pk) = X25519(sk, pk); an all-zero result (a small-order pk) is a failure (7.1.4).
    static auto dh(PrivateKey const& sk, PublicKey const& pk) -> std::optional<SharedSecret>
    {
        auto const z = x25519(sk, pk);
        return x25519_shared_secret_is_valid(z) ? std::optional{SharedSecret{z}} : std::nullopt;
    }
    static auto serialize(PublicKey const& pk) { return hpke_x25519_serialize_public_key(pk); }
    static auto deserialize(span<uint8_t const, npk> enc) -> std::optional<PublicKey>
    {
        return hpke_x25519_deserialize_public_key(enc);
    }
    static auto derive_key_pair(span<uint8_t const> ikm) { return hpke_x25519_derive_key_pair(ikm); }
};

// DH(sk, DeserializePublicKey(enc)), failing on a malformed enc
template <class Kem>
auto dh_with_encoded(typename Kem::PrivateKey const& sk, span<uint8_t const, Kem::npk> enc) -> std::optional<SharedSecret>
{
    auto const pk = Kem::deserialize(enc);
    return pk ? Kem::dh(sk, *pk) : std::nullopt;
}

// ExtractAndExpand(dh, kem_context) (7.1.1)
auto extract_and_expand(HpkeKem const kem, span<uint8_t const> dh_bytes, span<uint8_t const> kem_context)
    -> std::optional<SharedSecret>
{
    auto const suite = kem_suite_id(kem);
    auto const eae_prk = labeled_extract(suite, {}, "eae_prk", dh_bytes);
    SharedSecret shared_secret{};
    if (!labeled_expand(suite, eae_prk, "shared_secret", kem_context, shared_secret)) {
        return std::nullopt;
    }
    return shared_secret;
}

// The DH outputs and kem_context of Encap / AuthEncap / Decap / AuthDecap: one or two DH
// values, enc || pkRm [|| pkSm]. AuthEncap(pkR, skS) and AuthDecap(enc, skR, pkS) both add
// DH with the sender's static key as the second value.
template <class Kem>
struct KemInputs
{
    Bytes<2 * hpke_shared_secret_size> dh{};
    Bytes<3 * Kem::npk> kem_context{};
};

// Shared tail of Encap / Decap: the second DH for the auth modes, then ExtractAndExpand.
template <class Kem>
auto finish_kem(KemInputs<Kem>& inputs, std::optional<SharedSecret> const& auth_dh, typename Kem::PublicKey const* pk_s)
    -> std::optional<SharedSecret>
{
    if (pk_s != nullptr) {
        if (!auth_dh) {
            return std::nullopt;
        }
        inputs.dh.append(make_const_span(*auth_dh));
        inputs.kem_context.append(Kem::serialize(*pk_s));
    }
    return extract_and_expand(Kem::id, inputs.dh.view(), inputs.kem_context.view());
}

// Encap(pkR) (7.1.1) and AuthEncap(pkR, skS) (7.1.2) with the ephemeral key already derived.
template <class Kem>
auto encap(typename Kem::PrivateKey const& sk_e, typename Kem::PublicKey const& pk_r, typename Kem::PrivateKey const* sk_s)
    -> std::optional<SharedSecret>
{
    auto const ephemeral_dh = Kem::dh(sk_e, pk_r);
    if (!ephemeral_dh) {
        return std::nullopt;
    }
    KemInputs<Kem> inputs{};
    inputs.dh.append(make_const_span(*ephemeral_dh));
    inputs.kem_context.append(Kem::serialize(sk_e.public_key)).append(Kem::serialize(pk_r));
    return finish_kem<Kem>(
        inputs, sk_s != nullptr ? Kem::dh(*sk_s, pk_r) : std::nullopt, sk_s != nullptr ? &sk_s->public_key : nullptr);
}

// Decap(enc, skR) (7.1.1) and AuthDecap(enc, skR, pkS) (7.1.2)
template <class Kem>
auto decap(span<uint8_t const, Kem::npk> enc, typename Kem::PrivateKey const& sk_r, typename Kem::PublicKey const* pk_s)
    -> std::optional<SharedSecret>
{
    auto const ephemeral_dh = dh_with_encoded<Kem>(sk_r, enc);
    if (!ephemeral_dh) {
        return std::nullopt;
    }
    KemInputs<Kem> inputs{};
    inputs.dh.append(make_const_span(*ephemeral_dh));
    inputs.kem_context.append(enc).append(Kem::serialize(sk_r.public_key));
    return finish_kem<Kem>(inputs, pk_s != nullptr ? Kem::dh(sk_r, *pk_s) : std::nullopt, pk_s);
}

// ---- Key schedule (5.1) ------------------------------------------------------------------

// VerifyPSKInputs (5.1): psk and psk_id together or not at all, present exactly in the PSK
// modes, and a psk long enough to carry the required entropy.
auto psk_inputs_are_valid(HpkeMode const mode, span<uint8_t const> psk, span<uint8_t const> psk_id) -> bool
{
    bool const got_psk = !psk.empty();
    bool const psk_mode = mode == HpkeMode::psk || mode == HpkeMode::auth_psk;
    if (got_psk != !psk_id.empty() || got_psk != psk_mode) {
        return false;
    }
    return !got_psk || psk.size() >= hpke_min_psk_size;
}

// key_schedule_context = mode || psk_id_hash || info_hash (5.1)
auto key_schedule_context(span<uint8_t const> suite, HpkeMode const mode, span<uint8_t const> info, span<uint8_t const> psk_id)
    -> std::array<uint8_t, 1 + 2 * hpke_hash_size>
{
    std::array<uint8_t, 1 + 2 * hpke_hash_size> context{static_cast<uint8_t>(mode)};
    span_copy(span(context).subspan<1, hpke_hash_size>(), make_const_span(labeled_extract(suite, {}, "psk_id_hash", psk_id)));
    span_copy(span(context).last<hpke_hash_size>(), make_const_span(labeled_extract(suite, {}, "info_hash", info)));
    return context;
}

// key, base_nonce and exporter_secret from secret = LabeledExtract(shared_secret, "secret", psk) (5.1)
auto derive_context(
    span<uint8_t const> suite, HpkeKem const kem, HpkeAead const aead, Prk const& secret, span<uint8_t const> context)
    -> std::optional<HpkeContext>
{
    HpkeContext ctx{.kem = kem, .aead = aead};
    bool ok = labeled_expand(suite, secret, "key", context, span(ctx.key).first(hpke_aead_key_size(aead)));
    ok = ok && labeled_expand(suite, secret, "base_nonce", context, ctx.base_nonce);
    ok = ok && labeled_expand(suite, secret, "exp", context, ctx.exporter_secret);
    return ok ? std::optional{std::move(ctx)} : std::nullopt;
}

// KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id) (5.1)
auto key_schedule(
    HpkeKem const kem,
    HpkeMode const mode,
    HpkeAead const aead,
    std::optional<SharedSecret> const& shared_secret,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id) -> std::optional<HpkeContext>
{
    if (!shared_secret || !psk_inputs_are_valid(mode, psk, psk_id)) {
        return std::nullopt;
    }
    auto const suite = hpke_suite_id(kem, aead);
    auto const context = key_schedule_context(suite, mode, info, psk_id);
    auto const secret = labeled_extract(suite, make_const_span(*shared_secret), "secret", psk);
    return derive_context(suite, kem, aead, secret, context);
}

// SetupXS: derive the ephemeral key pair from ikm_e, Encap, KeySchedule.
template <class Kem>
auto setup_sender(
    HpkeMode const mode,
    HpkeAead const aead,
    typename Kem::PublicKey const& pk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    typename Kem::PrivateKey const* sk_s,
    span<uint8_t const> ikm_e) -> std::optional<HpkeSenderSetup<Kem::npk>>
{
    auto const sk_e = Kem::derive_key_pair(ikm_e);
    if (!sk_e) {
        return std::nullopt;
    }
    auto context = key_schedule(Kem::id, mode, aead, encap<Kem>(*sk_e, pk_r, sk_s), info, psk, psk_id);
    if (!context) {
        return std::nullopt;
    }
    return HpkeSenderSetup<Kem::npk>{Kem::serialize(sk_e->public_key), std::move(*context)};
}

// SetupXR: Decap, KeySchedule.
template <class Kem>
auto setup_recipient(
    HpkeMode const mode,
    HpkeAead const aead,
    span<uint8_t const, Kem::npk> enc,
    typename Kem::PrivateKey const& sk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    typename Kem::PublicKey const* pk_s) -> std::optional<HpkeContext>
{
    return key_schedule(Kem::id, mode, aead, decap<Kem>(enc, sk_r, pk_s), info, psk, psk_id);
}

// ---- Context operations (5.2, 5.3) ------------------------------------------------------

// ComputeNonce(seq) = base_nonce XOR I2OSP(seq, Nn) (5.2)
auto compute_nonce(HpkeContext const& ctx) -> std::array<uint8_t, hpke_nonce_size>
{
    std::array<uint8_t, hpke_nonce_size> nonce{};
    span_copy(nonce, make_const_span(ctx.base_nonce));
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        nonce[hpke_nonce_size - 1 - i] ^= static_cast<uint8_t>(ctx.seq >> (8U * i));
    }
    return nonce;
}

auto aead_seal(HpkeContext const& ctx, span<uint8_t const, hpke_nonce_size> nonce, span<uint8_t> buffer, span<uint8_t const> aad)
    -> std::array<uint8_t, hpke_tag_size>
{
    if (ctx.aead == HpkeAead::aes128_gcm) {
        Aes128Key key{};
        span_copy(key.data, span<uint8_t const>(ctx.key).first<Aes128Key::LENGTH>());
        return aes128_gcm_encrypt(key, nonce, buffer, aad);
    }
    Aes256Key key{};
    span_copy(key.data, span<uint8_t const>(ctx.key).first<Aes256Key::LENGTH>());
    return aes256_gcm_encrypt(key, nonce, buffer, aad);
}

auto aead_open(
    HpkeContext const& ctx,
    span<uint8_t const, hpke_nonce_size> nonce,
    span<uint8_t> buffer,
    span<uint8_t const, hpke_tag_size> tag,
    span<uint8_t const> aad) -> bool
{
    if (ctx.aead == HpkeAead::aes128_gcm) {
        Aes128Key key{};
        span_copy(key.data, span<uint8_t const>(ctx.key).first<Aes128Key::LENGTH>());
        return aes128_gcm_decrypt(key, nonce, buffer, tag, aad);
    }
    Aes256Key key{};
    span_copy(key.data, span<uint8_t const>(ctx.key).first<Aes256Key::LENGTH>());
    return aes256_gcm_decrypt(key, nonce, buffer, tag, aad);
}

}  // namespace

// ---- Public: DHKEM key handling ----------------------------------------------------------

auto hpke_p256_derive_key_pair(span<uint8_t const> ikm) -> std::optional<P256PrivateKey>
{
    if (ikm.size() < hpke_min_ikm_size) {
        return std::nullopt;
    }
    auto const suite = kem_suite_id(HpkeKem::p256);
    auto const dkp_prk = labeled_extract(suite, {}, "dkp_prk", ikm);
    for (uint32_t counter = 0; counter < 256; ++counter) {  // NOLINT(statusbar-block-statements) 7.1.3 rejection loop
        std::array<uint8_t, 1> const counter_byte{static_cast<uint8_t>(counter)};
        SecureArray<hpke_p256_private_key_size> candidate{};
        labeled_expand(suite, dkp_prk, "candidate", counter_byte, candidate);
        // bitmask is 0xFF for P-256: every candidate byte is kept
        if (auto key_pair = p256_keypair_from_scalar(make_const_span(candidate))) {
            return key_pair;
        }
    }
    return std::nullopt;
}

auto hpke_p256_serialize_public_key(P256PublicKey const& pk) -> std::array<uint8_t, hpke_p256_public_key_size>
{
    std::array<uint8_t, hpke_p256_public_key_size> out{0x04};
    span_copy(span(out).last<P256PublicKey::LENGTH>(), span<uint8_t const>(pk.data));
    return out;
}

auto hpke_p256_deserialize_public_key(span<uint8_t const, hpke_p256_public_key_size> encoded) -> std::optional<P256PublicKey>
{
    if (encoded[0] != 0x04 || !p256_decode_point_uncompressed(encoded.last<P256PublicKey::LENGTH>())) {
        return std::nullopt;
    }
    P256PublicKey pk{};
    span_copy(pk.data, encoded.last<P256PublicKey::LENGTH>());
    return pk;
}

auto hpke_x25519_derive_key_pair(span<uint8_t const> ikm) -> std::optional<X25519PrivateKey>
{
    if (ikm.size() < hpke_min_ikm_size) {
        return std::nullopt;
    }
    auto const suite = kem_suite_id(HpkeKem::x25519);
    auto const dkp_prk = labeled_extract(suite, {}, "dkp_prk", ikm);
    SecureArray<hpke_x25519_private_key_size> sk{};
    labeled_expand(suite, dkp_prk, "sk", {}, sk);  // Nsk = 32 always fits the info buffer
    return x25519_keypair_from_seed(make_const_span(sk));
}

auto hpke_x25519_serialize_public_key(X25519PublicKey const& pk) -> std::array<uint8_t, hpke_x25519_public_key_size>
{
    return pk.data;
}

auto hpke_x25519_deserialize_public_key(span<uint8_t const, hpke_x25519_public_key_size> encoded) -> X25519PublicKey
{
    X25519PublicKey pk{};
    span_copy(pk.data, encoded);
    return pk;
}

// ---- Public: context operations ----------------------------------------------------------

auto hpke_seal(HpkeContext& context, span<uint8_t const> aad, span<uint8_t> plaintext_to_ciphertext)
    -> std::optional<std::array<uint8_t, hpke_tag_size>>
{
    // 5.2 MessageLimitReached: seq must stay below 2^(8 * Nn) - 1; a 64-bit seq wraps far
    // sooner, so refuse the last representable value instead.
    if (context.seq == UINT64_MAX || plaintext_to_ciphertext.size() > aes_gcm_max_plaintext_size) {
        return std::nullopt;
    }
    auto const tag = aead_seal(context, compute_nonce(context), plaintext_to_ciphertext, aad);
    ++context.seq;
    return tag;
}

auto hpke_open(
    HpkeContext& context, span<uint8_t const> aad, span<uint8_t> ciphertext_to_plaintext, span<uint8_t const, hpke_tag_size> tag)
    -> bool
{
    if (context.seq == UINT64_MAX || !aead_open(context, compute_nonce(context), ciphertext_to_plaintext, tag, aad)) {
        return false;
    }
    ++context.seq;
    return true;
}

auto hpke_export(HpkeContext const& context, span<uint8_t const> exporter_context, span<uint8_t> out) -> bool
{
    if (out.empty() || out.size() > hpke_max_export_size || exporter_context.size() > hpke_max_exporter_context_size) {
        return false;
    }
    return labeled_expand(hpke_suite_id(context.kem, context.aead), context.exporter_secret, "sec", exporter_context, out);
}

// ---- Public: setup, DHKEM(P-256, HKDF-SHA256) --------------------------------------------

auto hpke_setup_base_s(HpkeAead const aead, P256PublicKey const& pk_r, span<uint8_t const> info, span<uint8_t const> ikm_e)
    -> std::optional<HpkeP256SenderSetup>
{
    return setup_sender<P256Kem>(HpkeMode::base, aead, pk_r, info, {}, {}, nullptr, ikm_e);
}

auto hpke_setup_base_r(
    HpkeAead const aead, span<uint8_t const, hpke_p256_public_key_size> enc, P256PrivateKey const& sk_r, span<uint8_t const> info)
    -> std::optional<HpkeContext>
{
    return setup_recipient<P256Kem>(HpkeMode::base, aead, enc, sk_r, info, {}, {}, nullptr);
}

auto hpke_setup_psk_s(
    HpkeAead const aead,
    P256PublicKey const& pk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    span<uint8_t const> ikm_e) -> std::optional<HpkeP256SenderSetup>
{
    return setup_sender<P256Kem>(HpkeMode::psk, aead, pk_r, info, psk, psk_id, nullptr, ikm_e);
}

auto hpke_setup_psk_r(
    HpkeAead const aead,
    span<uint8_t const, hpke_p256_public_key_size> enc,
    P256PrivateKey const& sk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id) -> std::optional<HpkeContext>
{
    return setup_recipient<P256Kem>(HpkeMode::psk, aead, enc, sk_r, info, psk, psk_id, nullptr);
}

auto hpke_setup_auth_s(
    HpkeAead const aead, P256PublicKey const& pk_r, span<uint8_t const> info, P256PrivateKey const& sk_s, span<uint8_t const> ikm_e)
    -> std::optional<HpkeP256SenderSetup>
{
    return setup_sender<P256Kem>(HpkeMode::auth, aead, pk_r, info, {}, {}, &sk_s, ikm_e);
}

auto hpke_setup_auth_r(
    HpkeAead const aead,
    span<uint8_t const, hpke_p256_public_key_size> enc,
    P256PrivateKey const& sk_r,
    span<uint8_t const> info,
    P256PublicKey const& pk_s) -> std::optional<HpkeContext>
{
    return setup_recipient<P256Kem>(HpkeMode::auth, aead, enc, sk_r, info, {}, {}, &pk_s);
}

auto hpke_setup_auth_psk_s(
    HpkeAead const aead,
    P256PublicKey const& pk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    P256PrivateKey const& sk_s,
    span<uint8_t const> ikm_e) -> std::optional<HpkeP256SenderSetup>
{
    return setup_sender<P256Kem>(HpkeMode::auth_psk, aead, pk_r, info, psk, psk_id, &sk_s, ikm_e);
}

auto hpke_setup_auth_psk_r(
    HpkeAead const aead,
    span<uint8_t const, hpke_p256_public_key_size> enc,
    P256PrivateKey const& sk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    P256PublicKey const& pk_s) -> std::optional<HpkeContext>
{
    return setup_recipient<P256Kem>(HpkeMode::auth_psk, aead, enc, sk_r, info, psk, psk_id, &pk_s);
}

// ---- Public: setup, DHKEM(X25519, HKDF-SHA256) -------------------------------------------

auto hpke_setup_base_s(HpkeAead const aead, X25519PublicKey const& pk_r, span<uint8_t const> info, span<uint8_t const> ikm_e)
    -> std::optional<HpkeX25519SenderSetup>
{
    return setup_sender<X25519Kem>(HpkeMode::base, aead, pk_r, info, {}, {}, nullptr, ikm_e);
}

auto hpke_setup_base_r(
    HpkeAead const aead,
    span<uint8_t const, hpke_x25519_public_key_size> enc,
    X25519PrivateKey const& sk_r,
    span<uint8_t const> info) -> std::optional<HpkeContext>
{
    return setup_recipient<X25519Kem>(HpkeMode::base, aead, enc, sk_r, info, {}, {}, nullptr);
}

auto hpke_setup_psk_s(
    HpkeAead const aead,
    X25519PublicKey const& pk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    span<uint8_t const> ikm_e) -> std::optional<HpkeX25519SenderSetup>
{
    return setup_sender<X25519Kem>(HpkeMode::psk, aead, pk_r, info, psk, psk_id, nullptr, ikm_e);
}

auto hpke_setup_psk_r(
    HpkeAead const aead,
    span<uint8_t const, hpke_x25519_public_key_size> enc,
    X25519PrivateKey const& sk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id) -> std::optional<HpkeContext>
{
    return setup_recipient<X25519Kem>(HpkeMode::psk, aead, enc, sk_r, info, psk, psk_id, nullptr);
}

auto hpke_setup_auth_s(
    HpkeAead const aead,
    X25519PublicKey const& pk_r,
    span<uint8_t const> info,
    X25519PrivateKey const& sk_s,
    span<uint8_t const> ikm_e) -> std::optional<HpkeX25519SenderSetup>
{
    return setup_sender<X25519Kem>(HpkeMode::auth, aead, pk_r, info, {}, {}, &sk_s, ikm_e);
}

auto hpke_setup_auth_r(
    HpkeAead const aead,
    span<uint8_t const, hpke_x25519_public_key_size> enc,
    X25519PrivateKey const& sk_r,
    span<uint8_t const> info,
    X25519PublicKey const& pk_s) -> std::optional<HpkeContext>
{
    return setup_recipient<X25519Kem>(HpkeMode::auth, aead, enc, sk_r, info, {}, {}, &pk_s);
}

auto hpke_setup_auth_psk_s(
    HpkeAead const aead,
    X25519PublicKey const& pk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    X25519PrivateKey const& sk_s,
    span<uint8_t const> ikm_e) -> std::optional<HpkeX25519SenderSetup>
{
    return setup_sender<X25519Kem>(HpkeMode::auth_psk, aead, pk_r, info, psk, psk_id, &sk_s, ikm_e);
}

auto hpke_setup_auth_psk_r(
    HpkeAead const aead,
    span<uint8_t const, hpke_x25519_public_key_size> enc,
    X25519PrivateKey const& sk_r,
    span<uint8_t const> info,
    span<uint8_t const> psk,
    span<uint8_t const> psk_id,
    X25519PublicKey const& pk_s) -> std::optional<HpkeContext>
{
    return setup_recipient<X25519Kem>(HpkeMode::auth_psk, aead, enc, sk_r, info, psk, psk_id, &pk_s);
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
