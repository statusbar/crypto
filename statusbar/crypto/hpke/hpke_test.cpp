// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// RFC 9180 HPKE against the CFRG test vectors (hpke_vectors.hpp): key derivation,
// sender and recipient setup, encryptions at the RFC's sequence numbers and the
// exports, for DHKEM(P-256, HKDF-SHA256) and DHKEM(X25519, HKDF-SHA256) with
// HKDF-SHA256 and AES-128-GCM or AES-256-GCM in all four modes; then the
// behaviour the vectors do not cover.

#include "statusbar/crypto/hpke/hpke.hpp"

#include "statusbar/crypto/25519/x25519.hpp"
#include "statusbar/crypto/hpke/hpke_vectors.hpp"
#include "statusbar/crypto/p256/p256_ecdsa.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <print>
#include <string>
#include <string_view>
#include <vector>

using namespace statusbar::crypto;
using namespace statusbar::crypto::rfc9180;
using statusbar::crypto::internal::span_compare;
using statusbar::crypto::internal::span_copy;

namespace {

auto from_hex(std::string_view hex) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(std::stoul(std::string(hex.substr(2 * i, 2)), nullptr, 16));
    }
    return out;
}

template <size_t N>
auto fixed(std::string_view hex) -> std::array<uint8_t, N>
{
    std::array<uint8_t, N> out{};
    span_copy(std::span<uint8_t>(out), std::span<uint8_t const>(from_hex(hex)).first(N));
    return out;
}

auto aead_of(Vector const& v) -> HpkeAead
{
    return static_cast<HpkeAead>(v.aead_id);
}

// The two KEMs as the vectors see them: how a published private scalar and
// public key are turned into the module's key types, and back.
struct P256T
{
    static constexpr uint16_t kem_id = 0x0010;
    static constexpr size_t npk = hpke_p256_public_key_size;
    static auto private_key(std::string_view skm_hex) -> P256PrivateKey
    {
        return p256_keypair_from_scalar(fixed<hpke_p256_private_key_size>(skm_hex)).value();
    }
    static auto public_key(std::string_view pkm_hex) -> P256PublicKey
    {
        return hpke_p256_deserialize_public_key(fixed<npk>(pkm_hex)).value();
    }
    static auto derive(std::span<uint8_t const> ikm) { return hpke_p256_derive_key_pair(ikm); }
    static auto serialize(P256PublicKey const& pk) { return hpke_p256_serialize_public_key(pk); }
};

struct X25519T
{
    static constexpr uint16_t kem_id = 0x0020;
    static constexpr size_t npk = hpke_x25519_public_key_size;
    static auto private_key(std::string_view skm_hex) -> X25519PrivateKey
    {
        return x25519_keypair_from_seed(fixed<hpke_x25519_private_key_size>(skm_hex));
    }
    static auto public_key(std::string_view pkm_hex) -> X25519PublicKey
    {
        return hpke_x25519_deserialize_public_key(fixed<npk>(pkm_hex));
    }
    static auto derive(std::span<uint8_t const> ikm) { return hpke_x25519_derive_key_pair(ikm); }
    static auto serialize(X25519PublicKey const& pk) { return hpke_x25519_serialize_public_key(pk); }
};

auto has_psk(Vector const& v) -> bool
{
    return v.mode == 1 || v.mode == 3;
}

auto has_sender_key(Vector const& v) -> bool
{
    return v.mode == 2 || v.mode == 3;
}

// The vector's SetupXS with the public inputs read from it.
template <class K>
auto setup_s(Vector const& v) -> std::optional<HpkeSenderSetup<K::npk>>
{
    auto const pk_r = K::public_key(v.pkRm);
    auto const info = from_hex(v.info);
    auto const psk = from_hex(v.psk);
    auto const psk_id = from_hex(v.psk_id);
    auto const ikm_e = from_hex(v.ikmE);
    switch (v.mode) {  // NOLINT(statusbar-block-statements) one case per RFC 9180 mode
        case 0:
            return hpke_setup_base_s(aead_of(v), pk_r, info, ikm_e);
        case 1:
            return hpke_setup_psk_s(aead_of(v), pk_r, info, psk, psk_id, ikm_e);
        case 2:
            return hpke_setup_auth_s(aead_of(v), pk_r, info, K::private_key(v.skSm), ikm_e);
        default:
            return hpke_setup_auth_psk_s(aead_of(v), pk_r, info, psk, psk_id, K::private_key(v.skSm), ikm_e);
    }
}

// The vector's SetupXR with the enc it publishes.
template <class K>
auto setup_r(Vector const& v) -> std::optional<HpkeContext>
{
    auto const enc = fixed<K::npk>(v.enc);
    auto const sk_r = K::private_key(v.skRm);
    auto const info = from_hex(v.info);
    auto const psk = from_hex(v.psk);
    auto const psk_id = from_hex(v.psk_id);
    switch (v.mode) {  // NOLINT(statusbar-block-statements) one case per RFC 9180 mode
        case 0:
            return hpke_setup_base_r(aead_of(v), enc, sk_r, info);
        case 1:
            return hpke_setup_psk_r(aead_of(v), enc, sk_r, info, psk, psk_id);
        case 2:
            return hpke_setup_auth_r(aead_of(v), enc, sk_r, info, K::public_key(v.pkSm));
        default:
            return hpke_setup_auth_psk_r(aead_of(v), enc, sk_r, info, psk, psk_id, K::public_key(v.pkSm));
    }
}

auto context_matches(HpkeContext const& ctx, Vector const& v) -> bool
{
    auto const key = from_hex(v.key);
    bool ok = key.size() == hpke_aead_key_size(ctx.aead) && static_cast<uint16_t>(ctx.kem) == v.kem_id;
    ok = ok && span_compare(std::span<uint8_t const>(ctx.key).first(key.size()), std::span<uint8_t const>(key));
    ok = ok && span_compare(std::span<uint8_t const>(ctx.base_nonce), std::span<uint8_t const>(from_hex(v.base_nonce)));
    return ok && span_compare(std::span<uint8_t const>(ctx.exporter_secret), std::span<uint8_t const>(from_hex(v.exporter_secret)));
}

// DeriveKeyPair(ikm) reproduces the vector's (skXm, pkXm).
template <class K>
auto key_pair_matches(std::string_view ikm_hex, std::string_view skm_hex, std::string_view pkm_hex) -> bool
{
    auto const kp = K::derive(from_hex(ikm_hex));
    bool ok = kp.has_value();
    ok = ok && span_compare(std::span<uint8_t const>(kp->data), std::span<uint8_t const>(from_hex(skm_hex)));
    return ok && span_compare(std::span<uint8_t const>(K::serialize(kp->public_key)), std::span<uint8_t const>(from_hex(pkm_hex)));
}

template <class K>
auto key_pairs_match(Vector const& v) -> bool
{
    bool ok = key_pair_matches<K>(v.ikmE, v.skEm, v.pkEm) && key_pair_matches<K>(v.ikmR, v.skRm, v.pkRm);
    return ok && (!has_sender_key(v) || key_pair_matches<K>(v.ikmS, v.skSm, v.pkSm));
}

auto seal_and_open_match(HpkeContext& sender, HpkeContext& recipient, Encryption const& e) -> bool
{
    auto const aad = from_hex(e.aad);
    auto buffer = from_hex(e.pt);
    auto const tag = hpke_seal(sender, aad, buffer);
    auto expected = from_hex(e.ct);
    std::vector<uint8_t> const expected_tag(expected.end() - static_cast<std::ptrdiff_t>(hpke_tag_size), expected.end());
    expected.resize(expected.size() - hpke_tag_size);
    bool ok = tag.has_value() && buffer == expected &&
        span_compare(std::span<uint8_t const>(*tag), std::span<uint8_t const>(expected_tag));
    ok = ok && hpke_open(recipient, aad, buffer, *tag) && buffer == from_hex(e.pt);
    return ok && sender.seq == e.seq + 1 && recipient.seq == e.seq + 1;
}

// Seal at e.seq reproduces e.ct (ciphertext || tag) and Open at e.seq recovers e.pt.
template <class K>
auto encryption_matches(Vector const& v, Encryption const& e) -> bool
{
    auto sender = setup_s<K>(v);
    auto recipient = setup_r<K>(v);
    if (!sender || !recipient) {
        return false;
    }
    sender->context.seq = e.seq;
    recipient->seq = e.seq;
    return seal_and_open_match(sender->context, *recipient, e);
}

auto export_matches(HpkeContext const& ctx, Export const& x) -> bool
{
    std::vector<uint8_t> out(x.length);
    return hpke_export(ctx, from_hex(x.exporter_context), out) && out == from_hex(x.exported_value);
}

// One vector's five checks for the KEM K; the TESTs below pick K by the vector's kem_id.
template <class K>
struct Check
{
    static auto derive(Vector const& v) -> bool { return key_pairs_match<K>(v); }
    static auto sender(Vector const& v) -> bool
    {
        auto const s = setup_s<K>(v);
        return s && span_compare(std::span<uint8_t const>(s->enc), std::span<uint8_t const>(from_hex(v.enc))) &&
            context_matches(s->context, v);
    }
    static auto recipient(Vector const& v) -> bool
    {
        auto const r = setup_r<K>(v);
        return r && context_matches(*r, v);
    }
    static auto encryptions(Vector const& v) -> bool
    {
        bool ok = true;
        for (auto const& e : v.encryptions) {
            ok = ok && encryption_matches<K>(v, e);
        }
        return ok;
    }
    static auto exports(Vector const& v) -> bool
    {
        auto const r = setup_r<K>(v);
        bool ok = r.has_value();
        for (auto const& x : v.exports) {
            ok = ok && export_matches(*r, x);
        }
        return ok;
    }
};

auto is_p256(Vector const& v) -> bool
{
    return v.kem_id == P256T::kem_id;
}

auto report(Vector const& v, std::string_view what) -> bool
{
    std::println("  RFC 9180 vector kem 0x{:04x} mode {} aead 0x{:04x}: {} disagrees", v.kem_id, v.mode, v.aead_id, what);
    return false;
}

// Behaviour fixtures: a recipient and a sender key pair and a base-mode setup.
auto recipient_key() -> P256PrivateKey
{
    std::array<uint8_t, 32> ikm{};
    ikm.fill(0x52);
    return hpke_p256_derive_key_pair(ikm).value();
}

constexpr std::array<uint8_t, 32> fixed_ikm_e{0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
                                              0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
                                              0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45};
constexpr std::array<uint8_t, 32> fixed_psk{0x50, 0x53, 0x4B, 0x50, 0x53, 0x4B, 0x50, 0x53, 0x4B, 0x50, 0x53,
                                            0x4B, 0x50, 0x53, 0x4B, 0x50, 0x53, 0x4B, 0x50, 0x53, 0x4B, 0x50,
                                            0x53, 0x4B, 0x50, 0x53, 0x4B, 0x50, 0x53, 0x4B, 0x50, 0x53};
constexpr std::array<uint8_t, 4> fixed_psk_id{'i', 'd', '0', '1'};
constexpr std::array<uint8_t, 5> fixed_aad{'a', 'd', 'a', 't', 'a'};

}  // namespace

TEST(hpke, rfc9180_vector_grid_is_both_kems)
{
    size_t p256 = 0;
    size_t x25519 = 0;
    for (auto const& v : vectors) {
        p256 += is_p256(v) ? 1 : 0;
        x25519 += v.kem_id == X25519T::kem_id ? 1 : 0;
    }
    EXPECT_EQ(p256, size_t{8});
    EXPECT_EQ(x25519, size_t{8});
}

TEST(hpke, rfc9180_derive_key_pair)
{
    for (auto const& v : vectors) {
        EXPECT_TRUE((is_p256(v) ? Check<P256T>::derive(v) : Check<X25519T>::derive(v)) || report(v, "DeriveKeyPair"));
    }
}

TEST(hpke, rfc9180_setup_sender)
{
    for (auto const& v : vectors) {
        EXPECT_TRUE((is_p256(v) ? Check<P256T>::sender(v) : Check<X25519T>::sender(v)) || report(v, "SetupS"));
    }
}

TEST(hpke, rfc9180_setup_recipient)
{
    for (auto const& v : vectors) {
        EXPECT_TRUE((is_p256(v) ? Check<P256T>::recipient(v) : Check<X25519T>::recipient(v)) || report(v, "SetupR"));
    }
}

TEST(hpke, rfc9180_encryptions)
{
    for (auto const& v : vectors) {
        EXPECT_TRUE((is_p256(v) ? Check<P256T>::encryptions(v) : Check<X25519T>::encryptions(v)) || report(v, "encryption"));
    }
}

TEST(hpke, rfc9180_exports)
{
    for (auto const& v : vectors) {
        EXPECT_TRUE((is_p256(v) ? Check<P256T>::exports(v) : Check<X25519T>::exports(v)) || report(v, "export"));
    }
}

TEST(hpke, open_rejects_tampering_and_keeps_seq)
{
    auto const sk_r = recipient_key();
    auto sender = hpke_setup_base_s(HpkeAead::aes256_gcm, sk_r.public_key, {}, fixed_ikm_e);
    auto recipient = hpke_setup_base_r(HpkeAead::aes256_gcm, sender->enc, sk_r, {});
    std::vector<uint8_t> buffer{1, 2, 3, 4, 5, 6, 7};
    auto const tag = hpke_seal(sender->context, fixed_aad, buffer).value();
    auto const ciphertext = buffer;

    buffer[3] ^= 0x10;
    EXPECT_FALSE(hpke_open(*recipient, fixed_aad, buffer, tag));
    EXPECT_EQ(recipient->seq, uint64_t{0});
    buffer = ciphertext;
    EXPECT_FALSE(hpke_open(*recipient, {}, buffer, tag));  // wrong aad
    buffer = ciphertext;
    EXPECT_TRUE(hpke_open(*recipient, fixed_aad, buffer, tag));
    EXPECT_EQ(recipient->seq, uint64_t{1});
    EXPECT_TRUE((buffer == std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7}));
}

TEST(hpke, wrong_psk_or_sender_key_breaks_the_context)
{
    auto const sk_r = recipient_key();
    auto const sk_s = hpke_p256_derive_key_pair(fixed_psk).value();  // any second key pair
    std::vector<uint8_t> buffer{9, 9, 9, 9};

    auto psk_sender = hpke_setup_psk_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, fixed_psk, fixed_psk_id, fixed_ikm_e);
    auto other_psk = fixed_psk;
    other_psk[0] ^= 0x01;
    auto psk_recipient = hpke_setup_psk_r(HpkeAead::aes128_gcm, psk_sender->enc, sk_r, {}, other_psk, fixed_psk_id);
    auto tag = hpke_seal(psk_sender->context, {}, buffer).value();
    EXPECT_FALSE(hpke_open(*psk_recipient, {}, buffer, tag));

    buffer = {9, 9, 9, 9};
    auto auth_sender = hpke_setup_auth_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, sk_s, fixed_ikm_e);
    auto auth_recipient = hpke_setup_auth_r(HpkeAead::aes128_gcm, auth_sender->enc, sk_r, {}, sk_r.public_key);  // not sk_s
    tag = hpke_seal(auth_sender->context, {}, buffer).value();
    EXPECT_FALSE(hpke_open(*auth_recipient, {}, buffer, tag));
}

TEST(hpke, psk_inputs_are_validated)
{
    auto const sk_r = recipient_key();
    std::array<uint8_t, 31> short_psk{};
    short_psk.fill(0x11);
    EXPECT_FALSE(hpke_setup_psk_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, fixed_psk, {}, fixed_ikm_e).has_value());
    EXPECT_FALSE(hpke_setup_psk_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, {}, fixed_psk_id, fixed_ikm_e).has_value());
    EXPECT_FALSE(hpke_setup_psk_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, short_psk, fixed_psk_id, fixed_ikm_e).has_value());
    EXPECT_TRUE(hpke_setup_psk_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, fixed_psk, fixed_psk_id, fixed_ikm_e).has_value());
}

TEST(hpke, malformed_enc_and_short_ikm_are_rejected)
{
    auto const sk_r = recipient_key();
    auto sender = hpke_setup_base_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, fixed_ikm_e);
    auto enc = sender->enc;
    enc[0] = 0x05;
    EXPECT_FALSE(hpke_setup_base_r(HpkeAead::aes128_gcm, enc, sk_r, {}).has_value());
    enc = sender->enc;
    enc[64] ^= 0x01;  // y off the curve
    EXPECT_FALSE(hpke_setup_base_r(HpkeAead::aes128_gcm, enc, sk_r, {}).has_value());
    EXPECT_FALSE(hpke_p256_derive_key_pair(std::span<uint8_t const>(fixed_ikm_e).first(31)).has_value());
    EXPECT_FALSE(hpke_x25519_derive_key_pair(std::span<uint8_t const>(fixed_ikm_e).first(31)).has_value());
}

TEST(hpke, x25519_round_trip_and_small_order_enc)
{
    auto const sk_r = hpke_x25519_derive_key_pair(fixed_psk).value();
    auto sender = hpke_setup_base_s(HpkeAead::aes256_gcm, sk_r.public_key, fixed_aad, fixed_ikm_e);
    auto recipient = hpke_setup_base_r(HpkeAead::aes256_gcm, sender->enc, sk_r, fixed_aad);
    EXPECT_TRUE(sender.has_value() && recipient.has_value());
    EXPECT_TRUE(sender->context.kem == HpkeKem::x25519 && recipient->kem == HpkeKem::x25519);
    EXPECT_TRUE(span_compare(std::span<uint8_t const>(sender->enc), std::span<uint8_t const>(sender->context.key)) == false);

    std::vector<uint8_t> buffer{0x10, 0x11, 0x12};
    auto const tag = hpke_seal(sender->context, fixed_aad, buffer).value();
    EXPECT_TRUE(hpke_open(*recipient, fixed_aad, buffer, tag));
    EXPECT_TRUE((buffer == std::vector<uint8_t>{0x10, 0x11, 0x12}));

    std::vector<uint8_t> from_sender(32);
    std::vector<uint8_t> from_recipient(32);
    EXPECT_TRUE(hpke_export(sender->context, fixed_aad, from_sender) && hpke_export(*recipient, fixed_aad, from_recipient));
    EXPECT_TRUE(from_sender == from_recipient);

    // RFC 7748 small-order u = 0: DH is all zeros, which 7.1.4 makes a setup failure.
    std::array<uint8_t, hpke_x25519_public_key_size> const zero_enc{};
    EXPECT_FALSE(hpke_setup_base_r(HpkeAead::aes256_gcm, zero_enc, sk_r, fixed_aad).has_value());
    EXPECT_FALSE(
        hpke_setup_base_s(HpkeAead::aes256_gcm, hpke_x25519_deserialize_public_key(zero_enc), {}, fixed_ikm_e).has_value());
}

TEST(hpke, the_two_kems_do_not_mix)
{
    // The same ikm derives different keys per KEM, and a context from one KEM
    // exports differently from the other's: the suite id carries the KEM.
    auto const p256 = hpke_p256_derive_key_pair(fixed_psk).value();
    auto const x25519 = hpke_x25519_derive_key_pair(fixed_psk).value();
    auto a = hpke_setup_base_s(HpkeAead::aes256_gcm, p256.public_key, {}, fixed_ikm_e);
    auto b = hpke_setup_base_s(HpkeAead::aes256_gcm, x25519.public_key, {}, fixed_ikm_e);
    EXPECT_TRUE(a->context.kem == HpkeKem::p256 && b->context.kem == HpkeKem::x25519);
    EXPECT_FALSE(span_compare(std::span<uint8_t const>(a->context.key), std::span<uint8_t const>(b->context.key)));
    EXPECT_EQ(hpke_kem_public_key_size(HpkeKem::p256), size_t{65});
    EXPECT_EQ(hpke_kem_public_key_size(HpkeKem::x25519), size_t{32});
}

TEST(hpke, export_limits_and_long_info)
{
    auto const sk_r = recipient_key();
    std::vector<uint8_t> const info(1000, 0xAB);  // info is hashed, so far beyond the HKDF info buffer
    auto sender = hpke_setup_base_s(HpkeAead::aes256_gcm, sk_r.public_key, info, fixed_ikm_e);
    auto recipient = hpke_setup_base_r(HpkeAead::aes256_gcm, sender->enc, sk_r, info);
    EXPECT_TRUE(sender.has_value() && recipient.has_value());

    std::vector<uint8_t> from_sender(64);
    std::vector<uint8_t> from_recipient(64);
    EXPECT_TRUE(hpke_export(sender->context, fixed_aad, from_sender));
    EXPECT_TRUE(hpke_export(*recipient, fixed_aad, from_recipient));
    EXPECT_TRUE(from_sender == from_recipient);

    std::vector<uint8_t> const too_long_context(hpke_max_exporter_context_size + 1, 0x01);
    std::vector<uint8_t> const max_context(hpke_max_exporter_context_size, 0x01);
    std::vector<uint8_t> too_much(hpke_max_export_size + 1);
    EXPECT_FALSE(hpke_export(*recipient, too_long_context, from_recipient));
    EXPECT_TRUE(hpke_export(*recipient, max_context, from_recipient));
    EXPECT_FALSE(hpke_export(*recipient, {}, too_much));
    EXPECT_FALSE(hpke_export(*recipient, {}, {}));
}

TEST(hpke, sequence_limit)
{
    auto const sk_r = recipient_key();
    auto sender = hpke_setup_base_s(HpkeAead::aes128_gcm, sk_r.public_key, {}, fixed_ikm_e);
    std::vector<uint8_t> buffer{1};
    sender->context.seq = UINT64_MAX;
    EXPECT_FALSE(hpke_seal(sender->context, {}, buffer).has_value());
    EXPECT_EQ(buffer[0], uint8_t{1});
}

//

TEST_MAIN(statusbar_crypto_hpke, hpke_test)
