// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for HPKE base mode over both KEMs: the first byte picks
// DHKEM(P-256) or DHKEM(X25519); both key pairs come from fuzz ikm; set up sender
// and recipient, round-trip one message, then reject a flipped tag bit.
#include "statusbar/crypto/hpke/hpke.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace statusbar::crypto;

namespace {

constexpr size_t fixed_prefix = 1 + 2 * hpke_min_ikm_size + 2;  // kem byte, ikm_r, ikm_e, two split bytes

void expect(bool const condition)
{
    if (!condition) {
        __builtin_trap();
    }
}

struct Split
{
    std::span<uint8_t const> ikm_r;
    std::span<uint8_t const> ikm_e;
    std::span<uint8_t const> info;
    std::span<uint8_t const> aad;
    std::span<uint8_t const> plaintext;
};

auto split(std::span<uint8_t const> all) -> Split
{
    size_t const rest = all.size() - fixed_prefix;
    size_t const info_len = rest == 0 ? 0 : all[fixed_prefix - 2] % (rest + 1);
    size_t const aad_len = rest - info_len == 0 ? 0 : all[fixed_prefix - 1] % (rest - info_len + 1);
    return Split{
        all.subspan(1, hpke_min_ikm_size),
        all.subspan(1 + hpke_min_ikm_size, hpke_min_ikm_size),
        all.subspan(fixed_prefix, info_len),
        all.subspan(fixed_prefix + info_len, aad_len),
        all.subspan(fixed_prefix + info_len + aad_len)};
}

// Seal with the sender, open with the recipient, then refuse a flipped tag bit.
void round_trip(HpkeContext& sender, HpkeContext& recipient, Split const& in)
{
    std::vector<uint8_t> buffer(in.plaintext.begin(), in.plaintext.end());
    auto const tag = hpke_seal(sender, in.aad, buffer);
    expect(tag.has_value());
    std::vector<uint8_t> const ciphertext = buffer;
    expect(hpke_open(recipient, in.aad, buffer, *tag));
    expect(buffer == std::vector<uint8_t>(in.plaintext.begin(), in.plaintext.end()));

    buffer = ciphertext;
    auto bad_tag = *tag;
    bad_tag[0] ^= 0x01;
    expect(!hpke_open(recipient, in.aad, buffer, bad_tag));
}

void fuzz_p256(Split const& in)
{
    auto const sk_r = hpke_p256_derive_key_pair(in.ikm_r);
    expect(sk_r.has_value());
    auto sender = hpke_setup_base_s(HpkeAead::aes256_gcm, sk_r->public_key, in.info, in.ikm_e);
    auto recipient = hpke_setup_base_r(HpkeAead::aes256_gcm, sender->enc, *sk_r, in.info);
    expect(sender.has_value() && recipient.has_value());
    round_trip(sender->context, *recipient, in);
}

void fuzz_x25519(Split const& in)
{
    auto const sk_r = hpke_x25519_derive_key_pair(in.ikm_r);
    expect(sk_r.has_value());
    auto sender = hpke_setup_base_s(HpkeAead::aes128_gcm, sk_r->public_key, in.info, in.ikm_e);
    auto recipient = hpke_setup_base_r(HpkeAead::aes128_gcm, sender->enc, *sk_r, in.info);
    expect(sender.has_value() && recipient.has_value());
    round_trip(sender->context, *recipient, in);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < fixed_prefix) {
        return 0;
    }
    std::span<uint8_t const> const all(data, size);
    auto const in = split(all);
    if ((all[0] & 0x01U) == 0) {
        fuzz_p256(in);
    } else {
        fuzz_x25519(in);
    }
    return 0;
}
