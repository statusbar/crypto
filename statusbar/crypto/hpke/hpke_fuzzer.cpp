// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for HPKE base mode: derive both key pairs from fuzz ikm, set
// up sender and recipient, round-trip one message, then reject a flipped tag bit.
#include "statusbar/crypto/hpke/hpke.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace statusbar::crypto;

namespace {

constexpr size_t fixed_prefix = 2 * hpke_min_ikm_size + 2;  // ikm_r, ikm_e, two split bytes

void expect(bool const condition)
{
    if (!condition) {
        __builtin_trap();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < fixed_prefix) {
        return 0;
    }
    std::span<uint8_t const> const all(data, size);
    auto const sk_r = hpke_p256_derive_key_pair(all.first(hpke_min_ikm_size));
    expect(sk_r.has_value());
    auto const ikm_e = all.subspan(hpke_min_ikm_size, hpke_min_ikm_size);
    size_t const rest = size - fixed_prefix;
    size_t const info_len = rest == 0 ? 0 : data[fixed_prefix - 2] % (rest + 1);
    size_t const aad_len = rest - info_len == 0 ? 0 : data[fixed_prefix - 1] % (rest - info_len + 1);
    auto const info = all.subspan(fixed_prefix, info_len);
    auto const aad = all.subspan(fixed_prefix + info_len, aad_len);
    auto const plaintext = all.subspan(fixed_prefix + info_len + aad_len);

    auto sender = hpke_setup_base_s(HpkeAead::aes256_gcm, sk_r->public_key, info, ikm_e);
    auto recipient = hpke_setup_base_r(HpkeAead::aes256_gcm, sender->enc, *sk_r, info);
    expect(sender.has_value() && recipient.has_value());
    std::vector<uint8_t> buffer(plaintext.begin(), plaintext.end());
    auto const tag = hpke_seal(sender->context, aad, buffer);
    expect(tag.has_value());
    std::vector<uint8_t> const ciphertext = buffer;
    expect(hpke_open(*recipient, aad, buffer, *tag));
    expect(buffer == std::vector<uint8_t>(plaintext.begin(), plaintext.end()));

    buffer = ciphertext;
    auto bad_tag = *tag;
    bad_tag[0] ^= 0x01;
    expect(!hpke_open(*recipient, aad, buffer, bad_tag));
    return 0;
}
