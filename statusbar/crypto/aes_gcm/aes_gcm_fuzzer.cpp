// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for AES-256-GCM: round trip with AAD, then rejection of a
// flipped ciphertext bit and of a dropped AAD.
#include "statusbar/crypto/aes_gcm/aes256_gcm.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_copy;

namespace {

constexpr size_t fixed_prefix = Aes256Key::LENGTH + aes_gcm_nonce_size + 1;  // key, nonce, split byte

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
    Aes256Key key{};
    span_copy(key.data, std::span<uint8_t const>(data, Aes256Key::LENGTH));
    std::array<uint8_t, aes_gcm_nonce_size> nonce{};
    span_copy(nonce, std::span<uint8_t const>(data + Aes256Key::LENGTH, aes_gcm_nonce_size));

    size_t const remaining = size - fixed_prefix;
    size_t const aad_len = remaining == 0 ? 0 : data[fixed_prefix - 1] % (remaining + 1);
    std::span<uint8_t const> const aad(data + fixed_prefix, aad_len);
    std::span<uint8_t const> const plaintext(data + fixed_prefix + aad_len, remaining - aad_len);

    std::vector<uint8_t> buffer(plaintext.begin(), plaintext.end());
    auto const tag = aes256_gcm_encrypt(key, nonce, buffer, aad);
    std::vector<uint8_t> const ciphertext = buffer;
    expect(aes256_gcm_decrypt(key, nonce, buffer, tag, aad));
    expect(buffer == std::vector<uint8_t>(plaintext.begin(), plaintext.end()));

    if (!ciphertext.empty()) {
        buffer = ciphertext;
        buffer[0] ^= 0x01;
        expect(!aes256_gcm_decrypt(key, nonce, buffer, tag, aad));
    }
    if (!aad.empty()) {
        buffer = ciphertext;
        expect(!aes256_gcm_decrypt(key, nonce, buffer, tag, std::span<uint8_t const>{}));
    }
    return 0;
}
