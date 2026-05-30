// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for ECIES encrypt/decrypt round-trip
#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/ecies/ecies.hpp"
#    include "statusbar/crypto/keys.hpp"
#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"
#    include "statusbar/crypto/util/test.hpp"

#    include <cstddef>
#    include <cstdint>
#    include <print>
#    include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_copy;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 64) {
        return 0;  // 32 seed + 32 entropy minimum
    }

    // Generate a valid P-256 keypair from fuzz seed for round-trip testing
    auto recipient_sk = p256_ecdsa_keypair_from_seed(std::span<uint8_t const, 32>(data, 32));
    std::array<uint8_t, 32> entropy{};
    span_copy(entropy, std::span<uint8_t const>(data + 32, 32));

    std::span<uint8_t const> plaintext(data + 64, size - 64);
    std::vector<uint8_t> ciphertext(ecies_output_size(plaintext.size()));

    // Encrypt with the recipient's public key
    auto enc_result = ecies_encrypt(
        recipient_sk.public_key,
        plaintext,
        std::span<uint8_t>(ciphertext.data(), ciphertext.size()),
        std::span<uint8_t const, 32>(entropy));
    if (enc_result.empty()) {
        return 0;  // encryption can fail with degenerate entropy
    }

    // Decrypt and verify round-trip.
    // Output buffer must be at least c_len (ciphertext minus ECIES overhead) for CBC decrypt.
    size_t c_len = enc_result.size() > ecies_fixed_overhead ? enc_result.size() - ecies_fixed_overhead : 0;
    std::vector<uint8_t> recovered(c_len);
    auto dec_result = ecies_decrypt(recipient_sk, enc_result, std::span<uint8_t>(recovered));
    if (dec_result.size() != plaintext.size()) {
        __builtin_trap();
    }
    for (size_t i = 0; i < dec_result.size(); ++i) {
        if (dec_result[i] != plaintext[i]) {
            __builtin_trap();
        }
    }

    // Feed raw fuzz data to ecies_decrypt to exercise validation paths (must not crash).
    // Uses data after the 32-byte seed as arbitrary ciphertext.
    if (size > 32) {
        std::span<uint8_t const> raw_ct(data + 32, size - 32);
        std::vector<uint8_t> raw_pt(raw_ct.size());
        auto raw_result = ecies_decrypt(recipient_sk, raw_ct, std::span<uint8_t>(raw_pt));
        test::do_not_optimize(raw_result);
    }

    return 0;
}

#else  // !STATUSBAR_CRYPTO_HAS_INT128
#    include <cstddef>
#    include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(uint8_t const*, size_t)
{
    return 0;
}
#endif  // STATUSBAR_CRYPTO_HAS_INT128
