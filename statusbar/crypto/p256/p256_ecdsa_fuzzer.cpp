// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for P-256 ECDSA sign/verify round-trip
#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
#    include "statusbar/crypto/util/test.hpp"

#    include <cstddef>
#    include <cstdint>
#    include <print>
#    include <span>

using namespace statusbar::crypto;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 32) {
        return 0;  // 32-byte seed minimum
    }

    auto sk = p256_ecdsa_keypair_from_seed(std::span<uint8_t const, 32>(data, 32));
    std::span<uint8_t const> message(data + 32, size - 32);

    // Sign and verify
    auto sig = p256_ecdsa_sign(sk, message);
    if (!p256_ecdsa_verify(sk.public_key, message, sig)) {
        __builtin_trap();
    }

    // Corrupt signature: flip bit in r component
    P256EcdsaSignature corrupted = sig;
    corrupted.data[0] ^= 0x01;
    if (p256_ecdsa_verify(sk.public_key, message, corrupted)) {
        __builtin_trap();
    }

    // Corrupt signature: flip bit in s component
    P256EcdsaSignature corrupted_s = sig;
    corrupted_s.data[32] ^= 0x01;
    if (p256_ecdsa_verify(sk.public_key, message, corrupted_s)) {
        __builtin_trap();
    }

    // Empty message
    std::span<uint8_t const> empty_msg;
    auto empty_sig = p256_ecdsa_sign(sk, empty_msg);
    if (!p256_ecdsa_verify(sk.public_key, empty_msg, empty_sig)) {
        __builtin_trap();
    }

    // Verify with fuzz-derived signature against valid key (must not crash)
    if (size >= 96) {
        P256EcdsaSignature fuzz_sig{};
        for (size_t i = 0; i < 64 && (32 + i) < size; ++i) {
            fuzz_sig.data[i] = data[32 + i];
        }
        auto fuzz_verify1 = p256_ecdsa_verify(sk.public_key, message, fuzz_sig);
        test::do_not_optimize(fuzz_verify1);
    }

    // Verify with fuzz-derived (possibly invalid) public key (must not crash)
    if (size >= 96) {
        P256PublicKey fuzz_pk{};
        for (size_t i = 0; i < 64 && (32 + i) < size; ++i) {
            fuzz_pk.data[i] = data[32 + i];
        }
        auto fuzz_verify2 = p256_ecdsa_verify(fuzz_pk, message, sig);
        test::do_not_optimize(fuzz_verify2);
    }

    // Exercise p256_keypair_from_scalar with fuzz-derived scalar (must not crash)
    {
        auto scalar_sk = p256_keypair_from_scalar(std::span<uint8_t const, 32>(data, 32));
        if (scalar_sk) {
            // If the scalar was valid, sign/verify should work
            auto scalar_sig = p256_ecdsa_sign(*scalar_sk, message);
            if (!p256_ecdsa_verify(scalar_sk->public_key, message, scalar_sig)) {
                __builtin_trap();
            }
        }
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
