// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for Ed25519 sign/verify and key conversion
#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/ed25519.hpp"
#    include "statusbar/crypto/util/test.hpp"

#    include <cstddef>
#    include <cstdint>
#    include <cstring>
#    include <print>
#    include <vector>

using namespace statusbar::crypto;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < ed25519_seed_size) {
        return 0;
    }
    auto seed = std::span<uint8_t const, ed25519_seed_size>(data, ed25519_seed_size);
    std::span<uint8_t const> message(data + ed25519_seed_size, size - ed25519_seed_size);

    auto sk = ed25519_keypair_from_seed(seed);
    auto pk = ed25519_public_key(sk);

    auto sig = ed25519_sign(sk, message);
    if (!ed25519_verify(pk, message, sig)) {
        __builtin_trap();
    }

    // Corrupt signature
    Ed25519Signature corrupted = sig;
    corrupted.data[0] ^= 0x01;
    if (ed25519_verify(pk, message, corrupted)) {
        __builtin_trap();
    }

    // Empty message
    std::span<uint8_t const> empty_msg;
    auto empty_sig = ed25519_sign(sk, empty_msg);
    if (!ed25519_verify(pk, empty_msg, empty_sig)) {
        __builtin_trap();
    }

    // Exercise Ed25519 -> X25519 key conversion (must not crash)
    auto x_pk = ed25519_pk_to_x25519_pk(pk);
    auto x_sk = ed25519_sk_to_x25519_sk(sk);
    test::do_not_optimize(x_pk);
    test::do_not_optimize(x_sk);

    // Verify with fuzz-derived (possibly invalid) public key (must not crash)
    if (size >= 64) {
        Ed25519PublicKey fuzz_pk{};
        for (size_t i = 0; i < 32; ++i) {
            fuzz_pk.data[i] = data[ed25519_seed_size + i];
        }
        auto fuzz_result = ed25519_verify(fuzz_pk, message, sig);
        test::do_not_optimize(fuzz_result);
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
