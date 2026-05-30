// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for X25519 ECDH key agreement
#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/x25519.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"
#    include "statusbar/crypto/util/test.hpp"

#    include <cstddef>
#    include <cstdint>
#    include <print>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_copy;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 64) {
        return 0;  // 32 bytes seed A + 32 bytes seed B
    }

    // Generate two keypairs from fuzz seeds
    auto sk_a = x25519_keypair_from_seed(std::span<uint8_t const, 32>(data, 32));
    auto sk_b = x25519_keypair_from_seed(std::span<uint8_t const, 32>(data + 32, 32));

    // Shared secret must be symmetric: x25519(sk_a, pk_b) == x25519(sk_b, pk_a)
    auto shared_ab = x25519(sk_a, sk_b.public_key);
    auto shared_ba = x25519(sk_b, sk_a.public_key);

    if (shared_ab != shared_ba) {
        __builtin_trap();
    }

    // Validate shared secret (reject low-order points)
    bool valid_ab = x25519_shared_secret_is_valid(std::span<uint8_t const, 32>(shared_ab));
    bool valid_ba = x25519_shared_secret_is_valid(std::span<uint8_t const, 32>(shared_ba));
    if (valid_ab != valid_ba) {
        __builtin_trap();
    }

    // Exercise x25519 with a fuzz-derived public key (arbitrary bytes, must not crash)
    if (size >= 96) {
        X25519PublicKey fuzz_pk{};
        span_copy(fuzz_pk.data, std::span<uint8_t const, 32>(data + 64, 32));
        auto shared_fuzz = x25519(sk_a, fuzz_pk);
        test::do_not_optimize(shared_fuzz);
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
