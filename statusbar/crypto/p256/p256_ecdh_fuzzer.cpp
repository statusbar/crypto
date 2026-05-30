// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for P-256 ECDH shared secret computation
#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/p256/p256_ecdh.hpp"
#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
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

    // Generate two valid P-256 keypairs from fuzz seeds
    auto sk_a = p256_ecdsa_keypair_from_seed(std::span<uint8_t const, 32>(data, 32));
    auto sk_b = p256_ecdsa_keypair_from_seed(std::span<uint8_t const, 32>(data + 32, 32));

    // Shared secret must be symmetric: ecdh(sk_a, pk_b) == ecdh(sk_b, pk_a)
    auto shared_ab = p256_ecdh(sk_a, sk_b.public_key);
    auto shared_ba = p256_ecdh(sk_b, sk_a.public_key);

    if (shared_ab != shared_ba) {
        __builtin_trap();
    }

    // Feed fuzz-derived public key to ensure no crash on invalid input
    if (size >= 128) {
        P256PublicKey fuzz_pk{};
        span_copy(fuzz_pk.data, std::span<uint8_t const>(data + 64, 64));
        // May return all-zeros for invalid keys, but must not crash
        auto shared_fuzz = p256_ecdh(sk_a, fuzz_pk);
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
