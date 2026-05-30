// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for PKCS#8/SPKI DER import (untrusted input parsing)
#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/ed25519.hpp"
#    include "statusbar/crypto/p256/p256_ecdsa.hpp"
#    include "statusbar/crypto/pkcs8/pkcs8_ed25519.hpp"
#    include "statusbar/crypto/pkcs8/pkcs8_p256.hpp"
#    include "statusbar/crypto/util/test.hpp"

#    include <cstddef>
#    include <cstdint>
#    include <print>
#    include <span>

using namespace statusbar::crypto;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    std::span<uint8_t const> input(data, size);

    // Exercise all four DER import functions with raw fuzz input (must not crash)
    auto ed_pk = spki_import_ed25519(input);
    test::do_not_optimize(ed_pk);

    auto ed_sk = pkcs8_import_ed25519(input);
    test::do_not_optimize(ed_sk);

    auto p256_pk = spki_import_p256(input);
    test::do_not_optimize(p256_pk);

    auto p256_sk = pkcs8_import_p256(input);
    test::do_not_optimize(p256_sk);

    // Round-trip: export then import Ed25519 keys (if we have 32 bytes for a seed)
    if (size >= 32) {
        auto seed = std::span<uint8_t const, 32>(data, 32);
        auto sk = ed25519_keypair_from_seed(seed);
        auto pk = ed25519_public_key(sk);

        auto spki_der = spki_export_ed25519(pk);
        auto reimported_pk = spki_import_ed25519(std::span<uint8_t const>(spki_der));
        if (!reimported_pk || reimported_pk->data != pk.data) {
            __builtin_trap();
        }

        auto pkcs8_der = pkcs8_export_ed25519(seed);
        auto reimported_sk = pkcs8_import_ed25519(std::span<uint8_t const>(pkcs8_der));
        if (!reimported_sk) {
            __builtin_trap();
        }
    }

    // Round-trip: export then import P-256 keys
    if (size >= 32) {
        auto p256_sk = p256_ecdsa_keypair_from_seed(std::span<uint8_t const, 32>(data, 32));

        auto spki_der = spki_export_p256(p256_sk.public_key);
        auto reimported_pk = spki_import_p256(std::span<uint8_t const>(spki_der));
        if (!reimported_pk || reimported_pk->data != p256_sk.public_key.data) {
            __builtin_trap();
        }

        auto pkcs8_der = pkcs8_export_p256(p256_sk);
        auto reimported_sk = pkcs8_import_p256(std::span<uint8_t const>(pkcs8_der));
        if (!reimported_sk) {
            __builtin_trap();
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
