// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Generic HMAC-SHA-256 (RFC 2104) implementation template.
// Internal header — used only by SHA-256 implementation files.

#pragma once

#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {
namespace internal {

/// @brief Generic HMAC-SHA-256 (RFC 2104) parameterized on SHA-256 operations.
///
/// Eliminates duplication between SW, ARM64 HW, and x86-64 HW implementations.
/// Supports optional two-part messages (message1 + message2).
///
/// @tparam Ctx SHA-256 context type (e.g. Sha256SwCtx, Sha256HwCtx).
/// @tparam HashOneShot Callable: (span<uint8_t const>) -> array<uint8_t, 32>.
/// @tparam CtxInit Callable: (Ctx&) -> void.
/// @tparam CtxUpdate Callable: (Ctx&, span<uint8_t const>) -> void.
/// @tparam CtxFinal Callable: (Ctx&) -> SecureArray<32>.
/// @param key HMAC key (hashed if longer than 64 bytes).
/// @param message1 First message part.
/// @param message2 Second message part (may be empty).
/// @param hash_oneshot One-shot SHA-256 function (used to hash long keys).
/// @param ctx_init Context initialization function.
/// @param ctx_update Context update function.
/// @param ctx_final Context finalization function.
/// @return 32-byte HMAC-SHA-256 digest.
template <typename Ctx, typename HashOneShot, typename CtxInit, typename CtxUpdate, typename CtxFinal>
auto sha256_hmac_generic(
    std::span<uint8_t const> key,
    std::span<uint8_t const> message1,
    std::span<uint8_t const> message2,
    HashOneShot hash_oneshot,
    CtxInit ctx_init,
    CtxUpdate ctx_update,
    CtxFinal ctx_final) -> std::array<uint8_t, 32>
{
    constexpr size_t block_size = 64;
    constexpr size_t digest_size = 32;

    // Step 1: Normalize key to exactly one block (64 bytes).
    SecureArray<block_size> key_block{};
    if (key.size() > block_size) {
        auto hashed = hash_oneshot(key);
        span_copy(std::span(key_block).template first<digest_size>(), make_const_span(hashed));
    } else {
        span_copy(std::span(key_block).first(key.size()), key);
    }

    // Step 2: ipad = key_block XOR 0x36
    SecureArray<block_size> ipad{};
    for (size_t i = 0; i < block_size; ++i) {
        ipad[i] = key_block[i] ^ 0x36;
    }

    // Step 3: opad = key_block XOR 0x5c
    SecureArray<block_size> opad{};
    for (size_t i = 0; i < block_size; ++i) {
        opad[i] = key_block[i] ^ 0x5c;
    }

    // Step 4: Inner hash = SHA-256(ipad || message1 || message2)
    Ctx inner_ctx;
    ctx_init(inner_ctx);
    ctx_update(inner_ctx, ipad);
    ctx_update(inner_ctx, message1);
    if (!message2.empty()) {
        ctx_update(inner_ctx, message2);
    }
    SecureArray<digest_size> inner = ctx_final(inner_ctx);

    // Step 5: Outer hash = SHA-256(opad || inner_hash)
    Ctx outer_ctx;
    ctx_init(outer_ctx);
    ctx_update(outer_ctx, opad);
    ctx_update(outer_ctx, std::span<uint8_t const>(inner.data(), digest_size));
    return ctx_final(outer_ctx);
}

}  // namespace internal
}  // namespace statusbar::crypto
