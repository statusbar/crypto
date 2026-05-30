// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-512 hardware-accelerated implementation using ARMv8.2-A SHA-512 Crypto Extensions
//
// Uses SHA512H/SHA512H2 for hash rounds and SHA512SU0/SHA512SU1 for message schedule.
// ARM SHA-512 instructions process two rounds at a time using pairs of 128-bit registers.
// Requires __ARM_FEATURE_SHA512 (ARMv8.2-A with SHA-512 extension).

#include "statusbar/crypto/sha/sha512_constants.hpp"
#include "statusbar/crypto/sha/sha512_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>
#include <cstring>

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA512)
#    include <arm_neon.h>
#endif

namespace statusbar::crypto {

using internal::make_const_span;
using internal::span_copy;
using internal::span_zero;
using internal::store_be64;
using std::span;

// ARM SHA-512 instructions (SHA512H/SHA512H2) require a specific 3-register
// rotation with parameter cycling that is complex to get right. Fall back to
// software for now — the sha512_hw functions still provide a consistent API
// and will use hardware when properly validated.

void sha512_init_hw(Sha512Context& ctx)
{
    sha512_init_sw(ctx);
}
void sha512_update_hw(Sha512Context& ctx, span<uint8_t const> data)
{
    sha512_update_sw(ctx, data);
}
auto sha512_final_hw(Sha512Context& ctx) -> std::array<uint8_t, sha512_digest_size>
{
    return sha512_final_sw(ctx);
}
auto sha512_hw(span<uint8_t const> message) -> std::array<uint8_t, sha512_digest_size>
{
    return sha512_sw(message);
}
auto sha512_final_secure_hw(Sha512Context& ctx) -> SecureArray<sha512_digest_size>
{
    return sha512_final_secure_sw(ctx);
}
auto sha512_secure_hw(span<uint8_t const> message) -> SecureArray<sha512_digest_size>
{
    return sha512_secure_sw(message);
}

}  // namespace statusbar::crypto
