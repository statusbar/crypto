// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-512 hardware-accelerated implementation for x86-64
//
// x86-64 does NOT have SHA-512 hardware instructions (only SHA-256 via SHA-NI).
// This file provides the _hw API by delegating to the software implementation.

#include "statusbar/crypto/sha/sha512_hw.hpp"

namespace statusbar::crypto {

using std::span;

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
