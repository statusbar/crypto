// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 Montgomery ladder — 32-bit reduced-radix implementation.
// See x25519_32.hpp. This mirrors curve25519_scalar_mult exactly, with every
// field operation routed through curve25519_fe32 (no __uint128_t).

#include "statusbar/crypto/25519/x25519_32.hpp"

#include "statusbar/crypto/25519/curve25519_fe32.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

namespace {

// Constant-time conditional swap: exchanges f and g iff b == 1.
void fe_cswap(Fe25519x32& f, Fe25519x32& g, uint32_t b)
{
    uint32_t const mask = static_cast<uint32_t>(0) - (b & 1U);
    for (int i = 0; i < 10; ++i) {
        uint32_t const x = mask & (f.limbs[static_cast<size_t>(i)] ^ g.limbs[static_cast<size_t>(i)]);
        f.limbs[static_cast<size_t>(i)] ^= x;
        g.limbs[static_cast<size_t>(i)] ^= x;
    }
}

}  // namespace

auto curve25519x32_scalar_mult(std::span<uint8_t const, 32> scalar, std::span<uint8_t const, 32> point_u) -> std::array<uint8_t, 32>
{
    // Copy and clamp the scalar per RFC 7748 Section 5. SecureArray zeroes it
    // on scope exit.
    SecureArray<32> s{};
    for (int i = 0; i < 32; ++i) {
        s[static_cast<size_t>(i)] = scalar[static_cast<size_t>(i)];
    }
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    auto u = fe25519x32_from_bytes(point_u);

    auto x_2 = fe25519x32_one();
    auto z_2 = fe25519x32_zero();
    auto x_3 = u;
    auto z_3 = fe25519x32_one();

    uint32_t swap = 0;

    for (int bit = 254; bit >= 0; --bit) {
        uint32_t const b = (static_cast<uint32_t>(s[static_cast<size_t>(bit / 8)]) >> (bit % 8)) & 1U;
        swap ^= b;
        fe_cswap(x_2, x_3, swap);
        fe_cswap(z_2, z_3, swap);
        swap = b;

        auto A = fe25519x32_add(x_2, z_2);
        auto AA = fe25519x32_sq(A);
        auto B = fe25519x32_sub(x_2, z_2);
        auto BB = fe25519x32_sq(B);
        auto E = fe25519x32_sub(AA, BB);
        auto C = fe25519x32_add(x_3, z_3);
        auto D = fe25519x32_sub(x_3, z_3);
        auto DA = fe25519x32_mul(D, A);
        auto CB = fe25519x32_mul(C, B);
        x_3 = fe25519x32_sq(fe25519x32_add(DA, CB));
        z_3 = fe25519x32_mul(u, fe25519x32_sq(fe25519x32_sub(DA, CB)));
        x_2 = fe25519x32_mul(AA, BB);
        z_2 = fe25519x32_mul(E, fe25519x32_add(AA, fe25519x32_mul_small(E, 121665)));
    }

    fe_cswap(x_2, x_3, swap);
    fe_cswap(z_2, z_3, swap);

    auto result = fe25519x32_mul(x_2, fe25519x32_invert(z_2));
    return fe25519x32_to_bytes(result);
}

}  // namespace statusbar::crypto
