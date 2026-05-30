// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/crypto/aes/aes_common_internal.hpp"

namespace statusbar::crypto::internal {

void state_from_bytes(State& s, std::span<uint8_t const, aes_block_size> in)
{
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            s[c][r] = in[(c * 4) + r];
        }
    }
}

void state_to_bytes(State const& s, std::span<uint8_t, aes_block_size> out)
{
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            out[(c * 4) + r] = s[c][r];
        }
    }
}

void add_round_key(State& s, std::array<uint8_t, aes_block_size> const& rk)
{
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            s[c][r] ^= rk[(c * 4) + r];
        }
    }
}

void sub_bytes(State& s)
{
    for (auto& col : s) {
        for (auto& b : col) {
            b = sbox[b];
        }
    }
}

void inv_sub_bytes(State& s)
{
    for (auto& col : s) {
        for (auto& b : col) {
            b = inv_sbox[b];
        }
    }
}

void shift_rows(State& s)
{
    // Row 1: rotate left by 1
    auto t = std::get<1>(std::get<0>(s));
    std::get<1>(std::get<0>(s)) = std::get<1>(std::get<1>(s));
    std::get<1>(std::get<1>(s)) = std::get<1>(std::get<2>(s));
    std::get<1>(std::get<2>(s)) = std::get<1>(std::get<3>(s));
    std::get<1>(std::get<3>(s)) = t;

    // Row 2: rotate left by 2
    std::swap(std::get<2>(std::get<0>(s)), std::get<2>(std::get<2>(s)));
    std::swap(std::get<2>(std::get<1>(s)), std::get<2>(std::get<3>(s)));

    // Row 3: rotate left by 3 (= right by 1)
    t = std::get<3>(std::get<3>(s));
    std::get<3>(std::get<3>(s)) = std::get<3>(std::get<2>(s));
    std::get<3>(std::get<2>(s)) = std::get<3>(std::get<1>(s));
    std::get<3>(std::get<1>(s)) = std::get<3>(std::get<0>(s));
    std::get<3>(std::get<0>(s)) = t;
}

void inv_shift_rows(State& s)
{
    // Row 1: rotate right by 1
    auto t = std::get<1>(std::get<3>(s));
    std::get<1>(std::get<3>(s)) = std::get<1>(std::get<2>(s));
    std::get<1>(std::get<2>(s)) = std::get<1>(std::get<1>(s));
    std::get<1>(std::get<1>(s)) = std::get<1>(std::get<0>(s));
    std::get<1>(std::get<0>(s)) = t;

    // Row 2: rotate right by 2
    std::swap(std::get<2>(std::get<0>(s)), std::get<2>(std::get<2>(s)));
    std::swap(std::get<2>(std::get<1>(s)), std::get<2>(std::get<3>(s)));

    // Row 3: rotate right by 3 (= left by 1)
    t = std::get<3>(std::get<0>(s));
    std::get<3>(std::get<0>(s)) = std::get<3>(std::get<1>(s));
    std::get<3>(std::get<1>(s)) = std::get<3>(std::get<2>(s));
    std::get<3>(std::get<2>(s)) = std::get<3>(std::get<3>(s));
    std::get<3>(std::get<3>(s)) = t;
}

void mix_columns(State& s)
{
    for (auto& col : s) {
        auto a0 = std::get<0>(col), a1 = std::get<1>(col), a2 = std::get<2>(col), a3 = std::get<3>(col);
        std::get<0>(col) = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        std::get<1>(col) = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        std::get<2>(col) = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        std::get<3>(col) = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

void inv_mix_columns(State& s)
{
    for (auto& col : s) {
        auto a0 = std::get<0>(col), a1 = std::get<1>(col), a2 = std::get<2>(col), a3 = std::get<3>(col);
        std::get<0>(col) = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        std::get<1>(col) = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        std::get<2>(col) = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        std::get<3>(col) = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

void left_shift_one(std::array<uint8_t, aes_block_size>& block)
{
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t const next_carry = block[i] >> 7;
        block[i] = static_cast<uint8_t>((block[i] << 1) | carry);
        carry = next_carry;
    }
}

auto constant_time_equal(std::span<uint8_t const, aes_block_size> a, std::span<uint8_t const, aes_block_size> b) -> bool
{
    uint8_t diff = 0;
    for (size_t i = 0; i < aes_block_size; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

auto cmac_derive_subkeys(std::array<uint8_t, aes_block_size> const& L) -> CmacSubkeys
{
    constexpr uint8_t rb = 0x87;
    CmacSubkeys sk;

    // K1 = (L << 1) ^ (msb(L) ? Rb : 0)
    sk.K1 = L;
    uint8_t msb = sk.K1[0] >> 7;
    left_shift_one(sk.K1);
    sk.K1[15] ^= static_cast<uint8_t>(rb & static_cast<uint8_t>(~msb + 1));

    // K2 = (K1 << 1) ^ (msb(K1) ? Rb : 0)
    sk.K2 = sk.K1;
    msb = sk.K2[0] >> 7;
    left_shift_one(sk.K2);
    sk.K2[15] ^= static_cast<uint8_t>(rb & static_cast<uint8_t>(~msb + 1));

    return sk;
}

}  // namespace statusbar::crypto::internal
