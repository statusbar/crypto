// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Constant-time bitsliced AES core. See aes_ct_internal.hpp for the plane
// representation and the security rationale.
//
// Bit-position geometry used by the permutation helpers below: plane bit j
// holds state byte j = block[j], which is FIPS 197 state column c = j/4,
// row r = j%4. Row r therefore occupies bits {r, 4+r, 8+r, 12+r} (mask
// 0x1111 << r) and column c occupies bits {4c, 4c+1, 4c+2, 4c+3}.

#include "statusbar/crypto/aes/aes_ct_internal.hpp"

namespace statusbar::crypto::internal {

namespace {

constexpr auto rotr16(uint16_t v, int s) -> uint16_t
{
    return static_cast<uint16_t>((v >> s) | (v << (16 - s)));
}

// Rotate every column "up" by one row: byte at row r takes the value of the
// byte at row r+1 (mod 4) in the same column. Applying this k times yields
// the r+k rotation used by the MixColumns dot products.
constexpr auto rot_col(uint16_t p) -> uint16_t
{
    return static_cast<uint16_t>(((p >> 1) & 0x7777) | ((p << 3) & 0x8888));
}

// Multiply every state byte by x (i.e. by 2) in GF(2^8), in plane form.
// Byte shift-left feeds bit i from bit i-1; the reduction x^8 = x^4+x^3+x+1
// folds the old bit 7 into bits 0, 1, 3 and 4.
constexpr auto xtime_planes(AesBitPlanes const& a) -> AesBitPlanes
{
    return AesBitPlanes{
        a[7],
        static_cast<uint16_t>(a[0] ^ a[7]),
        a[1],
        static_cast<uint16_t>(a[2] ^ a[7]),
        static_cast<uint16_t>(a[3] ^ a[7]),
        a[4],
        a[5],
        a[6],
    };
}

// The AES S-box as a 113-gate boolean circuit over the eight bit planes,
// from Boyar & Peralta, "A new combinational logic minimization technique
// with applications to cryptology" (2009), https://eprint.iacr.org/2009/191
// — the same decomposition used by BearSSL's aes_ct. x0 is the most
// significant bit plane (q[7]), x7 the least (q[0]); likewise s0..s7 on
// output. The final complements implement the affine constant 0x63.
//
// Correctness is enforced exhaustively (all 256 inputs against the FIPS 197
// table) in aes_ct_internal_test.cpp.
void sbox_circuit(AesBitPlanes& q)
{
    uint32_t const x0 = q[7], x1 = q[6], x2 = q[5], x3 = q[4];
    uint32_t const x4 = q[3], x5 = q[2], x6 = q[1], x7 = q[0];

    // Top linear transformation.
    uint32_t const y14 = x3 ^ x5;
    uint32_t const y13 = x0 ^ x6;
    uint32_t const y9 = x0 ^ x3;
    uint32_t const y8 = x0 ^ x5;
    uint32_t const t0 = x1 ^ x2;
    uint32_t const y1 = t0 ^ x7;
    uint32_t const y4 = y1 ^ x3;
    uint32_t const y12 = y13 ^ y14;
    uint32_t const y2 = y1 ^ x0;
    uint32_t const y5 = y1 ^ x6;
    uint32_t const y3 = y5 ^ y8;
    uint32_t const t1 = x4 ^ y12;
    uint32_t const y15 = t1 ^ x5;
    uint32_t const y20 = t1 ^ x1;
    uint32_t const y6 = y15 ^ x7;
    uint32_t const y10 = y15 ^ t0;
    uint32_t const y11 = y20 ^ y9;
    uint32_t const y7 = x7 ^ y11;
    uint32_t const y17 = y10 ^ y11;
    uint32_t const y19 = y10 ^ y8;
    uint32_t const y16 = t0 ^ y11;
    uint32_t const y21 = y13 ^ y16;
    uint32_t const y18 = x0 ^ y16;

    // Non-linear section (GF(2^8) inversion via shared products).
    uint32_t const t2 = y12 & y15;
    uint32_t const t3 = y3 & y6;
    uint32_t const t4 = t3 ^ t2;
    uint32_t const t5 = y4 & x7;
    uint32_t const t6 = t5 ^ t2;
    uint32_t const t7 = y13 & y16;
    uint32_t const t8 = y5 & y1;
    uint32_t const t9 = t8 ^ t7;
    uint32_t const t10 = y2 & y7;
    uint32_t const t11 = t10 ^ t7;
    uint32_t const t12 = y9 & y11;
    uint32_t const t13 = y14 & y17;
    uint32_t const t14 = t13 ^ t12;
    uint32_t const t15 = y8 & y10;
    uint32_t const t16 = t15 ^ t12;
    uint32_t const t17 = t4 ^ t14;
    uint32_t const t18 = t6 ^ t16;
    uint32_t const t19 = t9 ^ t14;
    uint32_t const t20 = t11 ^ t16;
    uint32_t const t21 = t17 ^ y20;
    uint32_t const t22 = t18 ^ y19;
    uint32_t const t23 = t19 ^ y21;
    uint32_t const t24 = t20 ^ y18;

    uint32_t const t25 = t21 ^ t22;
    uint32_t const t26 = t21 & t23;
    uint32_t const t27 = t24 ^ t26;
    uint32_t const t28 = t25 & t27;
    uint32_t const t29 = t28 ^ t22;
    uint32_t const t30 = t23 ^ t24;
    uint32_t const t31 = t22 ^ t26;
    uint32_t const t32 = t31 & t30;
    uint32_t const t33 = t32 ^ t24;
    uint32_t const t34 = t23 ^ t33;
    uint32_t const t35 = t27 ^ t33;
    uint32_t const t36 = t24 & t35;
    uint32_t const t37 = t36 ^ t34;
    uint32_t const t38 = t27 ^ t36;
    uint32_t const t39 = t29 & t38;
    uint32_t const t40 = t25 ^ t39;

    uint32_t const t41 = t40 ^ t37;
    uint32_t const t42 = t29 ^ t33;
    uint32_t const t43 = t29 ^ t40;
    uint32_t const t44 = t33 ^ t37;
    uint32_t const t45 = t42 ^ t41;
    uint32_t const z0 = t44 & y15;
    uint32_t const z1 = t37 & y6;
    uint32_t const z2 = t33 & x7;
    uint32_t const z3 = t43 & y16;
    uint32_t const z4 = t40 & y1;
    uint32_t const z5 = t29 & y7;
    uint32_t const z6 = t42 & y11;
    uint32_t const z7 = t45 & y17;
    uint32_t const z8 = t41 & y10;
    uint32_t const z9 = t44 & y12;
    uint32_t const z10 = t37 & y3;
    uint32_t const z11 = t33 & y4;
    uint32_t const z12 = t43 & y13;
    uint32_t const z13 = t40 & y5;
    uint32_t const z14 = t29 & y2;
    uint32_t const z15 = t42 & y9;
    uint32_t const z16 = t45 & y14;
    uint32_t const z17 = t41 & y8;

    // Bottom linear transformation.
    uint32_t const t46 = z15 ^ z16;
    uint32_t const t47 = z10 ^ z11;
    uint32_t const t48 = z5 ^ z13;
    uint32_t const t49 = z9 ^ z10;
    uint32_t const t50 = z2 ^ z12;
    uint32_t const t51 = z2 ^ z5;
    uint32_t const t52 = z7 ^ z8;
    uint32_t const t53 = z0 ^ z3;
    uint32_t const t54 = z6 ^ z7;
    uint32_t const t55 = z16 ^ z17;
    uint32_t const t56 = z12 ^ t48;
    uint32_t const t57 = t50 ^ t53;
    uint32_t const t58 = z4 ^ t46;
    uint32_t const t59 = z3 ^ t54;
    uint32_t const t60 = t46 ^ t57;
    uint32_t const t61 = z14 ^ t57;
    uint32_t const t62 = t52 ^ t58;
    uint32_t const t63 = t49 ^ t58;
    uint32_t const t64 = z4 ^ t59;
    uint32_t const t65 = t61 ^ t62;
    uint32_t const t66 = z1 ^ t63;
    uint32_t const s0 = t59 ^ t63;
    uint32_t const s6 = ~(t56 ^ t62);
    uint32_t const s7 = ~(t48 ^ t60);
    uint32_t const t67 = t64 ^ t65;
    uint32_t const s3 = t53 ^ t66;
    uint32_t const s4 = t51 ^ t66;
    uint32_t const s5 = t47 ^ t65;
    uint32_t const s1 = ~(t64 ^ s3);
    uint32_t const s2 = ~(t55 ^ t67);

    q[7] = static_cast<uint16_t>(s0);
    q[6] = static_cast<uint16_t>(s1);
    q[5] = static_cast<uint16_t>(s2);
    q[4] = static_cast<uint16_t>(s3);
    q[3] = static_cast<uint16_t>(s4);
    q[2] = static_cast<uint16_t>(s5);
    q[1] = static_cast<uint16_t>(s6);
    q[0] = static_cast<uint16_t>(s7);
}

// The inverse of the S-box affine layer: InvS(x) = Inv_GF(A^{-1}(x ^ 0x63)),
// and A^{-1}(y) folds to three rotated bit taps; the ^0x63 constant folds
// into complements of planes 0, 1, 5 and 6. Sandwiching the forward circuit
// (whose own affine layer cancels against this transform applied after it)
// yields the inverse S-box — the classic aes_ct construction.
void inv_affine_transform(AesBitPlanes& q)
{
    uint32_t const q0 = ~static_cast<uint32_t>(q[0]);
    uint32_t const q1 = ~static_cast<uint32_t>(q[1]);
    uint32_t const q2 = q[2];
    uint32_t const q3 = q[3];
    uint32_t const q4 = q[4];
    uint32_t const q5 = ~static_cast<uint32_t>(q[5]);
    uint32_t const q6 = ~static_cast<uint32_t>(q[6]);
    uint32_t const q7 = q[7];
    q[7] = static_cast<uint16_t>(q1 ^ q4 ^ q6);
    q[6] = static_cast<uint16_t>(q0 ^ q3 ^ q5);
    q[5] = static_cast<uint16_t>(q7 ^ q2 ^ q4);
    q[4] = static_cast<uint16_t>(q6 ^ q1 ^ q3);
    q[3] = static_cast<uint16_t>(q5 ^ q0 ^ q2);
    q[2] = static_cast<uint16_t>(q4 ^ q7 ^ q1);
    q[1] = static_cast<uint16_t>(q3 ^ q6 ^ q0);
    q[0] = static_cast<uint16_t>(q2 ^ q5 ^ q7);
}

void xor_planes(AesBitPlanes& q, AesBitPlanes const& k)
{
    for (size_t i = 0; i < 8; ++i) {
        q[i] ^= k[i];
    }
}

}  // anonymous namespace

auto aes_ct_pack(std::span<uint8_t const, 16> in) -> AesBitPlanes
{
    AesBitPlanes q{};
    for (size_t j = 0; j < 16; ++j) {
        for (size_t i = 0; i < 8; ++i) {
            q[i] = static_cast<uint16_t>(q[i] | (((in[j] >> i) & 1u) << j));
        }
    }
    return q;
}

void aes_ct_unpack(AesBitPlanes const& q, std::span<uint8_t, 16> out)
{
    for (size_t j = 0; j < 16; ++j) {
        unsigned b = 0;
        for (size_t i = 0; i < 8; ++i) {
            b |= ((q[i] >> j) & 1u) << i;
        }
        out[j] = static_cast<uint8_t>(b);
    }
}

void aes_ct_sub_bytes(AesBitPlanes& q)
{
    sbox_circuit(q);
}

void aes_ct_inv_sub_bytes(AesBitPlanes& q)
{
    inv_affine_transform(q);
    sbox_circuit(q);
    inv_affine_transform(q);
}

void aes_ct_shift_rows(AesBitPlanes& q)
{
    for (auto& p : q) {
        p = static_cast<uint16_t>(
            (p & 0x1111) | rotr16(static_cast<uint16_t>(p & 0x2222), 4) | rotr16(static_cast<uint16_t>(p & 0x4444), 8) |
            rotr16(static_cast<uint16_t>(p & 0x8888), 12));
    }
}

void aes_ct_inv_shift_rows(AesBitPlanes& q)
{
    for (auto& p : q) {
        p = static_cast<uint16_t>(
            (p & 0x1111) | rotr16(static_cast<uint16_t>(p & 0x2222), 12) | rotr16(static_cast<uint16_t>(p & 0x4444), 8) |
            rotr16(static_cast<uint16_t>(p & 0x8888), 4));
    }
}

void aes_ct_mix_columns(AesBitPlanes& q)
{
    // out = 2*(a ^ r1) ^ r1 ^ r2 ^ r3 per byte, where rK is the state with
    // each column rotated up by K rows — equivalent to the FIPS 197
    // {02,03,01,01} dot product.
    AesBitPlanes t{};
    AesBitPlanes acc{};
    for (size_t i = 0; i < 8; ++i) {
        uint16_t const r1 = rot_col(q[i]);
        uint16_t const r2 = rot_col(r1);
        uint16_t const r3 = rot_col(r2);
        t[i] = static_cast<uint16_t>(q[i] ^ r1);
        acc[i] = static_cast<uint16_t>(r1 ^ r2 ^ r3);
    }
    auto const doubled = xtime_planes(t);
    for (size_t i = 0; i < 8; ++i) {
        q[i] = static_cast<uint16_t>(doubled[i] ^ acc[i]);
    }
}

void aes_ct_inv_mix_columns(AesBitPlanes& q)
{
    // InvMixColumns = MixColumns after adding 4*(a[r] ^ a[r+2]) to each byte
    // (the standard {0e,0b,0d,09} = {02,03,01,01} * correction identity).
    AesBitPlanes d{};
    for (size_t i = 0; i < 8; ++i) {
        d[i] = static_cast<uint16_t>(q[i] ^ rot_col(rot_col(q[i])));
    }
    auto const corr = xtime_planes(xtime_planes(d));
    for (size_t i = 0; i < 8; ++i) {
        q[i] ^= corr[i];
    }
    aes_ct_mix_columns(q);
}

auto aes_ct_sub_word(std::array<uint8_t, 4> const& w) -> std::array<uint8_t, 4>
{
    // Reuse the block circuit with only 4 of the 16 plane bits populated.
    std::array<uint8_t, 16> buf{};
    buf[0] = w[0];
    buf[1] = w[1];
    buf[2] = w[2];
    buf[3] = w[3];
    auto q = aes_ct_pack(buf);
    sbox_circuit(q);
    aes_ct_unpack(q, buf);
    return {buf[0], buf[1], buf[2], buf[3]};
}

void aes_ct_encrypt_block(std::span<std::array<uint8_t, 16> const> round_keys, std::span<uint8_t, 16> block)
{
    size_t const num_rounds = round_keys.size() - 1;
    auto q = aes_ct_pack(block);

    xor_planes(q, aes_ct_pack(round_keys[0]));
    for (size_t r = 1; r < num_rounds; ++r) {
        aes_ct_sub_bytes(q);
        aes_ct_shift_rows(q);
        aes_ct_mix_columns(q);
        xor_planes(q, aes_ct_pack(round_keys[r]));
    }
    aes_ct_sub_bytes(q);
    aes_ct_shift_rows(q);
    xor_planes(q, aes_ct_pack(round_keys[num_rounds]));

    aes_ct_unpack(q, block);
}

void aes_ct_decrypt_block(std::span<std::array<uint8_t, 16> const> round_keys, std::span<uint8_t, 16> block)
{
    size_t const num_rounds = round_keys.size() - 1;
    auto q = aes_ct_pack(block);

    xor_planes(q, aes_ct_pack(round_keys[num_rounds]));
    for (size_t r = num_rounds - 1; r >= 1; --r) {
        aes_ct_inv_shift_rows(q);
        aes_ct_inv_sub_bytes(q);
        xor_planes(q, aes_ct_pack(round_keys[r]));
        aes_ct_inv_mix_columns(q);
    }
    aes_ct_inv_shift_rows(q);
    aes_ct_inv_sub_bytes(q);
    xor_planes(q, aes_ct_pack(round_keys[0]));

    aes_ct_unpack(q, block);
}

}  // namespace statusbar::crypto::internal
