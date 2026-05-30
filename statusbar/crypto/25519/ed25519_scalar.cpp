// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Ed25519 scalar arithmetic mod L — the order of the Ed25519 group,
// L = 2^252 + 27742317777372353535851937790883648493.
//
// sc_reduce (reduce a 512-bit value mod L) and sc_mul_add ((a*b+c) mod L) use
// 21-bit signed limbs and nothing wider than int64_t — unlike the 5x51-bit
// prime-field arithmetic they need no 128-bit integer type, so they are
// 32-bit-ALU portable as-is. They live in this own (ungated) translation
// unit, extracted from curve25519.cpp, so the 64-bit and 32-bit Ed25519
// backends share a single implementation.

#include "statusbar/crypto/25519/curve25519.hpp"
#include "statusbar/crypto/25519/curve25519_constants.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

namespace statusbar::crypto {

using std::span;

namespace {

using constants::SC_L0;
using constants::SC_L1;
using constants::SC_L2;
using constants::SC_L3;
using constants::SC_L4;
using constants::SC_L5;

// Load 3 bytes as a little-endian integer for scalar unpacking
auto load_3(uint8_t const* p) -> int64_t
{
    return static_cast<int64_t>(p[0]) | (static_cast<int64_t>(p[1]) << 8) | (static_cast<int64_t>(p[2]) << 16);
}

// Load 4 bytes as a little-endian integer for scalar unpacking
auto load_4(uint8_t const* p) -> int64_t
{
    return static_cast<int64_t>(p[0]) | (static_cast<int64_t>(p[1]) << 8) | (static_cast<int64_t>(p[2]) << 16) |
        (static_cast<int64_t>(p[3]) << 24);
}

}  // anonymous namespace

//
// Scalar operations mod L
//

// Reduce a 512-bit scalar (64 bytes) mod L where
// L = 2^252 + 27742317777372353535851937790883648493.
// Representation: 24 x 21-bit signed limbs (s0..s23).
// Algorithm: Schoolbook reduction of high limbs (s23 down to s18) into low
// limbs using the relation 2^252 = -27742317777372353535851937790883648493
// (mod L), expressed as 6 coefficients SC_L0..SC_L5 (see curve25519_constants.hpp).
// After two reduction passes with carry propagation,
// the result fits in 12 limbs (s0..s11) and is serialized to 32 bytes.
auto sc_reduce(span<uint8_t const, curve25519_wide_scalar_size> in) -> std::array<uint8_t, curve25519_scalar_size>
{
    // RAII workspace: all intermediate scalar limbs are securely zeroed on scope exit.
    SecureWorkArray<int64_t, 25> sc_work;  // s[0..23] + carry
    auto& s0 = sc_work[0];
    auto& s1 = sc_work[1];
    auto& s2 = sc_work[2];
    auto& s3 = sc_work[3];
    auto& s4 = sc_work[4];
    auto& s5 = sc_work[5];
    auto& s6 = sc_work[6];
    auto& s7 = sc_work[7];
    auto& s8 = sc_work[8];
    auto& s9 = sc_work[9];
    auto& s10 = sc_work[10];
    auto& s11 = sc_work[11];
    auto& s12 = sc_work[12];
    auto& s13 = sc_work[13];
    auto& s14 = sc_work[14];
    auto& s15 = sc_work[15];
    auto& s16 = sc_work[16];
    auto& s17 = sc_work[17];
    auto& s18 = sc_work[18];
    auto& s19 = sc_work[19];
    auto& s20 = sc_work[20];
    auto& s21 = sc_work[21];
    auto& s22 = sc_work[22];
    auto& s23 = sc_work[23];
    auto& carry = sc_work[24];

    s0 = (load_4(in.data() + 0) >> 0) & 0x1FFFFF;
    s1 = (load_4(in.data() + 2) >> 5) & 0x1FFFFF;
    s2 = (load_3(in.data() + 5) >> 2) & 0x1FFFFF;
    s3 = (load_4(in.data() + 7) >> 7) & 0x1FFFFF;
    s4 = (load_4(in.data() + 10) >> 4) & 0x1FFFFF;
    s5 = (load_3(in.data() + 13) >> 1) & 0x1FFFFF;
    s6 = (load_4(in.data() + 15) >> 6) & 0x1FFFFF;
    s7 = (load_3(in.data() + 18) >> 3) & 0x1FFFFF;
    s8 = (load_4(in.data() + 21) >> 0) & 0x1FFFFF;
    s9 = (load_4(in.data() + 23) >> 5) & 0x1FFFFF;
    s10 = (load_3(in.data() + 26) >> 2) & 0x1FFFFF;
    s11 = (load_4(in.data() + 28) >> 7) & 0x1FFFFF;
    s12 = (load_4(in.data() + 31) >> 4) & 0x1FFFFF;
    s13 = (load_3(in.data() + 34) >> 1) & 0x1FFFFF;
    s14 = (load_4(in.data() + 36) >> 6) & 0x1FFFFF;
    s15 = (load_3(in.data() + 39) >> 3) & 0x1FFFFF;
    s16 = (load_4(in.data() + 42) >> 0) & 0x1FFFFF;
    s17 = (load_4(in.data() + 44) >> 5) & 0x1FFFFF;
    s18 = (load_3(in.data() + 47) >> 2) & 0x1FFFFF;
    s19 = (load_4(in.data() + 49) >> 7) & 0x1FFFFF;
    s20 = (load_4(in.data() + 52) >> 4) & 0x1FFFFF;
    s21 = (load_3(in.data() + 55) >> 1) & 0x1FFFFF;
    s22 = (load_4(in.data() + 57) >> 6) & 0x1FFFFF;
    s23 = (load_4(in.data() + 60) >> 3);

    // First reduction pass: reduce s23..s18
    s11 += s23 * SC_L0;
    s12 += s23 * SC_L1;
    s13 += s23 * SC_L2;
    s14 -= s23 * SC_L3;
    s15 += s23 * SC_L4;
    s16 -= s23 * SC_L5;
    s23 = 0;

    s10 += s22 * SC_L0;
    s11 += s22 * SC_L1;
    s12 += s22 * SC_L2;
    s13 -= s22 * SC_L3;
    s14 += s22 * SC_L4;
    s15 -= s22 * SC_L5;
    s22 = 0;

    s9 += s21 * SC_L0;
    s10 += s21 * SC_L1;
    s11 += s21 * SC_L2;
    s12 -= s21 * SC_L3;
    s13 += s21 * SC_L4;
    s14 -= s21 * SC_L5;
    s21 = 0;

    s8 += s20 * SC_L0;
    s9 += s20 * SC_L1;
    s10 += s20 * SC_L2;
    s11 -= s20 * SC_L3;
    s12 += s20 * SC_L4;
    s13 -= s20 * SC_L5;
    s20 = 0;

    s7 += s19 * SC_L0;
    s8 += s19 * SC_L1;
    s9 += s19 * SC_L2;
    s10 -= s19 * SC_L3;
    s11 += s19 * SC_L4;
    s12 -= s19 * SC_L5;
    s19 = 0;

    s6 += s18 * SC_L0;
    s7 += s18 * SC_L1;
    s8 += s18 * SC_L2;
    s9 -= s18 * SC_L3;
    s10 += s18 * SC_L4;
    s11 -= s18 * SC_L5;
    s18 = 0;

    // Carry propagation
    carry = (s6 + (int64_t{1} << 20)) >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = (s8 + (int64_t{1} << 20)) >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = (s10 + (int64_t{1} << 20)) >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);
    carry = (s12 + (int64_t{1} << 20)) >> 21;
    s13 += carry;
    s12 -= carry * (int64_t{1} << 21);
    carry = (s14 + (int64_t{1} << 20)) >> 21;
    s15 += carry;
    s14 -= carry * (int64_t{1} << 21);
    carry = (s16 + (int64_t{1} << 20)) >> 21;
    s17 += carry;
    s16 -= carry * (int64_t{1} << 21);

    carry = (s7 + (int64_t{1} << 20)) >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = (s9 + (int64_t{1} << 20)) >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = (s11 + (int64_t{1} << 20)) >> 21;
    s12 += carry;
    s11 -= carry * (int64_t{1} << 21);
    carry = (s13 + (int64_t{1} << 20)) >> 21;
    s14 += carry;
    s13 -= carry * (int64_t{1} << 21);
    carry = (s15 + (int64_t{1} << 20)) >> 21;
    s16 += carry;
    s15 -= carry * (int64_t{1} << 21);

    // Second reduction pass: reduce s17..s12
    s5 += s17 * SC_L0;
    s6 += s17 * SC_L1;
    s7 += s17 * SC_L2;
    s8 -= s17 * SC_L3;
    s9 += s17 * SC_L4;
    s10 -= s17 * SC_L5;
    s17 = 0;

    s4 += s16 * SC_L0;
    s5 += s16 * SC_L1;
    s6 += s16 * SC_L2;
    s7 -= s16 * SC_L3;
    s8 += s16 * SC_L4;
    s9 -= s16 * SC_L5;
    s16 = 0;

    s3 += s15 * SC_L0;
    s4 += s15 * SC_L1;
    s5 += s15 * SC_L2;
    s6 -= s15 * SC_L3;
    s7 += s15 * SC_L4;
    s8 -= s15 * SC_L5;
    s15 = 0;

    s2 += s14 * SC_L0;
    s3 += s14 * SC_L1;
    s4 += s14 * SC_L2;
    s5 -= s14 * SC_L3;
    s6 += s14 * SC_L4;
    s7 -= s14 * SC_L5;
    s14 = 0;

    s1 += s13 * SC_L0;
    s2 += s13 * SC_L1;
    s3 += s13 * SC_L2;
    s4 -= s13 * SC_L3;
    s5 += s13 * SC_L4;
    s6 -= s13 * SC_L5;
    s13 = 0;

    s0 += s12 * SC_L0;
    s1 += s12 * SC_L1;
    s2 += s12 * SC_L2;
    s3 -= s12 * SC_L3;
    s4 += s12 * SC_L4;
    s5 -= s12 * SC_L5;
    s12 = 0;

    // Carry propagation
    carry = (s0 + (int64_t{1} << 20)) >> 21;
    s1 += carry;
    s0 -= carry * (int64_t{1} << 21);
    carry = (s2 + (int64_t{1} << 20)) >> 21;
    s3 += carry;
    s2 -= carry * (int64_t{1} << 21);
    carry = (s4 + (int64_t{1} << 20)) >> 21;
    s5 += carry;
    s4 -= carry * (int64_t{1} << 21);
    carry = (s6 + (int64_t{1} << 20)) >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = (s8 + (int64_t{1} << 20)) >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = (s10 + (int64_t{1} << 20)) >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);

    carry = (s1 + (int64_t{1} << 20)) >> 21;
    s2 += carry;
    s1 -= carry * (int64_t{1} << 21);
    carry = (s3 + (int64_t{1} << 20)) >> 21;
    s4 += carry;
    s3 -= carry * (int64_t{1} << 21);
    carry = (s5 + (int64_t{1} << 20)) >> 21;
    s6 += carry;
    s5 -= carry * (int64_t{1} << 21);
    carry = (s7 + (int64_t{1} << 20)) >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = (s9 + (int64_t{1} << 20)) >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = (s11 + (int64_t{1} << 20)) >> 21;
    s12 += carry;
    s11 -= carry * (int64_t{1} << 21);

    // Final reduction of s12
    s0 += s12 * SC_L0;
    s1 += s12 * SC_L1;
    s2 += s12 * SC_L2;
    s3 -= s12 * SC_L3;
    s4 += s12 * SC_L4;
    s5 -= s12 * SC_L5;
    s12 = 0;

    // First final carry chain (no rounding — simple >> 21)
    carry = s0 >> 21;
    s1 += carry;
    s0 -= carry * (int64_t{1} << 21);
    carry = s1 >> 21;
    s2 += carry;
    s1 -= carry * (int64_t{1} << 21);
    carry = s2 >> 21;
    s3 += carry;
    s2 -= carry * (int64_t{1} << 21);
    carry = s3 >> 21;
    s4 += carry;
    s3 -= carry * (int64_t{1} << 21);
    carry = s4 >> 21;
    s5 += carry;
    s4 -= carry * (int64_t{1} << 21);
    carry = s5 >> 21;
    s6 += carry;
    s5 -= carry * (int64_t{1} << 21);
    carry = s6 >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = s7 >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = s8 >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = s9 >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = s10 >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);
    carry = s11 >> 21;
    s12 += carry;
    s11 -= carry * (int64_t{1} << 21);

    // Second s12 fold-back
    s0 += s12 * SC_L0;
    s1 += s12 * SC_L1;
    s2 += s12 * SC_L2;
    s3 -= s12 * SC_L3;
    s4 += s12 * SC_L4;
    s5 -= s12 * SC_L5;

    // Second final carry chain (no rounding)
    carry = s0 >> 21;
    s1 += carry;
    s0 -= carry * (int64_t{1} << 21);
    carry = s1 >> 21;
    s2 += carry;
    s1 -= carry * (int64_t{1} << 21);
    carry = s2 >> 21;
    s3 += carry;
    s2 -= carry * (int64_t{1} << 21);
    carry = s3 >> 21;
    s4 += carry;
    s3 -= carry * (int64_t{1} << 21);
    carry = s4 >> 21;
    s5 += carry;
    s4 -= carry * (int64_t{1} << 21);
    carry = s5 >> 21;
    s6 += carry;
    s5 -= carry * (int64_t{1} << 21);
    carry = s6 >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = s7 >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = s8 >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = s9 >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = s10 >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);

    // Encode output
    std::array<uint8_t, curve25519_scalar_size> out{};
    out[0] = static_cast<uint8_t>(s0);
    out[1] = static_cast<uint8_t>(s0 >> 8);
    out[2] = static_cast<uint8_t>((s0 >> 16) | (s1 * 32));
    out[3] = static_cast<uint8_t>(s1 >> 3);
    out[4] = static_cast<uint8_t>(s1 >> 11);
    out[5] = static_cast<uint8_t>((s1 >> 19) | (s2 * 4));
    out[6] = static_cast<uint8_t>(s2 >> 6);
    out[7] = static_cast<uint8_t>((s2 >> 14) | (s3 * 128));
    out[8] = static_cast<uint8_t>(s3 >> 1);
    out[9] = static_cast<uint8_t>(s3 >> 9);
    out[10] = static_cast<uint8_t>((s3 >> 17) | (s4 * 16));
    out[11] = static_cast<uint8_t>(s4 >> 4);
    out[12] = static_cast<uint8_t>(s4 >> 12);
    out[13] = static_cast<uint8_t>((s4 >> 20) | (s5 * 2));
    out[14] = static_cast<uint8_t>(s5 >> 7);
    out[15] = static_cast<uint8_t>((s5 >> 15) | (s6 * 64));
    out[16] = static_cast<uint8_t>(s6 >> 2);
    out[17] = static_cast<uint8_t>(s6 >> 10);
    out[18] = static_cast<uint8_t>((s6 >> 18) | (s7 * 8));
    out[19] = static_cast<uint8_t>(s7 >> 5);
    out[20] = static_cast<uint8_t>(s7 >> 13);
    out[21] = static_cast<uint8_t>(s8);
    out[22] = static_cast<uint8_t>(s8 >> 8);
    out[23] = static_cast<uint8_t>((s8 >> 16) | (s9 * 32));
    out[24] = static_cast<uint8_t>(s9 >> 3);
    out[25] = static_cast<uint8_t>(s9 >> 11);
    out[26] = static_cast<uint8_t>((s9 >> 19) | (s10 * 4));
    out[27] = static_cast<uint8_t>(s10 >> 6);
    out[28] = static_cast<uint8_t>((s10 >> 14) | (s11 * 128));
    out[29] = static_cast<uint8_t>(s11 >> 1);
    out[30] = static_cast<uint8_t>(s11 >> 9);
    out[31] = static_cast<uint8_t>(s11 >> 17);
    return out;
}

// Compute (a * b + c) mod L. Same 21-bit limb representation as sc_reduce.
// Steps:
//   1. Load a, b, c as 12 x 21-bit limbs each
//   2. Schoolbook multiply a*b producing 23 x 42-bit products
//   3. Add c to the lower limbs
//   4. Reduce high limbs (s23..s18) mod L using the same 6 reduction coefficients
//   5. Carry propagation
//   6. Second reduction pass for s17..s12
//   7. Final carry and serialization to 32 bytes
auto sc_mul_add(
    span<uint8_t const, curve25519_scalar_size> a_bytes,
    span<uint8_t const, curve25519_scalar_size> b_bytes,
    span<uint8_t const, curve25519_scalar_size> c_bytes) -> std::array<uint8_t, curve25519_scalar_size>
{
    // RAII workspaces: all intermediate limbs are securely zeroed on scope exit.
    SecureWorkArray<int64_t, 12> a_work;  // a[0..11]
    auto& a0 = a_work[0];
    auto& a1 = a_work[1];
    auto& a2 = a_work[2];
    auto& a3 = a_work[3];
    auto& a4 = a_work[4];
    auto& a5 = a_work[5];
    auto& a6 = a_work[6];
    auto& a7 = a_work[7];
    auto& a8 = a_work[8];
    auto& a9 = a_work[9];
    auto& a10 = a_work[10];
    auto& a11 = a_work[11];

    SecureWorkArray<int64_t, 12> b_work;  // b[0..11]
    auto& b0 = b_work[0];
    auto& b1 = b_work[1];
    auto& b2 = b_work[2];
    auto& b3 = b_work[3];
    auto& b4 = b_work[4];
    auto& b5 = b_work[5];
    auto& b6 = b_work[6];
    auto& b7 = b_work[7];
    auto& b8 = b_work[8];
    auto& b9 = b_work[9];
    auto& b10 = b_work[10];
    auto& b11 = b_work[11];

    SecureWorkArray<int64_t, 12> c_work;  // c[0..11]
    auto& c0 = c_work[0];
    auto& c1 = c_work[1];
    auto& c2 = c_work[2];
    auto& c3 = c_work[3];
    auto& c4 = c_work[4];
    auto& c5 = c_work[5];
    auto& c6 = c_work[6];
    auto& c7 = c_work[7];
    auto& c8 = c_work[8];
    auto& c9 = c_work[9];
    auto& c10 = c_work[10];
    auto& c11 = c_work[11];

    SecureWorkArray<int64_t, 25> sc_work;  // s[0..23] + carry
    auto& s0 = sc_work[0];
    auto& s1 = sc_work[1];
    auto& s2 = sc_work[2];
    auto& s3 = sc_work[3];
    auto& s4 = sc_work[4];
    auto& s5 = sc_work[5];
    auto& s6 = sc_work[6];
    auto& s7 = sc_work[7];
    auto& s8 = sc_work[8];
    auto& s9 = sc_work[9];
    auto& s10 = sc_work[10];
    auto& s11 = sc_work[11];
    auto& s12 = sc_work[12];
    auto& s13 = sc_work[13];
    auto& s14 = sc_work[14];
    auto& s15 = sc_work[15];
    auto& s16 = sc_work[16];
    auto& s17 = sc_work[17];
    auto& s18 = sc_work[18];
    auto& s19 = sc_work[19];
    auto& s20 = sc_work[20];
    auto& s21 = sc_work[21];
    auto& s22 = sc_work[22];
    auto& s23 = sc_work[23];
    auto& carry = sc_work[24];

    // Load a (12 x 21-bit limbs)
    a0 = (load_4(a_bytes.data() + 0) >> 0) & 0x1FFFFF;
    a1 = (load_4(a_bytes.data() + 2) >> 5) & 0x1FFFFF;
    a2 = (load_3(a_bytes.data() + 5) >> 2) & 0x1FFFFF;
    a3 = (load_4(a_bytes.data() + 7) >> 7) & 0x1FFFFF;
    a4 = (load_4(a_bytes.data() + 10) >> 4) & 0x1FFFFF;
    a5 = (load_3(a_bytes.data() + 13) >> 1) & 0x1FFFFF;
    a6 = (load_4(a_bytes.data() + 15) >> 6) & 0x1FFFFF;
    a7 = (load_3(a_bytes.data() + 18) >> 3) & 0x1FFFFF;
    a8 = (load_4(a_bytes.data() + 21) >> 0) & 0x1FFFFF;
    a9 = (load_4(a_bytes.data() + 23) >> 5) & 0x1FFFFF;
    a10 = (load_3(a_bytes.data() + 26) >> 2) & 0x1FFFFF;
    a11 = (load_4(a_bytes.data() + 28) >> 7);

    // Load b
    b0 = (load_4(b_bytes.data() + 0) >> 0) & 0x1FFFFF;
    b1 = (load_4(b_bytes.data() + 2) >> 5) & 0x1FFFFF;
    b2 = (load_3(b_bytes.data() + 5) >> 2) & 0x1FFFFF;
    b3 = (load_4(b_bytes.data() + 7) >> 7) & 0x1FFFFF;
    b4 = (load_4(b_bytes.data() + 10) >> 4) & 0x1FFFFF;
    b5 = (load_3(b_bytes.data() + 13) >> 1) & 0x1FFFFF;
    b6 = (load_4(b_bytes.data() + 15) >> 6) & 0x1FFFFF;
    b7 = (load_3(b_bytes.data() + 18) >> 3) & 0x1FFFFF;
    b8 = (load_4(b_bytes.data() + 21) >> 0) & 0x1FFFFF;
    b9 = (load_4(b_bytes.data() + 23) >> 5) & 0x1FFFFF;
    b10 = (load_3(b_bytes.data() + 26) >> 2) & 0x1FFFFF;
    b11 = (load_4(b_bytes.data() + 28) >> 7);

    // Load c
    c0 = (load_4(c_bytes.data() + 0) >> 0) & 0x1FFFFF;
    c1 = (load_4(c_bytes.data() + 2) >> 5) & 0x1FFFFF;
    c2 = (load_3(c_bytes.data() + 5) >> 2) & 0x1FFFFF;
    c3 = (load_4(c_bytes.data() + 7) >> 7) & 0x1FFFFF;
    c4 = (load_4(c_bytes.data() + 10) >> 4) & 0x1FFFFF;
    c5 = (load_3(c_bytes.data() + 13) >> 1) & 0x1FFFFF;
    c6 = (load_4(c_bytes.data() + 15) >> 6) & 0x1FFFFF;
    c7 = (load_3(c_bytes.data() + 18) >> 3) & 0x1FFFFF;
    c8 = (load_4(c_bytes.data() + 21) >> 0) & 0x1FFFFF;
    c9 = (load_4(c_bytes.data() + 23) >> 5) & 0x1FFFFF;
    c10 = (load_3(c_bytes.data() + 26) >> 2) & 0x1FFFFF;
    c11 = (load_4(c_bytes.data() + 28) >> 7);

    // Compute s = a*b + c (24 limbs)
    s0 = c0 + (a0 * b0);
    s1 = c1 + (a0 * b1) + (a1 * b0);
    s2 = c2 + (a0 * b2) + (a1 * b1) + (a2 * b0);
    s3 = c3 + (a0 * b3) + (a1 * b2) + (a2 * b1) + (a3 * b0);
    s4 = c4 + (a0 * b4) + (a1 * b3) + (a2 * b2) + (a3 * b1) + (a4 * b0);
    s5 = c5 + (a0 * b5) + (a1 * b4) + (a2 * b3) + (a3 * b2) + (a4 * b1) + (a5 * b0);
    s6 = c6 + (a0 * b6) + (a1 * b5) + (a2 * b4) + (a3 * b3) + (a4 * b2) + (a5 * b1) + (a6 * b0);
    s7 = c7 + (a0 * b7) + (a1 * b6) + (a2 * b5) + (a3 * b4) + (a4 * b3) + (a5 * b2) + (a6 * b1) + (a7 * b0);
    s8 = c8 + (a0 * b8) + (a1 * b7) + (a2 * b6) + (a3 * b5) + (a4 * b4) + (a5 * b3) + (a6 * b2) + (a7 * b1) + (a8 * b0);
    s9 = c9 + (a0 * b9) + (a1 * b8) + (a2 * b7) + (a3 * b6) + (a4 * b5) + (a5 * b4) + (a6 * b3) + (a7 * b2) + (a8 * b1) + (a9 * b0);
    s10 = c10 + (a0 * b10) + (a1 * b9) + (a2 * b8) + (a3 * b7) + (a4 * b6) + (a5 * b5) + (a6 * b4) + (a7 * b3) + (a8 * b2) +
        (a9 * b1) + (a10 * b0);
    s11 = c11 + (a0 * b11) + (a1 * b10) + (a2 * b9) + (a3 * b8) + (a4 * b7) + (a5 * b6) + (a6 * b5) + (a7 * b4) + (a8 * b3) +
        (a9 * b2) + (a10 * b1) + (a11 * b0);
    s12 = (a1 * b11) + (a2 * b10) + (a3 * b9) + (a4 * b8) + (a5 * b7) + (a6 * b6) + (a7 * b5) + (a8 * b4) + (a9 * b3) + (a10 * b2) +
        (a11 * b1);
    s13 = (a2 * b11) + (a3 * b10) + (a4 * b9) + (a5 * b8) + (a6 * b7) + (a7 * b6) + (a8 * b5) + (a9 * b4) + (a10 * b3) + (a11 * b2);
    s14 = (a3 * b11) + (a4 * b10) + (a5 * b9) + (a6 * b8) + (a7 * b7) + (a8 * b6) + (a9 * b5) + (a10 * b4) + (a11 * b3);
    s15 = (a4 * b11) + (a5 * b10) + (a6 * b9) + (a7 * b8) + (a8 * b7) + (a9 * b6) + (a10 * b5) + (a11 * b4);
    s16 = (a5 * b11) + (a6 * b10) + (a7 * b9) + (a8 * b8) + (a9 * b7) + (a10 * b6) + (a11 * b5);
    s17 = (a6 * b11) + (a7 * b10) + (a8 * b9) + (a9 * b8) + (a10 * b7) + (a11 * b6);
    s18 = (a7 * b11) + (a8 * b10) + (a9 * b9) + (a10 * b8) + (a11 * b7);
    s19 = (a8 * b11) + (a9 * b10) + (a10 * b9) + (a11 * b8);
    s20 = (a9 * b11) + (a10 * b10) + (a11 * b9);
    s21 = (a10 * b11) + (a11 * b10);
    s22 = a11 * b11;
    s23 = 0;

    // Initial carry propagation (normalize product limbs before reduction)
    carry = (s0 + (int64_t{1} << 20)) >> 21;
    s1 += carry;
    s0 -= carry * (int64_t{1} << 21);
    carry = (s2 + (int64_t{1} << 20)) >> 21;
    s3 += carry;
    s2 -= carry * (int64_t{1} << 21);
    carry = (s4 + (int64_t{1} << 20)) >> 21;
    s5 += carry;
    s4 -= carry * (int64_t{1} << 21);
    carry = (s6 + (int64_t{1} << 20)) >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = (s8 + (int64_t{1} << 20)) >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = (s10 + (int64_t{1} << 20)) >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);
    carry = (s12 + (int64_t{1} << 20)) >> 21;
    s13 += carry;
    s12 -= carry * (int64_t{1} << 21);
    carry = (s14 + (int64_t{1} << 20)) >> 21;
    s15 += carry;
    s14 -= carry * (int64_t{1} << 21);
    carry = (s16 + (int64_t{1} << 20)) >> 21;
    s17 += carry;
    s16 -= carry * (int64_t{1} << 21);
    carry = (s18 + (int64_t{1} << 20)) >> 21;
    s19 += carry;
    s18 -= carry * (int64_t{1} << 21);
    carry = (s20 + (int64_t{1} << 20)) >> 21;
    s21 += carry;
    s20 -= carry * (int64_t{1} << 21);
    carry = (s22 + (int64_t{1} << 20)) >> 21;
    s23 += carry;
    s22 -= carry * (int64_t{1} << 21);

    carry = (s1 + (int64_t{1} << 20)) >> 21;
    s2 += carry;
    s1 -= carry * (int64_t{1} << 21);
    carry = (s3 + (int64_t{1} << 20)) >> 21;
    s4 += carry;
    s3 -= carry * (int64_t{1} << 21);
    carry = (s5 + (int64_t{1} << 20)) >> 21;
    s6 += carry;
    s5 -= carry * (int64_t{1} << 21);
    carry = (s7 + (int64_t{1} << 20)) >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = (s9 + (int64_t{1} << 20)) >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = (s11 + (int64_t{1} << 20)) >> 21;
    s12 += carry;
    s11 -= carry * (int64_t{1} << 21);
    carry = (s13 + (int64_t{1} << 20)) >> 21;
    s14 += carry;
    s13 -= carry * (int64_t{1} << 21);
    carry = (s15 + (int64_t{1} << 20)) >> 21;
    s16 += carry;
    s15 -= carry * (int64_t{1} << 21);
    carry = (s17 + (int64_t{1} << 20)) >> 21;
    s18 += carry;
    s17 -= carry * (int64_t{1} << 21);
    carry = (s19 + (int64_t{1} << 20)) >> 21;
    s20 += carry;
    s19 -= carry * (int64_t{1} << 21);
    carry = (s21 + (int64_t{1} << 20)) >> 21;
    s22 += carry;
    s21 -= carry * (int64_t{1} << 21);

    // First reduction pass: reduce s23..s18
    s11 += s23 * SC_L0;
    s12 += s23 * SC_L1;
    s13 += s23 * SC_L2;
    s14 -= s23 * SC_L3;
    s15 += s23 * SC_L4;
    s16 -= s23 * SC_L5;
    s23 = 0;

    s10 += s22 * SC_L0;
    s11 += s22 * SC_L1;
    s12 += s22 * SC_L2;
    s13 -= s22 * SC_L3;
    s14 += s22 * SC_L4;
    s15 -= s22 * SC_L5;
    s22 = 0;

    s9 += s21 * SC_L0;
    s10 += s21 * SC_L1;
    s11 += s21 * SC_L2;
    s12 -= s21 * SC_L3;
    s13 += s21 * SC_L4;
    s14 -= s21 * SC_L5;
    s21 = 0;

    s8 += s20 * SC_L0;
    s9 += s20 * SC_L1;
    s10 += s20 * SC_L2;
    s11 -= s20 * SC_L3;
    s12 += s20 * SC_L4;
    s13 -= s20 * SC_L5;
    s20 = 0;

    s7 += s19 * SC_L0;
    s8 += s19 * SC_L1;
    s9 += s19 * SC_L2;
    s10 -= s19 * SC_L3;
    s11 += s19 * SC_L4;
    s12 -= s19 * SC_L5;
    s19 = 0;

    s6 += s18 * SC_L0;
    s7 += s18 * SC_L1;
    s8 += s18 * SC_L2;
    s9 -= s18 * SC_L3;
    s10 += s18 * SC_L4;
    s11 -= s18 * SC_L5;
    s18 = 0;

    // Carry propagation
    carry = (s6 + (int64_t{1} << 20)) >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = (s8 + (int64_t{1} << 20)) >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = (s10 + (int64_t{1} << 20)) >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);
    carry = (s12 + (int64_t{1} << 20)) >> 21;
    s13 += carry;
    s12 -= carry * (int64_t{1} << 21);
    carry = (s14 + (int64_t{1} << 20)) >> 21;
    s15 += carry;
    s14 -= carry * (int64_t{1} << 21);
    carry = (s16 + (int64_t{1} << 20)) >> 21;
    s17 += carry;
    s16 -= carry * (int64_t{1} << 21);

    carry = (s7 + (int64_t{1} << 20)) >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = (s9 + (int64_t{1} << 20)) >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = (s11 + (int64_t{1} << 20)) >> 21;
    s12 += carry;
    s11 -= carry * (int64_t{1} << 21);
    carry = (s13 + (int64_t{1} << 20)) >> 21;
    s14 += carry;
    s13 -= carry * (int64_t{1} << 21);
    carry = (s15 + (int64_t{1} << 20)) >> 21;
    s16 += carry;
    s15 -= carry * (int64_t{1} << 21);

    // Second reduction pass
    s5 += s17 * SC_L0;
    s6 += s17 * SC_L1;
    s7 += s17 * SC_L2;
    s8 -= s17 * SC_L3;
    s9 += s17 * SC_L4;
    s10 -= s17 * SC_L5;
    s17 = 0;

    s4 += s16 * SC_L0;
    s5 += s16 * SC_L1;
    s6 += s16 * SC_L2;
    s7 -= s16 * SC_L3;
    s8 += s16 * SC_L4;
    s9 -= s16 * SC_L5;
    s16 = 0;

    s3 += s15 * SC_L0;
    s4 += s15 * SC_L1;
    s5 += s15 * SC_L2;
    s6 -= s15 * SC_L3;
    s7 += s15 * SC_L4;
    s8 -= s15 * SC_L5;
    s15 = 0;

    s2 += s14 * SC_L0;
    s3 += s14 * SC_L1;
    s4 += s14 * SC_L2;
    s5 -= s14 * SC_L3;
    s6 += s14 * SC_L4;
    s7 -= s14 * SC_L5;
    s14 = 0;

    s1 += s13 * SC_L0;
    s2 += s13 * SC_L1;
    s3 += s13 * SC_L2;
    s4 -= s13 * SC_L3;
    s5 += s13 * SC_L4;
    s6 -= s13 * SC_L5;
    s13 = 0;

    s0 += s12 * SC_L0;
    s1 += s12 * SC_L1;
    s2 += s12 * SC_L2;
    s3 -= s12 * SC_L3;
    s4 += s12 * SC_L4;
    s5 -= s12 * SC_L5;
    s12 = 0;

    // Carry propagation
    carry = (s0 + (int64_t{1} << 20)) >> 21;
    s1 += carry;
    s0 -= carry * (int64_t{1} << 21);
    carry = (s2 + (int64_t{1} << 20)) >> 21;
    s3 += carry;
    s2 -= carry * (int64_t{1} << 21);
    carry = (s4 + (int64_t{1} << 20)) >> 21;
    s5 += carry;
    s4 -= carry * (int64_t{1} << 21);
    carry = (s6 + (int64_t{1} << 20)) >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = (s8 + (int64_t{1} << 20)) >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = (s10 + (int64_t{1} << 20)) >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);

    carry = (s1 + (int64_t{1} << 20)) >> 21;
    s2 += carry;
    s1 -= carry * (int64_t{1} << 21);
    carry = (s3 + (int64_t{1} << 20)) >> 21;
    s4 += carry;
    s3 -= carry * (int64_t{1} << 21);
    carry = (s5 + (int64_t{1} << 20)) >> 21;
    s6 += carry;
    s5 -= carry * (int64_t{1} << 21);
    carry = (s7 + (int64_t{1} << 20)) >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = (s9 + (int64_t{1} << 20)) >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = (s11 + (int64_t{1} << 20)) >> 21;
    s12 += carry;
    s11 -= carry * (int64_t{1} << 21);

    // Final reduction of s12
    s0 += s12 * SC_L0;
    s1 += s12 * SC_L1;
    s2 += s12 * SC_L2;
    s3 -= s12 * SC_L3;
    s4 += s12 * SC_L4;
    s5 -= s12 * SC_L5;
    s12 = 0;

    // First final carry chain (no rounding — simple >> 21)
    carry = s0 >> 21;
    s1 += carry;
    s0 -= carry * (int64_t{1} << 21);
    carry = s1 >> 21;
    s2 += carry;
    s1 -= carry * (int64_t{1} << 21);
    carry = s2 >> 21;
    s3 += carry;
    s2 -= carry * (int64_t{1} << 21);
    carry = s3 >> 21;
    s4 += carry;
    s3 -= carry * (int64_t{1} << 21);
    carry = s4 >> 21;
    s5 += carry;
    s4 -= carry * (int64_t{1} << 21);
    carry = s5 >> 21;
    s6 += carry;
    s5 -= carry * (int64_t{1} << 21);
    carry = s6 >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = s7 >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = s8 >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = s9 >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = s10 >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);
    carry = s11 >> 21;
    s12 += carry;
    s11 -= carry * (int64_t{1} << 21);

    // Second s12 fold-back
    s0 += s12 * SC_L0;
    s1 += s12 * SC_L1;
    s2 += s12 * SC_L2;
    s3 -= s12 * SC_L3;
    s4 += s12 * SC_L4;
    s5 -= s12 * SC_L5;

    // Second final carry chain (no rounding)
    carry = s0 >> 21;
    s1 += carry;
    s0 -= carry * (int64_t{1} << 21);
    carry = s1 >> 21;
    s2 += carry;
    s1 -= carry * (int64_t{1} << 21);
    carry = s2 >> 21;
    s3 += carry;
    s2 -= carry * (int64_t{1} << 21);
    carry = s3 >> 21;
    s4 += carry;
    s3 -= carry * (int64_t{1} << 21);
    carry = s4 >> 21;
    s5 += carry;
    s4 -= carry * (int64_t{1} << 21);
    carry = s5 >> 21;
    s6 += carry;
    s5 -= carry * (int64_t{1} << 21);
    carry = s6 >> 21;
    s7 += carry;
    s6 -= carry * (int64_t{1} << 21);
    carry = s7 >> 21;
    s8 += carry;
    s7 -= carry * (int64_t{1} << 21);
    carry = s8 >> 21;
    s9 += carry;
    s8 -= carry * (int64_t{1} << 21);
    carry = s9 >> 21;
    s10 += carry;
    s9 -= carry * (int64_t{1} << 21);
    carry = s10 >> 21;
    s11 += carry;
    s10 -= carry * (int64_t{1} << 21);

    // Encode output
    std::array<uint8_t, curve25519_scalar_size> out{};
    out[0] = static_cast<uint8_t>(s0);
    out[1] = static_cast<uint8_t>(s0 >> 8);
    out[2] = static_cast<uint8_t>((s0 >> 16) | (s1 * 32));
    out[3] = static_cast<uint8_t>(s1 >> 3);
    out[4] = static_cast<uint8_t>(s1 >> 11);
    out[5] = static_cast<uint8_t>((s1 >> 19) | (s2 * 4));
    out[6] = static_cast<uint8_t>(s2 >> 6);
    out[7] = static_cast<uint8_t>((s2 >> 14) | (s3 * 128));
    out[8] = static_cast<uint8_t>(s3 >> 1);
    out[9] = static_cast<uint8_t>(s3 >> 9);
    out[10] = static_cast<uint8_t>((s3 >> 17) | (s4 * 16));
    out[11] = static_cast<uint8_t>(s4 >> 4);
    out[12] = static_cast<uint8_t>(s4 >> 12);
    out[13] = static_cast<uint8_t>((s4 >> 20) | (s5 * 2));
    out[14] = static_cast<uint8_t>(s5 >> 7);
    out[15] = static_cast<uint8_t>((s5 >> 15) | (s6 * 64));
    out[16] = static_cast<uint8_t>(s6 >> 2);
    out[17] = static_cast<uint8_t>(s6 >> 10);
    out[18] = static_cast<uint8_t>((s6 >> 18) | (s7 * 8));
    out[19] = static_cast<uint8_t>(s7 >> 5);
    out[20] = static_cast<uint8_t>(s7 >> 13);
    out[21] = static_cast<uint8_t>(s8);
    out[22] = static_cast<uint8_t>(s8 >> 8);
    out[23] = static_cast<uint8_t>((s8 >> 16) | (s9 * 32));
    out[24] = static_cast<uint8_t>(s9 >> 3);
    out[25] = static_cast<uint8_t>(s9 >> 11);
    out[26] = static_cast<uint8_t>((s9 >> 19) | (s10 * 4));
    out[27] = static_cast<uint8_t>(s10 >> 6);
    out[28] = static_cast<uint8_t>((s10 >> 14) | (s11 * 128));
    out[29] = static_cast<uint8_t>(s11 >> 1);
    out[30] = static_cast<uint8_t>(s11 >> 9);
    out[31] = static_cast<uint8_t>(s11 >> 17);
    return out;
}

auto sc_reduce_secure(span<uint8_t const, curve25519_wide_scalar_size> s) -> SecureArray<curve25519_scalar_size>
{
    return SecureArray<curve25519_scalar_size>(sc_reduce(s));
}

auto sc_mul_add_secure(
    span<uint8_t const, curve25519_scalar_size> a,
    span<uint8_t const, curve25519_scalar_size> b,
    span<uint8_t const, curve25519_scalar_size> c) -> SecureArray<curve25519_scalar_size>
{
    return SecureArray<curve25519_scalar_size>(sc_mul_add(a, b, c));
}

}  // namespace statusbar::crypto
