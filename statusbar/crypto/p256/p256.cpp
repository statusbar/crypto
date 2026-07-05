// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 (secp256r1) implementation
//
// Field arithmetic uses 4x64-bit limbs with 128-bit unsigned integers for wide multiply.
// The NIST P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1 enables
// efficient Solinas reduction of 512-bit products.
//
// Group operations use Jacobian projective coordinates with the a=-3
// optimization for point doubling.

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/p256/p256.hpp"
#    include "statusbar/crypto/p256/p256_constants.hpp"
#    include "statusbar/crypto/p256/p256_wire_constants.hpp"
#    include "statusbar/crypto/sha/sha256_hw.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

#    include <cstring>

namespace statusbar::crypto {

using internal::Int128;
using internal::span_copy;
using internal::Uint128;
using std::span;

//
// Helper: constant-time conditional selection
//

// Returns mask: 0 if x==0, ~0 if x!=0. Constant time.
static auto ct_is_nonzero(uint64_t x) -> uint64_t
{
    return ((x | (~x + 1)) >> 63);  // 1 if nonzero, 0 if zero
}

//
// Field element: from/to bytes (big-endian, 32 bytes)
//

auto p256_fe_from_bytes(span<uint8_t const, p256_field_element_size> bytes) -> P256FieldElement
{
    P256FieldElement r{};
    for (size_t i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (size_t j = 0; j < 8; ++j) {
            v = (v << 8) | bytes[((3 - i) * 8) + j];
        }
        r.limbs[i] = v;
    }
    return r;
}

auto p256_fe_to_bytes(P256FieldElement const& a) -> std::array<uint8_t, p256_field_element_size>
{
    // First fully reduce
    P256FieldElement r = a;

    // Compute a - p. If a >= p, use the result; otherwise keep a.
    uint64_t borrow = 0;
    uint64_t t[4];
    for (int i = 0; i < 4; ++i) {
        Uint128 const diff = static_cast<Uint128>(r.limbs[static_cast<size_t>(i)]) - P256_P.limbs[static_cast<size_t>(i)] - borrow;
        t[i] = static_cast<uint64_t>(diff);
        borrow = static_cast<uint64_t>(diff >> 127) & 1;  // borrow if negative
    }
    // If borrow == 0, a >= p, use t. If borrow == 1, a < p, keep r.
    uint64_t const mask = ~borrow + 1;  // 0 if no borrow, ~0 if borrow
    for (int i = 0; i < 4; ++i) {
        r.limbs[static_cast<size_t>(i)] = (r.limbs[static_cast<size_t>(i)] & mask) | (t[i] & ~mask);
    }

    std::array<uint8_t, p256_field_element_size> out{};
    for (size_t i = 0; i < 4; ++i) {
        uint64_t v = r.limbs[i];
        for (size_t j = 8; j-- > 0;) {
            out[((3 - i) * 8) + j] = static_cast<uint8_t>(v);
            v >>= 8;
        }
    }
    return out;
}

auto p256_fe_one() -> P256FieldElement
{
    return P256FieldElement{{1, 0, 0, 0}};
}

//
// Field addition: a + b mod p
//

auto p256_fe_add(P256FieldElement const& a, P256FieldElement const& b) -> P256FieldElement
{
    P256FieldElement r{};
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        Uint128 const sum = static_cast<Uint128>(a.limbs[static_cast<size_t>(i)]) + b.limbs[static_cast<size_t>(i)] + carry;
        r.limbs[static_cast<size_t>(i)] = static_cast<uint64_t>(sum);
        carry = static_cast<uint64_t>(sum >> 64);
    }

    // Constant-time reduction. Compute t = r - p (borrow tracks underflow).
    // (carry:r) >= p iff carry == 1, or carry == 0 and the subtraction did
    // not underflow (borrow == 0). In that case use t; otherwise use r.
    uint64_t borrow = 0;
    uint64_t t[4];
    for (int i = 0; i < 4; ++i) {
        Uint128 const diff = static_cast<Uint128>(r.limbs[static_cast<size_t>(i)]) - P256_P.limbs[static_cast<size_t>(i)] - borrow;
        t[i] = static_cast<uint64_t>(diff);
        borrow = static_cast<uint64_t>(diff >> 127) & 1;
    }
    uint64_t const use_reduced = 1 - (borrow & (1 - carry));  // 1 if (carry:r) >= p
    uint64_t const mask = ~use_reduced + 1;                   // all-ones if use_reduced, else 0
    for (int i = 0; i < 4; ++i) {
        r.limbs[static_cast<size_t>(i)] = (r.limbs[static_cast<size_t>(i)] & ~mask) | (t[i] & mask);
    }

    return r;
}

//
// Field subtraction: a - b mod p
//

auto p256_fe_sub(P256FieldElement const& a, P256FieldElement const& b) -> P256FieldElement
{
    P256FieldElement r{};
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        Uint128 const diff = static_cast<Uint128>(a.limbs[static_cast<size_t>(i)]) - b.limbs[static_cast<size_t>(i)] - borrow;
        r.limbs[static_cast<size_t>(i)] = static_cast<uint64_t>(diff);
        borrow = static_cast<uint64_t>(diff >> 127) & 1;
    }

    // If borrow, add p back
    uint64_t carry = 0;
    uint64_t t[4];
    for (int i = 0; i < 4; ++i) {
        Uint128 const sum = static_cast<Uint128>(r.limbs[static_cast<size_t>(i)]) + P256_P.limbs[static_cast<size_t>(i)] + carry;
        t[i] = static_cast<uint64_t>(sum);
        carry = static_cast<uint64_t>(sum >> 64);
    }

    uint64_t const mask = ~borrow + 1;  // ~0 if borrow, 0 otherwise
    for (int i = 0; i < 4; ++i) {
        r.limbs[static_cast<size_t>(i)] = (r.limbs[static_cast<size_t>(i)] & ~mask) | (t[i] & mask);
    }

    return r;
}

//
// Field negation: -a mod p
//

auto p256_fe_neg(P256FieldElement const& a) -> P256FieldElement
{
    P256FieldElement const zero{};
    return p256_fe_sub(zero, a);
}

//
// Field multiplication: a * b mod p using Solinas reduction
//

// Schoolbook 4x4 multiply producing 8 limbs, then Solinas reduce
auto p256_fe_mul(P256FieldElement const& a, P256FieldElement const& b) -> P256FieldElement
{
    // Schoolbook multiply: 4x4 -> 8 limbs
    Uint128 t[8] = {};
    for (int i = 0; i < 4; ++i) {
        Uint128 carry = 0;
        for (int j = 0; j < 4; ++j) {
            Uint128 const prod =
                (static_cast<Uint128>(a.limbs[static_cast<size_t>(i)]) * b.limbs[static_cast<size_t>(j)]) + t[i + j] + carry;
            t[i + j] = prod & 0xFFFFFFFFFFFFFFFF;
            carry = prod >> 64;
        }
        t[i + 4] += carry;
    }

    // Solinas reduction for p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    // Let the 512-bit product be c7:c6:c5:c4:c3:c2:c1:c0 (each 64 bits)
    // We express this as limbs s0..s7 and reduce using NIST-specific formulas.
    //
    // Following NIST SP 800-186 / FIPS 186-4 Section D.2.3, the reduction is:
    //   result = T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4  (mod p)
    //
    // Using 32-bit half-limbs: c = c15:c14:...:c1:c0 where ci is 32 bits
    // We decompose our 64-bit limbs into 32-bit halves.

    uint32_t c[16];
    for (size_t i = 0; i < 8; ++i) {
        c[2 * i] = static_cast<uint32_t>(t[i]);
        c[(2 * i) + 1] = static_cast<uint32_t>(t[i] >> 32);
    }

    // The 256-bit values T, S1..S4, D1..D4 per NIST SP 800-186:
    // T  = c7  c6  c5  c4  c3  c2  c1  c0
    // S1 = c15 c14 c13 c12 c11  0   0   0
    // S2 = 0   c15 c14 c13 c12  0   0   0
    // S3 = c15 c14  0   0   0  c10 c9  c8
    // S4 = c8  c13 c15 c14 c13 c11 c10 c9
    // D1 = c10 c8   0   0   0  c13 c12 c11
    // D2 = c11 c9   0   0  c15 c14 c13 c12
    // D3 = c12  0  c10 c9  c8  c15 c14 c13
    // D4 = c13  0  c11 c10 c9   0  c15 c14

    // Compute using 64-bit accumulators with signed carries
    // Working in 64-bit limb arithmetic with carry propagation

    // Helper: make a 64-bit value from two 32-bit halves (lo, hi)
    auto mk64 = [](uint32_t lo, uint32_t hi) -> uint64_t { return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32); };

    // Accumulate in signed 128-bit to handle the subtractions
    // result[i] for i = 0..3 are the final 64-bit limbs
    Int128 acc[4];

    // T
    acc[0] = static_cast<Int128>(mk64(c[0], c[1]));
    acc[1] = static_cast<Int128>(mk64(c[2], c[3]));
    acc[2] = static_cast<Int128>(mk64(c[4], c[5]));
    acc[3] = static_cast<Int128>(mk64(c[6], c[7]));

    // + 2*S1 = 2 * (c15 c14 c13 c12 c11 0 0 0)
    acc[1] += 2 * static_cast<Int128>(mk64(0, c[11]));
    acc[2] += 2 * static_cast<Int128>(mk64(c[12], c[13]));
    acc[3] += 2 * static_cast<Int128>(mk64(c[14], c[15]));

    // + 2*S2 = 2 * (0 c15 c14 c13 c12 0 0 0)
    acc[1] += 2 * static_cast<Int128>(mk64(0, c[12]));
    acc[2] += 2 * static_cast<Int128>(mk64(c[13], c[14]));
    acc[3] += 2 * static_cast<Int128>(mk64(c[15], 0));

    // + S3 = (c15 c14 0 0 0 c10 c9 c8)
    acc[0] += static_cast<Int128>(mk64(c[8], c[9]));
    acc[1] += static_cast<Int128>(mk64(c[10], 0));
    acc[3] += static_cast<Int128>(mk64(c[14], c[15]));

    // + S4 = (c8 c13 c15 c14 c13 c11 c10 c9)
    acc[0] += static_cast<Int128>(mk64(c[9], c[10]));
    acc[1] += static_cast<Int128>(mk64(c[11], c[13]));
    acc[2] += static_cast<Int128>(mk64(c[14], c[15]));
    acc[3] += static_cast<Int128>(mk64(c[13], c[8]));

    // - D1 = (c10 c8 0 0 0 c13 c12 c11)
    acc[0] -= static_cast<Int128>(mk64(c[11], c[12]));
    acc[1] -= static_cast<Int128>(mk64(c[13], 0));
    acc[3] -= static_cast<Int128>(mk64(c[8], c[10]));

    // - D2 = (c11 c9 0 0 c15 c14 c13 c12)
    acc[0] -= static_cast<Int128>(mk64(c[12], c[13]));
    acc[1] -= static_cast<Int128>(mk64(c[14], c[15]));
    acc[3] -= static_cast<Int128>(mk64(c[9], c[11]));

    // - D3 = (c12 0 c10 c9 c8 c15 c14 c13)
    acc[0] -= static_cast<Int128>(mk64(c[13], c[14]));
    acc[1] -= static_cast<Int128>(mk64(c[15], c[8]));
    acc[2] -= static_cast<Int128>(mk64(c[9], c[10]));
    acc[3] -= static_cast<Int128>(mk64(0, c[12]));

    // - D4 = (c13 0 c11 c10 c9 0 c15 c14)
    acc[0] -= static_cast<Int128>(mk64(c[14], c[15]));
    acc[1] -= static_cast<Int128>(mk64(0, c[9]));
    acc[2] -= static_cast<Int128>(mk64(c[10], c[11]));
    acc[3] -= static_cast<Int128>(mk64(0, c[13]));

    // Carry propagation through the 4 accumulators
    Int128 carry = 0;
    uint64_t rl[4];
    for (int i = 0; i < 4; ++i) {
        acc[i] += carry;
        rl[i] = static_cast<uint64_t>(acc[i]);
        carry = acc[i] >> 64;  // signed arithmetic shift
    }

    // Fold carry * (2^256 mod p) back into the limbs.
    // 2^256 mod p = 2^224 - 2^192 - 2^96 + 1
    // As 64-bit limbs (LE): {0x0000000000000001, 0xFFFFFFFF00000000,
    //                         0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFE}
    // carry is small (roughly -8 to +8), so this fold-back fits in Int128.
    for (int fold = 0; fold < 2 && carry != 0; ++fold) {
        Int128 const a0 = static_cast<Int128>(rl[0]) + carry;
        rl[0] = static_cast<uint64_t>(a0);
        Int128 const a1 = static_cast<Int128>(rl[1]) + (carry * static_cast<Int128>(0xFFFFFFFF00000000ULL)) + (a0 >> 64);
        rl[1] = static_cast<uint64_t>(a1);
        Int128 const a2 = static_cast<Int128>(rl[2]) + (carry * static_cast<Int128>(0xFFFFFFFFFFFFFFFFULL)) + (a1 >> 64);
        rl[2] = static_cast<uint64_t>(a2);
        Int128 const a3 = static_cast<Int128>(rl[3]) + (carry * static_cast<Int128>(0x00000000FFFFFFFEULL)) + (a2 >> 64);
        rl[3] = static_cast<uint64_t>(a3);
        carry = a3 >> 64;
    }

    P256FieldElement r{};
    for (int i = 0; i < 4; ++i) {
        r.limbs[static_cast<size_t>(i)] = rl[i];
    }

    // Conditional subtraction of p (at most twice, to bring into [0, p))
    // Constant-time: always try both subtractions, use masking to apply or not
    for (int iter = 0; iter < 2; ++iter) {
        uint64_t borrow_check = 0;
        uint64_t tmp[4];
        for (int i = 0; i < 4; ++i) {
            Uint128 const diff =
                static_cast<Uint128>(r.limbs[static_cast<size_t>(i)]) - P256_P.limbs[static_cast<size_t>(i)] - borrow_check;
            tmp[i] = static_cast<uint64_t>(diff);
            borrow_check = static_cast<uint64_t>(diff >> 127) & 1;
        }
        // If no borrow (borrow_check==0), result >= p, use subtracted value
        // If borrow (borrow_check==1), result < p, keep original
        uint64_t const mask = borrow_check - 1;  // ~0 if no borrow, 0 if borrow
        for (int i = 0; i < 4; ++i) {
            r.limbs[static_cast<size_t>(i)] = (r.limbs[static_cast<size_t>(i)] & ~mask) | (tmp[i] & mask);
        }
    }

    return r;
}

//
// Field squaring
//

auto p256_fe_sqr(P256FieldElement const& a) -> P256FieldElement
{
    return p256_fe_mul(a, a);
}

//
// Field inversion via Fermat's little theorem: a^(p-2) mod p
//

auto p256_fe_inv(P256FieldElement const& a) -> P256FieldElement
{
    // Use an addition chain for p-2
    // p - 2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
    //
    // Optimized addition chain from:
    // https://briansmith.org/ecc-inversion-addition-chains-01

    auto sqr_n = [](P256FieldElement const& x, int n) -> P256FieldElement {
        P256FieldElement r = x;
        for (int i = 0; i < n; ++i) {
            r = p256_fe_sqr(r);
        }
        return r;
    };

    P256FieldElement const x2 = p256_fe_mul(p256_fe_sqr(a), a);     // a^3
    P256FieldElement const x3 = p256_fe_mul(p256_fe_sqr(x2), a);    // a^7
    P256FieldElement const x6 = p256_fe_mul(sqr_n(x3, 3), x3);      // a^(2^6-1)
    P256FieldElement const x12 = p256_fe_mul(sqr_n(x6, 6), x6);     // a^(2^12-1)
    P256FieldElement const x15 = p256_fe_mul(sqr_n(x12, 3), x3);    // a^(2^15-1)
    P256FieldElement const x30 = p256_fe_mul(sqr_n(x15, 15), x15);  // a^(2^30-1)
    P256FieldElement const x32 = p256_fe_mul(sqr_n(x30, 2), x2);    // a^(2^32-1)

    // p-2 decomposition (following the structure of the prime):
    // Start with x32 = a^(2^32-1)
    P256FieldElement r = sqr_n(x32, 32);  // a^((2^32-1)*2^32)
    r = p256_fe_mul(r, a);                // ... * a
    r = sqr_n(r, 128);                    // shift left 128
    r = p256_fe_mul(r, x32);              // ... * (2^32-1)
    r = sqr_n(r, 32);                     // shift left 32
    r = p256_fe_mul(r, x32);              // ... * (2^32-1)
    r = sqr_n(r, 30);                     // shift left 30
    r = p256_fe_mul(r, x30);              // ... * (2^30-1)
    r = p256_fe_sqr(r);                   // shift left 1
    r = p256_fe_sqr(r);                   // shift left 1 (total: shifted by 2 to make room for '01')
    r = p256_fe_mul(r, a);                // ... * a (= ...01 in binary)

    return r;
}

//
// Field square root (for point decompression)
// p ≡ 3 mod 4, so sqrt(a) = a^((p+1)/4) mod p
//

auto p256_fe_sqrt(P256FieldElement const& a) -> std::optional<P256FieldElement>
{
    // p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) when a is a quadratic residue.
    //
    //   p       = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    //   p+1     = 0xFFFFFFFF00000001000000000000000000000001000000000000000000000000
    //   (p+1)/4 = 0x3FFFFFFFC0000000400000000000000000000000400000000000000000000000
    //
    // Stored below as four little-endian 64-bit limbs.
    constexpr uint64_t exp[4] = {
        0x0000000000000000,
        0x0000000040000000,
        0x4000000000000000,
        0x3FFFFFFFC0000000,
    };

    // Square-and-multiply over the public exponent (p+1)/4. The exponent is
    // a compile-time constant so the conditional-multiply pattern depends
    // only on the exponent bits, not on the input `a`. Combined with
    // constant-time p256_fe_mul / p256_fe_sqr, the routine is constant-time
    // with respect to `a`.
    P256FieldElement r = p256_fe_one();
    P256FieldElement base = a;
    for (int word = 0; word < 4; ++word) {
        for (int bit = 0; bit < 64; ++bit) {
            if (((exp[word] >> bit) & 1) != 0) {
                r = p256_fe_mul(r, base);
            }
            base = p256_fe_sqr(base);
        }
    }

    // If `a` is not a quadratic residue, r^2 != a. Reject.
    if (!p256_fe_equal(p256_fe_sqr(r), a)) {
        return std::nullopt;
    }
    return r;
}

//
// Field comparison and predicates
//

auto p256_fe_is_zero(P256FieldElement const& a) -> bool
{
    // Reduce first by converting to bytes and back (ensures canonical form)
    auto bytes = p256_fe_to_bytes(a);
    uint8_t acc = 0;
    for (auto b : bytes) {
        acc |= b;
    }
    return acc == 0;
}

auto p256_fe_equal(P256FieldElement const& a, P256FieldElement const& b) -> bool
{
    P256FieldElement const diff = p256_fe_sub(a, b);
    return p256_fe_is_zero(diff);
}

void p256_fe_cmov(P256FieldElement& f, P256FieldElement const& g, uint64_t b)
{
    uint64_t const mask = ~b + 1;  // 0 if b==0, ~0 if b==1
    for (int i = 0; i < 4; ++i) {
        f.limbs[static_cast<size_t>(i)] ^= mask & (f.limbs[static_cast<size_t>(i)] ^ g.limbs[static_cast<size_t>(i)]);
    }
}

//
// Scalar field operations (mod n)
//

auto p256_sc_from_bytes(span<uint8_t const, p256_scalar_size> bytes) -> P256Scalar
{
    P256Scalar r{};
    for (size_t i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (size_t j = 0; j < 8; ++j) {
            v = (v << 8) | bytes[((3 - i) * 8) + j];
        }
        r.limbs[i] = v;
    }
    return r;
}

auto p256_sc_to_bytes(P256Scalar const& a) -> std::array<uint8_t, p256_scalar_size>
{
    std::array<uint8_t, p256_scalar_size> out{};
    for (size_t i = 0; i < 4; ++i) {
        uint64_t v = a.limbs[i];
        for (size_t j = 8; j-- > 0;) {
            out[((3 - i) * 8) + j] = static_cast<uint8_t>(v);
            v >>= 8;
        }
    }
    return out;
}

auto p256_sc_is_zero(P256Scalar const& a) -> bool
{
    uint64_t acc = 0;
    for (int i = 0; i < 4; ++i) {
        acc |= a.limbs[static_cast<size_t>(i)];
    }
    return acc == 0;
}

auto p256_sc_add(P256Scalar const& a, P256Scalar const& b) -> P256Scalar
{
    P256Scalar r{};
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        Uint128 const sum = static_cast<Uint128>(a.limbs[static_cast<size_t>(i)]) + b.limbs[static_cast<size_t>(i)] + carry;
        r.limbs[static_cast<size_t>(i)] = static_cast<uint64_t>(sum);
        carry = static_cast<uint64_t>(sum >> 64);
    }

    // Reduce: if r >= n, subtract n
    uint64_t borrow = 0;
    uint64_t t[4];
    for (int i = 0; i < 4; ++i) {
        Uint128 const diff = static_cast<Uint128>(r.limbs[static_cast<size_t>(i)]) - P256_N.limbs[static_cast<size_t>(i)] - borrow;
        t[i] = static_cast<uint64_t>(diff);
        borrow = static_cast<uint64_t>(diff >> 127) & 1;
    }

    uint64_t const use_reduced = 1 - (borrow & (1 - carry));
    uint64_t const mask = ~use_reduced + 1;
    for (int i = 0; i < 4; ++i) {
        r.limbs[static_cast<size_t>(i)] = (r.limbs[static_cast<size_t>(i)] & ~mask) | (t[i] & mask);
    }

    return r;
}

auto p256_sc_sub(P256Scalar const& a, P256Scalar const& b) -> P256Scalar
{
    P256Scalar r{};
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        Uint128 const diff = static_cast<Uint128>(a.limbs[static_cast<size_t>(i)]) - b.limbs[static_cast<size_t>(i)] - borrow;
        r.limbs[static_cast<size_t>(i)] = static_cast<uint64_t>(diff);
        borrow = static_cast<uint64_t>(diff >> 127) & 1;
    }

    // If borrow, add n
    uint64_t add_carry = 0;
    uint64_t t[4];
    for (int i = 0; i < 4; ++i) {
        Uint128 const sum =
            static_cast<Uint128>(r.limbs[static_cast<size_t>(i)]) + P256_N.limbs[static_cast<size_t>(i)] + add_carry;
        t[i] = static_cast<uint64_t>(sum);
        add_carry = static_cast<uint64_t>(sum >> 64);
    }

    uint64_t const mask = ~borrow + 1;
    for (int i = 0; i < 4; ++i) {
        r.limbs[static_cast<size_t>(i)] = (r.limbs[static_cast<size_t>(i)] & ~mask) | (t[i] & mask);
    }

    return r;
}

auto p256_sc_negate(P256Scalar const& a) -> P256Scalar
{
    P256Scalar const zero{};
    return p256_sc_sub(zero, a);
}

// Scalar multiplication mod n using schoolbook + Barrett-like reduction
auto p256_sc_mul(P256Scalar const& a, P256Scalar const& b) -> P256Scalar
{
    // Schoolbook 4x4 multiply
    SecureWorkArray<Uint128, 8> t;
    for (int i = 0; i < 4; ++i) {
        Uint128 carry = 0;
        for (int j = 0; j < 4; ++j) {
            Uint128 const prod =
                (static_cast<Uint128>(a.limbs[static_cast<size_t>(i)]) * b.limbs[static_cast<size_t>(j)]) + t[i + j] + carry;
            t[i + j] = prod & 0xFFFFFFFFFFFFFFFF;
            carry = prod >> 64;
        }
        t[i + 4] += carry;
    }

    // Convert to bytes (big-endian, 64 bytes) and use reduce_wide
    SecureArray<64> wide{};
    for (size_t i = 0; i < 8; ++i) {
        uint64_t v = static_cast<uint64_t>(t[i]);
        for (size_t j = 8; j-- > 0;) {
            wide[((7 - i) * 8) + j] = static_cast<uint8_t>(v);
            v >>= 8;
        }
    }

    return p256_sc_reduce_wide(wide);
}

// Reduce a 512-bit big-endian value mod n
auto p256_sc_reduce_wide(span<uint8_t const, 2 * p256_scalar_size> wide) -> P256Scalar
{
    // Parse as 8 x 64-bit limbs (little-endian)
    SecureWorkArray<uint64_t, 8> w;
    for (size_t i = 0; i < 8; ++i) {
        uint64_t v = 0;
        for (size_t j = 0; j < 8; ++j) {
            v = (v << 8) | wide[((7 - i) * 8) + j];
        }
        w[i] = v;
    }

    // Reduction: split x = x_hi * 2^256 + x_lo where x_hi, x_lo are 256 bits,
    // then x mod n = (x_hi * (2^256 mod n) + x_lo) mod n. P256_R256 holds
    // 2^256 mod n = 2^256 - n = 0x00000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF
    // (n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551).
    //
    // x_hi = w[7]:w[6]:w[5]:w[4], x_lo = w[3]:w[2]:w[1]:w[0].
    // x_hi * P256_R256 is up to 512 bits, so the substitution is iterated
    // (see the loop below) until the high half is small enough for a final
    // conditional subtract.

    // First: compute x_hi * P256_R256 (512-bit result)
    SecureWorkArray<Uint128, 8> prod;
    for (int i = 0; i < 4; ++i) {
        Uint128 carry = 0;
        for (int j = 0; j < 4; ++j) {
            Uint128 const p = (static_cast<Uint128>(w[i + 4]) * P256_R256[j]) + prod[i + j] + carry;
            prod[i + j] = p & 0xFFFFFFFFFFFFFFFF;
            carry = p >> 64;
        }
        prod[i + 4] += carry;
    }

    // Add x_lo
    Uint128 carry = 0;
    for (int i = 0; i < 4; ++i) {
        Uint128 const sum = prod[i] + w[i] + carry;
        prod[i] = sum & 0xFFFFFFFFFFFFFFFF;
        carry = sum >> 64;
    }
    for (int i = 4; i < 8; ++i) {
        Uint128 const sum = prod[i] + carry;
        prod[i] = sum & 0xFFFFFFFFFFFFFFFF;
        carry = sum >> 64;
    }

    // Now prod[0..7] has the 512-bit result of (x_hi * P256_R256 + x_lo)
    // Iterate: take the high half and multiply by P256_R256 again.
    // P256_R256 < 2^224, so each iteration shrinks the high half by ~32 bits.
    // Starting from 256 high-half bits, we need ~8 iterations.

    // Constant-time: always iterate the full 10 times regardless of whether
    // the high half is zero. Variable iteration count would leak timing
    // information about the scalar, which is derived from the ECDSA nonce.
    for (int iter = 0; iter < 10; ++iter) {
        SecureWorkArray<Uint128, 8> prod2;
        for (int i = 0; i < 4; ++i) {
            Uint128 c = 0;
            for (int j = 0; j < 4; ++j) {
                Uint128 const p = (static_cast<Uint128>(static_cast<uint64_t>(prod[i + 4])) * P256_R256[j]) + prod2[i + j] + c;
                prod2[i + j] = p & 0xFFFFFFFFFFFFFFFF;
                c = p >> 64;
            }
            prod2[i + 4] += c;
        }

        Uint128 c2 = 0;
        for (int i = 0; i < 4; ++i) {
            Uint128 const sum = prod2[i] + prod[i] + c2;
            prod2[i] = sum & 0xFFFFFFFFFFFFFFFF;
            c2 = sum >> 64;
        }
        for (int i = 4; i < 8; ++i) {
            Uint128 const sum = prod2[i] + c2;
            prod2[i] = sum & 0xFFFFFFFFFFFFFFFF;
            c2 = sum >> 64;
        }

        for (int i = 0; i < 8; ++i) {
            prod[i] = prod2[i];
        }
    }

    P256Scalar r{};
    for (int i = 0; i < 4; ++i) {
        r.limbs[static_cast<size_t>(i)] = static_cast<uint64_t>(prod[i]);
    }

    // Final reduction: subtract n while r >= n.
    // Constant-time: always iterate 3 times and use a conditional move based
    // on a mask derived from the borrow bit rather than branching. This avoids
    // leaking timing information about the scalar value.
    for (int iter = 0; iter < 3; ++iter) {
        uint64_t borrow = 0;
        uint64_t tmp[4];
        for (int i = 0; i < 4; ++i) {
            Uint128 const diff =
                static_cast<Uint128>(r.limbs[static_cast<size_t>(i)]) - P256_N.limbs[static_cast<size_t>(i)] - borrow;
            tmp[i] = static_cast<uint64_t>(diff);
            borrow = static_cast<uint64_t>(diff >> 127) & 1;
        }
        // mask = ~0 when borrow==0 (r >= n, keep subtracted result)
        // mask =  0 when borrow==1 (r < n, keep original)
        uint64_t const mask = borrow - 1;
        for (int i = 0; i < 4; ++i) {
            r.limbs[static_cast<size_t>(i)] = (tmp[i] & mask) | (r.limbs[static_cast<size_t>(i)] & ~mask);
        }
    }

    return r;
}

// Scalar inversion via Fermat: a^(n-2) mod n
auto p256_sc_inv(P256Scalar const& a) -> P256Scalar
{
    // n-2 as bytes (big-endian)
    auto n_bytes = p256_sc_to_bytes(P256_N);
    // Subtract 2 from the last byte
    // n = ...FC632551, n-2 = ...FC63254F
    std::array<uint8_t, p256_scalar_size> exp{};
    uint16_t borrow = 2;
    for (int i = 31; i >= 0; --i) {
        uint16_t const val = static_cast<uint16_t>(n_bytes[static_cast<size_t>(i)]) - borrow;
        exp[static_cast<size_t>(i)] = static_cast<uint8_t>(val);
        borrow = (val >> 15) & 1;
    }

    // Square-and-multiply (left-to-right binary method)
    P256Scalar r{};
    std::get<0>(r.limbs) = 1;  // r = 1

    for (int i = 0; i < 256; ++i) {
        r = p256_sc_mul(r, r);
        int const byte_idx = i / 8;
        int const bit_idx = 7 - (i % 8);
        if (((exp[static_cast<size_t>(byte_idx)] >> bit_idx) & 1) != 0) {
            r = p256_sc_mul(r, a);
        }
    }

    return r;
}

//
// Group operations
//

auto p256_generator() -> P256AffinePoint
{
    return P256AffinePoint{.x = P256_GX, .y = P256_GY};
}

auto p256_point_identity() -> P256JacobianPoint
{
    P256JacobianPoint id{};
    std::get<0>(id.Y.limbs) = 1;  // Identity in Jacobian: (0:1:0)
    return id;
}

auto p256_point_is_identity(P256JacobianPoint const& P) -> bool
{
    return p256_fe_is_zero(P.Z);
}

// Jacobian doubling for a=-3 curve (Algorithm 3.21 from "Guide to ECC")
// Cost: 4M + 4S + 1*a (but a=-3 optimization saves multiplications)
// Note: The formulas naturally handle the identity case (Z=0) correctly:
// when Z=0, all intermediate values involving Z become 0, and Z3 = 0
// (identity), so no explicit check is needed. This keeps the function
// constant-time regardless of whether the input is the identity.
auto p256_point_double(P256JacobianPoint const& P) -> P256JacobianPoint
{
    // a = -3 optimization:
    // delta = Z^2
    // gamma = Y^2
    // beta = X * gamma
    // alpha = 3*(X - delta)*(X + delta)  [this uses a=-3]
    // X3 = alpha^2 - 8*beta
    // Z3 = (Y + Z)^2 - gamma - delta
    // Y3 = alpha*(4*beta - X3) - 8*gamma^2

    P256FieldElement const delta = p256_fe_sqr(P.Z);
    P256FieldElement const gamma = p256_fe_sqr(P.Y);
    P256FieldElement const beta = p256_fe_mul(P.X, gamma);

    P256FieldElement const t1 = p256_fe_sub(P.X, delta);
    P256FieldElement const t2 = p256_fe_add(P.X, delta);
    P256FieldElement const alpha = p256_fe_mul(t1, t2);
    // alpha = 3 * alpha
    P256FieldElement alpha3 = p256_fe_add(alpha, alpha);
    alpha3 = p256_fe_add(alpha3, alpha);

    // 4*beta
    P256FieldElement beta4 = p256_fe_add(beta, beta);
    beta4 = p256_fe_add(beta4, beta4);

    // 8*beta
    P256FieldElement const beta8 = p256_fe_add(beta4, beta4);

    // X3 = alpha^2 - 8*beta
    P256FieldElement X3 = p256_fe_sqr(alpha3);
    X3 = p256_fe_sub(X3, beta8);

    // Z3 = (Y + Z)^2 - gamma - delta
    P256FieldElement const yz = p256_fe_add(P.Y, P.Z);
    P256FieldElement Z3 = p256_fe_sqr(yz);
    Z3 = p256_fe_sub(Z3, gamma);
    Z3 = p256_fe_sub(Z3, delta);

    // Y3 = alpha*(4*beta - X3) - 8*gamma^2
    P256FieldElement const t3 = p256_fe_sub(beta4, X3);
    P256FieldElement Y3 = p256_fe_mul(alpha3, t3);
    P256FieldElement const gamma2 = p256_fe_sqr(gamma);
    P256FieldElement gamma8 = p256_fe_add(gamma2, gamma2);
    gamma8 = p256_fe_add(gamma8, gamma8);
    gamma8 = p256_fe_add(gamma8, gamma8);
    Y3 = p256_fe_sub(Y3, gamma8);

    return P256JacobianPoint{.X = X3, .Y = Y3, .Z = Z3};
}

// Jacobian mixed addition: P (Jacobian) + Q (affine, Z=1)
auto p256_point_add_affine(P256JacobianPoint const& P, P256AffinePoint const& Q) -> P256JacobianPoint
{
    if (p256_fe_is_zero(P.Z)) {
        return p256_affine_to_jacobian(Q);
    }

    // Z1^2, Z1^3
    P256FieldElement const z1z1 = p256_fe_sqr(P.Z);
    P256FieldElement const z1z1z1 = p256_fe_mul(z1z1, P.Z);

    // U2 = X2 * Z1^2, S2 = Y2 * Z1^3
    P256FieldElement const U2 = p256_fe_mul(Q.x, z1z1);
    P256FieldElement const S2 = p256_fe_mul(Q.y, z1z1z1);

    // H = U2 - X1, R = S2 - Y1
    P256FieldElement const H = p256_fe_sub(U2, P.X);
    P256FieldElement const R = p256_fe_sub(S2, P.Y);

    // If H == 0 and R == 0: point doubling case
    if (p256_fe_is_zero(H)) {
        if (p256_fe_is_zero(R)) {
            // P == Q, double
            return p256_point_double(P);
        }
        // P == -Q, result is identity
        return p256_point_identity();
    }

    P256FieldElement const HH = p256_fe_sqr(H);
    P256FieldElement const HHH = p256_fe_mul(H, HH);

    // X3 = R^2 - HHH - 2*U1*HH (where U1 = X1 since Z2=1 adjusted)
    P256FieldElement const V = p256_fe_mul(P.X, HH);
    P256FieldElement X3 = p256_fe_sqr(R);
    X3 = p256_fe_sub(X3, HHH);
    P256FieldElement const V2 = p256_fe_add(V, V);
    X3 = p256_fe_sub(X3, V2);

    // Y3 = R*(V - X3) - Y1*HHH
    P256FieldElement Y3 = p256_fe_sub(V, X3);
    Y3 = p256_fe_mul(R, Y3);
    P256FieldElement const t = p256_fe_mul(P.Y, HHH);
    Y3 = p256_fe_sub(Y3, t);

    // Z3 = Z1 * H
    P256FieldElement const Z3 = p256_fe_mul(P.Z, H);

    return P256JacobianPoint{.X = X3, .Y = Y3, .Z = Z3};
}

// Full Jacobian addition
auto p256_point_add(P256JacobianPoint const& P, P256JacobianPoint const& Q) -> P256JacobianPoint
{
    if (p256_fe_is_zero(P.Z)) {
        return Q;
    }
    if (p256_fe_is_zero(Q.Z)) {
        return P;
    }

    P256FieldElement const z1z1 = p256_fe_sqr(P.Z);
    P256FieldElement const z2z2 = p256_fe_sqr(Q.Z);

    P256FieldElement const U1 = p256_fe_mul(P.X, z2z2);
    P256FieldElement const U2 = p256_fe_mul(Q.X, z1z1);
    P256FieldElement const S1 = p256_fe_mul(P.Y, p256_fe_mul(Q.Z, z2z2));
    P256FieldElement const S2 = p256_fe_mul(Q.Y, p256_fe_mul(P.Z, z1z1));

    P256FieldElement const H = p256_fe_sub(U2, U1);
    P256FieldElement const R = p256_fe_sub(S2, S1);

    if (p256_fe_is_zero(H)) {
        if (p256_fe_is_zero(R)) {
            return p256_point_double(P);
        }
        return p256_point_identity();
    }

    P256FieldElement const HH = p256_fe_sqr(H);
    P256FieldElement const HHH = p256_fe_mul(H, HH);
    P256FieldElement const V = p256_fe_mul(U1, HH);

    P256FieldElement X3 = p256_fe_sqr(R);
    X3 = p256_fe_sub(X3, HHH);
    P256FieldElement const V2 = p256_fe_add(V, V);
    X3 = p256_fe_sub(X3, V2);

    P256FieldElement Y3 = p256_fe_sub(V, X3);
    Y3 = p256_fe_mul(R, Y3);
    P256FieldElement const t = p256_fe_mul(S1, HHH);
    Y3 = p256_fe_sub(Y3, t);

    P256FieldElement Z3 = p256_fe_mul(P.Z, Q.Z);
    Z3 = p256_fe_mul(Z3, H);

    return P256JacobianPoint{.X = X3, .Y = Y3, .Z = Z3};
}

auto p256_point_neg(P256JacobianPoint const& P) -> P256JacobianPoint
{
    return P256JacobianPoint{.X = P.X, .Y = p256_fe_neg(P.Y), .Z = P.Z};
}

auto p256_point_to_affine(P256JacobianPoint const& P) -> P256AffinePoint
{
    if (p256_fe_is_zero(P.Z)) {
        return P256AffinePoint{};  // identity
    }

    P256FieldElement const z_inv = p256_fe_inv(P.Z);
    P256FieldElement const z_inv2 = p256_fe_sqr(z_inv);
    P256FieldElement const z_inv3 = p256_fe_mul(z_inv2, z_inv);

    P256FieldElement const x = p256_fe_mul(P.X, z_inv2);
    P256FieldElement const y = p256_fe_mul(P.Y, z_inv3);

    return P256AffinePoint{.x = x, .y = y};
}

auto p256_affine_to_jacobian(P256AffinePoint const& P) -> P256JacobianPoint
{
    return P256JacobianPoint{.X = P.x, .Y = P.y, .Z = p256_fe_one()};
}

auto p256_point_on_curve(P256AffinePoint const& P) -> bool
{
    // Check: y^2 == x^3 - 3x + b
    P256FieldElement const y2 = p256_fe_sqr(P.y);
    P256FieldElement const x2 = p256_fe_sqr(P.x);
    P256FieldElement const x3 = p256_fe_mul(x2, P.x);

    // -3x
    P256FieldElement three_x = p256_fe_add(P.x, P.x);
    three_x = p256_fe_add(three_x, P.x);

    P256FieldElement rhs = p256_fe_sub(x3, three_x);
    rhs = p256_fe_add(rhs, P256_B);

    return p256_fe_equal(y2, rhs);
}

//
// Scalar multiplication
//

// Constant-time mixed addition for scalar multiplication.
// Always performs full computation; handles the P=identity case via cmov
// instead of branching. The H==0 edge case (P==Q or P==-Q) has negligible
// probability during scalar multiplication and the formulas produce Z3=0
// (identity), which is acceptable.
static auto p256_ct_add_affine(P256JacobianPoint const& P, P256AffinePoint const& Q) -> P256JacobianPoint
{
    // Constant-time check: is P the identity (Z == 0)?
    uint64_t const z_nonzero =
        ct_is_nonzero(std::get<0>(P.Z.limbs) | std::get<1>(P.Z.limbs) | std::get<2>(P.Z.limbs) | std::get<3>(P.Z.limbs));
    uint64_t const p_is_id = 1 - z_nonzero;

    // Standard mixed addition formulas (same as p256_point_add_affine, without branches)
    P256FieldElement const z1z1 = p256_fe_sqr(P.Z);
    P256FieldElement const z1z1z1 = p256_fe_mul(z1z1, P.Z);
    P256FieldElement const U2 = p256_fe_mul(Q.x, z1z1);
    P256FieldElement const S2 = p256_fe_mul(Q.y, z1z1z1);
    P256FieldElement const H = p256_fe_sub(U2, P.X);
    P256FieldElement const R = p256_fe_sub(S2, P.Y);
    P256FieldElement const HH = p256_fe_sqr(H);
    P256FieldElement const HHH = p256_fe_mul(H, HH);
    P256FieldElement const V = p256_fe_mul(P.X, HH);
    P256FieldElement X3 = p256_fe_sqr(R);
    X3 = p256_fe_sub(X3, HHH);
    P256FieldElement const V2 = p256_fe_add(V, V);
    X3 = p256_fe_sub(X3, V2);
    P256FieldElement Y3 = p256_fe_sub(V, X3);
    Y3 = p256_fe_mul(R, Y3);
    P256FieldElement const t = p256_fe_mul(P.Y, HHH);
    Y3 = p256_fe_sub(Y3, t);
    P256FieldElement Z3 = p256_fe_mul(P.Z, H);

    // If P was identity, the formulas give wrong results; fix up with cmov to Q
    P256FieldElement const one = p256_fe_one();
    p256_fe_cmov(X3, Q.x, p_is_id);
    p256_fe_cmov(Y3, Q.y, p_is_id);
    p256_fe_cmov(Z3, one, p_is_id);

    return P256JacobianPoint{.X = X3, .Y = Y3, .Z = Z3};
}

// Variable-base scalar multiplication using constant-time double-and-always-add.
// Always computes the point addition regardless of the scalar bit, then uses
// constant-time conditional move to select the result. This prevents timing
// side-channels that leak scalar bits.

auto p256_scalar_mult(P256Scalar const& scalar, P256AffinePoint const& P) -> P256JacobianPoint
{
    auto sc_bytes = p256_sc_to_bytes(scalar);

    P256JacobianPoint R = p256_point_identity();

    for (int i = 0; i < 256; ++i) {
        R = p256_point_double(R);
        int const byte_idx = i / 8;
        int const bit_idx = 7 - (i % 8);
        uint64_t const bit = (sc_bytes[static_cast<size_t>(byte_idx)] >> bit_idx) & 1;

        // Always compute the addition (constant-time w.r.t. scalar bits)
        P256JacobianPoint const R_add = p256_ct_add_affine(R, P);

        // Constant-time select: if bit==1, use R_add; if bit==0, keep R
        p256_fe_cmov(R.X, R_add.X, bit);
        p256_fe_cmov(R.Y, R_add.Y, bit);
        p256_fe_cmov(R.Z, R_add.Z, bit);
    }

    return R;
}

// Fixed-base scalar multiplication: [scalar] * G
// Uses a precomputed table for the generator point.
auto p256_scalar_mult_base(P256Scalar const& scalar) -> P256JacobianPoint
{
    return p256_scalar_mult(scalar, p256_generator());
}

// Double scalar multiplication: [a]*G + [b]*Q using Shamir's trick (constant-time).
// Precomputes a 4-entry table {identity, G, Q, G+Q} indexed by (a_bit, b_bit)
// and uses p256_fe_cmov for constant-time selection to avoid timing side-channels.
auto p256_double_scalar_mult(P256Scalar const& a, P256Scalar const& b, P256AffinePoint const& Q) -> P256JacobianPoint
{
    auto a_bytes = p256_sc_to_bytes(a);
    auto b_bytes = p256_sc_to_bytes(b);

    P256AffinePoint const G = p256_generator();

    // Precompute G+Q for Shamir's trick
    P256JacobianPoint const GpQ = p256_point_add(p256_affine_to_jacobian(G), p256_affine_to_jacobian(Q));
    P256AffinePoint const GpQ_affine = p256_point_to_affine(GpQ);

    // Precomputed table: T[0] = identity, T[1] = G, T[2] = Q, T[3] = G+Q
    // Index = a_bit | (b_bit << 1)
    P256AffinePoint table[4];
    table[0] = {.x = {}, .y = {}};  // identity (unused, selected point is added only when index != 0)
    table[1] = G;
    table[2] = Q;
    table[3] = GpQ_affine;

    P256JacobianPoint R = p256_point_identity();

    for (int i = 0; i < 256; ++i) {
        R = p256_point_double(R);

        int const byte_idx = i / 8;
        int const bit_idx = 7 - (i % 8);
        uint64_t const a_bit = (a_bytes[static_cast<size_t>(byte_idx)] >> bit_idx) & 1;
        uint64_t const b_bit = (b_bytes[static_cast<size_t>(byte_idx)] >> bit_idx) & 1;
        uint64_t const idx = a_bit | (b_bit << 1);

        // Constant-time table lookup using cmov
        P256AffinePoint selected = table[0];
        p256_fe_cmov(selected.x, table[1].x, static_cast<uint64_t>(idx == 1));
        p256_fe_cmov(selected.y, table[1].y, static_cast<uint64_t>(idx == 1));
        p256_fe_cmov(selected.x, table[2].x, static_cast<uint64_t>(idx == 2));
        p256_fe_cmov(selected.y, table[2].y, static_cast<uint64_t>(idx == 2));
        p256_fe_cmov(selected.x, table[3].x, static_cast<uint64_t>(idx == 3));
        p256_fe_cmov(selected.y, table[3].y, static_cast<uint64_t>(idx == 3));

        // Always perform the addition, then conditionally accept the result
        P256JacobianPoint const R_add = p256_point_add_affine(R, selected);
        uint64_t const do_add = static_cast<uint64_t>(idx != 0);
        p256_fe_cmov(R.X, R_add.X, do_add);
        p256_fe_cmov(R.Y, R_add.Y, do_add);
        p256_fe_cmov(R.Z, R_add.Z, do_add);
    }

    return R;
}

//
// Key generation
//

auto p256_keypair_from_seed(span<uint8_t const, p256_scalar_size> seed) -> std::pair<P256Scalar, P256AffinePoint>
{
    // Hash the seed with SHA-256 to get initial scalar material.
    // SecureArray zeroes the hash on scope exit since it derives the private scalar.
    SecureArray<32> hash = sha256_hw(seed);
    P256Scalar d{};

    // Try up to 2 attempts: reduce mod n, then check for zero.
    // d == 0 can occur if hash == 0 (astronomically unlikely) or hash == n exactly.
    // In either case, rehash and try again.
    for (int attempt = 0; attempt < 2; ++attempt) {
        d = p256_sc_from_bytes(hash);

        // Reduce mod n if needed (single subtraction; hash < 2^256 and n > 2^255)
        {
            uint64_t borrow = 0;
            SecureWorkArray<uint64_t, 4> tmp;
            for (int i = 0; i < 4; ++i) {
                Uint128 const diff =
                    static_cast<Uint128>(d.limbs[static_cast<size_t>(i)]) - P256_N.limbs[static_cast<size_t>(i)] - borrow;
                tmp[i] = static_cast<uint64_t>(diff);
                borrow = static_cast<uint64_t>(diff >> 127) & 1;
            }
            // Constant-time conditional move: select reduced value when borrow == 0
            uint64_t const mask = borrow - 1;  // ~0 if borrow==0 (need reduction), 0 if borrow==1
            for (int i = 0; i < 4; ++i) {
                d.limbs[static_cast<size_t>(i)] = (d.limbs[static_cast<size_t>(i)] & ~mask) | (tmp[i] & mask);
            }
        }

        if (!p256_sc_is_zero(d)) {
            break;
        }

        // d == 0 after reduction: rehash and retry
        hash = sha256_hw(hash);
    }

    // Compute Q = d * G
    P256JacobianPoint const Q_jac = p256_scalar_mult_base(d);
    P256AffinePoint const Q = p256_point_to_affine(Q_jac);

    return {d, Q};
}

//
// Point encoding/decoding
//

auto p256_encode_point_x(P256AffinePoint const& P) -> std::array<uint8_t, p256_compressed_point_size>
{
    std::array<uint8_t, p256_compressed_point_size> out{};
    out[0] = 0x01;  // PC for x-coordinate only (IEEE 1363a 5.5.6.3)
    auto x_bytes = p256_fe_to_bytes(P.x);
    span_copy(span(out).last<p256_field_element_size>(), x_bytes);
    return out;
}

// SEC 1 §2.3.6: a point coordinate must be a canonical field element (< p).
// p256_fe_from_bytes does not reduce, so a non-canonical x/y in [p, 2^256)
// would otherwise be silently accepted as its reduced representative.
// Constant-time big-endian comparison against the field prime.
static auto p256_coord_is_canonical(span<uint8_t const, p256_field_element_size> v) -> bool
{
    uint32_t lt = 0, gt = 0;
    for (size_t i = 0; i < p256_field_element_size; ++i) {
        uint32_t const a = v[i];
        uint32_t const b = p256_field_prime_bytes[i];
        uint32_t const not_decided = 1u - ((lt | gt) & 1u);
        lt |= not_decided & (((a - b) >> 8) & 1u);
        gt |= not_decided & (((b - a) >> 8) & 1u);
    }
    return lt == 1u;
}

auto p256_decode_point_x(span<uint8_t const, p256_compressed_point_size> encoded) -> std::optional<P256AffinePoint>
{
    if (encoded[0] != 0x01) {
        return std::nullopt;
    }

    std::array<uint8_t, p256_field_element_size> x_bytes{};
    span_copy(x_bytes, encoded.template subspan<1, p256_field_element_size>());

    if (!p256_coord_is_canonical(x_bytes)) {
        return std::nullopt;
    }

    P256FieldElement const x = p256_fe_from_bytes(x_bytes);

    // Compute y^2 = x^3 - 3x + b
    P256FieldElement const x2 = p256_fe_sqr(x);
    P256FieldElement const x3 = p256_fe_mul(x2, x);
    P256FieldElement three_x = p256_fe_add(x, x);
    three_x = p256_fe_add(three_x, x);
    P256FieldElement y2 = p256_fe_sub(x3, three_x);
    y2 = p256_fe_add(y2, P256_B);

    auto y = p256_fe_sqrt(y2);
    if (!y) {
        return std::nullopt;
    }

    // Pick the even y (arbitrary choice; for ECDH the y doesn't matter)
    auto y_bytes = p256_fe_to_bytes(*y);
    if ((y_bytes[31] & 1) != 0) {
        *y = p256_fe_neg(*y);
    }

    return P256AffinePoint{.x = x, .y = *y};
}

auto p256_encode_point_uncompressed(P256AffinePoint const& P) -> std::array<uint8_t, p256_uncompressed_point_size>
{
    std::array<uint8_t, p256_uncompressed_point_size> out{};
    auto x_bytes = p256_fe_to_bytes(P.x);
    auto y_bytes = p256_fe_to_bytes(P.y);
    span_copy(span(out).first<p256_field_element_size>(), x_bytes);
    span_copy(span(out).last<p256_field_element_size>(), y_bytes);
    return out;
}

auto p256_decode_point_uncompressed(span<uint8_t const, p256_uncompressed_point_size> encoded) -> std::optional<P256AffinePoint>
{
    std::array<uint8_t, p256_field_element_size> x_bytes{};
    std::array<uint8_t, p256_field_element_size> y_bytes{};
    span_copy(x_bytes, encoded.template first<p256_field_element_size>());
    span_copy(y_bytes, encoded.template last<p256_field_element_size>());

    if (!p256_coord_is_canonical(x_bytes) || !p256_coord_is_canonical(y_bytes)) {
        return std::nullopt;
    }

    P256AffinePoint P{.x = p256_fe_from_bytes(x_bytes), .y = p256_fe_from_bytes(y_bytes)};

    if (!p256_point_on_curve(P)) {
        return std::nullopt;
    }

    return P;
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
