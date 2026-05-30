// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// HKDF-SHA-256 (RFC 5869)
// Reference: https://www.rfc-editor.org/rfc/rfc5869

#include "statusbar/crypto/hkdf/hkdf.hpp"

#include "statusbar/crypto/sha/sha256_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <algorithm>

namespace statusbar::crypto {

using internal::make_const_span;
using internal::span_copy;
using std::span;

// HKDF-Extract: PRK = HMAC-SHA-256(salt, IKM)
// The salt is used as the HMAC key and IKM as the HMAC message.
// If salt is not provided, RFC 5869 Section 2.2 specifies using a string of
// HashLen (32) zero bytes as the default salt.
auto hkdf_sha256_extract(span<uint8_t const> salt, span<uint8_t const> ikm) -> SecureArray<hkdf_sha256_prk_size>
{
    if (salt.empty()) {
        std::array<uint8_t, hkdf_sha256_prk_size> zero_salt{};
        return sha256_hmac_hw(zero_salt, ikm);
    }
    return sha256_hmac_hw(salt, ikm);
}

// HKDF-Expand: derive OKM from PRK using iterative HMAC.
// RFC 5869 Section 2.3:
//   N = ceil(L / HashLen), where L = okm.size() and HashLen = 32
//   T(0) = empty string
//   T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i), for i = 1..N
//   OKM = first L bytes of T(1) || T(2) || ... || T(N)
// The maximum output length is 255 * HashLen = 8160 bytes (since i is a single octet).
auto hkdf_sha256_expand(span<uint8_t const, hkdf_sha256_prk_size> prk, span<uint8_t const> info, span<uint8_t> okm) -> bool
{
    size_t const N = (okm.size() + hkdf_sha256_prk_size - 1) / hkdf_sha256_prk_size;
    if (N > 255 || okm.empty()) {
        return false;
    }

    // Reject info larger than 256 bytes — the fixed-size buffer cannot hold more.
    // This is an explicit API contract rather than silent truncation.
    // For AVTP key derivation, use build_ed25519_transport_key_info() or
    // build_p256_transport_key_info() to ensure proper structure.
    if (info.size() > hkdf_sha256_max_info_size) {
        return false;
    }

    SecureArray<hkdf_sha256_prk_size> T_prev{};
    size_t offset = 0;

    for (size_t i = 1; i <= N; ++i) {
        // Assemble the HMAC input buffer: T(i-1) || info || i
        // - T(i-1) is 32 bytes for i > 1, or empty for i == 1 (T(0) = "")
        // - info is the application context string
        // - i is a single octet (1..255)
        // Fixed-size buffer is used because info for AVTP is always small.
        SecureArray<hkdf_sha256_prk_size + hkdf_sha256_max_info_size + 1> hmac_input{};
        size_t hmac_len = 0;

        // Append T(i-1) for iterations after the first.
        if (i > 1) {
            span_copy(span(hmac_input).first<hkdf_sha256_prk_size>(), make_const_span(T_prev));
            hmac_len += hkdf_sha256_prk_size;
        }

        // Append the info/context bytes.
        span_copy(span(hmac_input).subspan(hmac_len, info.size()), info);
        hmac_len += info.size();

        // Append the 1-byte iteration counter.
        hmac_input[hmac_len++] = static_cast<uint8_t>(i);

        // Compute T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i).
        // hmac_input is SecureArray — zeroed by RAII at end of each iteration.
        T_prev = sha256_hmac_hw(prk, span<uint8_t const>(hmac_input.data(), hmac_len));

        // Copy T(i) (or a prefix of it for the final iteration) into the output.
        size_t const copy_len = std::min(hkdf_sha256_prk_size, okm.size() - offset);
        span_copy(okm.subspan(offset, copy_len), span<uint8_t const>(T_prev.data(), copy_len));
        offset += copy_len;
    }

    // T_prev is SecureArray — zeroed by RAII.

    return true;
}

// One-shot Extract-then-Expand: first derive PRK from salt and IKM,
// then expand PRK with info to produce the requested OKM bytes.
auto hkdf_sha256(span<uint8_t const> salt, span<uint8_t const> ikm, span<uint8_t const> info, span<uint8_t> okm) -> bool
{
    auto prk = hkdf_sha256_extract(salt, ikm);
    return hkdf_sha256_expand(prk, info, okm);
}

}  // namespace statusbar::crypto
