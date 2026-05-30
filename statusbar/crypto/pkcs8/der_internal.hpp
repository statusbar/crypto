// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Shared DER (Distinguished Encoding Rules) parsing utilities
// for PKCS#8 and SPKI encoding/decoding.
// Not part of the public API.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {
namespace internal {

// Read DER length at pos, advance pos. Returns SIZE_MAX on error.
inline auto der_read_length(std::span<uint8_t const> data, size_t& pos) -> size_t
{
    if (pos >= data.size()) {
        return SIZE_MAX;
    }
    uint8_t const b = data[pos++];
    if (b < 0x80) {
        return static_cast<size_t>(b);
    }
    size_t const n = b & 0x7F;
    auto is_invalid_der_length_header = [](size_t byte_count, size_t pos, size_t data_size) -> bool {
        return byte_count == 0 || byte_count > 2 || pos + byte_count > data_size;
    };
    if (is_invalid_der_length_header(n, pos, data.size())) {
        return SIZE_MAX;
    }
    size_t len = 0;
    for (size_t i = 0; i < n; ++i) {
        len = (len << 8) | data[pos++];
    }
    return len;
}

}  // namespace internal
}  // namespace statusbar::crypto
