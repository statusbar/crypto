// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for POLYVAL (RFC 8452 Section 3)
#include "statusbar/crypto/polyval/polyval_hw.hpp"
#include "statusbar/crypto/polyval/polyval_sw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

using namespace statusbar::crypto;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    // Need at least 16 bytes for the hash key
    if (size < polyval_block_size) {
        return 0;
    }

    // First 16 bytes are the POLYVAL key
    PolyvalKey H;
    internal::span_copy(H.data, std::span<uint8_t const, polyval_block_size>(data, polyval_block_size));

    // Remaining bytes are the input; round down to a multiple of 16
    size_t const input_len = ((size - polyval_block_size) / polyval_block_size) * polyval_block_size;
    std::span<uint8_t const> input(data + polyval_block_size, input_len);

    if (input.empty()) {
        return 0;
    }

    // SW one-shot
    auto result_sw = polyval_sw(H, input);

    // HW one-shot must match SW
    auto result_hw = polyval_hw(H, input);
    if (result_sw != result_hw) {
        __builtin_trap();
    }

    // Incremental SW must match one-shot
    {
        std::array<uint8_t, polyval_block_size> acc{};
        polyval_update_sw(H, input, acc);
        if (acc != result_sw) {
            __builtin_trap();
        }
    }

    // Incremental HW must match one-shot
    {
        std::array<uint8_t, polyval_block_size> acc{};
        polyval_update_hw(H, input, acc);
        if (acc != result_hw) {
            __builtin_trap();
        }
    }

    // Split input into two halves and verify incremental consistency
    if (input_len >= 2 * polyval_block_size) {
        size_t const split = (input_len / polyval_block_size / 2) * polyval_block_size;
        std::array<uint8_t, polyval_block_size> acc_split{};
        polyval_update_sw(H, input.first(split), acc_split);
        polyval_update_sw(H, input.subspan(split), acc_split);
        if (acc_split != result_sw) {
            __builtin_trap();
        }
    }

    return 0;
}
