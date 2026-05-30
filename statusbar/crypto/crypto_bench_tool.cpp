// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
//
// Crypto benchmark tool — exercises AES-128, SHA-256, and CMAC primitives
// in both software and hardware-accelerated variants. Uses run_hw() so the
// sampling loop reads rdtscp/cntvct_el0 directly — important for AES block
// and SHA-one-block timings which are sub-microsecond.
//
// Build: make build
// Run:   ./build/build-Release/statusbar/statusbar-crypto-bench

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/benchmark/benchmark.hpp"
#    include "statusbar/crypto/25519/curve25519.hpp"
#    include "statusbar/crypto/25519/curve25519_fe32.hpp"
#    include "statusbar/crypto/crypto.hpp"
#    include "statusbar/crypto/p256/p256.hpp"
#    include "statusbar/crypto/p256/p256_fe32.hpp"
#    include "statusbar/crypto/p256/p256_sc32.hpp"

#    include <array>
#    include <cstdint>
#    include <print>
#    include <span>
#    include <string>
#    include <vector>

using namespace statusbar::benchmark;
using namespace statusbar::crypto;

namespace {

auto make_random_bytes(size_t len) -> std::vector<uint8_t>
{
    std::vector<uint8_t> buf(len);
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<uint8_t>((i * 1103515245U + 12345U) & 0xFFU);
    }
    return buf;
}

auto make_aes128_key() -> Aes128Key
{
    Aes128Key key;
    for (size_t i = 0; i < Aes128Key::LENGTH; ++i) {
        key.data[i] = static_cast<uint8_t>(i);
    }
    return key;
}

void bench_aes128_block()
{
    std::println("=== AES-128 Block ===\n");

    // Block ops are ~5-50 cycles; need a large batch_size so counter read
    // overhead (~30-50 cycles on arm64/x86_64) drops below ~0.1% of the sample.
    BenchmarkConfig const cfg{.warmup_iterations = 200, .measurement_iterations = 2000, .batch_size = 10000};
    auto const key = make_aes128_key();
    auto const rk_sw = aes128_expand_key_sw(key);
    auto const rk_hw = aes128_expand_key_hw(key);

    {
        std::array<uint8_t, aes128_block_size> block{};
        auto stats = run_hw(
            "aes128/encrypt_block_sw",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    aes128_encrypt_block_sw(rk_sw, std::span<uint8_t, aes128_block_size>{block});
                }
                do_not_optimize(block);
            },
            cfg);
        report("aes128/encrypt_block_sw", stats);
    }

    {
        std::array<uint8_t, aes128_block_size> block{};
        auto stats = run_hw(
            "aes128/encrypt_block_hw",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    aes128_encrypt_block_hw(rk_hw, std::span<uint8_t, aes128_block_size>{block});
                }
                do_not_optimize(block);
            },
            cfg);
        report("aes128/encrypt_block_hw", stats);
    }

    {
        std::array<uint8_t, aes128_block_size> block{};
        auto stats = run_hw(
            "aes128/decrypt_block_hw",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    aes128_decrypt_block_hw(rk_hw, std::span<uint8_t, aes128_block_size>{block});
                }
                do_not_optimize(block);
            },
            cfg);
        report("aes128/decrypt_block_hw", stats);
    }

    {
        // 4 independent blocks, pipelined — measures throughput rather than
        // latency. Each iteration mutates all 4 blocks in place, so the
        // data-dependency chain keeps the inner loop honest.
        std::array<uint8_t, 4 * aes128_block_size> blocks{};
        auto stats = run_hw(
            "aes128/encrypt_blocks_x4_hw",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    aes128_encrypt_blocks_x4_hw(rk_hw, std::span<uint8_t, 4 * aes128_block_size>{blocks});
                }
                do_not_optimize(blocks);
            },
            cfg);
        report("aes128/encrypt_blocks_x4_hw", stats);
        // Reported time is per 4-block call. Per-block throughput ≈ median / 4.
        std::println("  → per-block throughput: {:.2f} ns\n", stats.median / 4.0);
    }

    {
        // expand_key is pure — compiler would CSE iterations if we only
        // barrier at end. Keep do_not_optimize per-call; the sample-loop
        // hoist still pays off by taking one timer read per sample.
        auto stats = run_hw(
            "aes128/expand_key_hw",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    auto rk = aes128_expand_key_hw(key);
                    do_not_optimize(rk);
                }
            },
            BenchmarkConfig{.warmup_iterations = 200, .measurement_iterations = 2000, .batch_size = 1000});
        report("aes128/expand_key_hw", stats);
    }

    std::println("");
}

void bench_aes128_cmac()
{
    std::println("=== AES-128 CMAC ===\n");

    BenchmarkConfig const cfg{.warmup_iterations = 200, .measurement_iterations = 2000, .batch_size = 10};
    auto const key = make_aes128_key();
    auto const rk = aes128_expand_key_hw(key);

    for (size_t sz : {16UL, 64UL, 256UL, 1024UL, 4096UL}) {
        auto msg = make_random_bytes(sz);
        auto name = std::format("cmac/hw/{}", sz);
        auto stats = run_hw(
            name,
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    auto tag = aes128_cmac_hw(rk, std::span<uint8_t const>{msg});
                    do_not_optimize(tag);
                }
            },
            cfg);
        report(name, stats);
    }

    std::println("");
}

void bench_sha256()
{
    std::println("=== SHA-256 ===\n");

    BenchmarkConfig const cfg{.warmup_iterations = 200, .measurement_iterations = 2000, .batch_size = 10};

    for (size_t sz : {32UL, 64UL, 256UL, 1024UL, 4096UL, 16384UL}) {
        auto msg = make_random_bytes(sz);

        {
            auto name = std::format("sha256/sw/{}", sz);
            auto stats = run_hw(
                name,
                [&](size_t n) {
                    for (size_t k = 0; k < n; ++k) {
                        auto digest = sha256_sw(std::span<uint8_t const>{msg});
                        do_not_optimize(digest);
                    }
                },
                cfg);
            report(name, stats);
        }

        {
            auto name = std::format("sha256/hw/{}", sz);
            auto stats = run_hw(
                name,
                [&](size_t n) {
                    for (size_t k = 0; k < n; ++k) {
                        auto digest = sha256_hw(std::span<uint8_t const>{msg});
                        do_not_optimize(digest);
                    }
                },
                cfg);
            report(name, stats);
        }
    }

    std::println("");
}

void bench_sha256_hmac()
{
    std::println("=== HMAC-SHA-256 ===\n");

    BenchmarkConfig const cfg{.warmup_iterations = 200, .measurement_iterations = 2000, .batch_size = 10};
    auto const key = make_random_bytes(32);

    for (size_t sz : {64UL, 256UL, 1024UL}) {
        auto msg = make_random_bytes(sz);
        auto name = std::format("hmac_sha256/hw/{}", sz);
        auto stats = run_hw(
            name,
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    auto tag = sha256_hmac_hw(std::span<uint8_t const>{key}, std::span<uint8_t const>{msg});
                    do_not_optimize(tag);
                }
            },
            cfg);
        report(name, stats);
    }

    std::println("");
}

// Deterministic 32-byte test vector derived from a seed.
auto seeded_bytes(uint32_t seed) -> std::array<uint8_t, 32>
{
    std::array<uint8_t, 32> b{};
    uint32_t s = seed;
    for (auto& x : b) {
        s = (s * 1103515245U) + 12345U;
        x = static_cast<uint8_t>(s >> 16);
    }
    return b;
}

// Benchmark a 64-bit (128-bit-integer) operation against its 32-bit
// reduced-radix counterpart and report the cost ratio.
template <typename F64, typename F32>
void compare(std::string const& op, F64 f64, F32 f32, BenchmarkConfig const& cfg)
{
    auto const s64 = run_hw(op + "/64bit", f64, cfg);
    report(op + "/64bit", s64);
    auto const s32 = run_hw(op + "/32bit", f32, cfg);
    report(op + "/32bit", s32);
    std::println("  → 32-bit costs {:.2f}x the 64-bit (128-bit-int) path\n", s32.median / s64.median);
}

// Compares the __uint128_t-based field/scalar arithmetic against the portable
// 32-bit reduced-radix implementations (curve25519_fe32, p256_fe32, p256_sc32).
void bench_ec_field()
{
    std::println("=== EC field arithmetic — 64-bit (128-bit int) vs 32-bit reduced-radix ===\n");

    BenchmarkConfig const mcfg{.warmup_iterations = 200, .measurement_iterations = 2000, .batch_size = 2000};
    BenchmarkConfig const icfg{.warmup_iterations = 50, .measurement_iterations = 500, .batch_size = 20};

    auto const ba = seeded_bytes(0x1234ABCDU);
    auto const bb = seeded_bytes(0x9E3779B9U);
    std::span<uint8_t const, 32> const sa{ba};
    std::span<uint8_t const, 32> const sb{bb};

    {
        auto a = fe25519_from_bytes(sa);
        auto const b = fe25519_from_bytes(sb);
        auto a32 = fe25519x32_from_bytes(sa);
        auto const b32 = fe25519x32_from_bytes(sb);
        compare(
            "curve25519/fe_mul",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a = fe25519_mul(a, b);
                }
                do_not_optimize(a);
            },
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a32 = fe25519x32_mul(a32, b32);
                }
                do_not_optimize(a32);
            },
            mcfg);
        compare(
            "curve25519/fe_sq",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a = fe25519_sq(a);
                }
                do_not_optimize(a);
            },
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a32 = fe25519x32_sq(a32);
                }
                do_not_optimize(a32);
            },
            mcfg);
        compare(
            "curve25519/fe_invert",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a = fe25519_invert(a);
                }
                do_not_optimize(a);
            },
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a32 = fe25519x32_invert(a32);
                }
                do_not_optimize(a32);
            },
            icfg);
    }

    {
        auto a = p256_fe_from_bytes(sa);
        auto const b = p256_fe_from_bytes(sb);
        auto a32 = p256_fe32_from_bytes(sa);
        auto const b32 = p256_fe32_from_bytes(sb);
        compare(
            "p256/fe_mul",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a = p256_fe_mul(a, b);
                }
                do_not_optimize(a);
            },
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a32 = p256_fe32_mul(a32, b32);
                }
                do_not_optimize(a32);
            },
            mcfg);
        compare(
            "p256/fe_inv",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a = p256_fe_inv(a);
                }
                do_not_optimize(a);
            },
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a32 = p256_fe32_inv(a32);
                }
                do_not_optimize(a32);
            },
            icfg);
    }

    {
        auto a = p256_sc_from_bytes(sa);
        auto const b = p256_sc_from_bytes(sb);
        auto a32 = p256_sc32_from_bytes(sa);
        auto const b32 = p256_sc32_from_bytes(sb);
        compare(
            "p256/sc_mul",
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a = p256_sc_mul(a, b);
                }
                do_not_optimize(a);
            },
            [&](size_t n) {
                for (size_t k = 0; k < n; ++k) {
                    a32 = p256_sc32_mul(a32, b32);
                }
                do_not_optimize(a32);
            },
            mcfg);
    }

    std::println("");
}

}  // namespace

auto main() -> int
{
    std::println("StatusBar Crypto Benchmarks (C++)\n");
    std::println("Using HardwareTimer (counter frequency: {} Hz)\n", HardwareTimer::ticks_per_second());

    bench_aes128_block();
    bench_aes128_cmac();
    bench_sha256();
    bench_sha256_hmac();
    bench_ec_field();

    std::println("Done.");
    return 0;
}

#else  // !STATUSBAR_CRYPTO_HAS_INT128
#    include <print>
auto main() -> int
{
    std::println("crypto_bench_tool: requires 128-bit integer support; skipped.");
    return 0;
}
#endif  // STATUSBAR_CRYPTO_HAS_INT128
