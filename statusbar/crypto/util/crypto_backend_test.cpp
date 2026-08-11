// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the crypto backend report: the report must agree with the raw
// probes the *_hw dispatchers use, and the one-line summary must agree with
// the report. Which backends are actually "hw" depends on the host CPU, so
// the tests assert consistency, not specific values — except SHA-512, which
// has no hardware backend anywhere yet.

#include "statusbar/crypto/util/crypto_backend.hpp"

#include "statusbar/crypto/util/crypto_cpu.hpp"
#include "statusbar/test/test.hpp"

#include <format>
#include <string>

using namespace statusbar::crypto;

TEST(crypto_backend, report_matches_dispatch_probes)
{
    auto const r = crypto_backend_report();
    EXPECT_EQ(r.aes == CryptoBackend::hardware, internal::cpu_aes_hw_probe());
    EXPECT_EQ(r.sha256 == CryptoBackend::hardware, internal::cpu_sha256_hw_probe());
    EXPECT_EQ(r.polyval == CryptoBackend::hardware, internal::cpu_polyval_hw_probe());
}

TEST(crypto_backend, sha512_is_software_until_a_hw_backend_lands)
{
    // Both sha512_hw_* TUs delegate to software today. If this fails, a HW
    // backend was added — update cpu_sha512_hw_probe() and this test together.
    EXPECT_EQ(crypto_backend_report().sha512, CryptoBackend::software);
}

TEST(crypto_backend, report_is_stable)
{
    EXPECT_EQ(crypto_backend_report(), crypto_backend_report());
}

TEST(crypto_backend, summary_matches_report)
{
    auto const r = crypto_backend_report();
    auto const expected = std::format(
        "aes={} sha256={} sha512={} polyval={}", to_string(r.aes), to_string(r.sha256), to_string(r.sha512), to_string(r.polyval));
    EXPECT_EQ(crypto_backend_summary(), expected);
    // The view is NUL-terminated (documented for retention / C interop).
    // NOLINTNEXTLINE(readability-simplify-subscript-expr) — deliberately reads one past size()
    EXPECT_EQ(*(crypto_backend_summary().data() + crypto_backend_summary().size()), '\0');
}

TEST(crypto_backend, to_string_labels)
{
    EXPECT_EQ(to_string(CryptoBackend::hardware), "hw");
    EXPECT_EQ(to_string(CryptoBackend::software), "sw");
}

TEST_MAIN(statusbar_crypto_util, crypto_backend_test)
