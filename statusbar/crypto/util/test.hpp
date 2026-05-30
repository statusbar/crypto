// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Shared test helpers for statusbar_crypto tests.

#pragma once

#include <print>

namespace statusbar::crypto::test {

/// @brief Global test failure counter, incremented by check() on failure.
inline int failures = 0;

/// @brief Check a test condition and report failure.
/// @param cond The condition to test (true = pass, false = fail).
/// @param name Descriptive name of the test, printed on failure.
inline void check(bool cond, char const* name)
{
    if (!cond) {
        std::print(stderr, "FAIL: {}\n", name);
        ++failures;
    }
}

/// @brief Print test results summary and return the failure count.
/// @param test_name Name of the test suite, used in the summary output.
/// @return 0 if all tests passed, otherwise the number of failures.
inline int report(char const* test_name)
{
    if (failures == 0) {
        std::println("{}: all tests passed", test_name);
    } else {
        std::print(stderr, "{}: {} test(s) FAILED\n", test_name, failures);
    }
    return failures;
}

/// @brief Prevent the compiler from optimizing away a computed value.
///
/// Uses inline asm to force the compiler to materialize the result,
/// ensuring the function call that produced it cannot be eliminated.
/// @tparam T Type of the value to preserve.
/// @param value The value that must not be optimized away.
template <typename T>
inline void do_not_optimize(T const& value)
{
    asm volatile("" : : "g"(value) : "memory");
}

}  // namespace statusbar::crypto::test
