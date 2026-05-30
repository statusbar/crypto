// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SecureArray and secure_zero utilities for statusbar_crypto.
// Lightweight header that can be included by other statusbar_crypto headers
// without pulling in the full crypto_util_internal.hpp.

#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace statusbar::crypto {
namespace internal {

/// @brief Memory zeroing that resists dead-store elimination.
///
/// Uses platform-specific secure zeroing when available, falling back to
/// volatile pointer writes that compilers must not optimize away.
/// @param buf The byte span to zero.
inline void secure_zero(std::span<uint8_t> buf)
{
    // An empty span has nothing to zero, and span::data() may be
    // nullptr — explicit_bzero declares argument 1 as nonnull, so
    // explicit_bzero(nullptr, 0) is undefined behavior.
    if (buf.empty()) {
        return;
    }
#if __has_include(<string.h>) && (defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__))
    // explicit_bzero is guaranteed not to be optimized away (glibc/BSD)
    explicit_bzero(buf.data(), buf.size());
#else
    // Volatile fallback — compilers must not elide writes through volatile pointers
    uint8_t volatile* p = buf.data();
    for (size_t i = 0; i < buf.size(); ++i) {
        p[i] = 0;
    }
#endif
}

/// @brief Overload for arbitrary trivially-copyable types (e.g. SHA context structs, SecureArray).
/// @tparam T The type to zero (must not be implicitly convertible to span<uint8_t>).
/// @param obj The object to zero.
template <typename T>
    requires(!std::convertible_to<T&, std::span<uint8_t>>)
inline void secure_zero(T& obj)
{
    // Constant-time volatile zero wipe — the reinterpret_cast to
    // `uint8_t volatile*` is intentional and prevents the optimizer
    // from eliding the stores.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    uint8_t volatile* p = reinterpret_cast<uint8_t volatile*>(&obj);
    for (size_t i = 0; i < sizeof(T); ++i) {
        p[i] = 0;
    }
}

}  // namespace internal

/// @brief RAII reference to a value that securely zeroes its contents on destruction.
/// Use for stack-allocated variables that need to be zeroed on scope exit.
template <typename T>
    requires std::is_trivially_copyable_v<T>
struct SecureZeroRef
{
    T& ref;
    ~SecureZeroRef() { internal::secure_zero(ref); }
};

/// @brief RAII byte array that securely zeroes its contents on destruction.
///
/// Inherits from std::array<uint8_t, N> so it can be used anywhere a
/// std::array is accepted. The destructor uses volatile writes to prevent
/// dead-store elimination.
/// @tparam N Size of the array in bytes.
template <size_t N>
struct SecureArray : std::array<uint8_t, N>
{
    SecureArray() = default;
    SecureArray(std::array<uint8_t, N> const& other)
        : std::array<uint8_t, N>(other)
    {}
    auto operator=(std::array<uint8_t, N> const& other) -> SecureArray&
    {
        std::array<uint8_t, N>::operator=(other);
        return *this;
    }
    ~SecureArray() { internal::secure_zero(*this); }
};

/// @brief RAII array of arbitrary element type that securely zeroes on destruction.
///
/// Use for stack-allocated working buffers (message schedules, scalar limbs, etc.)
/// whose contents may include sensitive intermediate values.
/// @tparam T Element type.
/// @tparam N Number of elements.
template <typename T, size_t N>
struct SecureWorkArray
{
    T data[N]{};
    auto operator[](size_t i) -> T& { return data[i]; }
    auto operator[](size_t i) const -> T const& { return data[i]; }
    ~SecureWorkArray() { internal::secure_zero(*this); }
};

}  // namespace statusbar::crypto
