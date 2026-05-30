// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Single point of truth for whether the compiler provides a usable 128-bit
// integer type (__int128).
//
// The 5x51-bit Curve25519 and 4x64-bit P-256 field/scalar arithmetic depends
// on __int128 for 64x64->128 multiplication. GCC (>= 4.6) and Clang both
// define __SIZEOF_INT128__ exactly when that type is available — true on
// 64-bit targets, false on 32-bit ALUs (arm32, i386, RISC-V32), where the
// reduced-radix *32 implementations are used instead.
//
// STATUSBAR_CRYPTO_HAS_INT128 is derived directly from that compiler macro,
// so the crypto tree compiles unconditionally under any build system with no
// feature-detection step — a porter simply lists every source file. It may
// be pre-defined on the command line (e.g. -DSTATUSBAR_CRYPTO_HAS_INT128=0)
// to build and exercise the 32-bit code path on a 64-bit host for testing.

#pragma once

#if !defined(STATUSBAR_CRYPTO_HAS_INT128)
#    if defined(__SIZEOF_INT128__)
#        define STATUSBAR_CRYPTO_HAS_INT128 1
#    else
#        define STATUSBAR_CRYPTO_HAS_INT128 0
#    endif
#endif
