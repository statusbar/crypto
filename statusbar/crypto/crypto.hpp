#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/crypto/25519/curve25519.hpp"
#include "statusbar/crypto/25519/ed25519.hpp"
#include "statusbar/crypto/25519/x25519.hpp"
#include "statusbar/crypto/aes/aes128.hpp"
#include "statusbar/crypto/aes/aes128_hw.hpp"
#include "statusbar/crypto/aes/aes256.hpp"
#include "statusbar/crypto/aes/aes256_hw.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/aes_cbc/aes_cbc.hpp"
#include "statusbar/crypto/aes_gcm_siv/aes128_gcm_siv.hpp"
#include "statusbar/crypto/aes_gcm_siv/aes256_gcm_siv.hpp"
#include "statusbar/crypto/aes_siv/aes128_siv.hpp"
#include "statusbar/crypto/aes_siv/aes256_siv.hpp"
#include "statusbar/crypto/ecies/ecies.hpp"
#include "statusbar/crypto/ecies/x25519_ecies.hpp"
#include "statusbar/crypto/hkdf/hkdf.hpp"
#include "statusbar/crypto/kdf2/kdf2.hpp"
#include "statusbar/crypto/p256/p256.hpp"
#include "statusbar/crypto/p256/p256_ecdh.hpp"
#include "statusbar/crypto/p256/p256_ecdsa.hpp"
#include "statusbar/crypto/pkcs8/pkcs8_ed25519.hpp"
#include "statusbar/crypto/pkcs8/pkcs8_p256.hpp"
#include "statusbar/crypto/polyval/polyval_hw.hpp"
#include "statusbar/crypto/polyval/polyval_sw.hpp"
#include "statusbar/crypto/sha/sha256.hpp"
#include "statusbar/crypto/sha/sha256_hw.hpp"
#include "statusbar/crypto/sha/sha512.hpp"
#include "statusbar/crypto/sha/sha512_hw.hpp"
#include "statusbar/crypto/types.hpp"
#include "statusbar/crypto/util/crypto_concepts.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

// Module header — includes all crypto sub-modules.
// Consumers who also use the statusbar-avb package and need AVTP key
// management should additionally include
// "statusbar/avtp_crypto/avtp_crypto.hpp" from that package.
