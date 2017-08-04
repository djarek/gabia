//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef HK_CRYPTO_HKDF_HPP
#define HK_CRYPTO_HKDF_HPP

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include <gsl/gsl>

namespace gabia {
namespace crypto {

constexpr auto hkdf_output_key_size = 32;

inline void hkdf(gsl::span<const gsl::byte> input_key,
                 gsl::span<const gsl::byte> salt,
                 gsl::span<const gsl::byte> info,
                 gsl::span<gsl::byte, hkdf_output_key_size> output_key) {
    auto ret = wc_HKDF(
        SHA512, reinterpret_cast<const ::byte*>(input_key.data()),
        input_key.size_bytes(), reinterpret_cast<const ::byte*>(salt.data()),
        salt.size_bytes(), reinterpret_cast<const ::byte*>(info.data()),
        info.size_bytes(), reinterpret_cast<::byte*>(output_key.data()),
        output_key.size_bytes());
    Expects(ret == 0);
}

} // namespace crypto
} // namespace gabia

#endif // HK_CRYPTO_HKDF_HPP
