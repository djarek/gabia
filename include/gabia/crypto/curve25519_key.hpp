//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_CRYPTO_CURVE25519_KEY
#define GABIA_CRYPTO_CURVE25519_KEY

#include <gabia/crypto/random_device.hpp>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

namespace gabia {
namespace crypto {

class curve25519_key {
public:
    constexpr static auto public_key_size = 32;
    constexpr static auto shared_secret_size = 32;

    curve25519_key() {
        auto ret = wc_curve25519_init(&key);
        Expects(ret == 0);
        random_device rng{};
        rng.generate(key);
    }
    curve25519_key(gsl::span<const gsl::byte, public_key_size> public_key) {
        auto ret = wc_curve25519_init(&key);
        Expects(ret == 0);
        auto public_key_ptr =
            reinterpret_cast<const ::byte*>(public_key.data());
        ret = wc_curve25519_import_public_ex(public_key_ptr,
                                             public_key.size_bytes(), &key,
                                             EC25519_LITTLE_ENDIAN);
        Expects(ret == 0);
    }
    ~curve25519_key() { wc_curve25519_free(&key); }

    void calculate_shared_secret(
        curve25519_key& public_key,
        gsl::span<gsl::byte, shared_secret_size> shared_secret_out) {
        auto shared_secret_ptr =
            reinterpret_cast<::byte*>(shared_secret_out.data());
        ::word32 out_len = shared_secret_out.size_bytes();
        auto ret = wc_curve25519_shared_secret_ex(&key, &public_key.key,
                                                  shared_secret_ptr, &out_len,
                                                  EC25519_LITTLE_ENDIAN);
        Expects(ret == 0);
    }
    void export_public_key(
        gsl::span<gsl::byte, public_key_size> public_key_out) {
        auto public_key_ptr = reinterpret_cast<::byte*>(public_key_out.data());
        ::word32 out_len = public_key_out.size_bytes();
        auto ret = wc_curve25519_export_public_ex(
            &key, public_key_ptr, &out_len, EC25519_LITTLE_ENDIAN);
        Expects(ret == 0);
    }

private:
    ::curve25519_key key;
};

} // namespace crypto
} // namespace gabia

#endif // GABIA_CRYPTO_CURVE25519_KEY
