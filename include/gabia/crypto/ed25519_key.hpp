//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_CRYPTO_ED25519_KEY
#define GABIA_CRYPTO_ED25519_KEY

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <gabia/crypto/random_device.hpp>

namespace gabia {
namespace crypto {

class ed25519_key {
public:
    constexpr static auto signature_size = 64;
    constexpr static auto key_size = 64;
    constexpr static auto public_key_size = 32;
    constexpr static auto private_key_size = 32;
    ed25519_key(gsl::span<const gsl::byte, private_key_size> private_key,
                gsl::span<const gsl::byte, public_key_size> public_key) {
        auto public_key_ptr =
            reinterpret_cast<const ::byte*>(public_key.data());
        auto private_key_ptr =
            reinterpret_cast<const ::byte*>(private_key.data());
        auto ret = wc_ed25519_import_private_key(
            private_key_ptr, private_key.size_bytes(), public_key_ptr,
            public_key.size_bytes(), &key);
        Expects(ret == 0);
    }

    ed25519_key(gsl::span<const gsl::byte, public_key_size> public_key) {
        auto public_key_ptr =
            reinterpret_cast<const ::byte*>(public_key.data());
        auto ret = wc_ed25519_init(&key);
        Expects(ret == 0);
        ret = wc_ed25519_import_public(public_key_ptr, public_key.size_bytes(),
                                       &key);
        Expects(ret == 0);
    }
    ed25519_key() {
        auto ret = wc_ed25519_init(&key);
        Expects(ret == 0);
        random_device rng{};
        rng.generate(key);
        has_private = true;
    }
    ~ed25519_key() { wc_ed25519_free(&key); }

    void sign(gsl::span<const gsl::byte> message,
              gsl::span<gsl::byte, signature_size> signature_out) const {
        Expects(has_private);
        ::word32 out_len = signature_out.size_bytes();
        auto msg_ptr = reinterpret_cast<const ::byte*>(message.data());
        auto signature_ptr = reinterpret_cast<::byte*>(signature_out.data());

        auto ret = wc_ed25519_sign_msg(msg_ptr, message.size_bytes(),
                                       signature_ptr, &out_len, &key);
        Expects(ret == 0);
    }

    bool verify(gsl::span<const gsl::byte> message,
                gsl::span<gsl::byte, signature_size> signature) const {
        auto msg_ptr = reinterpret_cast<const ::byte*>(message.data());
        auto signature_ptr = reinterpret_cast<::byte*>(signature.data());
        int stat = 0;
        auto ret =
            wc_ed25519_verify_msg(signature_ptr, signature.size_bytes(),
                                  msg_ptr, message.size_bytes(), &stat, &key);
        Expects(ret == 0 || ret == SIG_VERIFY_E);
        return stat == 1;
    }

    void export_private_key(
        gsl::span<gsl::byte, private_key_size> private_key_out,
        gsl::span<gsl::byte, public_key_size> public_key_out) const {
        Expects(has_private);
        ::word32 private_size = private_key_out.size_bytes();
        ::word32 public_size = public_key_out.size_bytes();
        auto private_key_ptr =
            reinterpret_cast<::byte*>(private_key_out.data());
        auto public_key_ptr = reinterpret_cast<::byte*>(public_key_out.data());
        auto ret = wc_ed25519_export_key(&key, private_key_ptr, &private_size,
                                         public_key_ptr, &public_size);
        Expects(ret == 0);
        Expects(private_size == private_key_size);
        Expects(public_size == public_key_size);
    }

    void export_public_key(
        gsl::span<gsl::byte, public_key_size> public_key_out) const {
        ::word32 public_size = public_key_out.size_bytes();
        auto public_key_ptr = reinterpret_cast<::byte*>(public_key_out.data());
        auto ret = wc_ed25519_export_public(&key, public_key_ptr, &public_size);
        Expects(ret == 0);
        Expects(public_size = public_key_size);
    }

private:
    mutable ::ed25519_key key;
    bool has_private = false;
};

} // namespace crypto
} // namespace gabia

#endif // GABIA_CRYPTO_ED25519_KEY
