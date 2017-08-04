//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_RANDOM_DEVICE_HPP
#define GABIA_RANDOM_DEVICE_HPP

#include <gabia/noncopyable.hpp>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>

#include <gsl/gsl>

namespace gabia {
namespace crypto {

class random_device : noncopyable, nonmovable {
public:
    random_device() {
        auto ret = wc_InitRng(&rng);
        Expects(ret == 0);
    }

    void generate(gsl::span<gsl::byte> block) {
        auto ret = wc_RNG_GenerateBlock(
            &rng, reinterpret_cast<::byte*>(block.data()), block.size_bytes());
        Expects(ret == 0);
    }
    void generate(::curve25519_key& key) {
        auto ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key);
        Expects(ret == 0);
    }
    void generate(::ed25519_key& key) {
        auto ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key);
        Expects(ret == 0);
    }

    ~random_device() {
        auto ret = wc_FreeRng(&rng);
        Expects(ret == 0);
    }

private:
    WC_RNG rng;
};

} // namespace crypto
} // namespace gabia

#endif // GABIA_RANDOM_DEVICE_HPP
