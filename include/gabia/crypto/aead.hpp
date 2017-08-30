//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_CRYPTO_AEAD_HPP
#define GABIA_CRYPTO_AEAD_HPP

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <boost/endian/arithmetic.hpp>

#include <gsl/gsl_algorithm>
#include <gsl/gsl>

namespace gabia {

namespace crypto {

constexpr auto aead_key_size = 32;
constexpr auto aead_nonce_size = 12;
constexpr auto aead_auth_tag_size = 16;

struct aead_secrets {
    std::array<gsl::byte, aead_key_size> our_key;
    uint64_t our_counter = 0;

    std::array<gsl::byte, aead_key_size> peer_key;
    uint64_t peer_counter = 0;
};

namespace details {

inline std::array<gsl::byte, aead_nonce_size> aead_generate_nonce(
    uint64_t& counter) {
    std::array<gsl::byte, aead_nonce_size> ret = {};
    auto ret_span = gsl::make_span(ret).last(sizeof(uint64_t));
    boost::endian::little_uint64_t counter_le = counter;
    auto counter_span = gsl::as_bytes(gsl::make_span(&counter_le, 1));
    gsl::copy(counter_span, ret_span);
    ++counter;
    return ret;
}

} // namespace

inline void aead_encrypt(gsl::span<const gsl::byte, aead_key_size> key,
                         gsl::span<const gsl::byte, aead_nonce_size> nonce,
                         gsl::span<const gsl::byte> aad,
                         gsl::span<const gsl::byte> message,
                         gsl::span<gsl::byte> ciphertext_out) {
    Expects(ciphertext_out.size_bytes() >= aead_auth_tag_size);
    Expects(message.size_bytes() + aead_auth_tag_size ==
            ciphertext_out.size_bytes());
    const auto auth_tag_span = ciphertext_out.last(aead_auth_tag_size);
    const auto key_ptr = reinterpret_cast<const ::byte*>(key.data());
    const auto iv_ptr = reinterpret_cast<const ::byte*>(nonce.data());
    const auto aad_ptr = reinterpret_cast<const ::byte*>(aad.data());
    const auto message_ptr = reinterpret_cast<const ::byte*>(message.data());

    auto cipher_text_ptr = reinterpret_cast<::byte*>(ciphertext_out.data());
    auto auth_tag_ptr = reinterpret_cast<::byte*>(auth_tag_span.data());

    auto ret = wc_ChaCha20Poly1305_Encrypt(
        key_ptr, iv_ptr, aad_ptr, aad.size_bytes(), message_ptr,
        message.size_bytes(), cipher_text_ptr, auth_tag_ptr);
    Expects(ret == 0);
}

inline bool aead_decrypt(gsl::span<const gsl::byte, aead_key_size> key,
                         gsl::span<const gsl::byte, aead_nonce_size> nonce,
                         gsl::span<const gsl::byte> aad,
                         gsl::span<const gsl::byte> ciphertext,
                         gsl::span<gsl::byte> message_out) {
    Expects(ciphertext.size_bytes() >= aead_auth_tag_size);
    Expects(message_out.size_bytes() + aead_auth_tag_size ==
            ciphertext.size_bytes());
    const auto auth_tag_span = ciphertext.last(aead_auth_tag_size);
    ciphertext = ciphertext.first(ciphertext.size_bytes() - aead_auth_tag_size);
    const auto key_ptr = reinterpret_cast<const ::byte*>(key.data());
    const auto iv_ptr = reinterpret_cast<const ::byte*>(nonce.data());
    const auto aad_ptr = reinterpret_cast<const ::byte*>(aad.data());
    const auto cipher_text_ptr =
        reinterpret_cast<const ::byte*>(ciphertext.data());
    const auto auth_tag_ptr =
        reinterpret_cast<const ::byte*>(auth_tag_span.data());

    auto message_ptr = reinterpret_cast<::byte*>(message_out.data());
    auto ret = wc_ChaCha20Poly1305_Decrypt(
        key_ptr, iv_ptr, aad_ptr, aad.size_bytes(), cipher_text_ptr,
        ciphertext.size_bytes(), auth_tag_ptr, message_ptr);
    Expects(ret == MAC_CMP_FAILED_E || ret == 0);
    return ret == 0;
}

template <typename Secrets>
void aead_encrypt(Secrets& secrets, gsl::span<const gsl::byte> aad,
                  gsl::span<const gsl::byte> message,
                  gsl::span<gsl::byte> ciphertext_out) {
    auto our_nonce = details::aead_generate_nonce(secrets.our_counter);
    aead_encrypt({secrets.our_key}, {our_nonce}, aad, message, ciphertext_out);
}

template <typename Secrets>
bool aead_decrypt(Secrets& secrets, gsl::span<const gsl::byte> aad,
                  gsl::span<const gsl::byte> ciphertext,
                  gsl::span<gsl::byte> message_out) {
    auto peer_nonce = details::aead_generate_nonce(secrets.peer_counter);
    auto ret = aead_decrypt({secrets.peer_key}, {peer_nonce}, aad, ciphertext,
                            message_out);
    if (!ret) {
        // If decryption failed we can't leave the counter incremented -
        // disallow DoS via spoofing.
        --secrets.peer_counter;
    }
    return ret;
}

} // namespace crypto

} // namespace gabia
#endif // GABIA_CRYPTO_AEAD_HPP
