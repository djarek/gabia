//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_SRP_CONTEXT_HPP
#define GABIA_SRP_CONTEXT_HPP

#include <gabia/noncopyable.hpp>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/srp.h>

#include <gsl/gsl>

namespace gabia {
namespace crypto {

constexpr auto srp_modulus_size = 384;
constexpr auto srp_generator_size = 1;
constexpr auto srp_verifier_size = srp_modulus_size;
constexpr auto srp_salt_size = 16;
constexpr auto srp_hash_size = 64;
constexpr auto srp_secret_key_size = 32;
constexpr auto srp_public_key_size = srp_modulus_size;
constexpr auto srp_shared_secret_size = srp_hash_size;
constexpr auto srp_proof_size = srp_hash_size;

enum class srp_side { server, client };

class basic_srp_context : noncopyable, nonmovable {
protected:
    basic_srp_context(srp_side side) {
        auto wc_srp_side = SrpSide::SRP_SERVER_SIDE;
        if (side == srp_side::client) {
            wc_srp_side = SrpSide::SRP_CLIENT_SIDE;
        }
        auto ret = wc_SrpInit(&srp, SrpType::SRP_TYPE_SHA512, wc_srp_side);
        Expects(ret == 0);
        srp.keyGenFunc_cb = kdf;
    }
    ~basic_srp_context() { wc_SrpTerm(&srp); }

    void set_username(gsl::span<const gsl::byte> user_name) {
        auto ret = wc_SrpSetUsername(
            &srp, reinterpret_cast<const ::byte*>(user_name.data()),
            user_name.size_bytes());
        Expects(ret == 0);
    }
    void set_params(gsl::span<const gsl::byte, srp_modulus_size> modulus,
                    gsl::span<const gsl::byte, srp_generator_size> generator,
                    gsl::span<const gsl::byte, srp_salt_size> salt) {
        auto ret = wc_SrpSetParams(
            &srp, reinterpret_cast<const ::byte*>(modulus.data()),
            modulus.size_bytes(),
            reinterpret_cast<const ::byte*>(generator.data()),
            generator.size_bytes(),
            reinterpret_cast<const ::byte*>(salt.data()), salt.size_bytes());
        Expects(ret == 0);
    }
    void set_password(gsl::span<const gsl::byte> password) {
        auto ret = wc_SrpSetPassword(
            &srp, reinterpret_cast<const ::byte*>(password.data()),
            password.size_bytes());
        Expects(ret == 0);
    }
    void set_verifier(gsl::span<const gsl::byte, srp_verifier_size> verifier) {
        auto ret = wc_SrpSetVerifier(
            &srp, reinterpret_cast<const ::byte*>(verifier.data()),
            verifier.size_bytes());
        Expects(ret == 0);
    }
    void gen_verifier(gsl::span<gsl::byte, srp_verifier_size> verifier_out) {
        ::word32 size = verifier_out.size_bytes();
        auto ret = wc_SrpGetVerifier(
            &srp, reinterpret_cast<::byte*>(verifier_out.data()), &size);
        Expects(ret == 0);
        Expects(size == verifier_out.size_bytes());
    }
    void set_secret_key(
        gsl::span<const gsl::byte, srp_secret_key_size> secret_key) {
        auto ret = wc_SrpSetPrivate(
            &srp, reinterpret_cast<const ::byte*>(secret_key.data()),
            secret_key.size_bytes());
        Expects(ret == 0);
    }
    void gen_public_key(
        gsl::span<gsl::byte, srp_public_key_size> public_key_out) {
        ::word32 size = public_key_out.size_bytes();
        auto ret = wc_SrpGetPublic(
            &srp, reinterpret_cast<::byte*>(public_key_out.data()), &size);
        Expects(ret == 0);
        Expects(size == public_key_out.size_bytes());
        std::copy(public_key_out.begin(), public_key_out.end(),
                  our_public_key.begin());
    }

    void compute_shared_secret(
        gsl::span<const gsl::byte, srp_public_key_size> peer_public_key_in) {
        Expects(peer_public_key_in.size_bytes() == peer_public_key.size());
        std::copy(peer_public_key_in.begin(), peer_public_key_in.end(),
                  peer_public_key.begin());
        // Need to copy the key, due to the fact that wc_SrpComputeKey does not
        // take
        // pointer to const args(would need const_cast).
        auto client_key_ptr = reinterpret_cast<::byte*>(peer_public_key.data());
        auto server_key_ptr = reinterpret_cast<::byte*>(our_public_key.data());
        if (srp.side == SrpSide::SRP_CLIENT_SIDE) {
            std::swap(client_key_ptr, server_key_ptr);
        }

        auto ret =
            wc_SrpComputeKey(&srp, client_key_ptr, peer_public_key.size(),
                             server_key_ptr, our_public_key.size());
        Expects(ret == 0);
    }
    void gen_proof(gsl::span<gsl::byte, srp_proof_size> proof_out) {
        ::word32 size = proof_out.size_bytes();
        auto ret = wc_SrpGetProof(
            &srp, reinterpret_cast<::byte*>(proof_out.data()), &size);
        Expects(ret == 0);
        Expects(size == proof_out.size_bytes());
    }
    bool verify_peer_proof(
        gsl::span<const gsl::byte, srp_proof_size> peer_proof) {
        auto proof_ptr = reinterpret_cast<const ::byte*>(peer_proof.data());
        auto ret = wc_SrpVerifyPeersProof(&srp, const_cast<::byte*>(proof_ptr),
                                          peer_proof.size_bytes());
        return ret == 0;
    }

    gsl::span<const gsl::byte, srp_shared_secret_size> get_shared_secret()
        const {
        Expects(srp.keySz == srp_shared_secret_size);
        return gsl::as_bytes(gsl::make_span(srp.key, srp.keySz));
    }

    static int kdf(::Srp* srp, ::byte* secret, ::word32 size) {
        SrpHash hash{};
        int r = BAD_FUNC_ARG;

        srp->key = static_cast<byte*>(
            XMALLOC(SHA512_DIGEST_SIZE, NULL, DYNAMIC_TYPE_SRP));
        if (srp->key == NULL) {
            return MEMORY_E;
        }

        srp->keySz = SHA512_DIGEST_SIZE;

        r = wc_InitSha512(&hash.data.sha512);
        if (!r) r = wc_Sha512Update(&hash.data.sha512, secret, size);
        if (!r) r = wc_Sha512Final(&hash.data.sha512, srp->key);

        // ForceZero(&hash, sizeof(SrpHash)); // TODO: SECURITY SECURE CLEAR
        // MEMORY
        // OF HASH

        return r;
    }

    ::Srp srp;
    std::array<gsl::byte, srp_public_key_size>
        our_public_key; // TODO: SECURITY SECURE CLEAR MEMORY
    std::array<gsl::byte, srp_public_key_size>
        peer_public_key; // TODO: SECURITY SECURE CLEAR MEMORY
};

struct srp_server_context : basic_srp_context {
    srp_server_context() : basic_srp_context{srp_side::server} {}
    using basic_srp_context::set_username;
    using basic_srp_context::set_params;
    using basic_srp_context::set_verifier;
    using basic_srp_context::set_secret_key;
    using basic_srp_context::gen_public_key;
    using basic_srp_context::compute_shared_secret;
    using basic_srp_context::gen_proof;
    using basic_srp_context::verify_peer_proof;
    using basic_srp_context::get_shared_secret;
};

} // namespace crypto
} // namespace gabia

#endif // GABIA_SRP_CONTEXT_HPP
