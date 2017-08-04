//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef HK_SESSION_HPP
#define HK_SESSION_HPP

#include <gabia/pairing/constants.hpp>

#include <gabia/crypto/curve25519_key.hpp>
#include <gabia/crypto/ed25519_key.hpp>
#include <gabia/crypto/hkdf.hpp>
#include <gabia/crypto/srp_context.hpp>

#include <boost/variant.hpp>

#include <memory>

namespace gabia {
namespace pairing {
namespace setup {

struct m1_data {
    pairing::state state;
    pairing::method method;

    bool invalid() const {
        return state != pairing::state::m1 ||
               (method != pairing::method::pair_setup &&
                method != pairing::method::unknown);
    }
};

struct m3_data {
    pairing::state state;
    std::vector<gsl::byte> srp_pub_key;
    std::vector<gsl::byte> srp_proof;

    bool invalid() const {
        return state != pairing::state::m3 ||
               srp_pub_key.size() != crypto::srp_public_key_size ||
               srp_proof.size() != crypto::srp_proof_size;
    }
};

struct m5_data {
    pairing::state state;
    std::vector<gsl::byte> controller_identifier;
    std::vector<gsl::byte> controller_ltpk;
    std::vector<gsl::byte> controller_signature;

    bool invalid() const {
        return state != pairing::state::m5 ||
               controller_identifier.size() <= 0 ||
               controller_ltpk.size() != crypto::ed25519_key::public_key_size ||
               controller_signature.size() !=
                   crypto::ed25519_key::signature_size;
    }
};

template <typename KeyStore>
struct server_context {
    using key_store_type = KeyStore;

    explicit server_context(key_store_type& pairings) : pairings{pairings} {}

    template <typename Request, typename Response>
    void handle_m1(Request& request, Response& response);
    template <typename Request, typename Response>
    void handle_m3(Request& request, Response& response);

    template <typename Request, typename Response>
    void handle_m5(Request& request, Response& response);

private:
    void parse(std::istream& request_payload, m3_data& request_data);
    void parse(std::istream& request_payload, m5_data& request_data);

    key_store_type& pairings;

    crypto::srp_server_context srp{};
    std::array<gsl::byte, crypto::hkdf_output_key_size> session_key;

    const std::string our_identifier{
        "DA:AD:BE:EF:DE:AD"}; // TODO: Should retrieve
                              // this from accessory
                              // server configuration
};
} // namespace setup

namespace verify {

struct m1_data {
    pairing::state state;
    std::vector<gsl::byte> controller_curve25519_key;
};

struct m3_data {
    pairing::state state;
    std::vector<gsl::byte> controller_identifier;
    std::vector<gsl::byte> controller_signature;

    bool invalid() {
        return state != pairing::state::m3 ||
               controller_identifier.size() <= 0 ||
               controller_signature.size() !=
                   crypto::ed25519_key::signature_size;
    }
};

template <typename KeyStore>
class server_context {
public:
    using key_store_type = KeyStore;

    explicit server_context(key_store_type& pairings) : pairings{pairings} {}

    template <typename Request, typename Response>
    void handle_m1(Request& request, Response& response);
    template <typename Request, typename Response>
    void handle_m3(Request& request, Response& response);

    void generate(crypto::aead_secrets& secrets) const;

private:
    void parse(std::istream& request_payload, m1_data& request_data);
    void parse(std::istream& request_payload, m3_data& request_data);

    std::array<gsl::byte, crypto::curve25519_key::shared_secret_size>
        shared_secret; // TODO SECURITY: Secure memset in destructor

    std::array<gsl::byte, crypto::hkdf_output_key_size>
        session_key; // TODO SECURITY: Secure memset in destructor
    std::vector<gsl::byte> ios_curve25519_public_key{
        crypto::curve25519_key::public_key_size};
    std::vector<gsl::byte> our_curve25519_public_key{
        crypto::curve25519_key::public_key_size};

    key_store_type& pairings;
    const std::string our_identifier{
        "DA:AD:BE:EF:DE:AD"}; // TODO: Should retrieve
                              // this from accessory
                              // server configuration
};
} // verify
namespace pairings {
struct m1_list_data {
    pairing::state state;
    pairing::method method;

    bool invalid() const {
        return state != pairing::state::m1 ||
               method != pairing::method::pairings_list;
    }
};

struct m1_add_data {
    pairing::state state;
    pairing::method method;
    pairing::pairing_entry new_pairing;

    bool invalid() const {
        return state != pairing::state::m1 ||
               method != pairing::method::pairing_add ||
               new_pairing.identifier.empty();
    }
};

struct m1_remove_data {
    pairing::state state;
    pairing::method method;
    std::vector<gsl::byte> identifier;

    bool invalid() const {
        return state != pairing::state::m1 ||
               method != pairing::method::pairing_remove || identifier.empty();
    }
};

template <typename KeyStore>
class server_context {
public:
    using key_store_type = KeyStore;

    server_context(KeyStore& key_store) : key_store{key_store} {}

    template <typename Request, typename Response, typename RemoveCallback>
    void handle_m1(Request& request, Response& response,
                   RemoveCallback&& remove_callback);

private:
    void parse(std::istream& request_payload,
               boost::variant<boost::blank, m1_add_data, m1_remove_data,
                              m1_list_data>& data);

    key_store_type& key_store;
};
}
} // namespace pairing
} // namespace gabia

#include "session.ipp"

#endif // HK_SESSION_HPP
