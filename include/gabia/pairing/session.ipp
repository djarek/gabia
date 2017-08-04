//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#include <gabia/bytes.hpp>
#include <gabia/crypto/random_device.hpp>
#include <gabia/pairing/session.hpp>
#include <gabia/tlv8.hpp>

#include <boost/beast.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/stream.hpp>
#include <string>

namespace gabia {
namespace pairing {

namespace beast = boost::beast;
using beast::http::status;
using array_istream = boost::iostreams::stream<boost::iostreams::array_source>;
using vector_ostream = boost::iostreams::stream<
    boost::iostreams::back_insert_device<std::vector<char>>>;

struct device_info_parameters {
    gsl::cstring_span<> info;
    gsl::cstring_span<> salt;
};

inline auto generate_device_info(const device_info_parameters& parameters,
                                 gsl::span<const gsl::byte> secret,
                                 gsl::span<const gsl::byte> identifier,
                                 gsl::span<const gsl::byte> ltpk) {
    std::vector<gsl::byte> device_info{};
    device_info.reserve(crypto::hkdf_output_key_size + identifier.size_bytes() +
                        ltpk.size_bytes());
    device_info.resize(crypto::hkdf_output_key_size);

    crypto::hkdf(secret, as_bytes(parameters.salt), as_bytes(parameters.info),
                 {device_info});
    auto identifier_bytes = as_bytes(identifier);
    device_info.insert(device_info.end(), identifier_bytes.begin(),
                       identifier_bytes.end());
    device_info.insert(device_info.end(), ltpk.begin(), ltpk.end());
    return device_info;
}

inline std::vector<gsl::byte> generate_device_info(
    gsl::span<const gsl::byte, crypto::curve25519_key::public_key_size>
        sender_key,
    gsl::span<const gsl::byte> sender_identifier,
    gsl::span<const gsl::byte, crypto::curve25519_key::public_key_size>
        peer_key) {
    std::vector<gsl::byte> device_info;
    device_info.reserve(sender_key.size_bytes() +
                        sender_identifier.size_bytes() + peer_key.size_bytes());
    device_info.insert(device_info.end(), sender_key.begin(), sender_key.end());
    device_info.insert(device_info.end(), sender_identifier.begin(),
                       sender_identifier.end());
    device_info.insert(device_info.end(), peer_key.begin(), peer_key.end());
    return device_info;
}

namespace setup {

template <typename KeyStore>
template <typename Request, typename Response>
void server_context<KeyStore>::handle_m1(Request& request, Response& response) {
    tlv::item item = {};
    m1_data request_data = {};
    auto response_payload = beast::ostream(response.body);
    array_istream request_payload{request.body.data(), request.body.size()};
    while (request_payload.good() && tlv::read(request_payload, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::state:
                if (item.data.size() != sizeof(gsl::byte)) {
                    response.result(status::bad_request);
                    return;
                }
                request_data.state = static_cast<pairing::state>(item.data[0]);
                break;
            case pairing::tag::method:
                if (item.data.size() != sizeof(gsl::byte)) {
                    response.result(status::bad_request);
                    return;
                }
                request_data.method =
                    static_cast<pairing::method>(item.data[0]);
                break;
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }

    if (request_payload.bad() || request_payload.fail() ||
        request_data.invalid()) {
        response.result(status::bad_request);
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::unknown);
        return;
    }

    tlv::write(response_payload, pairing::tag::state, pairing::state::m2);

    if (!pairings.empty()) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::unavailable);
        response.result(status::too_many_requests);
        return;
    }

    if (!pairings.can_attempt_setup()) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::max_tries);
        response.result(status::too_many_requests);
        return;
    }

    auto key_item =
        tlv::item::make(pairing::tag::public_key, crypto::srp_public_key_size);
    auto salt_item = tlv::item::make(
        pairing::tag::salt, constants::salt.begin(), constants::salt.end());

    srp.set_username(as_bytes(constants::user_name));
    srp.set_params({constants::modulus}, {constants::generator},
                   {constants::salt});
    srp.set_verifier({constants::verifier});
    srp.gen_public_key({key_item.data});
    tlv::write(response_payload, key_item);
    tlv::write(response_payload, salt_item);
    response.result(status::ok);
}

template <typename KeyStore>
void server_context<KeyStore>::parse(std::istream& request_payload,
                                     m3_data& request_data) {
    tlv::item item = {};
    while (request_payload.good() && tlv::read(request_payload, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::state:
                if (item.data.size() != sizeof(gsl::byte)) {
                    request_payload.setstate(std::istream::failbit);
                    return;
                }
                request_data.state = static_cast<pairing::state>(item.data[0]);
                break;
            case pairing::tag::public_key:
                request_data.srp_pub_key = std::move(item.data);
                break;
            case pairing::tag::proof:
                request_data.srp_proof = std::move(item.data);
                break;
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }
}

template <typename KeyStore>
template <typename Request, typename Response>
void server_context<KeyStore>::handle_m3(Request& request, Response& response) {
    m3_data request_data = {};
    auto response_payload = beast::ostream(response.body);
    array_istream request_payload{request.body.data(), request.body.size()};
    parse(request_payload, request_data);
    tlv::write(response_payload, pairing::tag::state, pairing::state::m4);
    if (request_payload.bad() || request_payload.fail() ||
        request_data.state != pairing::state::m3 ||
        request_data.srp_proof.size() != crypto::srp_proof_size ||
        request_data.srp_pub_key.size() != crypto::srp_public_key_size) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::unknown);
        response.result(status::bad_request);
        return;
    }

    srp.compute_shared_secret({request_data.srp_pub_key});

    if (!srp.verify_peer_proof({request_data.srp_proof})) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::authentication);
        pairings.set_failed_setup_attempt();
        response.result(status::bad_request);
        return;
    }

    auto shared_secret = srp.get_shared_secret();
    crypto::hkdf(shared_secret, as_bytes(constants::setup_session_salt),
                 as_bytes(constants::setup_session_info), {session_key});

    auto server_proof_item =
        tlv::item::make(pairing::tag::proof, crypto::srp_proof_size);
    srp.gen_proof({server_proof_item.data});
    tlv::write(response_payload, server_proof_item);
    response.result(status::ok);
}

template <typename KeyStore>
void server_context<KeyStore>::parse(std::istream& request_payload,
                                     m5_data& request_data) {
    tlv::item item = {};
    std::vector<gsl::byte> encrypted_data = {};
    while (request_payload.good() && tlv::read(request_payload, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::state:
                if (item.data.size() != sizeof(gsl::byte)) {
                    request_payload.setstate(std::istream::failbit);
                    return;
                }
                request_data.state = static_cast<pairing::state>(item.data[0]);
                break;
            case pairing::tag::encrypted_data:
                encrypted_data = std::move(item.data);
                break;
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }

    if (request_payload.bad() || request_payload.fail() ||
        encrypted_data.size() <= crypto::aead_auth_tag_size) {
        request_payload.setstate(std::istream::failbit);
        return;
    }

    auto message_span =
        gsl::make_span(encrypted_data)
            .first(encrypted_data.size() - crypto::aead_auth_tag_size);
    bool success =
        crypto::aead_decrypt({session_key}, as_bytes(constants::setup_m5_nonce),
                             {}, encrypted_data, message_span);
    if (!success) {
        Expects(success);
        // TODO: return authentication error!
        return;
    }

    array_istream stream{reinterpret_cast<const char*>(message_span.data()),
                         gsl::narrow<std::size_t>(message_span.size_bytes())};
    while (stream.good() && tlv::read(stream, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::identifier:
                request_data.controller_identifier = std::move(item.data);
                break;
            case pairing::tag::public_key:
                request_data.controller_ltpk = std::move(item.data);
                break;
            case pairing::tag::signature:
                request_data.controller_signature = std::move(item.data);
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }
}

template <typename KeyStore>
template <typename Request, typename Response>
void server_context<KeyStore>::handle_m5(Request& request, Response& response) {
    auto response_payload = beast::ostream(response.body);
    array_istream request_payload{request.body.data(), request.body.size()};
    m5_data request_data = {};
    parse(request_payload, request_data);
    tlv::write(response_payload, pairing::tag::state, pairing::state::m6);
    if (request_payload.bad() || request_payload.fail() ||
        request_data.invalid()) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::unknown);
        response.result(status::bad_request);
        return;
    }

    pairing::pairing_entry new_pairing{
        std::move(request_data.controller_identifier),
        {{request_data.controller_ltpk}},
        pairing::flags::admin};
    auto controller_info =
        generate_device_info({constants::controller_signing_info,
                              constants::controller_signing_salt},
                             srp.get_shared_secret(), new_pairing.identifier,
                             {request_data.controller_ltpk});
    if (!new_pairing.ltpk.verify({controller_info},
                                 request_data.controller_signature)) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::authentication);
        response.result(status::bad_request);
        return;
    }

    pairings.emplace(std::move(
        new_pairing)); // TODO: Catch exception, if fails, send MaxPeers error

    auto& our_ltpk = pairings.get_our_ltsk();
    std::array<gsl::byte, crypto::ed25519_key::public_key_size> our_ltpk_bytes;
    our_ltpk.export_public_key({our_ltpk_bytes});
    auto accessory_info = generate_device_info(
        {constants::accessory_signing_info, constants::accessory_signing_salt},
        srp.get_shared_secret(), as_bytes(our_identifier), {our_ltpk_bytes});
    std::array<gsl::byte, crypto::ed25519_key::signature_size> our_signature;
    our_ltpk.sign({accessory_info}, {our_signature});

    std::vector<char> encrypted_data{};
    vector_ostream subtlv_stream{encrypted_data};
    tlv::write(subtlv_stream, tag::identifier, our_identifier);
    tlv::write(subtlv_stream, tag::public_key, our_ltpk_bytes);
    tlv::write(subtlv_stream, tag::signature, our_signature);
    std::array<char, crypto::aead_auth_tag_size> dummy_tag = {};
    subtlv_stream.write(dummy_tag.data(), dummy_tag.size());
    subtlv_stream.flush();
    auto in_span =
        as_bytes(encrypted_data)
            .first(encrypted_data.size() - crypto::aead_auth_tag_size);
    crypto::aead_encrypt(session_key, as_bytes(constants::setup_m6_nonce), {},
                         in_span, as_writeable_bytes(encrypted_data));
    tlv::write(response_payload, tag::encrypted_data, encrypted_data);

    response.result(status::ok);
}

} // namespace setup

namespace verify {

template <typename KeyStore>
template <typename Request, typename Response>
void server_context<KeyStore>::handle_m1(Request& request, Response& response) {
    array_istream request_payload{request.body.data(), request.body.size()};
    auto response_payload = beast::ostream(response.body);
    m1_data request_data = {};

    tlv::write(response_payload, pairing::tag::state, pairing::state::m2);
    parse(request_payload, request_data);
    if (request_payload.bad() || request_payload.fail()) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::unknown);
        response.result(status::bad_request);
        return;
    }

    crypto::curve25519_key controller_key{
        {request_data.controller_curve25519_key}};
    crypto::curve25519_key our_key{};

    our_key.calculate_shared_secret(controller_key, {shared_secret});
    crypto::hkdf({shared_secret}, as_bytes(constants::verify_session_salt),
                 as_bytes(constants::verify_session_info), {session_key});
    our_key.export_public_key({our_curve25519_public_key});

    auto accessory_device_info = generate_device_info(
        {our_curve25519_public_key}, as_bytes(our_identifier),
        {request_data.controller_curve25519_key});
    ios_curve25519_public_key =
        std::move(request_data.controller_curve25519_key);
    auto& our_ltpk = pairings.get_our_ltsk();
    std::array<gsl::byte, crypto::ed25519_key::signature_size> our_signature{};
    our_ltpk.sign({accessory_device_info}, {our_signature});

    std::vector<char> encrypted_data{};
    vector_ostream subtlv_stream{encrypted_data};
    tlv::write(subtlv_stream, tag::identifier, our_identifier);
    tlv::write(subtlv_stream, tag::signature, our_signature);
    std::array<char, crypto::aead_auth_tag_size> dummy_tag = {};
    subtlv_stream.write(dummy_tag.data(), dummy_tag.size());
    subtlv_stream.flush();
    auto in_span =
        as_bytes(encrypted_data)
            .first(encrypted_data.size() - crypto::aead_auth_tag_size);
    crypto::aead_encrypt(session_key, as_bytes(constants::verify_m2_nonce), {},
                         in_span, as_writeable_bytes(encrypted_data));

    tlv::write(response_payload, tag::public_key,
               as_bytes(our_curve25519_public_key));
    tlv::write(response_payload, tag::encrypted_data, encrypted_data);
    response.result(status::ok);
}

template <typename KeyStore>
void server_context<KeyStore>::parse(std::istream& request_payload,
                                     m1_data& request_data) {
    tlv::item item = {};
    pairing::state state = pairing::state::unknown;
    while (request_payload.good() && tlv::read(request_payload, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::state:
                if (item.data.size() != sizeof(gsl::byte)) {
                    request_payload.setstate(std::istream::failbit);
                    return;
                }
                state = static_cast<pairing::state>(item.data[0]);
                break;
            case pairing::tag::public_key:
                request_data.controller_curve25519_key = std::move(item.data);
                break;
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }

    if (request_payload.bad() || request_payload.fail() ||
        request_data.controller_curve25519_key.size() !=
            crypto::curve25519_key::public_key_size ||
        state != pairing::state::m1) {
        request_payload.setstate(std::istream::failbit);
        return;
    }
}

template <typename KeyStore>
void server_context<KeyStore>::parse(std::istream& request_payload,
                                     m3_data& request_data) {
    tlv::item item = {};
    std::vector<gsl::byte> encrypted_data{};

    while (request_payload.good() && tlv::read(request_payload, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::state:
                if (item.data.size() != sizeof(gsl::byte)) {
                    request_payload.setstate(std::istream::failbit);
                    return;
                }
                request_data.state = static_cast<pairing::state>(item.data[0]);
                break;
            case pairing::tag::encrypted_data:
                encrypted_data = std::move(item.data);
                break;
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }

    if (request_payload.bad() || request_payload.fail() ||
        encrypted_data.size() < crypto::aead_auth_tag_size) {
        request_payload.setstate(std::istream::failbit);
        return;
    }

    auto message_span = gsl::make_span(encrypted_data);
    message_span =
        message_span.first(encrypted_data.size() - crypto::aead_auth_tag_size);
    bool success = crypto::aead_decrypt({session_key},
                                        as_bytes(constants::verify_m3_nonce),
                                        {}, {encrypted_data}, message_span);
    if (!success) {
        Expects(success);
        // TODO: return authentication error!
        return;
    }

    array_istream stream{reinterpret_cast<const char*>(message_span.data()),
                         gsl::narrow<std::size_t>(message_span.size_bytes())};
    while (stream.good() && tlv::read(stream, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::identifier:
                request_data.controller_identifier = std::move(item.data);
                break;
            case pairing::tag::signature:
                request_data.controller_signature = std::move(item.data);
                break;
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }
}

template <typename KeyStore>
template <typename Request, typename Response>
void server_context<KeyStore>::handle_m3(Request& request, Response& response) {
    array_istream request_payload{request.body.data(), request.body.size()};
    auto response_payload = beast::ostream(response.body);
    m3_data request_data = {};

    tlv::write(response_payload, pairing::tag::state, pairing::state::m4);
    parse(request_payload, request_data);
    if (request_payload.bad() || request_payload.bad() ||
        request_data.invalid()) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::unknown);
        response.result(status::bad_request);
        return;
    }

    auto ios_device_info = generate_device_info(
        {ios_curve25519_public_key}, {request_data.controller_identifier},
        {our_curve25519_public_key});
    auto pairing_it = pairings.find(request_data.controller_identifier);
    if (pairing_it == pairings.end()) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::authentication);
        return;
    }

    if (!pairing_it->ltpk.verify({ios_device_info},
                                 {request_data.controller_signature})) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::authentication);
        return;
    }
    // M4 response does not contain any other tlv8 items
    response.result(status::ok);
}

template <typename KeyStore>
void server_context<KeyStore>::generate(crypto::aead_secrets& secrets) const {
    constexpr auto salt = make_cstring_span("Control-Salt");
    constexpr auto read_info = make_cstring_span("Control-Read-Encryption-Key");
    constexpr auto write_info =
        make_cstring_span("Control-Write-Encryption-Key");

    crypto::hkdf({shared_secret}, as_bytes(salt), as_bytes(read_info),
                 {secrets.our_key});
    crypto::hkdf({shared_secret}, as_bytes(salt), as_bytes(write_info),
                 {secrets.peer_key});
}

} // namespace verify

namespace pairings {

template <typename KeyStore>
template <typename Request, typename Response, typename RemoveCallback>
void server_context<KeyStore>::handle_m1(Request& request, Response& response,
                                         RemoveCallback&& remove_callback) {
    boost::variant<boost::blank, m1_add_data, m1_remove_data, m1_list_data>
        request_data;
    array_istream request_payload{request.body.data(), request.body.size()};
    parse(request_payload, request_data);
    auto response_payload = beast::ostream(response.body);
    tlv::write(response_payload, pairing::tag::state, pairing::state::m2);
    if (request_payload.bad() || request_payload.fail()) {
        tlv::write(response_payload, pairing::tag::error,
                   pairing::error::unknown);
        response.result(status::bad_request);
        return;
    }

    switch (request_data.which()) {
        case 0:
            tlv::write(response_payload, pairing::tag::error,
                       pairing::error::unknown);
            response.result(status::bad_request);
            break;
        case 1: { // add pairing
            auto& add_data = boost::get<m1_add_data>(request_data);
            if (add_data.invalid()) {
                tlv::write(response_payload, pairing::tag::error,
                           pairing::error::unknown);
                response.result(status::bad_request);
                break;
            }

            try {
                key_store.emplace(std::move(add_data.new_pairing));
            } catch (const std::exception& e) {
                tlv::write(response_payload, pairing::tag::error,
                           pairing::error::max_peers);
                response.result(status::bad_request);
                break;
            }

            response.result(status::ok);
            break;
        }

        case 2: { // remove pairing
            auto& remove_data = boost::get<m1_remove_data>(request_data);
            if (remove_data.invalid()) {
                tlv::write(response_payload, pairing::tag::error,
                           pairing::error::unknown);
                response.result(status::bad_request);
                return;
            }

            auto pairing_it = key_store.find({remove_data.identifier});
            if (pairing_it == key_store.end()) {
                // Return success if it does not exist
                break;
            }

            auto final_operation = gsl::finally(
                [this, pairing_it]() { key_store.erase(pairing_it); });
            try {
                remove_callback({remove_data.identifier});
            } catch (const std::exception& e) {
                throw;
            }

            break;
        }
        case 3: { // list pairing
            auto& list_data = boost::get<m1_list_data>(request_data);
            if (list_data.invalid()) {
                tlv::write(response_payload, pairing::tag::error,
                           pairing::error::unknown);
                response.result(status::bad_request);
                return;
            }
            bool first_time = true;
            for (const auto& entry : key_store) {
                if (!first_time) {
                    tlv::item seprator{
                        static_cast<gsl::byte>(pairing::tag::separator), {}};
                    tlv::write(response_payload, seprator);
                }
                first_time = false;
                tlv::write(response_payload, pairing::tag::identifier,
                           entry.identifier);
                std::array<gsl::byte, crypto::ed25519_key::public_key_size>
                    ltpk_bytes;
                entry.ltpk.export_public_key({ltpk_bytes});
                tlv::write(response_payload, pairing::tag::public_key,
                           ltpk_bytes);
                tlv::write(response_payload, pairing::tag::permissions,
                           static_cast<gsl::byte>(entry.flags));
            }
            response.result(status::ok);
            break;
        }
        default:
            Expects(false);
    }
}

template <typename KeyStore>
void server_context<KeyStore>::parse(
    std::istream& request_payload,
    boost::variant<boost::blank, m1_add_data, m1_remove_data, m1_list_data>&
        data) {
    tlv::item item = {};
    pairing::state state{};
    pairing::method method{};

    std::vector<gsl::byte> identifier{};
    std::vector<gsl::byte> public_key{};
    pairing::flags flags{};

    while (request_payload.good() && tlv::read(request_payload, item)) {
        switch (static_cast<pairing::tag>(item.tag)) {
            case pairing::tag::state:
                if (item.data.size() != sizeof(gsl::byte)) {
                    request_payload.setstate(std::istream::failbit);
                    return;
                }
                state = static_cast<pairing::state>(item.data[0]);
                break;
            case pairing::tag::method:
                if (item.data.size() != sizeof(gsl::byte)) {
                    request_payload.setstate(std::istream::failbit);
                    return;
                }
                method = static_cast<pairing::method>(item.data[0]);
                break;
            case pairing::tag::identifier:
                identifier = std::move(item.data);
                break;
            case pairing::tag::public_key:
                public_key = std::move(item.data);
                break;
            case pairing::tag::permissions:
                flags = static_cast<pairing::flags>(item.data[0]);
                break;
            default:
                // HAP non-commercial spec R1: 12.1.1: "TLV items with
                // unrecognized types must be silently ignored."
                break;
        }
    }

    switch (method) {
        case pairing::method::pairing_add: {
            m1_add_data add_data{
                state, method, {std::move(identifier), {public_key}, flags}};
            data = std::move(add_data);
            break;
        }
        case pairing::method::pairing_remove: {
            m1_remove_data remove_data{state, method, std::move(identifier)};
            data = std::move(remove_data);
            break;
        }
        case pairing::method::pairings_list: {
            m1_list_data list_data{state, method};
            data = std::move(list_data);
            break;
        }
        default:
            request_payload.setstate(std::istream::failbit);
            break;
    }
}

} // namespace pairings

} // namespace pairing
} // namespace gabia
