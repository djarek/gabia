#include "server.hpp"

#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/stream.hpp>

#include <fstream>
#include <json.hpp>
#include <thread>
#include <vector>

#define CORO_YIELD BOOST_ASIO_CORO_YIELD
#define CORO_REENTER BOOST_ASIO_CORO_REENTER

using njson = nlohmann::json;

server::server(asio::io_service& service) : acceptor{service} {
#define LAMBDA_BIND(func)                                 \
    [this](peer& controller, peer::request_type& request, \
           asio::yield_context& yield) { func(controller, request, yield); }
    routes = std::vector<route_handler>{
        {"/pair-setup", LAMBDA_BIND(handle_pair_setup)},
        {"/pair-verify", LAMBDA_BIND(handle_pair_verify)},
        {"/pairings", LAMBDA_BIND(handle_pairings)},
        {"/accessories", LAMBDA_BIND(handle_discovery)},
        {"/characteristics", LAMBDA_BIND(handle_characteristics)}};
#undef LAMBDA_BIND
}

void server::start() {
    asio::ip::tcp::endpoint ep{asio::ip::address_v6::any(), 8080};
    beast::error_code err{};
    acceptor.open(ep.protocol(), err);
    if (err) {
        std::cerr << "Unable to open acceptor: " << err.message() << std::endl;
        return;
    }

    acceptor.set_option(asio::ip::tcp::acceptor::reuse_address{true}, err);
    if (err) {
        std::cerr << "Unable to enable address reuse: " << err.message()
                  << std::endl;
        return;
    }

    acceptor.bind(ep, err);
    if (err) {
        std::cerr << "Unable to bind acceptor: " << err.message() << std::endl;
        return;
    }

    acceptor.listen(16, err);
    if (err) {
        std::cerr << "Unable to listen on acceptor: " << err.message()
                  << std::endl;
        return;
    }
    async_accept();
}

void server::async_accept() {
    auto new_peer = std::make_shared<peer>(acceptor.get_io_service());
    acceptor.async_accept(
        new_peer->socket.next_layer(), [this, new_peer](beast::error_code err) {
            if (err) {
                std::cerr << "Accept error: " << err.message() << std::endl;
                async_accept();
                return;
            }

            asio::spawn(acceptor.get_io_service(),
                        [this, new_peer](asio::yield_context yield) {
                            try {
                                connection_main(*new_peer, yield);
                            } catch (const std::exception& e) {
                                std::cerr << "Caught exception: " << e.what()
                                          << " disconnecting client."
                                          << std::endl;
                            }
                        });
            async_accept();
        });
}

void server::connection_main(peer& controller, asio::yield_context yield) {
    beast::error_code error{};
    auto final_operation = gsl::finally([this, &controller]() {
        peers.erase(controller.shared_from_this());
        controller.disconnect();
    });
    while (controller.is_connected()) {
        peer::request_type request;
        controller.async_recv(request, yield[error]);
        if (error) {
            // TODO: EOF?
            std::cerr << "async_read error: " << error.message() << std::endl;
            return;
        }

        dispatch(controller, request, yield);
    }
}

void server::dispatch(peer& controller, peer::request_type& request,
                      asio::yield_context& yield) {
    auto route_it = std::find_if(
        routes.begin(), routes.end(), [&request](const route_handler& r) {
            return request.target().find(r.url) != beast::string_view::npos;
        });
    if (route_it != routes.end()) {
        route_it->callback(controller, request, yield);
        return;
    }
    peer::response_type response = {};
    response.result(beast::http::status::not_found);
    beast::error_code error{};
    controller.async_send(response, yield[error]);
    if (error) {
        controller.disconnect();
    }
}

void server::handle_pair_setup(peer& controller, peer::request_type& request,
                               asio::yield_context& yield) {
    beast::error_code error{};
    gabia::pairing::setup::server_context<decltype(pairings)> context{pairings};
    auto response = make_tlv_response(request);

    context.handle_m1(request, response);
    controller.async_send(response, yield[error]);
    if (error || response.result() != beast::http::status::ok) {
        std::cerr << "Error while sending M2: " << error.message() << std::endl;
        controller.disconnect();
        return;
    }

    controller.async_recv(request, yield[error]);
    if (error || request.target() != "/pair-setup") {
        std::cerr << "Error while receiving M3: " << error.message()
                  << std::endl;
        controller.disconnect();
        return;
    }

    response = make_tlv_response(request);
    context.handle_m3(request, response);
    controller.async_send(response, yield[error]);
    if (error || response.result() != beast::http::status::ok) {
        std::cerr << "Error while sending M4: " << error.message() << std::endl;
        controller.disconnect();
        return;
    }

    controller.async_recv(request, yield[error]);
    if (error || request.target() != "/pair-setup") {
        std::cerr << "Error while receiving M5: " << error.message()
                  << std::endl;
        controller.disconnect();
        return;
    }

    response = make_tlv_response(request);
    context.handle_m5(request, response);
    controller.async_send(response, yield[error]);
    if (error || response.result() != beast::http::status::ok) {
        std::cerr << "Error while sending M6: " << error.message() << std::endl;
        controller.disconnect();
        return;
    }
}

void server::handle_pair_verify(peer& controller, peer::request_type& request,
                                asio::yield_context& yield) {
    beast::error_code error{};
    gabia::pairing::verify::server_context<decltype(pairings)> context{
        pairings};
    auto response = make_tlv_response(request);
    context.handle_m1(request, response);
    controller.async_send(response, yield[error]);
    if (error || response.result() != beast::http::status::ok) {
        std::cerr << "Error while sending M2: " << error.message() << std::endl;
        controller.disconnect();
        return;
    }

    controller.async_recv(request, yield[error]);
    if (error || request.target() != "/pair-verify") {
        std::cerr << "Error while receiving M3: " << error.message()
                  << std::endl;
        controller.disconnect();
        return;
    }

    response = make_tlv_response(request);
    context.handle_m3(request, response);
    controller.async_send(response, yield[error]);
    if (error || response.result() != beast::http::status::ok) {
        std::cerr << "Error while sending M4: " << error.message() << std::endl;
        controller.disconnect();
        return;
    }

    gabia::crypto::aead_secrets secrets;
    context.generate(secrets);
    controller.enable_session_security(secrets);
}

void server::handle_discovery(peer& controller, peer::request_type& request,
                              asio::yield_context& yield) {
    peer::response_type response = {};
    response.result(beast::http::status::ok);
    response.set(beast::http::field::content_type, "application/hap+json");
    response.keep_alive(request.keep_alive());
    {
        auto payload = beast::ostream(response.body);
        payload
            << "{\"accessories\":[{\"aid\":1,\"services\":[{\"type\":"
               "\"3E\",\"iid\":1,\"characteristics\":[{\"perms\":[\"pw\"],"
               "\"type\":\"14\",\"iid\":2,\"format\":\"bool\"},{\"value\":"
               "\"Manufacturer\",\"perms\":[\"pr\"],\"type\":\"20\","
               "\"iid\":3,\"format\":\"string\"},{\"value\":\"Model "
               "Name\",\"perms\":[\"pr\"],\"type\":\"21\",\"iid\":4,"
               "\"format\":\"string\"},{\"value\":\"Device Name\",\"perms\":["
               "\"pr\"],\"type\":\"23\",\"iid\":5,\"format\":\"string\"},{"
               "\"value\":\"DUP4BL4D4\",\"perms\":[\"pr\"],\"type\":\"30\","
               "\"iid\":6,\"format\":\"string\"}]},{\"type\":\"43\","
               "\"iid\":8,\"characteristics\":[{\"value\":null,\"perms\":["
               "\"pr\",\"pw\",\"ev\"],\"type\":\"25\",\"iid\":9,\"format\":"
               "\"bool\"},{\"value\":\"Device Name\",\"perms\":[\"pr\"],"
               "\"type\":\"23\",\"iid\":10,\"format\":\"string\"}]}]}]}";
    }

    beast::error_code error = {};
    controller.async_send(response, yield[error]);
    if (error) {
        controller.disconnect();
    }
}

static bool g_value = false;

void server::handle_characteristics(peer& controller,
                                    peer::request_type& request,
                                    asio::yield_context& yield) {
    beast::error_code error{};
    using array_istream =
        boost::iostreams::stream<boost::iostreams::array_source>;
    peer::response_type response = {};
    response.keep_alive(request.keep_alive());
    if (request.method() == beast::http::verb::put) {
        array_istream request_payload{request.body.data(), request.body.size()};
        nlohmann::json root;
        request_payload >> root;
        response.result(beast::http::status::no_content);
        const auto& characteristics_array = root.at("characteristics");
        for (const auto& write_object : characteristics_array) {
            auto aid = write_object.at("aid").get<uint64_t>();
            auto iid = write_object.at("iid").get<uint64_t>();
            auto it = write_object.find("value");
            if (it == write_object.end()) {
                continue;
            }

            auto value = it->get<int>();
            if (aid == 1 && iid == 9) {
                g_value = value;
                std::cout << "On changed, current value: " << std::boolalpha
                          << g_value << std::endl;
                std::ofstream value_file{"/sys/class/gpio/gpio2/value"};
                value_file << value;

            } else if (aid == 1 && iid == 2) {
                std::cout << "IDENTIFY value: " << std::boolalpha << value
                          << std::endl;
                std::ofstream value_file{"/sys/class/gpio/gpio2/value"};
                for (int i = 1; i < 6; ++i) {
                    value_file << i % 2;
                    value_file.flush();
                    std::this_thread::sleep_for(std::chrono::milliseconds{500});
                }
            }
        }
    } else if (request.method() == beast::http::verb::get) {
        nlohmann::json root;
        root["characteristics"] = nlohmann::json::array({nlohmann::json::object(
            {{"aid", 1}, {"iid", 9}, {"value", g_value}})});
        beast::ostream(response.body) << root;
        response.result(beast::http::status::ok);
        response.set(beast::http::field::content_type, "application/hap+json");
    } else {
        response.result(beast::http::status::method_not_allowed);
    }

    controller.async_send(response, yield[error]);
    if (error) {
        controller.disconnect();
    }
}

void server::handle_pairings(peer& controller, peer::request_type& request,
                             asio::yield_context& yield) {
    gabia::pairing::pairings::server_context<decltype(pairings)> context{
        pairings};
    auto response = make_tlv_response(request);
    context.handle_m1(request, response, [](gsl::span<gsl::byte> identifier) {

    });

    beast::error_code error{};
    controller.async_send(response, yield[error]);
    if (error) {
        controller.disconnect();
    }
}
