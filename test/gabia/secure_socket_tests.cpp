#include <gabia/secure_socket.hpp>

#include <boost/beast/http/message.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/test/stream.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/test/unit_test.hpp>

namespace gabia {

namespace asio = boost::asio;
namespace beast = boost::beast;

BOOST_AUTO_TEST_SUITE(secure_socket_tests)

struct socket_pair {
    secure_socket<beast::test::stream> server_;
    secure_socket<beast::test::stream> client_;
    socket_pair(asio::io_service& service)
        : server_{service}, client_{connect(server_.next_layer())} {
        crypto::aead_secrets secrets{};
        secrets.our_key = {static_cast<gsl::byte>(0x01)};
        secrets.peer_key = {static_cast<gsl::byte>(0x02)};
        server_.set_secrets(secrets);
        using std::swap;
        swap(secrets.our_key, secrets.peer_key);
        client_.set_secrets(secrets);
    }
};

using request_t = beast::http::request<beast::http::string_body>;
using response_t = beast::http::response<beast::http::string_body>;

constexpr auto attribute_db =
    "{\"accessories\":[{\"aid\":1,\"services\":[{\"type\":"
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

BOOST_AUTO_TEST_CASE(sync_transaction_success) {
    asio::io_service service;
    socket_pair sockets{service};
    auto& client = sockets.client_;
    auto& server = sockets.server_;
    beast::flat_buffer buffer;

    request_t sent_request, received_request;
    sent_request.target("/accessories");
    sent_request.method(beast::http::verb::get);
    beast::http::write(client, sent_request);
    beast::http::read(server, buffer, received_request);
    BOOST_CHECK_EQUAL(boost::lexical_cast<std::string>(sent_request),
                      boost::lexical_cast<std::string>(received_request));

    response_t sent_response, received_response;
    sent_response.result(beast::http::status::ok);
    sent_response.set(beast::http::field::content_type, "application/hap+json");
    sent_response.body = attribute_db;
    sent_response.prepare_payload();

    beast::http::write(server, sent_response);
    beast::http::read(client, buffer, received_response);
    BOOST_CHECK_EQUAL(boost::lexical_cast<std::string>(sent_response),
                      boost::lexical_cast<std::string>(received_response));
}

BOOST_AUTO_TEST_CASE(async_transaction_success) {
    asio::io_service service;
    socket_pair sockets{service};
    auto& client = sockets.client_;
    auto& server = sockets.server_;
    beast::flat_buffer buffer;

    request_t sent_request, received_request;
    sent_request.target("/accessories");
    sent_request.method(beast::http::verb::get);
    beast::http::async_write(client, sent_request, [](beast::error_code error) {
        BOOST_CHECK(!error);
    });
    beast::http::async_read(
        server, buffer, received_request, [&](beast::error_code error) {
            BOOST_CHECK(!error);
            BOOST_CHECK_EQUAL(
                boost::lexical_cast<std::string>(sent_request),
                boost::lexical_cast<std::string>(received_request));
        });
    service.run();

    response_t sent_response, received_response;
    sent_response.result(beast::http::status::ok);
    sent_response.set(beast::http::field::content_type, "application/hap+json");
    sent_response.body = attribute_db;
    sent_response.prepare_payload();

    beast::http::async_write(
        server, sent_response,
        [](beast::error_code error) { BOOST_CHECK(!error); });
    beast::http::async_read(
        client, buffer, received_response, [&](beast::error_code error) {
            BOOST_CHECK(!error);
            BOOST_CHECK_EQUAL(
                boost::lexical_cast<std::string>(sent_response),
                boost::lexical_cast<std::string>(received_response));
        });
    service.reset();
    service.run();
}

} // namespace gabia

} // BOOST_AUTO_TEST_SUITE(secure_socket_tests)
