#ifndef HK_PEER_HPP
#define HK_PEER_HPP

#include <gabia.hpp>

#include <boost/asio/spawn.hpp>
#include <boost/beast.hpp>
#include <boost/coroutine/all.hpp>
#include <gsl/gsl>
#include <memory>

namespace asio = boost::asio;
namespace beast = boost::beast;

class peer : public std::enable_shared_from_this<peer> {
public:
    using response_type = beast::http::response<beast::http::dynamic_body>;
    using request_type = beast::http::request<beast::http::vector_body<char>>;
    using pointer_type = std::shared_ptr<peer>;
    using weak_pointer_type = std::weak_ptr<peer>;
    friend class server;

    peer(asio::io_service& service) : socket{service} {}

    bool is_connected() { return socket.lowest_layer().is_open(); }

    void disconnect() {
        if (socket.is_open()) {
            socket.lowest_layer().close();
        }
    }

    template <typename Handler>
    auto async_recv(request_type& request, Handler&& handler) {
        request = {};
        if (!encryption_enabled) {
            return beast::http::async_read(socket.next_layer(), recv_buffer,
                                           request,
                                           std::forward<Handler&&>(handler));
        }
        return beast::http::async_read(socket, recv_buffer, request,
                                       std::forward<Handler&&>(handler));
    }

    template <typename Handler>
    auto async_send(response_type& response, Handler&& handler) {
        // TODO: Async responses
        // TODO: close after send if keep alive not set
        response.prepare_payload();
        if (!encryption_enabled) {
            return beast::http::async_write(socket.next_layer(), response,
                                            std::forward<Handler&&>(handler));
        }

        return beast::http::async_write(socket, response,
                                        std::forward<Handler&&>(handler));
    }

    void enable_session_security(const gabia::crypto::aead_secrets& secrets) {
        Expects(!encryption_enabled);
        socket.set_secrets(secrets);
        encryption_enabled = true;
    }

private:
    bool encryption_enabled = false;
    beast::flat_buffer recv_buffer{8192};
    gabia::secure_socket<asio::ip::tcp::socket> socket;
};

inline peer::response_type make_tlv_response(peer::request_type& request) {
    peer::response_type response;
    response.keep_alive(request.keep_alive());
    response.set(beast::http::field::content_type, "application/pairing+tlv8");
    return response;
}

#endif // HK_PEER_HPP
