#ifndef HK_SERVER_HPP
#define HK_SERVER_HPP

#include <gabia/pairing/manager.hpp>
#include "peer.hpp"

#include <boost/asio.hpp>
#include <iostream>
#include <memory>
#include <unordered_set>

class peer_entry {
public:
    peer_entry(peer::pointer_type ptr) : ptr{ptr}, raw_ptr{ptr.get()} {}

    struct hash {
        std::size_t operator()(const peer_entry& entry) const {
            return std::hash<decltype(entry.raw_ptr)>{}(entry.raw_ptr);
        }
    };

    friend bool operator==(const peer_entry& left, const peer_entry& right) {
        return left.raw_ptr == right.raw_ptr;
    }

    peer::weak_pointer_type ptr;

private:
    peer* raw_ptr =
        {}; // NOTE: DO NOT DEREFENCE THIS, used for weak_ptr comparison
};

class server {
public:
    server(asio::io_service& service);

    void start();

private:
    struct route_handler {
        template <typename Handler>
        route_handler(const char* url, Handler handler)
            : url{url}, callback{handler} {}
        beast::string_view url;
        std::function<void(peer&, peer::request_type&, asio::yield_context&)>
            callback;
    };

    void connection_main(peer& controller, asio::yield_context yield);
    using peer_set_type = std::unordered_set<peer_entry, peer_entry::hash>;

    void async_accept();

    void dispatch(peer& controller, peer::request_type& request,
                  asio::yield_context& yield);

    void handle_pair_verify(peer& controller, peer::request_type&,
                            asio::yield_context& yield);
    void handle_pair_setup(peer& controller, peer::request_type&,
                           asio::yield_context& yield);

    void handle_discovery(peer& controller, peer::request_type&,
                          asio::yield_context& yield);

    void handle_characteristics(peer& controller, peer::request_type&,
                                asio::yield_context& yield);

    gabia::pairing::manager pairings;
    std::vector<route_handler> routes;
    asio::ip::tcp::acceptor acceptor;
    peer_set_type peers;
};

#endif // HK_SERVER_HPP
