#include "server.hpp"

int main() {
    asio::io_service service;
    server srv{service};
    srv.start();
    service.run();
    return 0;
}
