//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_SECURE_SOCKET_HPP
#define GABIA_SECURE_SOCKET_HPP

#include <gabia/bytes.hpp>
#include <gabia/crypto/aead.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/endian/arithmetic.hpp>

#define CORO_YIELD BOOST_ASIO_CORO_YIELD
#define CORO_REENTER BOOST_ASIO_CORO_REENTER

namespace gabia {

namespace asio = boost::asio;
namespace beast = boost::beast;

template <typename DynamicBuffer>
auto prepare_or_error(DynamicBuffer& buffer, size_t n,
                      beast::error_code& error) {
    boost::optional<typename DynamicBuffer::mutable_buffers_type> sequence;
    try {
        sequence = buffer.prepare(n);
    } catch (const std::length_error&) {
        error = asio::error::message_size;
    }
    return sequence;
}

template <typename Stream>
class secure_socket {
public:
    using next_layer_type = typename std::remove_reference<Stream>::type;
    using lowest_layer_type =
        typename beast::get_lowest_layer<next_layer_type>::type;
    constexpr static auto max_payload_length = 1024;

    secure_socket() = default;

    explicit secure_socket(asio::io_service& service)
        : next_layer_stream{service} {}

    template <class... Args>
    secure_socket(crypto::aead_secrets secrets, Args&&... args)
        : secrets{secrets}, next_layer_stream{std::forward<Args>(args)...} {}

    auto& next_layer() { return next_layer_stream; }

    const auto& next_layer() const { return next_layer_stream; }

    auto& lowest_layer() { return next_layer().lowest_layer(); }

    const auto& lowest_layer() const { return next_layer().lowest_layer(); }

    auto& get_io_service() { return lowest_layer().get_io_service(); }

    bool is_open() const { return lowest_layer().is_open(); }

    void close() { lowest_layer().close(); }

    void close(beast::error_code& error) { lowest_layer().close(error); }

    template <typename ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& sequence,
                           beast::error_code& error) {
        error = {};
        std::vector<gsl::byte> pdu{};
        encrypt_pdu(pdu, sequence);
        asio::write(next_layer(), asio::buffer(pdu), error);
        if (error) {
            return 0;
        }

        return pdu.size() - sizeof(uint16_t) - crypto::aead_auth_tag_size;
    }

    template <typename ConstBufferSequence>
    auto write_some(const ConstBufferSequence& sequence) {
        beast::error_code error;
        auto n = write_some(sequence, error);
        if (error) {
            // TODO: should a function from detail subnamespace be used??
            boost::asio::detail::throw_exception(beast::system_error{error});
        }
        return n;
    }

    template <typename MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& sequence,
                          beast::error_code& error) {
        error = {};
        if (decrypted_buffer.size() > 0) {
            // We have already decrypted data ready to be retrieved from the
            // buffer
            auto consumed =
                boost::asio::buffer_copy(sequence, decrypted_buffer.data());
            decrypted_buffer.consume(consumed);
            return consumed;
        }

        boost::endian::little_int16_t payload_length = 0;
        size_t transferred = raw_buffer.size();
        // Need to attempt length extraction before the loop, because the raw
        // buffer might contain unparsed PDUs.
        extract_pdu_length(payload_length);
        while (transferred < sizeof(payload_length) + payload_length +
                                 crypto::aead_auth_tag_size) {
            auto mb = prepare_or_error(raw_buffer, max_payload_length, error);
            if (error) {
                return 0;
            }

            transferred += next_layer().read_some(*mb, error);
            if (error) {
                return 0;
            }
            raw_buffer.commit(transferred);
            extract_pdu_length(payload_length);
        }

        auto success = decrypt_pdu(payload_length);
        if (!success) {
            // Forged/spoofed message
            // TODO: use a more appropriate error code
            error = asio::error::no_permission;
            decrypted_buffer.consume(payload_length);
            return 0;
        }

        auto consumed =
            boost::asio::buffer_copy(sequence, decrypted_buffer.data());
        decrypted_buffer.consume(consumed);
        return consumed;
    }

    template <typename MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& sequence) {
        beast::error_code error = {};
        auto n = read_some(sequence, error);
        if (error) {
            // TODO: should a function from detail subnamespace be used??
            boost::asio::detail::throw_exception(beast::system_error{error});
        }
        return n;
    }

    template <typename MutableBufferSequence, typename Handler>
    auto async_read_some(MutableBufferSequence sequence, Handler&& handler) {
        beast::async_completion<Handler, void(beast::error_code, size_t)> init{
            handler};
        if (decrypted_buffer.size() > 0) {
            auto consumed =
                boost::asio::buffer_copy(sequence, decrypted_buffer.data());
            decrypted_buffer.consume(consumed);
            next_layer().get_io_service().post(beast::bind_handler(
                init.completion_handler, beast::error_code{}, consumed));
        } else {
            async_read_some_op<
                MutableBufferSequence,
                beast::handler_type<Handler,
                                    void(beast::error_code, std::size_t)>>
                operation{*this, sequence, std::move(init.completion_handler)};
            operation(beast::error_code{}, 0);
        }
        return init.result.get();
    }

    template <typename ConstBufferSequence, typename Handler>
    auto async_write_some(ConstBufferSequence sequence, Handler&& handler) {
        beast::async_completion<Handler, void(beast::error_code, size_t)> init{
            handler};

        async_write_some_op<
            ConstBufferSequence,
            beast::handler_type<Handler, void(beast::error_code, std::size_t)>>
            operation{*this, sequence, std::move(init.completion_handler)};
        operation(beast::error_code{}, 0);
        return init.result.get();
    }

    void set_secrets(const crypto::aead_secrets& secrets) {
        this->secrets = secrets;
    }

private:
    template <typename ConstBufferSequence, typename Handler>
    struct async_write_some_op : public asio::coroutine {
        template <typename DeducedHandler>
        async_write_some_op(secure_socket& socket,
                            const ConstBufferSequence& sequence,
                            DeducedHandler&& handler)
            : state_ptr(std::forward<DeducedHandler>(handler), socket,
                        sequence) {}

        void operator()(beast::error_code error, size_t n) {
            CORO_REENTER(*this) {
                boost::ignore_unused(n);

                state_ptr->socket.encrypt_pdu(state_ptr->sequence,
                                              state_ptr->pdu);
                CORO_YIELD asio::async_write(state_ptr->socket.next_layer(),
                                             asio::buffer(state_ptr->pdu),
                                             *this);
                auto n = state_ptr->pdu.size() - sizeof(uint16_t) -
                         crypto::aead_auth_tag_size;
                state_ptr.invoke(error, n);
            }
        }

        friend void* asio_handler_allocate(std::size_t size,
                                           async_write_some_op* op) {
            using boost::asio::asio_handler_allocate;
            return asio_handler_allocate(
                size, std::addressof(op->state_ptr.handler()));
        }

        friend void asio_handler_deallocate(void* p, std::size_t size,
                                            async_write_some_op* op) {
            using boost::asio::asio_handler_deallocate;
            asio_handler_deallocate(p, size,
                                    std::addressof(op->state_ptr.handler()));
        }

        friend bool asio_handler_is_continuation(async_write_some_op* op) {
            using boost::asio::asio_handler_is_continuation;
            return asio_handler_is_continuation(
                std::addressof(op->state_ptr.handler()));
        }

        template <class Function>
        friend void asio_handler_invoke(Function&& f, async_write_some_op* op) {
            using boost::asio::asio_handler_invoke;
            asio_handler_invoke(f, std::addressof(op->state_ptr.handler()));
        }

        struct state {
            state(Handler& handler, secure_socket& socket,
                  const ConstBufferSequence& sequence)
                : socket{socket},
                  sequence{sequence},
                  pdu{beast::handler_alloc<char, Handler>{handler}} {}

            secure_socket& socket;
            ConstBufferSequence sequence;
            using alloc_t = beast::handler_alloc<gsl::byte, Handler>;
            std::vector<gsl::byte, alloc_t> pdu;
        };

        beast::handler_ptr<state, Handler> state_ptr;
    };

    template <typename MutableBufferSequence, typename Handler>
    struct async_read_some_op : public asio::coroutine {
        template <typename DeducedHandler>
        async_read_some_op(secure_socket& socket,
                           const MutableBufferSequence& sequence,
                           DeducedHandler&& handler)
            : socket{socket},
              sequence{sequence},
              handler{std::forward<DeducedHandler>(handler)} {}
        secure_socket& socket;
        MutableBufferSequence sequence;
        Handler handler;

        size_t transferred = 0;
        boost::endian::little_int16_t payload_length = 0;
        boost::optional<beast::flat_buffer::mutable_buffers_type> raw_sequence;

        void operator()(beast::error_code error, size_t n) {
            CORO_REENTER(*this) {
                transferred = socket.raw_buffer.size();
                // Need to attempt length extraction before the loop, because
                // the raw buffer might contain unparsed PDUs.
                socket.extract_pdu_length(payload_length);
                while (transferred < sizeof(payload_length) + payload_length +
                                         crypto::aead_auth_tag_size) {
                    raw_sequence =
                        prepare_or_error(socket.raw_buffer, 1024, error);
                    if (error) {
                        socket.get_io_service().post(
                            beast::bind_handler(handler, error, 0));
                        return;
                    }
                    CORO_YIELD socket.next_layer().async_read_some(
                        *raw_sequence, *this);
                    transferred += n;
                    if (error) {
                        // TODO: What about eof?
                        handler(error, 0);
                        return;
                    }
                    socket.raw_buffer.commit(transferred);
                    socket.extract_pdu_length(payload_length);
                }

                bool success = socket.decrypt_pdu(payload_length);
                if (!success) {
                    socket.decrypted_buffer.consume(payload_length);
                    // TODO: use a more appropriate error code
                    error = asio::error::no_permission;
                    handler(error, 0);
                    return;
                }
                auto consumed = boost::asio::buffer_copy(
                    sequence, socket.decrypted_buffer.data());
                socket.decrypted_buffer.consume(consumed);
                handler(error, consumed);
            }
        }

        friend void* asio_handler_allocate(std::size_t size,
                                           async_read_some_op* op) {
            using boost::asio::asio_handler_allocate;
            return asio_handler_allocate(size, std::addressof(op->handler));
        }

        friend void asio_handler_deallocate(void* p, std::size_t size,
                                            async_read_some_op* op) {
            using boost::asio::asio_handler_deallocate;
            asio_handler_deallocate(p, size, std::addressof(op->handler));
        }

        friend bool asio_handler_is_continuation(async_read_some_op* op) {
            using boost::asio::asio_handler_is_continuation;
            return asio_handler_is_continuation(std::addressof(op->handler));
        }

        template <class Function>
        friend void asio_handler_invoke(Function&& f, async_read_some_op* op) {
            using boost::asio::asio_handler_invoke;
            asio_handler_invoke(f, std::addressof(op->handler));
        }
    };

    bool decrypt_pdu(boost::endian::little_int16_t& payload_length) {
        auto payload_length_bytes =
            gsl::as_writeable_bytes(gsl::make_span(&payload_length, 1));
        auto cipher_text =
            buffer_span_cast(raw_buffer.data())
                .subspan(sizeof(payload_length),
                         payload_length + crypto::aead_auth_tag_size);
        auto message_buffer = decrypted_buffer.prepare(
            payload_length); // Not supposed to throw length error
        auto message_span = mutable_buffer_span_cast(message_buffer);
        auto success = crypto::aead_decrypt(secrets, payload_length_bytes,
                                            {cipher_text}, message_span);
        raw_buffer.consume(sizeof(payload_length) + payload_length +
                           crypto::aead_auth_tag_size);
        decrypted_buffer.commit(payload_length);
        return success;
    }

    template <typename ConstBufferSequence, typename ByteVector>
    void encrypt_pdu(ConstBufferSequence& sequence, ByteVector& pdu) {
        boost::endian::little_int16_t payload_length = std::min<std::size_t>(
            asio::buffer_size(sequence), max_payload_length);
        pdu.resize(sizeof(payload_length) + payload_length +
                   crypto::aead_auth_tag_size);
        auto payload_length_bytes =
            gsl::as_bytes(gsl::make_span(&payload_length, 1));
        auto payload =
            gsl::make_span(pdu).subspan(sizeof(payload_length), payload_length);
        auto cipher_text = gsl::make_span(pdu).subspan(sizeof(payload_length));
        auto aad = gsl::make_span(pdu).first(sizeof(payload_length));

        asio::buffer_copy(asio::buffer(payload), sequence,
                          payload.size_bytes());
        std::copy(payload_length_bytes.begin(), payload_length_bytes.end(),
                  aad.begin());
        crypto::aead_encrypt(secrets, aad, payload, cipher_text);
    }

    void extract_pdu_length(boost::endian::little_int16_t& payload_length) {
        auto payload_length_bytes =
            gsl::as_writeable_bytes(gsl::make_span(&payload_length, 1));
        asio::buffer_copy(asio::buffer(payload_length_bytes),
                          raw_buffer.data());
    }

    Stream next_layer_stream;
    crypto::aead_secrets secrets = {};
    bool session_security_enabled = false;

    beast::flat_buffer raw_buffer{2048};
    beast::flat_buffer decrypted_buffer{2048};
};
} // namespace gabia

#undef CORO_YIELD
#undef CORO_REENTER

#endif // GABIA_SECURE_SOCKET_HPP
