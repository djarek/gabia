//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_BYTES_HPP
#define GABIA_BYTES_HPP

#include <boost/asio.hpp>

#include <gsl/gsl>

namespace gabia {

template <typename T>
auto as_bytes(T&& t) {
    return gsl::as_bytes(gsl::make_span(t));
}

template <typename T>
auto as_writeable_bytes(T&& t) {
    return gsl::as_writeable_bytes(gsl::make_span(t));
}

template <size_t N>
constexpr auto make_cstring_span(const char (&cstring)[N]) {
    return gsl::cstring_span<N - 1>{cstring, N - 1};
}

template <typename... Ts>
constexpr auto as_byte_array(Ts&&... ts) {
    return std::array<gsl::byte, sizeof...(ts)>{static_cast<gsl::byte>(ts)...};
}

template <typename ConstBufferSequence>
auto buffer_span_cast(const ConstBufferSequence& sequence) {
    return gsl::make_span(boost::asio::buffer_cast<const gsl::byte*>(sequence),
                          boost::asio::buffer_size(sequence));
}

template <typename MutableBufferSequence>
auto mutable_buffer_span_cast(const MutableBufferSequence& sequence) {
    return gsl::make_span(boost::asio::buffer_cast<gsl::byte*>(sequence),
                          boost::asio::buffer_size(sequence));
}
} // namespace gabia

namespace boost {
namespace asio {
template <typename PodType>
auto buffer(gsl::span<PodType> span) {
    return boost::asio::mutable_buffer(span.data(), span.size_bytes());
}
} // namespace asio
} // namespace boost

#endif // GABIA_BYTES_HPP
