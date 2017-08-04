//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef GABIA_TLV8_HPP
#define GABIA_TLV8_HPP

#include <gsl/gsl>

namespace gabia {
namespace tlv {

constexpr auto fragment_header_size = 2;
constexpr auto max_fragment_data_size = 255;

struct item {
    gsl::byte tag;
    std::vector<gsl::byte> data;

    template <typename TagType>
    static item make(TagType tag, size_t data_size) {
        return {static_cast<gsl::byte>(tag), std::vector<gsl::byte>{data_size}};
    }

    template <typename TagType, typename InputIterator>
    static item make(TagType tag, InputIterator begin, InputIterator end) {
        return {static_cast<gsl::byte>(tag),
                std::vector<gsl::byte>{begin, end}};
    }
};

inline std::istream& read(
    std::istream& istream, item& input_item,
    std::size_t max_size = std::numeric_limits<size_t>::max()) {
    std::array<uint8_t, fragment_header_size> header = {};
    bool first_fragment = true;
    input_item = {};
    while (istream.good()) {
        if (!first_fragment &&
            static_cast<gsl::byte>(istream.peek()) != input_item.tag) {
            break;
        }

        if (!istream.read(reinterpret_cast<char*>(header.data()), header.size())
                 .good()) {
            if (istream.eof()) {
                istream.clear(std::istream::eofbit);
            }
            break;
        }

        auto tag = static_cast<gsl::byte>(header[0]);
        auto fragment_size = static_cast<std::size_t>(header[1]);
        if (first_fragment) {
            input_item.tag = tag;
            first_fragment = false;
        }

        auto new_size = input_item.data.size() + fragment_size;
        if (new_size > max_size) {
            istream.setstate(istream.rdstate() | std::istream::badbit);
            break;
        }
        input_item.data.resize(new_size);
        auto span = gsl::make_span(input_item.data).last(fragment_size);
        if (!istream.read(reinterpret_cast<char*>(span.data()),
                          span.size_bytes())) {
            break;
        }
    }
    return istream;
}

inline std::ostream& write(std::ostream& ostream, gsl::byte tag,
                           gsl::span<const gsl::byte> item_data) {
    while (!item_data.empty()) {
        auto fragment_size = std::min<std::ptrdiff_t>(item_data.size_bytes(),
                                                      max_fragment_data_size);
        auto fragment = item_data.first(fragment_size);
        std::array<gsl::byte, fragment_header_size> header = {
            tag, gsl::narrow<gsl::byte>(fragment.size_bytes())};

        ostream.write(reinterpret_cast<const char*>(header.data()),
                      header.size());
        ostream.write(reinterpret_cast<const char*>(fragment.data()),
                      fragment.size_bytes());
        item_data = item_data.subspan(fragment_size);
    }
    return ostream;
}

template <typename T>
struct is_tag : std::false_type {};

template <typename T, typename ReturnType>
using enable_if_integral_or_pod_t = std::enable_if_t<
    std::is_integral<typename std::remove_reference<T>::type>::value ||
        std::is_enum<typename std::remove_reference<T>::type>::value,
    ReturnType>;

template <typename T, typename ReturnType>
using enable_if_tag_t = std::enable_if_t<
    tlv::is_tag<typename std::remove_reference<T>::type>::value, ReturnType>;

template <
    typename TagType, typename IntegralType,
    typename U = enable_if_tag_t<TagType, std::true_type>,
    typename V = enable_if_integral_or_pod_t<IntegralType, std::true_type>>
std::ostream& write(std::ostream& ostream, TagType tag,
                    const IntegralType& data) {
    auto span = gsl::make_span(&data, 1);
    return write(ostream, gsl::narrow<gsl::byte>(tag), gsl::as_bytes(span));
}

template <typename TagType, typename Container,
          typename U = enable_if_tag_t<TagType, std::true_type>>
auto write(std::ostream& ostream, TagType tag, const Container& data)
    -> decltype(data.data(), ostream) {
    auto span = gsl::make_span(data);
    return write(ostream, gsl::narrow<gsl::byte>(tag), gsl::as_bytes(span));
}

inline std::ostream& write(std::ostream& ostream, const item& output_item) {
    auto span = gsl::span<const gsl::byte>{output_item.data};
    return write(ostream, output_item.tag, {output_item.data});
}

template <>
struct is_tag<gsl::byte> : std::true_type {};

} // namespace tlv
} // namespace gabia

#endif // GABIA_TLV8_HPP
