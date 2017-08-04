//
// Copyright (c) 2017 Damian Jarek (damian dot jarek93 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/djarek/gabia
//

#ifndef HK_PAIRING_MANAGER_HPP
#define HK_PAIRING_MANAGER_HPP

#include <gabia/crypto/ed25519_key.hpp>
#include <gsl/gsl_byte>
#include <vector>

namespace gabia {
namespace pairing {

enum class flags : uint8_t {
    user = 0x00,
    admin = 0x01,
};

struct pairing_entry {
    std::vector<gsl::byte> identifier;
    crypto::ed25519_key ltpk;
    pairing::flags flags;
};

constexpr auto max_setup_attempts = 100;

class manager {
public:
    using implementation_type = std::vector<pairing_entry>;
    using const_iterator = typename implementation_type::const_iterator;

    void emplace(pairing_entry pairing) { pairings.emplace_back(pairing); }

    const_iterator find(gsl::span<const gsl::byte> identifier) const {
        return std::find_if(
            begin(), end(),
            [&identifier](const pairing::pairing_entry& pairing) {
                return gsl::make_span(pairing.identifier) == identifier;
            });
    }

    const_iterator erase(gsl::span<const gsl::byte> identifier) {
        auto admin_pairings = 0;
        auto it = std::remove_if(
            pairings.begin(), pairings.end(),
            [&identifier,
             &admin_pairings](const pairing::pairing_entry& pairing) {
                if (pairing.flags == pairing::flags::admin) {
                    admin_pairings++;
                }
                return gsl::make_span(pairing.identifier) == identifier;
            });
        if (admin_pairings == 0) {
            pairings.clear();
            return pairings.end();
        }

        return pairings.erase(it, pairings.end());
    }

    const_iterator erase(const_iterator it) { return erase({it->identifier}); }

    auto count_admins() const {
        std::count_if(begin(), end(), [](const pairing_entry& pairing) {
            return pairing.flags == pairing::flags::admin;
        });
    }

    const_iterator begin() const { return pairings.cbegin(); }

    const_iterator end() const { return pairings.cend(); }

    bool empty() const { return pairings.empty(); }

    crypto::ed25519_key& get_our_ltsk() { return our_ltsk; }

    bool can_attempt_setup() const {
        return setup_attempts < max_setup_attempts;
    }

    void set_failed_setup_attempt() { ++setup_attempts; }

private:
    crypto::ed25519_key our_ltsk{}; // Acessory Long-Term-Secret-Key
    implementation_type pairings;
    uint8_t setup_attempts = 0;
};

} // namespace pairing
} // namespace gabia

#endif // HK_PAIRING_MANAGER_HPP
