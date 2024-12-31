#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>

#include "openssl/evp.h"
#include "openssl/rsa.h"

namespace ssap::crypto {

class keymanager {
public:
    static keymanager &get_instance() {
        static keymanager instance;
        return instance;
    }
    std::optional<uint32_t> generate_key() {
        static constexpr unsigned int bits = 2048;
        EVP_PKEY *keypair = EVP_RSA_gen(2048);
        if (!keypair)
            return std::nullopt;
        uint32_t id = m_next_key_id;
        m_keys.insert_or_assign(
            id, std::shared_ptr<EVP_PKEY>(keypair, &EVP_PKEY_free));
        if (m_keys.size() < 0xFFFFFFFFU) {
            ++m_next_key_id;
            while (m_keys.contains(m_next_key_id)) {
                ++m_next_key_id;
            }
        }
        return id;
    }
    std::optional<std::shared_ptr<EVP_PKEY>> get_key(uint32_t id) {
        auto it = m_keys.find(id);
        if (it == m_keys.end())
            return std::nullopt;
        return it->second;
    }
    void erase_key(uint32_t id) {
        m_keys.erase(id);
        m_next_key_id = id;
    }

private:
    keymanager() = default;
    keymanager(keymanager const &) = delete;
    keymanager(keymanager &&) = delete;
    keymanager &operator=(keymanager const &) = delete;
    keymanager &operator=(keymanager &&) = delete;
    uint32_t m_next_key_id = 0;
    std::unordered_map<uint32_t, std::shared_ptr<EVP_PKEY>> m_keys;
};

} // namespace ssap::crypto
