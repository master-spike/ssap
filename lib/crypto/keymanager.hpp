#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>

#define OPENSSL_NO_DEPRECATED
#include "openssl/evp.h"

namespace ssap::crypto {

class keymanager {
public:
    static keymanager& get_instance() {
        static keymanager instance;
        return instance;
    }
    std::optional<uint32_t> generate_key();
    std::optional<std::shared_ptr<EVP_PKEY>> get_key(uint32_t id);
    void erase_key(uint32_t id);

private:
    keymanager() = default;
    keymanager(keymanager const&) = delete;
    keymanager(keymanager&&) = delete;
    keymanager& operator=(keymanager const&) = delete;
    keymanager& operator=(keymanager&&) = delete;
    uint32_t m_next_key_id = 0;
    std::unordered_map<uint32_t, std::shared_ptr<EVP_PKEY>> m_keys;
};

} // namespace ssap::crypto
