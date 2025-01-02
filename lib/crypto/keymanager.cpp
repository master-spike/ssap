#include "keymanager.hpp"

#define OPENSSL_NO_DEPRECATED
#include "openssl/rsa.h"

namespace ssap::crypto {

std::optional<uint32_t> keymanager::generate_key() {
    static constexpr unsigned int bits = 2048;
    EVP_PKEY* keypair = EVP_RSA_gen(2048);
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

std::optional<std::shared_ptr<EVP_PKEY>> keymanager::get_key(uint32_t id) {
    auto it = m_keys.find(id);
    if (it == m_keys.end())
        return std::nullopt;
    return it->second;
}

void keymanager::erase_key(uint32_t id) {
    m_keys.erase(id);
    m_next_key_id = id;
}

} // namespace ssap::crypto

