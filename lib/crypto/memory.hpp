#pragma once

#include <memory>

#include <openssl/types.h>

// OpenSSL forward declarations
extern "C" {
void EVP_PKEY_free(EVP_PKEY*);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX*);
}
// End of forward declarations

namespace ssap::crypto {

template <typename OpenSSLType>
struct deleter_for {
    static_assert(false, "deleter_for not specialized for this type");
};

template <>
struct deleter_for<EVP_PKEY> {
    void operator()(EVP_PKEY* p) {
        EVP_PKEY_free(p);
    }
};

template <>
struct deleter_for<EVP_PKEY_CTX> {
    void operator()(EVP_PKEY_CTX* p) {
        EVP_PKEY_CTX_free(p);
    }
};

template <typename OpenSSLType>
using ossl_unique_ptr = std::unique_ptr<OpenSSLType, deleter_for<OpenSSLType>>;

#define MAKE_OSSL_UNIQUE_PTR(type, name, ptr)                                  \
    ::ssap::crypto::ossl_unique_ptr<type> name(                                \
        ptr, ::ssap::crypto::deleter_for<type>{})

} // namespace ssap::crypto
