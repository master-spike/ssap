#pragma once

#include <memory>
#include <type_traits>

#define OPENSSL_NO_DEPRECATED
#include <openssl/crypto.h>
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

template <typename T>
class ossl_allocator {
    static_assert(
        std::is_same_v<T, std::remove_cvref_t<T>>,
        "T is not a cv-unqualified object type");

public:
    using pointer = T*;
    using const_pointer = const T*;
    using void_pointer = void*;
    using const_void_pointer = const void*;
    using value_type = T;
    using size_type = size_t;
    using difference_type = ptrdiff_t;

    [[nodiscard]] constexpr pointer allocate(size_type n) {
        void_pointer p = OPENSSL_malloc(n * sizeof(T));
        return reinterpret_cast<pointer>(p);
    }

    constexpr void deallocate(pointer p, [[maybe_unused]] size_type n) {
        OPENSSL_free(p);
    }
};

} // namespace ssap::crypto
