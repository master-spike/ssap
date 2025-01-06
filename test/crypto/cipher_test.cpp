#include "crypto/cipher.hpp"

#include <span>
#include <variant>

#include <catch2/catch_test_macros.hpp>
#include <openssl/evp.h>

#include "memory.h"

TEST_CASE("rsa encrypt-decrypt block") {
    std::string sample_str(
        "the quick brown fox jumps over the lazy dog, the quick brown fox "
        "jumps over the lazy dog, the quick brown fox jumps over the lazy dog, "
        "the quick brown fox jumps over the lazy dog");

    MAKE_OSSL_UNIQUE_PTR(EVP_PKEY, pkey, EVP_RSA_gen(2048));
    REQUIRE(pkey);

    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> check_ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr),
        EVP_PKEY_CTX_free);
    REQUIRE(EVP_PKEY_public_check(check_ctx.get()));
    REQUIRE(EVP_PKEY_private_check(check_ctx.get()));

    auto r = ssap::crypto::rsa_encrypt_block<char>(
        std::span<char>(sample_str.begin(), sample_str.end()), pkey.get());

    REQUIRE(r.has_value());
    REQUIRE(r.value().size() > 0);

    INFO("encrypted size : " << r.value().size());

    auto s = ssap::crypto::rsa_decrypt_block(
        std::span<const uint8_t>(r.value().begin(), r.value().end()),
        pkey.get());

    REQUIRE(s.has_value());

    std::string str_decrypted(s.value().begin(), s.value().end());

    // INFO("decrypted string : " << str_decrypted);
    INFO("decrypted size : " << s.value().size());
    REQUIRE(str_decrypted == sample_str);
}

namespace detail {

struct foo {
    std::array<float, 6> f;
    uint64_t u;
};

} // namespace detail

TEST_CASE("rsa encrypt-decrypt variant") {
    std::variant<unsigned, float, char> v;

    MAKE_OSSL_UNIQUE_PTR(EVP_PKEY, pkey, EVP_RSA_gen(2048));
    REQUIRE(pkey);

    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> check_ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr),
        EVP_PKEY_CTX_free);
    REQUIRE(EVP_PKEY_public_check(check_ctx.get()));
    REQUIRE(EVP_PKEY_private_check(check_ctx.get()));

    std::span<std::variant<unsigned, float, char>> v_span(&v, 1);

    auto r =
        ssap::crypto::rsa_encrypt_block<std::variant<unsigned, float, char>>(
            v_span, pkey.get());

    REQUIRE(r.has_value());
    REQUIRE(r.value().size() > 0);

    auto d = ssap::crypto::rsa_decrypt_block(
        std::span(r.value().begin(), r.value().end()), pkey.get());

    REQUIRE(d.has_value());
    REQUIRE(d.value().size() == sizeof(decltype(v)));

    decltype(v) u;
    std::memcpy(&u, d.value().data(), sizeof(decltype(u)));
    REQUIRE(v == u);
}
