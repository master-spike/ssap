#include "crypto/keymanager.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("keymanager")
{
    using ssap::crypto::keymanager;
    auto key_id = keymanager::get_instance().generate_key();

    REQUIRE(key_id.has_value());

    auto key = keymanager::get_instance().get_key(key_id.value());

    REQUIRE(key.has_value());
    REQUIRE(key.value().get() != nullptr);

    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX *)> ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key.value().get(), nullptr),
        EVP_PKEY_CTX_free);
    REQUIRE(EVP_PKEY_public_check(ctx.get()));
    REQUIRE(EVP_PKEY_private_check(ctx.get()));

    keymanager::get_instance().erase_key(key_id.value());
    key = keymanager::get_instance().get_key(key_id.value());

    REQUIRE(!key.has_value());
}
