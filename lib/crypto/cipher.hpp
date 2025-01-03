#pragma once

#include "memory.hpp"

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#define OPENSSL_NO_DEPRECATED
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace ssap::crypto {

static constexpr size_t kOAEPPaddingBytes = 42;

template <typename T>
std::span<const uint8_t> as_u8s(std::span<const T> in) {
    auto size = in.size_bytes();
    std::span<const uint8_t> out(
        reinterpret_cast<const uint8_t*>(in.data()), size);

    return out;
}

template <typename T>
std::optional<std::vector<uint8_t, ossl_allocator<uint8_t>>> rsa_encrypt_block(
    std::span<const T> input, EVP_PKEY* key) {

    std::span<const uint8_t> in = as_u8s<T>(input);

    size_t max_input_length = EVP_PKEY_get_size(key) - kOAEPPaddingBytes;
    if (max_input_length < in.size()) {
        return std::nullopt;
    }

    MAKE_OSSL_UNIQUE_PTR(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(key, nullptr));

    if (!ctx) {
        return std::nullopt;
    }
    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    size_t out_len = 0;

    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &out_len, in.data(), in.size()) <=
        0)
    {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    std::vector<uint8_t, ossl_allocator<uint8_t>> out(out_len, '\0');

    if (EVP_PKEY_encrypt(
            ctx.get(), out.data(), &out_len, in.data(), in.size()) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    ERR_print_errors_fp(stderr);

    out.resize(out_len);

    return out;
}

inline std::optional<std::vector<uint8_t, ossl_allocator<uint8_t>>>
rsa_decrypt_block(std::span<const uint8_t> in, EVP_PKEY* key) {

    size_t max_input_length = EVP_PKEY_get_size(key);
    if (max_input_length < in.size()) {
        return std::nullopt;
    }

    MAKE_OSSL_UNIQUE_PTR(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(key, nullptr));

    if (!ctx) {
        return std::nullopt;
    }
    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    size_t out_len = 0;

    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &out_len, in.data(), in.size()) <=
        0)
    {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    std::vector<uint8_t, ossl_allocator<uint8_t>> out(out_len, '\0');

    if (EVP_PKEY_decrypt(
            ctx.get(), out.data(), &out_len, in.data(), in.size()) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    out.resize(out_len);

    ERR_print_errors_fp(stderr);

    return out;
}

} // namespace ssap::crypto
