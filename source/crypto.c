/*
 * crypto.c
 *
 * Copyright (c) 2020, DarkMatterCore <pabloacurielz@gmail.com>.
 *
 * This file is part of dlc-wad-splitter (https://github.com/DarkMatterCore/dlc-wad-splitter).
 *
 * dlc-wad-splitter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dlc-wad-splitter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ninty-233.h>
#include <mbedtls/rsa.h>

#include "utils.h"
#include "crypto.h"

bool cryptoAes128CbcContextInit(CryptoAes128CbcContext *ctx, const void *key, const void *iv, bool is_encryptor)
{
    if (!ctx || !key || !iv)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    int ret = 0;
    
    /* Initialize AES context. */
    mbedtls_aes_init(&(ctx->aes_ctx));
    
    /* Set AES key. */
    ret = (is_encryptor ? mbedtls_aes_setkey_enc(&(ctx->aes_ctx), (const u8*)key, AES_BLOCK_SIZE_BITS) : mbedtls_aes_setkey_dec(&(ctx->aes_ctx), (const u8*)key, AES_BLOCK_SIZE_BITS));
    if (ret != 0)
    {
        ERROR_MSG("Failed to set AES key! (%d).", ret);
        goto out;
    }
    
    /* Copy IV. */
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    
out:
    if (ret != 0) mbedtls_aes_free(&(ctx->aes_ctx));
    
    return (ret == 0);
}

void cryptoAes128CbcContextFree(CryptoAes128CbcContext *ctx)
{
    if (!ctx) return;
    mbedtls_aes_free(&(ctx->aes_ctx));
    memset(ctx, 0, sizeof(CryptoAes128CbcContext));
}

void cryptoAes128CbcContextResetIv(CryptoAes128CbcContext *ctx, const void *iv)
{
    if (!ctx || !iv) return;
    
    /* Copy IV. */
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
}

bool cryptoAes128CbcContextCrypt(CryptoAes128CbcContext *ctx, void *dst, const void *src, u64 size, bool encrypt)
{
    if (!ctx || !dst || !src || (size % AES_BLOCK_SIZE) != 0)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    int ret = 0;
    
    /* Perform AES-CBC crypto. */
    ret = mbedtls_aes_crypt_cbc(&(ctx->aes_ctx), (encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT), size, ctx->iv, (const u8*)src, (u8*)dst);
    if (ret != 0) ERROR_MSG("AES %s failed! (%d).", (encrypt ? "encryption" : "decryption"), ret);
    
    return (ret == 0);
}

bool cryptoAes128CbcCrypt(const void *key, const void *iv, void *dst, const void *src, u64 size, bool encrypt)
{
    if (!key || !iv || !dst || !src || (size % AES_BLOCK_SIZE) != 0)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    CryptoAes128CbcContext ctx = {0};
    bool success = false;
    
    /* Initialize AES-128-CBC context. */
    if (!cryptoAes128CbcContextInit(&ctx, key, iv, encrypt))
    {
        ERROR_MSG("Failed to initialize AES-128-CBC context!");
        return false;
    }
    
    /* Perform AES-128-CBC crypto operation. */
    if (!cryptoAes128CbcContextCrypt(&ctx, dst, src, size, encrypt))
    {
        ERROR_MSG("Failed to perform AES-128-CBC %s!", (encrypt ? "encryption" : "decryption"));
        goto out;
    }
    
    success = true;
    
out:
    cryptoAes128CbcContextFree(&ctx);
    
    return success;
}

bool cryptoVerifyEcdsaSignature(const void *public_key, const void *signature, bool padded_sig, const void *data_hash, u64 data_hash_size)
{
    const u8 *public_key_u8 = NULL, *signature_u8 = NULL;
    
    ec_point pub_key = {0};
    u8 full_pub_key[ECC_PUB_KEY_SIZE] = {0};
    
    element r = {0}, s = {0};
    u8 full_sig[ECDSA_SIG_SIZE] = {0};
    
    mpz_t hash = {0};
    int result = 0;
    
    if (!(public_key_u8 = (const u8*)public_key) || !(signature_u8 = (const u8*)signature) || !data_hash || !data_hash_size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    /* Generate padded ECC public key. */
    /* Wii ECC public keys are normally 60 bytes long. */
    memcpy(full_pub_key + 2, public_key_u8, 30);
    memcpy(full_pub_key + 34, public_key_u8 + 30, 30);
    
    /* Convert ECC public key byte stream to a GF(2^m) element. */
    os_to_point(full_pub_key, &pub_key);
    
    if (padded_sig)
    {
        /* Copy ECDSA signature as-is. */
        memcpy(full_sig, signature_u8, ECDSA_SIG_SIZE);
    } else {
        /* Generate padded ECDSA signature. */
        /* Wii ECDSA signatures are normally 60 bytes long. */
        memcpy(full_sig + 2, signature_u8, 30);
        memcpy(full_sig + 34, signature_u8 + 30, 30);
    }
    
    /* Convert ECDSA signature byte stream to a GF(2^m) element. */
    os_to_elem(full_sig, r);
    os_to_elem(full_sig + 32, s);
    
    /* Convert hash to a multi-precision integer. */
    mpz_init(hash);
    mpz_import(hash, data_hash_size, 1, sizeof(u8), 0, 0, data_hash);
    
    /* Verify ECDSA signature. */
    result = ecdsa_verify(hash, &pub_key, r, s);
    mpz_clear(hash);
    
    return (result != 0);
}

bool cryptoVerifyRsaSignature(const void *public_key, u64 public_key_size, u64 public_exponent, const void *signature, const void *data_hash, u64 data_hash_size)
{
    if (!public_key || (public_key_size != RSA2048_SIG_SIZE && public_key_size != RSA4096_SIG_SIZE) || !signature || !data_hash || (data_hash_size != SHA1_HASH_SIZE && \
        data_hash_size != SHA256_HASH_SIZE))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    int ret = 0;
    mbedtls_rsa_context rsa_ctx = {0};
    bool success = false;
    
    /* Initialize RSA context. */
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    
    /* Set RSA public key (modulus). */
    ret = mbedtls_mpi_read_binary(&(rsa_ctx.N), (const u8*)public_key, public_key_size);
    if (ret != 0)
    {
        ERROR_MSG("Failed to set RSA public key! (%d).", ret);
        goto out;
    }
    
    /* Set RSA public exponent value. */
    ret = mbedtls_mpi_lset(&(rsa_ctx.E), (mbedtls_mpi_sint)public_exponent);
    if (ret != 0)
    {
        ERROR_MSG("Failed to set RSA public exponent! (%d).", ret);
        goto out;
    }
    
    /* Set RSA public key (modulus) size. */
    rsa_ctx.len = public_key_size;
    
    /* Verify RSA signature. */
    ret = mbedtls_rsa_pkcs1_verify(&rsa_ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, (data_hash_size == SHA256_HASH_SIZE ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA1), data_hash_size, (const u8*)data_hash, \
                                   (const u8*)signature);
    if (ret != 0 && ret != MBEDTLS_ERR_RSA_VERIFY_FAILED)
    {
        ERROR_MSG("RSA signature verification failed! Bad data? (%d).", ret);
        goto out;
    }
    
    success = (ret == 0);
    
out:
    mbedtls_rsa_free(&rsa_ctx);
    
    return success;
}
