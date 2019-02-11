/**************************************************
* File name: hash_drbg.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Feb 9th, 2019
* Description: implement hash DRBG construction functions
**************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "hash_drbg_error_codes.h"
#include "hash_drbg.h"

int hash_df(HASH_DRBG_CTX *drbg_ctx,
            unsigned char *input,
            unsigned int input_len,
            unsigned int output_len,
            unsigned char *output)
{
    unsigned int output_bit_len = output_len * 8;    /* size in bits */
    unsigned char counter = 1;
    unsigned char bits_to_return[4];
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned char *p = output;
#ifdef _HASH_DRBG_DEBUG
	int i;
#endif

    int residual;
    EVP_MD_CTX *md_ctx;

    if ( (!(input)) || (!(output)) )
    {
        return INVALID_NULL_VALUE_INPUT;
    }

    if ( (!(input_len)) || (!(output_len)) )
    {
        return INVALID_INPUT_LENGTH;
    }

    
    if ( output_len > (255 * drbg_ctx->hash_output_len) )
    {
        return INVALID_INPUT_LENGTH;
    }

    /* present an 32-bit unsigned int in big-endian format */
    bits_to_return[0] = (unsigned char)((output_bit_len >> 24) & 0xFF);
    bits_to_return[1] = (unsigned char)((output_bit_len >> 16) & 0xFF);
    bits_to_return[2] = (unsigned char)((output_bit_len >> 8) & 0xFF);
    bits_to_return[3] = (unsigned char)(output_bit_len & 0xFF);

    if ( !(md_ctx = EVP_MD_CTX_new()) )
    {
        return MEMOMY_ALLOCATION_FAIL;
    }
    
    residual = (int)(output_len);
    while (residual > 0)
    {
        EVP_DigestInit_ex(md_ctx, drbg_ctx->md, NULL);
        EVP_DigestUpdate(md_ctx, &counter, sizeof(counter));
        EVP_DigestUpdate(md_ctx, bits_to_return, sizeof(bits_to_return));
        EVP_DigestUpdate(md_ctx, input, input_len);
        EVP_DigestFinal_ex(md_ctx, md_value, NULL);
#ifdef _HASH_DRBG_DEBUG
		printf("Hash(counter||no_of_bits_to_return||input_string) value:\n");
		for (i = 0; i < (int)(drbg_ctx->hash_output_len); i++)
		{
			printf("0x%x  ", md_value[i]);
		}
		printf("\n");
#endif

        if ( residual >= (int)(drbg_ctx->hash_output_len) )
        {
            memcpy(p, md_value, drbg_ctx->hash_output_len);
        }
        else
        {
            memcpy(p, md_value, residual);
        }

        counter++;
        p += drbg_ctx->hash_output_len;
        residual -= drbg_ctx->hash_output_len;
    }

    EVP_MD_CTX_free(md_ctx);
    return 0;
}

HASH_DRBG_CTX* hash_drbg_ctx_new(void)
{
    HASH_DRBG_CTX *p;

    if ( !(p = (HASH_DRBG_CTX *)malloc(sizeof(HASH_DRBG_CTX))) )
    {
        return NULL;
    }
    return p;
}

void hash_drbg_ctx_free(HASH_DRBG_CTX *drbg_ctx)
{
    if (drbg_ctx)
    {
        memset(drbg_ctx, 0, sizeof(HASH_DRBG_CTX));
        free(drbg_ctx);
    }
}

int hash_drbg_instantiate(const EVP_MD *md,
                          unsigned char *entropy,
                          unsigned int entropy_len,
                          unsigned char *nonce,
                          unsigned int nonce_len,
                          unsigned char *per_string,
                          unsigned int per_string_len,
                          HASH_DRBG_CTX *drbg_ctx)
{
    int error_code;
    unsigned int hash_output_len;
    unsigned char *seed_material, *buffer, *p;
    unsigned int seed_material_len;
#ifdef _HASH_DRBG_DEBUG
	int i;
#endif

    if ( (!(md)) || (!(entropy)) || (!(drbg_ctx)) )
    {
        return INVALID_NULL_VALUE_INPUT;
    }

    if ( !(entropy_len) )
    {
        return INVALID_INPUT_LENGTH;
    }

    drbg_ctx->md = md;
    hash_output_len = EVP_MD_size(md);
    switch (hash_output_len)
    {
        case 32:
            drbg_ctx->hash_output_len = 32;
            drbg_ctx->seed_byte_len = 55;
            drbg_ctx->security_strength = 16;
            break;
        case 64:
            drbg_ctx->hash_output_len = 64;
            drbg_ctx->seed_byte_len = 111;
            drbg_ctx->security_strength = 32;
            break;
        default:
            return INVALID_HASH_ALGORITHM;
    }

    if ( entropy_len < drbg_ctx->security_strength )
    {
        return INVALID_INPUT_LENGTH;
    }

    seed_material_len = entropy_len + nonce_len + per_string_len;
    if ( (!(seed_material = (unsigned char *)malloc(seed_material_len))) )
    {
        return MEMOMY_ALLOCATION_FAIL;
    }
    p = seed_material;
    memcpy(p, entropy, entropy_len);
    p += entropy_len;

    if (nonce_len)
    {
        memcpy(p, nonce, nonce_len);
        p += nonce_len;
    }

    if (per_string_len)
    {
        memcpy(p, per_string, per_string_len);
    }

#ifdef _HASH_DRBG_DEBUG
	printf("Seed material length is %d bytes.\n", seed_material_len);
	printf("Seed material:\n");
	for (i = 0; i < (int)seed_material_len; i++)
	{
		printf("0x%x  ", seed_material[i]);
	}
	printf("\n");
#endif
    if ( error_code = hash_df(drbg_ctx,
                              seed_material,
                              seed_material_len,
                              drbg_ctx->seed_byte_len,
                              drbg_ctx->V) )
    {
        free(seed_material);
        return error_code;
    }
    free(seed_material);
#ifdef _HASH_DRBG_DEBUG
	printf("V:\n");
	for (i = 0; i < (int)(drbg_ctx->seed_byte_len); i++)
	{
		printf("0x%x  ", drbg_ctx->V[i]);
	}
	printf("\n");
#endif

    if ( !(buffer = (unsigned char *)malloc((1 + drbg_ctx->seed_byte_len))) )
    {
        return MEMOMY_ALLOCATION_FAIL;
    }
    p = buffer;
    p[0] = 0;
    p++;
    memcpy(p, drbg_ctx->V, drbg_ctx->seed_byte_len);

    if ( error_code = hash_df(drbg_ctx,
                              buffer,
                              (1 + drbg_ctx->seed_byte_len),
                              drbg_ctx->seed_byte_len,
                              drbg_ctx->C) )
    {
        free(buffer);
        return error_code;
    }
    free(buffer);
#ifdef _HASH_DRBG_DEBUG
	printf("C:\n");
	for (i = 0; i < (int)(drbg_ctx->seed_byte_len); i++)
	{
		printf("0x%x  ", drbg_ctx->C[i]);
	}
	printf("\n");
#endif

    drbg_ctx->reseed_counter = 1;
    return 0;
}

int reseed_hash_drbg(HASH_DRBG_CTX *drbg_ctx,
                     unsigned char *entropy,
                     unsigned int entropy_len,
                     unsigned char *addition_input,
                     unsigned int addition_input_len)
{
    int error_code;
    unsigned char *seed_material, *buffer, *p;
    unsigned int seed_material_len;
#ifdef _HASH_DRBG_DEBUG
	int i;
#endif

    if ( (!(drbg_ctx)) || (!(entropy)) )
    {
        return INVALID_NULL_VALUE_INPUT;
    }

    if ( (!(entropy_len)) || (entropy_len < drbg_ctx->security_strength) )
    {
        return INVALID_INPUT_LENGTH;
    }

    seed_material_len = 1 + drbg_ctx->seed_byte_len + entropy_len + addition_input_len;
    if ( (!(seed_material = (unsigned char *)malloc(seed_material_len))) )
    {
        return MEMOMY_ALLOCATION_FAIL;
    }

    p = seed_material;
    p[0] = 1;
    p++;
    memcpy(p, drbg_ctx->V, drbg_ctx->seed_byte_len);
    p += drbg_ctx->seed_byte_len;
    memcpy(p, entropy, entropy_len);
    p += entropy_len;

    if (addition_input_len)
    {
        memcpy(p, addition_input, addition_input_len);
    }
#ifdef _HASH_DRBG_DEBUG
	printf("Seed material length is %d bytes.\n", seed_material_len);
	printf("Seed material:\n");
	for (i = 0; i < (int)seed_material_len; i++)
	{
		printf("0x%x  ", seed_material[i]);
	}
	printf("\n");
#endif

    if ( error_code = hash_df(drbg_ctx,
                              seed_material,
                              seed_material_len,
                              drbg_ctx->seed_byte_len,
                              drbg_ctx->V) )
    {
        free(seed_material);
        return error_code;
    }
    free(seed_material);

    if ( !(buffer = (unsigned char *)malloc((1 + drbg_ctx->seed_byte_len))) )
    {
        return MEMOMY_ALLOCATION_FAIL;
    }
    p = buffer;
    p[0] = 0;
    p++;
    memcpy(p, drbg_ctx->V, drbg_ctx->seed_byte_len);
#ifdef _HASH_DRBG_DEBUG
	printf("V:\n");
	for (i = 0; i < (int)(drbg_ctx->seed_byte_len); i++)
	{
		printf("0x%x  ", drbg_ctx->V[i]);
	}
	printf("\n");
#endif

    if ( error_code = hash_df(drbg_ctx,
                              buffer,
                              (1 + drbg_ctx->seed_byte_len),
                              drbg_ctx->seed_byte_len,
                              drbg_ctx->C) )
    {
        free(buffer);
        return error_code;
    }
    free(buffer);
#ifdef _HASH_DRBG_DEBUG
	printf("C:\n");
	for (i = 0; i < (int)(drbg_ctx->seed_byte_len); i++)
	{
		printf("0x%x  ", drbg_ctx->C[i]);
	}
	printf("\n");
#endif

    drbg_ctx->reseed_counter = (long long)(1);
    return 0;
}

int hash_gen(HASH_DRBG_CTX *drbg_ctx,
             unsigned int output_len,
             unsigned char *output)
{
    int error_code;
    unsigned char data[MAX_SEED_BYTE_LENGTH];
    unsigned char module_1[56] = {1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char module_2[112] = {1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int residual;
    unsigned char *p;
    EVP_MD_CTX *md_ctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_data = NULL, *bn_one = NULL, *bn_module = NULL, *bn_sum = NULL;
#ifdef _HASH_DRBG_DEBUG
	int i;
	char *q;
#endif

    if ( (!(drbg_ctx)) || (!(output)) )
    {
        return INVALID_NULL_VALUE_INPUT;
    }
    if ( (!(output_len)) )
    {
        return INVALID_INPUT_LENGTH;
    }

    p = output;
    if ( !(md_ctx = EVP_MD_CTX_new()) )
    {
        return MEMOMY_ALLOCATION_FAIL;
    }
    memcpy(data, drbg_ctx->V, drbg_ctx->seed_byte_len);
#ifdef _HASH_DRBG_DEBUG
	printf("data:\n");
	for (i = 0; i < (int)(drbg_ctx->seed_byte_len); i++)
	{
		printf("0x%x  ", data[i]);
	}
	printf("\n");
#endif
    residual = (int)output_len;
    if ( (!(bn_ctx = BN_CTX_secure_new())) )
    {
        EVP_MD_CTX_free(md_ctx);
        return MEMOMY_ALLOCATION_FAIL;
    }
    BN_CTX_start(bn_ctx);
    bn_data = BN_CTX_get(bn_ctx);
    bn_one = BN_CTX_get(bn_ctx);
    bn_module = BN_CTX_get(bn_ctx);
    bn_sum = BN_CTX_get(bn_ctx);
    if ( !(bn_sum) )
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
        EVP_MD_CTX_free(md_ctx);
        return MEMOMY_ALLOCATION_FAIL;
    }

    error_code = BIG_NUM_ARITHMETIC_ERROR;
    if ( !(BN_one(bn_one)) )
    {
        goto clean_up;
    }
    switch (drbg_ctx->seed_byte_len)
    {
        case 55:
            if ( !(BN_bin2bn(module_1, sizeof(module_1), bn_module)) )
            {
                goto clean_up;
            }
            break;
        case 111:
            if ( !(BN_bin2bn(module_2, sizeof(module_2), bn_module)) )
            {
                goto clean_up;
            }
			break;
        default:
            goto clean_up;
    }
#ifdef _HASH_DRBG_DEBUG
	printf("Module: \n");
	q = BN_bn2hex(bn_module);
	printf("%s\n", q);
	OPENSSL_free(q);
	printf("\n");
#endif

    while (residual > 0 )
    {
        EVP_DigestInit_ex(md_ctx, drbg_ctx->md, NULL);
        EVP_DigestUpdate(md_ctx, data, drbg_ctx->seed_byte_len);
        EVP_DigestFinal_ex(md_ctx, md_value, NULL);
#ifdef _HASH_DRBG_DEBUG
		printf("w:\n");
		for (i = 0; i < (int)(drbg_ctx->hash_output_len); i++)
		{
			printf("0x%x  ", md_value[i]);
		}
		printf("\n");
#endif

        if ( residual >= (int)(drbg_ctx->hash_output_len) )
        {
            memcpy(p, md_value, drbg_ctx->hash_output_len);
        }
        else
        {
            memcpy(p, md_value, residual);
        }

        p += drbg_ctx->hash_output_len;
        residual -= drbg_ctx->hash_output_len;

        if (residual > 0)
        {
            if ( !(BN_bin2bn(data, drbg_ctx->seed_byte_len, bn_data)) )
            {
                goto clean_up;
            }
            if ( (!(BN_mod_add(bn_sum, bn_data, bn_one, bn_module, bn_ctx))) )
            {
                goto clean_up;
            }
            if ( BN_bn2binpad(bn_sum,
                              data,
                              drbg_ctx->seed_byte_len) != drbg_ctx->seed_byte_len )
            {
                goto clean_up;
            }
        }
    }
    error_code = 0;

clean_up:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EVP_MD_CTX_free(md_ctx);
    return error_code;
}

int gen_rnd_bytes_with_hash_drbg(HASH_DRBG_CTX *drbg_ctx,
                                 unsigned int rnd_byte_len,
                                 unsigned char *addition_input,
                                 unsigned int addition_input_len,
                                 unsigned char *rnd)
{
    int error_code, rtn_val;
    unsigned char module_1[56] = {1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char module_2[112] = {1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char prefix_char, reseed_cnt[8];
    EVP_MD_CTX *md_ctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_w = NULL, *bn_V = NULL, *bn_module = NULL, *bn_H = NULL;
    BIGNUM *bn_C = NULL, *bn_reseed_cnt = NULL, *bn_sum = NULL;
    BIGNUM *bn_tmp_sum_1 = NULL, *bn_tmp_sum_2 = NULL;
#ifdef _HASH_DRBG_DEBUG
	int i;
#endif

    if ( (!(drbg_ctx)) || (!(rnd)) )
    {
        return INVALID_NULL_VALUE_INPUT;
    }
    if ( drbg_ctx->reseed_counter > MAX_RESEED_INTERVAL )
    {
        return REQUIRE_RESEED;
    }

    if ( (!(rnd_byte_len)) || (rnd_byte_len > MAX_BYTE_COUNT_PER_REQUEST) )
    {
        return INVALID_INPUT_LENGTH;
    }

    reseed_cnt[0] = (unsigned char )((drbg_ctx->reseed_counter >> 56) & 0xFF);
    reseed_cnt[1] = (unsigned char )((drbg_ctx->reseed_counter >> 48) & 0xFF);
    reseed_cnt[2] = (unsigned char )((drbg_ctx->reseed_counter >> 40) & 0xFF);
    reseed_cnt[3] = (unsigned char )((drbg_ctx->reseed_counter >> 32) & 0xFF);
    reseed_cnt[4] = (unsigned char )((drbg_ctx->reseed_counter >> 24) & 0xFF);
    reseed_cnt[5] = (unsigned char )((drbg_ctx->reseed_counter >> 16) & 0xFF);
    reseed_cnt[6] = (unsigned char )((drbg_ctx->reseed_counter >> 8) & 0xFF);
    reseed_cnt[7] = (unsigned char )(drbg_ctx->reseed_counter & 0xFF);

    if ( !(md_ctx = EVP_MD_CTX_new()) )
    {
        return MEMOMY_ALLOCATION_FAIL;
    }
    if ( !(bn_ctx = BN_CTX_secure_new()) )
    {
        EVP_MD_CTX_free(md_ctx);
        return MEMOMY_ALLOCATION_FAIL;
    }
    BN_CTX_start(bn_ctx);
    bn_w = BN_CTX_get(bn_ctx);
    bn_V = BN_CTX_get(bn_ctx);
    bn_module = BN_CTX_get(bn_ctx);
    bn_H = BN_CTX_get(bn_ctx);
    bn_C = BN_CTX_get(bn_ctx);
    bn_reseed_cnt = BN_CTX_get(bn_ctx);
    bn_sum = BN_CTX_get(bn_ctx);
    bn_tmp_sum_1 = BN_CTX_get(bn_ctx);
    bn_tmp_sum_2 = BN_CTX_get(bn_ctx);
    if ( !(bn_tmp_sum_2) )
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
        EVP_MD_CTX_free(md_ctx);
        return MEMOMY_ALLOCATION_FAIL;
    }

    error_code = BIG_NUM_ARITHMETIC_ERROR;
    switch (drbg_ctx->seed_byte_len)
    {
        case 55:
            if ( !(BN_bin2bn(module_1, sizeof(module_1), bn_module)) )
            {
                goto clean_up;
            }
            break;
        case 111:
            if ( !(BN_bin2bn(module_2, sizeof(module_2), bn_module)) )
            {
                goto clean_up;
            }
			break;
        default:
            goto clean_up;
    }

    if (addition_input_len)
    {
        prefix_char = 2;
        EVP_DigestInit_ex(md_ctx, drbg_ctx->md, NULL);
        EVP_DigestUpdate(md_ctx, &prefix_char, sizeof(prefix_char));
        EVP_DigestUpdate(md_ctx, drbg_ctx->V, drbg_ctx->seed_byte_len);
        EVP_DigestUpdate(md_ctx, addition_input, addition_input_len);
        EVP_DigestFinal_ex(md_ctx, md_value, NULL);
#ifdef _HASH_DRBG_DEBUG
		printf("w = Hash(0x02||V||additional_input) is:\n");
		for (i = 0; i < (int)(drbg_ctx->hash_output_len); i++)
		{
			printf("0x%x  ", md_value[i]);
		}
		printf("\n");
#endif

        if ( !(BN_bin2bn(md_value, drbg_ctx->hash_output_len, bn_w)) )
        {
            goto clean_up;
        }
        if ( !(BN_bin2bn(drbg_ctx->V, drbg_ctx->seed_byte_len, bn_V)) )
        {
            goto clean_up;
        }
        if ( !(BN_mod_add(bn_sum, bn_V, bn_w, bn_module, bn_ctx)) )
        {
            goto clean_up;
        }
        if ( BN_bn2binpad(bn_sum,
                          drbg_ctx->V,
                          drbg_ctx->seed_byte_len) != drbg_ctx->seed_byte_len )
        {
            goto clean_up;
        }
#ifdef _HASH_DRBG_DEBUG
		printf("V:\n");
		for (i = 0; i < (int)(drbg_ctx->seed_byte_len); i++)
		{
			printf("0x%x  ", drbg_ctx->V[i]);
		}
		printf("\n");
#endif
    }
    
    if ( (rtn_val = hash_gen(drbg_ctx,
                             rnd_byte_len,
                             rnd)) )
    {
        error_code = rtn_val;
        goto clean_up;
    }

    prefix_char = 3;
    EVP_DigestInit_ex(md_ctx, drbg_ctx->md, NULL);
    EVP_DigestUpdate(md_ctx, &prefix_char, sizeof(prefix_char));
    EVP_DigestUpdate(md_ctx, drbg_ctx->V, drbg_ctx->seed_byte_len);
    EVP_DigestFinal_ex(md_ctx, md_value, NULL);
#ifdef _HASH_DRBG_DEBUG
	printf("H:\n");
	for (i = 0; i < (int)(drbg_ctx->hash_output_len); i++)
	{
		printf("0x%x  ", md_value[i]);
	}
	printf("\n");
#endif

    if ( !(BN_bin2bn(md_value, drbg_ctx->hash_output_len, bn_H)) )
    {
        goto clean_up;
    }
    if ( !(BN_bin2bn(drbg_ctx->V, drbg_ctx->seed_byte_len, bn_V)) )
    {
        goto clean_up;
    }
    if ( !(BN_bin2bn(drbg_ctx->C, drbg_ctx->seed_byte_len, bn_C)) )
    {
        goto clean_up;
    }
    if ( !(BN_bin2bn(reseed_cnt, sizeof(reseed_cnt), bn_reseed_cnt)) )
    {
        goto clean_up;
    }

    if ( (!(BN_mod_add(bn_tmp_sum_1, bn_V, bn_H, bn_module, bn_ctx))) )
    {
        goto clean_up;
    }
    if ( (!(BN_mod_add(bn_tmp_sum_2, bn_tmp_sum_1, bn_C, bn_module, bn_ctx))) )
    {
        goto clean_up;
    }
    if ( (!(BN_mod_add(bn_sum, bn_tmp_sum_2, bn_reseed_cnt, bn_module, bn_ctx))) )
    {
        goto clean_up;
    }
    if ( BN_bn2binpad(bn_sum,
                      drbg_ctx->V,
                      drbg_ctx->seed_byte_len) != drbg_ctx->seed_byte_len )
    {
        goto clean_up;
    }
#ifdef _HASH_DRBG_DEBUG
	printf("V:\n");
	for (i = 0; i < (int)(drbg_ctx->seed_byte_len); i++)
	{
		printf("0x%x  ", drbg_ctx->V[i]);
	}
	printf("\n");
#endif
    error_code = 0;
    (drbg_ctx->reseed_counter)++;

clean_up:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EVP_MD_CTX_free(md_ctx);
    return error_code;
}
