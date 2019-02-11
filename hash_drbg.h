/**************************************************
* File name: hash_drbg.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Feb 8th, 2019
* Description: declare hash DRBG construction functions
**************************************************/

#ifndef HEADER_HASH_DRBG_CONSTRUCTION_FUNCTIONS_H
  #define HEADER_HASH_DRBG_CONSTRUCTION_FUNCTIONS_H 

#include <openssl/evp.h>

#define MAX_SEED_BYTE_LENGTH   (unsigned int)(111)
#define MAX_RESEED_INTERVAL    (long long)(281474976710656)
#define MAX_BYTE_COUNT_PER_REQUEST    (unsigned int)(65536)

/* The macro '_HASH_DRBG_DEBUG' can only be defined in debug version.
   It must be undefined in release vesion! */
//#define _HASH_DRBG_DEBUG

typedef struct hash_drbg_context {
  const EVP_MD *md;
  unsigned char V[MAX_SEED_BYTE_LENGTH];
  unsigned char C[MAX_SEED_BYTE_LENGTH];
  unsigned int hash_output_len;
  unsigned int security_strength;
  unsigned int seed_byte_len;
  long long reseed_counter;
} HASH_DRBG_CTX;

#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: hash_df
* Function: evaluate Hash_df (hash derivation function)
* Parameters:
    drbg_ctx[in]      Hash DRBG context
    input[in]         input message
    input[in]         length of input message, size in bytes
    output_len[in]    the number to be returned, size in bytes
    output[out]       output of Hash_df function
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
  Hash_df function is defined in chapter 10.3.1, 'Derivation Function 
  Using a Hash Function (Hash_df)' of NIST SP 800-90A Rev.1.
**************************************************/
int hash_df(HASH_DRBG_CTX *drbg_ctx,
            unsigned char *input,
            unsigned int input_len,
            unsigned int output_len,
            unsigned char *output);

/**************************************************
* Name: hash_drbg_ctx_new
* Function: create a Hash DRBG context
* Return value:
    A pointer that points to the new created Hash DRBG context
    structure is returned. NULL is returned when an error occurs.
* Notes:
  The Hash DRBG context created by this function must be freed 
  by invoking hash_drbg_ctx_free( ), otherwise memory leak occurs.
**************************************************/
HASH_DRBG_CTX* hash_drbg_ctx_new(void);

/**************************************************
* Name: hash_drbg_ctx_free
* Function: free a Hash DRBG context
* Parameters:
    drbg_ctx[in]      Hash DRBG context
**************************************************/
void hash_drbg_ctx_free(HASH_DRBG_CTX *drbg_ctx);

/**************************************************
* Name: hash_drbg_instantiate
* Function: instantiate a Hash DRBG
* Parameters:
    md[in]              a pointer that points to a EVP_MD 
                        structure defined in OpenSSL
    entropy[in]         input entropy
    entropy_len[in]     length of input entropy, size in bytes
    nonce[in]           input nonce
    nonce_len[in]       length of input nonce
    per_string          input personalization string
    per_string_len[in]  length of personalization string, size in bytes
    drbg_ctx[in]        Hash DRBG context
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. Minimum entropy and Minimum entropy input length are defined in chapter 
   10.1, 'DRBG Mechanisms Based on Hash Functions' of NIST SP 800-90A Rev.1.
2. The hash algorithm employed by the Hash DRBG is determined by the 
   parameter 'md'. Optional hash algorithm set includes SHA-256 and SHA-512.
   SHA-256 is recommended in this implementation. Implicitly, some other 
   algorithms, such as SHA3-256 and SHA3-512 can be used here although they 
   are not included in NIST SP 800-90A Rev.1.
**************************************************/
int hash_drbg_instantiate(const EVP_MD *md,
                          unsigned char *entropy,
                          unsigned int entropy_len,
                          unsigned char *nonce,
                          unsigned int nonce_len,
                          unsigned char *per_string,
                          unsigned int per_string_len,
                          HASH_DRBG_CTX *drbg_ctx);

/**************************************************
* Name: reseed_hash_drbg
* Function: reseed a Hash DRBG
* Parameters:
    drbg_ctx[in]            Hash DRBG context
    entropy[in]             input entropy
    entropy_len[in]         length of input entropy, size in bytes
    addition_input[in]      additional input
    addition_input_len[in]  length of additional input, size in bytes
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. Minimum entropy, minimum entropy input length and reseed interval are 
   defined in chapter 10.1, 'DRBG Mechanisms Based on Hash Functions' of 
   NIST SP 800-90A Rev.1.
2. When prediction resistance is required, this function must be invoked 
   each time before generating random bytes with the Hash DRBG, that is,
   before invoking gen_rnd_bytes_with_hash_drbg( ).
**************************************************/
int reseed_hash_drbg(HASH_DRBG_CTX *drbg_ctx,
                     unsigned char *entropy,
                     unsigned int entropy_len,
                     unsigned char *addition_input,
                     unsigned int addition_input_len);

/**************************************************
* Name: hash_gen
* Function: evaluate HashGen function
* Parameters:
    drbg_ctx[in]      Hash DRBG context
    output_len[in]    the number to be returned, size in bytes
    output[out]       output of random bytes
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
  HashGen function is defined in chapter 10.1.1.4, 'Generating 
  Pseudorandom Bits Using Hash_DRBG' of NIST SP 800-90A Rev.1.
**************************************************/
int hash_gen(HASH_DRBG_CTX *drbg_ctx,
             unsigned int output_len,
             unsigned char *output);

/**************************************************
* Name: gen_rnd_bytes_with_hash_drbg
* Function: generate pseudorandom byts using Hash_DRBG
* Parameters:
    drbg_ctx[in]            Hash DRBG context
    rnd_byte_len[in]        the number to be returned, size in bytes
    addition_input[in]      additional input
    addition_input_len[in]  length of additional input, size in bytes
    rnd[out]                output of pseudorandom bytes
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. Maximum number of bits per request is defined in chapter 10.1, 
   'DRBG Mechanisms Based on Hash Functions' of NIST SP 800-90A Rev.1.
2. The maximum length of pseudorandom bytes generated by this function 
   is 65536-byte. When more pseudorandom bytes are required, this 
   function must be invoked iteratively.
**************************************************/
int gen_rnd_bytes_with_hash_drbg(HASH_DRBG_CTX *drbg_ctx,
                                 unsigned int rnd_byte_len,
                                 unsigned char *addition_input,
                                 unsigned int addition_input_len,
                                 unsigned char *rnd);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_HASH_DRBG_CONSTRUCTION_FUNCTIONS_H */
