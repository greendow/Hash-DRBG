/**************************************************
* File name: hash_drbg_error_codes.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Feb 7th, 2019
* Description: define error codes used in hash
    DRBG functions
**************************************************/

#ifndef HEADER_HASH_DRBG_ERROR_CODES_H
  #define HEADER_HASH_DRBG_ERROR_CODES_H

#define INVALID_NULL_VALUE_INPUT    0x1000
#define INVALID_INPUT_LENGTH        0x1001
#define MEMOMY_ALLOCATION_FAIL      0x1002
#define INVALID_HASH_ALGORITHM      0x1003
#define REQUIRE_RESEED              0x1004
#define BIG_NUM_ARITHMETIC_ERROR    0x1005

#endif /* end of HEADER_HASH_DRBG_ERROR_CODES_H */
