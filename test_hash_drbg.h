/**************************************************
* File name: test_hash_drbg.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Feb 10th, 2019
* Description: declare hash DRBG test functions
**************************************************/

#ifndef HEADER_HASH_DRBG_TEST_FUNCTIONS_H
  #define HEADER_HASH_DRBG_TEST_FUNCTIONS_H

#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: test_sha256_hash_drbg_without_prediction_resistance
* Function: evaluate Hash_DRBG output based on SHA-256
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
  Test data are excerpted from the document provided by NIST.
  See test_data_1.txt for details.
**************************************************/
int test_sha256_hash_drbg_without_prediction_resistance(void);

/**************************************************
* Name: test_sha256_hash_drbg_with_prediction_resistance
* Function: evaluate Hash_DRBG output based on SHA-256
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
  Test data are excerpted from the document provided by NIST.
  See test_data_2.txt for details.
**************************************************/
int test_sha256_hash_drbg_with_prediction_resistance(void);

/**************************************************
* Name: test_sha512_hash_drbg_without_prediction_resistance
* Function: evaluate Hash_DRBG output based on SHA-512
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
  Test data are excerpted from the document provided by NIST.
  See test_data_3.txt for details.
**************************************************/
int test_sha512_hash_drbg_without_prediction_resistance(void);

/**************************************************
* Name: test_sha512_hash_drbg_with_prediction_resistance
* Function: evaluate Hash_DRBG output based on SHA-512
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
  Test data are excerpted from the document provided by NIST.
  See test_data_4.txt for details.
**************************************************/
int test_sha512_hash_drbg_with_prediction_resistance(void);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_HASH_DRBG_TEST_FUNCTIONS_H */