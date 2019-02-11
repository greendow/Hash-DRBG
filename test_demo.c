/**************************************************
* File name: test_demo.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Feb 10th, 2019
* Description: implement hash DRBG test demo programs
**************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "test_hash_drbg.h"

int main(void)
{
    int error_code;

    printf("\n*******************************************\n");
    printf("Test SHA-256 Hash DRBG without prediction resistance:\n");
    if ( error_code = test_sha256_hash_drbg_without_prediction_resistance() )
    {
        printf("Generating random bytes test failed!\n");
        printf("Error code: 0x%x", error_code);
        return error_code;
    }
    printf("Generating random bytes test succeeded!\n");

    printf("\n*******************************************\n");
    printf("Test SHA-256 Hash DRBG with prediction resistance:\n");
    if ( error_code = test_sha256_hash_drbg_with_prediction_resistance() )
    {
        printf("Generating random bytes test failed!\n");
        printf("Error code: 0x%x", error_code);
        return error_code;
    }
    printf("Generating random bytes test succeeded!\n");

    printf("\n*******************************************\n");
    printf("Test SHA-512 Hash DRBG without prediction resistance:\n");
    if ( error_code = test_sha512_hash_drbg_without_prediction_resistance() )
    {
        printf("Generating random bytes test failed!\n");
        printf("Error code: 0x%x", error_code);
        return error_code;
    }
    printf("Generating random bytes test succeeded!\n");

    printf("\n*******************************************\n");
    printf("Test SHA-256 Hash DRBG with prediction resistance:\n");
    if ( error_code = test_sha512_hash_drbg_with_prediction_resistance() )
    {
        printf("Generating random bytes test failed!\n");
        printf("Error code: 0x%x", error_code);
        return error_code;
    }
    printf("Generating random bytes test succeeded!\n");

#if defined(_WIN32) || defined(_WIN64)
	system("pause");
#endif
    return 0;
}