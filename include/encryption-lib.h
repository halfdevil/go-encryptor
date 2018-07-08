//
// Created by Jiten Sharma on 06/07/18.
//

#ifndef ENCRYPTION_SDK_ENCRYPTION_LIB_H
#define ENCRYPTION_SDK_ENCRYPTION_LIB_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

typedef struct _cipher_params {
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
} cipher_params;

int data_encrypt_decrypt(const cipher_params *params, unsigned char *input,
	int input_size, unsigned char *output,
	unsigned int *output_len);

int file_encrypt_decrypt(const cipher_params *params, FILE *input, FILE *output);

int data_generate_sha256(const char *data, unsigned char *hash);
int file_generate_sha256(FILE *input, unsigned char *hash);

#endif //ENCRYPTION_SDK_ENCRYPTION_LIB_H
