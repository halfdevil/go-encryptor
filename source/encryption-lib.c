//
// Created by Jiten Sharma on 06/07/18.
//

#include <memory.h>
#include <string.h>
#include <openssl/sha.h>
#include "encryption-sdk.h"
#include "encryption-lib.h"

int data_encrypt_decrypt(const cipher_params *params, unsigned char *input,
                          int input_size, unsigned char *output,
                         unsigned int *output_len) {
    int out_len;
    EVP_CIPHER_CTX *ctx;

	int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
	unsigned char *out_buf = (unsigned char*)malloc(BUFFER_SIZE + cipher_block_size);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
		SAFE_FREE(out_buf);
        return -1;
    }

    if (!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)) {
		SAFE_FREE(out_buf);
        EVP_CIPHER_CTX_cleanup(ctx);
        return -2;
    }

    if (!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)) {
		SAFE_FREE(out_buf);
        EVP_CIPHER_CTX_cleanup(ctx);
        return -3;
    }

    if (!EVP_CipherUpdate(ctx, out_buf, &out_len, input, input_size)) {
		SAFE_FREE(out_buf);
        EVP_CIPHER_CTX_cleanup(ctx);
        return -5;
    }

	memcpy(output, out_buf, out_len);
    *output_len = (unsigned int)out_len;

    if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
		SAFE_FREE(out_buf);
        EVP_CIPHER_CTX_cleanup(ctx);
        return -7;
    }

	if (out_len > 0) {
		memcpy(output + *output_len, out_buf, out_len);
		*output_len += (unsigned int)out_len;
	}
	
	SAFE_FREE(out_buf);
	EVP_CIPHER_CTX_cleanup(ctx);

    return 0;
}

int file_encrypt_decrypt(const cipher_params *params, FILE *input, FILE *output) {
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);

	unsigned char *in_buf = (unsigned char*)malloc(BUFFER_SIZE);
	unsigned char *out_buf = (unsigned char*)malloc(BUFFER_SIZE + cipher_block_size);

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)) {
        EVP_CIPHER_CTX_cleanup(ctx);
		SAFE_FREE(in_buf);
		SAFE_FREE(out_buf);
        return -2;
    }

    if (!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)) {
        EVP_CIPHER_CTX_cleanup(ctx);
		SAFE_FREE(in_buf);
		SAFE_FREE(out_buf);
        return -3;
    }

    while (1) {
        num_bytes_read = (int)fread(in_buf, sizeof(unsigned char), BUFFER_SIZE, input);
        if (ferror(input)) {
            EVP_CIPHER_CTX_cleanup(ctx);
			SAFE_FREE(in_buf);
			SAFE_FREE(out_buf);
            return -4;
        }

        if (!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)) {
            EVP_CIPHER_CTX_cleanup(ctx);
			SAFE_FREE(in_buf);
			SAFE_FREE(out_buf);
            return -5;
        }

        fwrite(out_buf, sizeof(unsigned char), (size_t)out_len, output);
        if (ferror(output)) {
            EVP_CIPHER_CTX_cleanup(ctx);
			SAFE_FREE(in_buf);
			SAFE_FREE(out_buf);
            return -6;
        }

        if (num_bytes_read < BUFFER_SIZE)
            break;
    }

    if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
        EVP_CIPHER_CTX_cleanup(ctx);
		SAFE_FREE(in_buf);
		SAFE_FREE(out_buf);
        return -7;
    }

    fwrite(out_buf, sizeof(unsigned char), (size_t)out_len, output);
    if (ferror(output)) {
        EVP_CIPHER_CTX_cleanup(ctx);
		SAFE_FREE(in_buf);
		SAFE_FREE(out_buf);
        return -6;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
	SAFE_FREE(in_buf);
	SAFE_FREE(out_buf);

    return 0;
}

int data_generate_sha256(const char *data, unsigned char *hash) {
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        return -1;
    }

    if (!SHA256_Update(&ctx, data, strlen(data))) {
        return -2;
    }

    if (!SHA256_Final(hash, &ctx)) {
        return -3;
    }

    return 0;
}

int file_generate_sha256(FILE *input, unsigned char *hash) {
    unsigned char in_buf[BUFFER_SIZE];
    int num_bytes_read;

    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        return -1;
    }

    fseek(input, 0, SEEK_SET);

    while (1) {
        num_bytes_read = (int)fread(in_buf, sizeof(unsigned char), BUFFER_SIZE, input);
        if (ferror(input)) {
            return -1;
        }

        if (!SHA256_Update(&ctx, in_buf, (size_t)num_bytes_read)) {
            return -2;
        }

        if (num_bytes_read < BUFFER_SIZE)
            break;
    }

    if (!SHA256_Final(hash, &ctx)) {
        return -3;
    }

    fseek(input, 0, SEEK_SET);

    return 0;
}