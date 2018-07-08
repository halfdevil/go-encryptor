//
// Created by Jiten Sharma on 06/07/18.
//

#include "encryption-sdk-impl.h"
#include "encryption-lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <openssl/rand.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

encryptor_key* __get_encryptor_key(sdk_application *application,
                                   int key_id)
{
    if (application) {
        if (application->__context) {
            application_data *data = (application_data*)application->__context;

			int i = 0;
			for (i = 0; i < data->num_keys; i++) {
				if (data->keys[i].key_id == key_id)
					return &data->keys[i];
			}
        }
    }

    return NULL;
}

int __is_file_hash_same(FILE *input, unsigned char *hash) {
	unsigned char file_hash[32];

	file_generate_sha256(input, file_hash);

	if (memcmp(hash, file_hash, sizeof(file_hash)) == 0)
		return 1;

	return 0;
}

long __encrypt_file(struct _sdk_encryptor *this,
                  int key_id,
                  const char *input_file,
                  const char *output_file,
                  sdk_error *error) {
    encrypted_file_header header;
    FILE *input, *output;

    unsigned char *enterprise_key = NULL;
    unsigned char content_key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    RAND_bytes(content_key, sizeof(content_key));
    RAND_bytes(iv, sizeof(iv));

    input = fopen(input_file, "rb");
    if (!input) {
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open input file");

        return -1;
    }

    output = fopen(output_file, "wb");
    if (!output) {
        fclose(input);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open output file");

        return -2;
    }
	
	memset(&header, 0, sizeof(encrypted_file_header));
	header.signature = SDK_SIGNATURE;
	header.password_file = 0;
	memcpy(header.iv, iv, sizeof(iv));

    if (file_generate_sha256(input, header.file_hash) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to generate sha256 hash");

        return -3;
    }
	
    if (this->__context) {
        encryptor_data *data = (encryptor_data*)this->__context;
        encryptor_key *enc_key = __get_encryptor_key(data->application, key_id);

        if (enc_key) {
            enterprise_key = enc_key->key.data;
            header.key_id = (unsigned int)enc_key->key_id;
        }
    }

    if (!enterprise_key) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to get enterprise key");

        return -4;
    }
	
    cipher_params params;
    params.iv = iv;
    params.key = enterprise_key;
    params.encrypt = 1;
    params.cipher_type = EVP_aes_256_cbc();

    if (data_encrypt_decrypt(&params, content_key, sizeof(content_key),
                             header.enterprise_key, &header.enterprise_key_len) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to encrypt content key");

        return -5;
    }

    fwrite(&header, 1, sizeof(encrypted_file_header), output);
    if (ferror(output)) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to write header to file");

        return -6;
    }

    params.iv = iv;
    params.key = content_key;
    params.encrypt = 1;
    params.cipher_type = EVP_aes_256_cbc();

    if (file_encrypt_decrypt(&params, input, output) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to encrypt content");

        return -7;
    }

    fclose(input);
    fclose(output);

    return 0;
}

long __encrypt_file_with_password(struct _sdk_encryptor *this,
                                int key_id,
                                const char *password,
                                const char *input_file,
                                const char *output_file,
                                sdk_error *error) {
    encrypted_file_header header;
    FILE *input, *output;

    unsigned char *enterprise_key = NULL;
    unsigned char password_key[32];
    unsigned char content_key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    RAND_bytes(content_key, sizeof(content_key));
    RAND_bytes(iv, sizeof(iv));

    input = fopen(input_file, "rb");
    if (!input) {
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open input file");

        return -1;
    }

    output = fopen(output_file, "wb");
    if (!output) {
        fclose(input);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open output file");

        return -2;
    }
	
	memset(&header, 0, sizeof(encrypted_file_header));
	header.signature = SDK_SIGNATURE;
	header.password_file = 1;
	memcpy(header.iv, iv, sizeof(iv));

    if (file_generate_sha256(input, header.file_hash) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to generate sha256 hash");

        return -3;
    }
	
    if (this->__context) {
        encryptor_data *data = (encryptor_data*)this->__context;
        encryptor_key *enc_key = __get_encryptor_key(data->application, key_id);

        if (enc_key) {
            enterprise_key = enc_key->key.data;
            header.key_id = (unsigned int)enc_key->key_id;
        }
    }

    if (!enterprise_key) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to get enterprise key");

        return -4;
    }

    cipher_params params;
    params.iv = iv;
    params.key = enterprise_key;
    params.encrypt = 1;
    params.cipher_type = EVP_aes_256_cbc();

    if (data_encrypt_decrypt(&params, content_key, sizeof(content_key),
                             header.enterprise_key, &header.enterprise_key_len) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to encrypt content key with enterprise key");

        return -5;
    }

    if (data_generate_sha256(password, password_key) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to generate password key");

        return -6;
    }

    params.iv = iv;
    params.key = password_key;
    params.encrypt = 1;
    params.cipher_type = EVP_aes_256_cbc();

    if (data_encrypt_decrypt(&params, content_key, sizeof(content_key),
                             header.password_key, &header.password_key_len) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to encrypt content key with password key");

        return -7;
    }

    fwrite(&header, 1, sizeof(encrypted_file_header), output);
    if (ferror(output)) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to write header to file");

        return -8;
    }

    params.iv = iv;
    params.key = content_key;
    params.encrypt = 1;
    params.cipher_type = EVP_aes_256_cbc();

    if (file_encrypt_decrypt(&params, input, output) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to encrypt content");

        return -9;
    }

    fclose(input);
    fclose(output);

    return 0;
}

long __decrypt_file(struct _sdk_encryptor *this,
                  int key_id,
                  const char *input_file,
                  const char *output_file,
                  sdk_error *error) {
    encrypted_file_header header;
    FILE *input, *output;

    unsigned char *enterprise_key = NULL;
    unsigned char content_key[AES_256_KEY_SIZE];
    unsigned int content_key_len;

    input = fopen(input_file, "rb");
    if (!input) {
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open input file");

        return -1;
    }

    output = fopen(output_file, "wb");
    if (!output) {
        fclose(input);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open output file");

        return -2;
    }

    fread(&header, 1, sizeof(encrypted_file_header), input);
    if (ferror(input)) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to read header from file");

        return -2;
    }

    if (this->__context) {
        encryptor_data *data = (encryptor_data*)this->__context;
        encryptor_key *enc_key = __get_encryptor_key(data->application, key_id);

        if (enc_key) {
            enterprise_key = enc_key->key.data;
        }
    }

    if (!enterprise_key) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to get enterprise key");

        return -3;
    }

    cipher_params params;
    params.iv = header.iv;
    params.key = enterprise_key;
    params.encrypt = 0;
    params.cipher_type = EVP_aes_256_cbc();

    if (data_encrypt_decrypt(&params, header.enterprise_key,
                             header.enterprise_key_len,
                             content_key, &content_key_len) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to decrypt content key with enterprise key");

        return -4;
    }

    params.iv = header.iv;
    params.key = content_key;
    params.encrypt = 0;
    params.cipher_type = EVP_aes_256_cbc();

    if (file_encrypt_decrypt(&params, input, output) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to decrypt content");

        return -9;
    }

    fclose(input);
    fclose(output);

	input = fopen(output_file, "rb");
	if (!input) {
		error->error_code = -2;
		error->error_type = sdk_error_type_fatal;
		strcpy(error->error_msg, "unable to open output file for checking");

		return -10;
	}

	if (!__is_file_hash_same(input, header.file_hash)) {
		fclose(input);
		error->error_code = -2;
		error->error_type = sdk_error_type_fatal;
		strcpy(error->error_msg, "file hash mismatch");

		return -11;
	}

	fclose(input);
	
    return 0;
}

long __decrypt_file_with_password(struct _sdk_encryptor *this,
                                const char *password,
                                const char *input_file,
                                const char *output_file,
                                sdk_error *error) {
    encrypted_file_header header;
    FILE *input, *output;

    unsigned char password_key[32];
    unsigned char content_key[AES_256_KEY_SIZE];
    unsigned int content_key_len;

    input = fopen(input_file, "rb");
    if (!input) {
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open input file");

        return -1;
    }

    output = fopen(output_file, "wb");
    if (!output) {
        fclose(input);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to open output file");

        return -2;
    }

    fread(&header, 1, sizeof(encrypted_file_header), input);
    if (ferror(input)) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to read header from file");

        return -3;
    }

    if (data_generate_sha256(password, password_key) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to generate sha256 of password");

        return -4;
    }

    cipher_params params;
    params.iv = header.iv;
    params.key = password_key;
    params.encrypt = 0;
    params.cipher_type = EVP_aes_256_cbc();

    if (data_encrypt_decrypt(&params, header.password_key,
                             header.password_key_len,
                             content_key, &content_key_len) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to decrypt content key with enterprise key");

        return -4;
    }

    params.iv = header.iv;
    params.key = content_key;
    params.encrypt = 0;
    params.cipher_type = EVP_aes_256_cbc();

    if (file_encrypt_decrypt(&params, input, output) != 0) {
        fclose(input);
        fclose(output);
        error->error_code = -2;
        error->error_type = sdk_error_type_fatal;
        strcpy(error->error_msg, "unable to decrypt content");

        return -9;
    }

    fclose(input);
    fclose(output);

	input = fopen(output_file, "rb");
	if (!input) {
		error->error_code = -2;
		error->error_type = sdk_error_type_fatal;
		strcpy(error->error_msg, "unable to open output file for checking");

		return -10;
	}

	if (!__is_file_hash_same(input, header.file_hash)) {
		fclose(input);
		error->error_code = -2;
		error->error_type = sdk_error_type_fatal;
		strcpy(error->error_msg, "file hash mismatch");

		return -11;
	}

	fclose(input);

    return 0;
}

int __is_file_encrypted(struct _sdk_encryptor *this,
                      const char *file) {
    encrypted_file_header header;
    FILE *input;

    input = fopen(file, "rb");
    if (!input) {
        return 0;
    }

    fread(&header, 1, sizeof(encrypted_file_header), input);
    if (ferror(input)) {
        return 0;
    }

    if (header.signature == SDK_SIGNATURE)
        return 1;

    fclose(input);

    return 0;
}

int __is_file_encrypted_with_password(struct _sdk_encryptor *this,
									const char *file) {
	encrypted_file_header header;
	FILE *input;

	input = fopen(file, "rb");
	if (!input) {
		return 0;
	}

	fread(&header, 1, sizeof(encrypted_file_header), input);
	if (ferror(input)) {
		return 0;
	}

	if (header.signature == SDK_SIGNATURE)
	{
		if (header.password_file)
			return 1;
	}

	fclose(input);

	return 0;
}

void __release_encryptor(struct _sdk_encryptor *this) {
    if (this) {
        SAFE_FREE(this->__context);
        SAFE_FREE(this);
    }
}

void __register_key(struct _sdk_application *this,
					int key_id,
                    const sdk_blob *key) {
    if (this) {
        if (this->__context) {
            application_data *data = (application_data*)this->__context;

            if ((data->num_keys % 10) == 0) {
                data->keys = (encryptor_key*)realloc(data->keys,
                        sizeof(encryptor_key) * (data->num_keys + 10));
            }

			sdk_blob key_blob;
			key_blob.size = key->size;
			key_blob.data = (unsigned char*)malloc(key->size);
			memcpy(key_blob.data, key->data, key_blob.size);
			
			data->keys[data->num_keys].key = key_blob;
            data->keys[data->num_keys].key_id = key_id;

            data->num_keys++;
        }
    }
}

sdk_encryptor* __get_encryptor(struct _sdk_application *this) {
    if (this) {
        if (this->__context) {
            application_data *data = (application_data*)this->__context;
            return data->encryptor;
        }
    }

    return NULL;
}

void __release_application(struct _sdk_application *this) {
	int i = 0;
    if (this) {
        if (this->__context) {
            application_data *data = (application_data*)this->__context;			
			for (i = 0; i < data->num_keys; i++) {
				unsigned char *key_data = data->keys[i].key.data;
				SAFE_FREE(key_data);
			}

            SAFE_FREE(data->keys);
        }

        SAFE_FREE(this->__context);
        SAFE_FREE(this);
    }
}

sdk_application* __get_application(struct _sdk *this) {
    if (this) {
        if (this->__context) {
            sdk_data *data = (sdk_data*)this->__context;
            return data->application;
        }
    }

    return NULL;
}

void __release_sdk(struct _sdk *this) {
    if (this) {
        SAFE_FREE(this->__context);
        SAFE_FREE(this);
    }
}

int __is_sdk_loaded(struct _sdk * this)
{
	if (this) {
		if (this->__context) {
			sdk_data *data = (sdk_data*)this->__context;
			return data->loaded;
		}
	}

	return 0;
}

sdk* __load_sdk() {
    sdk_encryptor *lenc = (sdk_encryptor*)malloc(sizeof(sdk_encryptor));
    memset(lenc, 0, sizeof(sdk_encryptor));

    lenc->encrypt_file = __encrypt_file;
    lenc->encrypt_file_with_password = __encrypt_file_with_password;
    lenc->decrypt_file = __decrypt_file;
    lenc->decrypt_file_with_password = __decrypt_file_with_password;
    lenc->is_file_encrypted = __is_file_encrypted;
	lenc->is_file_encrypted_with_password = __is_file_encrypted_with_password;
    lenc->release = __release_encryptor;

    application_data *lapp_data = (application_data*)malloc(sizeof(application_data));
    memset(lapp_data, 0, sizeof(application_data));

    lapp_data->num_keys = 0;
    lapp_data->encryptor = lenc;

    sdk_application *lapp = (sdk_application*)malloc(sizeof(sdk_application));
    memset(lapp, 0, sizeof(sdk_application));

    lapp->__context = lapp_data;
    lapp->get_encryptor = __get_encryptor;
    lapp->register_key = __register_key;
    lapp->release = __release_application;

    encryptor_data *lenc_data = (encryptor_data*)malloc(sizeof(encryptor_data));
    lenc_data->application = lapp;
    lenc->__context = lenc_data;

    sdk_data *lsdk_data = (sdk_data*)malloc(sizeof(sdk_data));
    lsdk_data->application = lapp;
	lsdk_data->loaded = 1;

    sdk *lsdk = (sdk*)malloc(sizeof(sdk));
    lsdk->__context = lsdk_data;
	lsdk->is_sdk_loaded = __is_sdk_loaded;
    lsdk->get_application = __get_application;
    lsdk->release = __release_sdk;

    return lsdk;
}

void __unload_sdk(sdk *this) {
	if (this) {
		sdk_application *app = this->get_application(this);
		sdk_encryptor *enc = app->get_encryptor(app);

		enc->release(enc);
		app->release(app);
		this->release(this);
	}
}
