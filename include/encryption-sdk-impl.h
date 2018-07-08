//
// Created by Jiten Sharma on 06/07/18.
//

#ifndef ENCRYPTION_SDK_ENCRYPTION_SDK_IMPL_H
#define ENCRYPTION_SDK_ENCRYPTION_SDK_IMPL_H

#include "encryption-sdk.h"
#define SDK_SIGNATURE 0x1482

typedef struct _encrypted_file_header {
    unsigned int signature;
    unsigned int password_file;
    unsigned int key_id;
    unsigned char iv[16];
    unsigned char enterprise_key[48];
    unsigned int enterprise_key_len;
    unsigned char password_key[48];
    unsigned int password_key_len;
    unsigned char file_hash[32];
} encrypted_file_header;

typedef struct _encryptor_key {
    int key_id;
    sdk_blob key;
} encryptor_key;

typedef struct _encryptor_data {
    sdk_application *application;
} encryptor_data;

typedef struct _application_data {
    encryptor_key *keys;
    int num_keys;
    sdk_encryptor *encryptor;
} application_data;

typedef struct _sdk_data {
	int loaded;
    sdk_application *application;
} sdk_data;

long __encrypt_file(struct _sdk_encryptor *this,
                  int key_id,
                  const char *input_file,
                  const char *output_file,
                  sdk_error *error);

long __encrypt_file_with_password(struct _sdk_encryptor *this,
                                int key_id,
                                const char *password,
                                const char *input_file,
                                const char *output_file,
                                sdk_error *error);

long __decrypt_file(struct _sdk_encryptor *this,
                  int key_id,
                  const char *input_file,
                  const char *output_file,
                  sdk_error *error);

long __decrypt_file_with_password(struct _sdk_encryptor *this,
                                const char *password,
                                const char *input_file,
                                const char *output_file,
                                sdk_error *error);

int __is_file_encrypted(struct _sdk_encryptor *this,
                      const char *file);

int __is_file_encrypted_with_password(struct _sdk_encryptor *this,
									const char *file);

void __release_encryptor(struct _sdk_encryptor *this);
void __register_key(struct _sdk_application *this,
				  int key_id,
                  const sdk_blob *key);

sdk_encryptor* __get_encryptor(struct _sdk_application *this);
void __release_application(struct _sdk_application *this);

sdk_application* __get_application(struct _sdk *this);
void __release_sdk(struct _sdk *this);

int __is_sdk_loaded(struct _sdk *this);

sdk* __load_sdk();
void __unload_sdk(sdk *this);

#endif //ENCRYPTION_SDK_ENCRYPTION_SDK_IMPL_H
