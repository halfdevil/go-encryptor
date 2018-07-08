#ifndef ENCRYPTION_SDK_WRAPPER_LIBRARY_H
#define ENCRYPTION_SDK_WRAPPER_LIBRARY_H

#include "encryption-sdk.h"

DLL_EXPORT int load_sdk();
DLL_EXPORT void unload_sdk();

DLL_EXPORT sdk* get_sdk();

DLL_EXPORT int is_sdk_loaded();
DLL_EXPORT void register_key(int key_id, const char *key);

DLL_EXPORT int encrypt_file(int key_id,
	const char *input_file,
	const char *output_file,
	char *error);

DLL_EXPORT int encrypt_file_with_password(int key_id,
	const char *password,
	const char *input_file,
	const char *output_file,
	char *error);

DLL_EXPORT int decrypt_file(int key_id,
	const char *input_file,
	const char *output_file,
	char *error);

DLL_EXPORT int decrypt_file_with_password(const char *password,
	const char *input_file,
	const char *output_file,
	char *error);

DLL_EXPORT int is_file_encrypted(const char *file);
DLL_EXPORT int is_file_encrypted_with_password(const char *file);

#endif