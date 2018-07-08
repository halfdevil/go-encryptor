
#include "encryption-sdk-wrapper.h"
#include "encryption-sdk-impl.h"
#include "encryption-lib.h"
#include <string.h>

sdk *g_sdk = NULL;

int load_sdk()
{
	if (!g_sdk)
		g_sdk = __load_sdk();

	return g_sdk->is_sdk_loaded(g_sdk);
}

void unload_sdk()
{
	if (g_sdk) {
		__unload_sdk(g_sdk);
		g_sdk = NULL;
	}
}

sdk* get_sdk()
{
	if (g_sdk && g_sdk->is_sdk_loaded(g_sdk))
		return g_sdk;

	return NULL;
}

int is_sdk_loaded()
{
	if (g_sdk)
		return g_sdk->is_sdk_loaded(g_sdk);

	return 0;
}

void register_key(int key_id, const char * key)
{
	unsigned char hash[32];

	if (!is_sdk_loaded())
		return;
		
	data_generate_sha256(key, hash);
	
	sdk_blob key_blob;
	key_blob.data = hash;
	key_blob.size = 32;

	sdk_application *app = g_sdk->get_application(g_sdk);
	app->register_key(app, key_id, &key_blob);
}

int encrypt_file(int key_id, const char * input_file, 
	const char * output_file, char * error)
{
	if (!is_sdk_loaded())
		return -1;

	sdk_application *app = g_sdk->get_application(g_sdk);
	sdk_encryptor *enc = app->get_encryptor(app);

	sdk_error err;
	if (enc->encrypt_file(enc, key_id, input_file, output_file, &err) != 0) {
		strcpy(error, err.error_msg);
		return -2;
	}

	return 0;
}

int encrypt_file_with_password(int key_id, const char * password, const char * input_file, 
	const char * output_file, char * error)
{
	if (!is_sdk_loaded())
		return -1;

	sdk_application *app = g_sdk->get_application(g_sdk);
	sdk_encryptor *enc = app->get_encryptor(app);

	sdk_error err;
	if (enc->encrypt_file_with_password(enc, key_id, password, input_file, output_file, &err) != 0) {
		strcpy(error, err.error_msg);
		return -2;
	}

	return 0;
}

int decrypt_file(int key_id, const char * input_file, 
	const char * output_file, char * error)
{
	if (!is_sdk_loaded())
		return -1;

	sdk_application *app = g_sdk->get_application(g_sdk);
	sdk_encryptor *enc = app->get_encryptor(app);

	sdk_error err;
	if (enc->decrypt_file(enc, key_id, input_file, output_file, &err) != 0) {
		strcpy(error, err.error_msg);
		return -2;
	}

	return 0;
}

int decrypt_file_with_password(const char * password, const char * input_file, 
	const char * output_file, char * error)
{
	if (!is_sdk_loaded())
		return -1;

	sdk_application *app = g_sdk->get_application(g_sdk);
	sdk_encryptor *enc = app->get_encryptor(app);

	sdk_error err;
	if (enc->decrypt_file_with_password(enc, password, input_file, output_file, &err) != 0) {
		strcpy(error, err.error_msg);
		return -2;
	}

	return 0;
}

int is_file_encrypted(const char * file)
{
	if (!is_sdk_loaded())
		return -1;

	sdk_application *app = g_sdk->get_application(g_sdk);
	sdk_encryptor *enc = app->get_encryptor(app);

	return enc->is_file_encrypted(enc, file);
}

int is_file_encrypted_with_password(const char * file)
{
	if (!is_sdk_loaded())
		return -1;

	sdk_application *app = g_sdk->get_application(g_sdk);
	sdk_encryptor *enc = app->get_encryptor(app);

	return enc->is_file_encrypted_with_password(enc, file);
}

