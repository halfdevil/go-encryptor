
#include "encryption-sdk-wrapper.h"
#include <stdio.h>
#include <openssl/sha.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef _WIN32
#define TEST_FOLDER "test\\"
#else
#define TEST_FOLDER "test/"
#endif

void* load_dll(const char *dll_path) {
	void *handle = NULL;

#ifdef _WIN32
	handle = LoadLibraryA(dll_path);
#endif

	return handle;
}

void* get_func_ptr(void *handle, const char *func) {
	load_sdk_fptr fptr = NULL;

#ifdef _WIN32
	fptr = (load_sdk_fptr)GetProcAddress(handle, func);
#endif

	return fptr;
}

int generate_sha256(const char *data, unsigned char *hash) {
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

int main() {
	load_sdk_fptr load_sdk;
	get_sdk_fptr get_sdk;

	sdk *lsdk;
	sdk_application *lapp;
	sdk_encryptor *lenc;
	sdk_error lerr;

	void *handle = load_dll("../encryption-sdk/Debug/encryption-sdk.dll");
	if (!handle) {
		printf("Unable to load dll");
		return -1;
	}

	load_sdk = (load_sdk_fptr)get_func_ptr(handle, "load_sdk");
	if (!load_sdk) {
		printf("Unable to get load_sdk function ptr");
		return -2;
	}

	if (!load_sdk()) {
		printf("Unable to load sdk");
		return -3;
	}

	get_sdk = (get_sdk_fptr)get_func_ptr(handle, "get_sdk");
	if (!get_sdk) {
		printf("Unable to get get_sdk function ptr");
		return -4;
	}

	lsdk = get_sdk();
	if (!lsdk) {
		printf("get_sdk failed");
		return -5;
	}

	lapp = lsdk->get_application(lsdk);
	lenc = lapp->get_encryptor(lapp);

	unsigned char enterprise_key[32];
	int key_id = 999;

	if (generate_sha256("ENTERPRISE_KEY", enterprise_key) != 0) {
		printf("Unable to generate enterprise key");
		return -6;
	}

	sdk_blob key_blob;
	key_blob.size = sizeof(enterprise_key);
	key_blob.data = enterprise_key;

	lapp->register_key(lapp, key_id, &key_blob);
	lenc->encrypt_file_with_password(lenc, key_id, "PASSWORD", TEST_FOLDER "part1.zip", TEST_FOLDER "part1.zip.enc", &lerr);
	lenc->decrypt_file_with_password(lenc, "PASSWORD1", TEST_FOLDER "part1.zip.enc", TEST_FOLDER "part1_new.zip", &lerr);

	lenc->release(lenc);
	lapp->release(lapp);
	lsdk->release(lsdk);

	return 0;
}