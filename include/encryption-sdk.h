#ifndef ENCRYPTION_SDK_LIBRARY_H
#define ENCRYPTION_SDK_LIBRARY_H

#ifdef _WIN32
	#ifdef BUILD_DLL
		#define DLL_EXPORT __declspec(dllexport)
	#else
		#define DLL_EXPORT
	#endif
#else
	#define DLL_EXPORT
#endif

#define SDK_ERROR_MSG_LEN 1024
#define SAFE_FREE(p) { if (p) { free(p); p = NULL; } }

typedef enum _sdk_error_type {
    sdk_error_type_unknown = -1,
    sdk_error_type_fatal = -2
} sdk_error_type;

typedef long sdk_error_code;

typedef struct _sdk_error {
    sdk_error_type error_type;
    sdk_error_code  error_code;
    char error_msg[SDK_ERROR_MSG_LEN];
} sdk_error;

typedef struct _sdk_blob {
    unsigned char *data;
    unsigned int size;
} sdk_blob;

typedef struct _sdk_encryptor {
    void *__context;

    long (*encrypt_file)(struct _sdk_encryptor *this,
                         int key_id,
                         const char *input_file,
                         const char *output_file,
                         sdk_error *error);

    long (*encrypt_file_with_password)(struct _sdk_encryptor *this,
                                       int key_id,
                                       const char *password,
                                       const char *input_file,
                                       const char *output_file,
                                       sdk_error *error);

    long (*decrypt_file)(struct _sdk_encryptor *this,
                         int key_id,
                         const char *input_file,
                         const char *output_file,
                         sdk_error *error);

    long (*decrypt_file_with_password)(struct _sdk_encryptor *this,
                                       const char *password,
                                       const char *input_file,
                                       const char *output_file,
                                       sdk_error *error);

    int (*is_file_encrypted)(struct _sdk_encryptor *this,
                             const char *file);

	int (*is_file_encrypted_with_password)(struct _sdk_encryptor *this, 
		                                   const char *file);

    void (*release)(struct _sdk_encryptor *this);
} sdk_encryptor;

typedef struct _sdk_application {
    void *__context;

    void (*register_key)(struct _sdk_application *this,
						 int key_id,
                         const sdk_blob *key);

    sdk_encryptor* (*get_encryptor)(struct _sdk_application *this);
    void (*release)(struct _sdk_application *this);
} sdk_application;

typedef struct _sdk {
    void *__context;

    sdk_application* (*get_application)(struct _sdk *this);
	int (*is_sdk_loaded)(struct _sdk *this);
    void (*release)(struct _sdk *this);
} sdk;

typedef int (*load_sdk_fptr)();
typedef void (*unload_sdk_fptr)();
typedef sdk* (*get_sdk_fptr)();

typedef int (*is_sdk_loaded_fptr)();
typedef void (*register_key_fptr)(int key_id, const char *key);

typedef int (*encrypt_file_fptr)(int key_id,
	const char *input_file,
	const char *output_file,
	char *error);

typedef int (*encrypt_file_with_password_fptr)(int key_id,
	const char *password,
	const char *input_file,
	const char *output_file,
	char *error);

typedef int (*decrypt_file_fptr)(int key_id,
	const char *input_file,
	const char *output_file,
	char *error);

typedef int (*decrypt_file_with_password_fptr)(const char *password,
	const char *input_file,
	const char *output_file,
	char *error);

typedef int (*is_file_encrypted_fptr)(const char *file);
typedef int (*is_file_encrypted_with_password_fptr)(const char *file);

#endif