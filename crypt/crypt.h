#ifdef CRYPT_EXPORTS
#define CRYPT_RSA __declspec(dllexport)
#else
#define CRYPT_RSA __declspec(dllimport)
#endif


#pragma warning(disable:4996)

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define ERR_SUCCESS                         (0)

#define ERR_ALREADY_SET_PRIVATE_BIO         (-1)
#define ERR_ALREADY_SET_PRIVATE_RSA         (-2)
#define ERR_FAIL_TO_SET_PRIVATE_BIO         (-3)
#define ERR_FAIL_TO_SET_PRIVATE_RSA         (-4)
#define ERR_ALREADY_SET_PUBLIC_BIO          (-5)
#define ERR_ALREADY_SET_PUBLIC_RSA          (-6)
#define ERR_FAIL_TO_SET_PUBLIC_BIO          (-7)
#define ERR_FAIL_TO_SET_PUBLIC_RSA          (-8)
#define ERR_BITS_MUST_BE_POSITIVE           (-9)

#define ERR_CANNOT_OPEN_FILE                (-10)

#define ERR_MUST_BE_NOT_NULL                (-11)
#define ERR_MUST_BE_MULTIPLES_OF_4          (-12)
#define ERR_MUST_BE_BASE64                  (-13)

#define ERR_LENGTH_OF_STRING                (130)

#ifdef __cplusplus
extern "C" {
#endif

    CRYPT_RSA size_t mm_get_size_file(const char* _filepath);
    CRYPT_RSA int mm_write_binary_file(const char* _filepath, unsigned char* _binary, size_t _length);
    CRYPT_RSA int mm_read_binary_file(unsigned char* _binary, size_t _length, const char* _filepath);
    CRYPT_RSA int mm_write_text_file(const char* _filepath, unsigned char* _text, size_t _length);
    CRYPT_RSA int mm_read_text_file(unsigned char* _text, size_t _length, const char* _filepath);

    CRYPT_RSA void mm_rsa_generate_pair_key_in_string(unsigned char* _private_key, char* _public_key, int _bits);
    CRYPT_RSA void mm_rsa_generate_pair_key_in_file(char* _filepath_private_key, char* _filepath_public_key, int _bits);

    CRYPT_RSA int mm_rsa_encrypt_public_with_key_string(unsigned char* _crypt, unsigned char* _plain, unsigned char* _key, int _bits);
    CRYPT_RSA int mm_rsa_decrypt_private_with_key_string(unsigned char* _plain, unsigned char* _crypt, unsigned char* _key, int _bits);
    CRYPT_RSA int mm_rsa_encrypt_private_with_key_string(unsigned char* _crypt, unsigned char* _plain, unsigned char* _key, int _bits);
    CRYPT_RSA int mm_rsa_decrypt_public_with_key_string(unsigned char* _plain, unsigned char* _crypt, unsigned char* _key, int _bits);
    CRYPT_RSA int mm_rsa_encrypt_public_with_key_file(unsigned char* _crypt, unsigned char* _plain, const char* _filepath_key, int _bits);
    CRYPT_RSA int mm_rsa_decrypt_private_with_key_file(unsigned char* _plain, unsigned char* _crypt, const char* _filepath_key, int _bits);
    CRYPT_RSA int mm_rsa_encrypt_private_with_key_file(unsigned char* _crypt, unsigned char* _plain, const char* _filepath_key, int _bits);
    CRYPT_RSA int mm_rsa_decrypt_public_with_key_file(unsigned char* _plain, unsigned char* _crypt, const char* _filepath_key, int _bits);

    CRYPT_RSA void mm_print_last_error(const char* _msg);

#ifdef __cplusplus
}
#endif
