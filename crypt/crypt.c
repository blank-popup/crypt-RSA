#include <stdio.h>
#include <stdint.h>

#include "crypt.h"


int write_file_mode(const char* _filepath, unsigned char* _binary, size_t _length, const char* _mode)
{
    if (_binary == NULL) {
        fprintf(stderr, "Binary cannot be null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    if (_mode == NULL) {
        fprintf(stderr, "Writing mode cannot be null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    FILE* fp = fopen(_filepath, _mode);
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file[%s] for writing\n", _filepath);
        return ERR_CANNOT_OPEN_FILE;
    }

    fwrite(_binary, sizeof(unsigned char), _length, fp);

    fclose(fp);

    return ERR_SUCCESS;
}

int read_file_mode(unsigned char* _binary, size_t _length, const char* _filepath, const char* _mode)
{
    if (_binary == NULL) {
        fprintf(stderr, "Reading buffer cannot be null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    if (_mode == NULL) {
        fprintf(stderr, "Reading mode cannot be null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    FILE* fp = fopen(_filepath, _mode);
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file[%s] for reading\n", _filepath);
        return ERR_CANNOT_OPEN_FILE;
    }

    fread(_binary, sizeof(unsigned char), _length, fp);

    fclose(fp);

    return ERR_SUCCESS;
}

size_t mm_get_size_file(const char* _filepath)
{
    FILE* fp = fopen(_filepath, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file[%s] for checking size\n", _filepath);
        return ERR_CANNOT_OPEN_FILE;
    }

    fseek(fp, 0L, SEEK_END);
    size_t size = ftell(fp);

    return size;
}

int mm_write_binary_file(const char* _filepath, unsigned char* _binary, size_t _length)
{
    return write_file_mode(_filepath, _binary, _length, "wb");
}

int mm_read_binary_file(unsigned char* _binary, size_t _length, const char* _filepath)
{
    return read_file_mode(_binary, _length, _filepath, "rb");
}

int mm_write_text_file(const char* _filepath, unsigned char* _text, size_t _length)
{
    return write_file_mode(_filepath, _text, _length, "w");
}

int mm_read_text_file(unsigned char* _text, size_t _length, const char* _filepath)
{
    return read_file_mode(_text, _length, _filepath, "r");
}


typedef struct _rsa_crypt_param {
    BIO* bio;
    RSA* rsa;
    int padding;
} rsa_crypt_param;


void mm_rsa_generate_pair_key_in_string(unsigned char* _private_key, char* _public_key, int _bits)
{
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);

    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, _bits, bne, NULL);

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    BIO* bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL);
    BIO* bio_public = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_public, pkey);

    int length_private = BIO_pending(bio_private);
    int length_public = BIO_pending(bio_public);

    BIO_read(bio_private, _private_key, length_private);
    _private_key[length_private] = '\0';
    BIO_read(bio_public, _public_key, length_public);
    _public_key[length_public] = '\0';

    BIO_free_all(bio_private);
    BIO_free_all(bio_public);
    EVP_PKEY_free(pkey);
}

void mm_rsa_generate_pair_key_in_file(char* _filepath_private_key, char* _filepath_public_key, int _bits)
{
    unsigned char* private_key = (unsigned char*)malloc(_bits);
    if (private_key == NULL) {
        return;
    }
    memset(private_key, 0x00, _bits);
    unsigned char* public_key = (unsigned char*)malloc(_bits);
    if (public_key == NULL) {
        free(private_key);
        return;
    }
    memset(public_key, 0x00, _bits);

    mm_rsa_generate_pair_key_in_string(private_key, public_key, _bits);
    if (private_key != NULL) {
        mm_write_binary_file(_filepath_private_key, private_key, strlen(private_key));
        free(private_key);
    }
    if (public_key != NULL) {
        mm_write_binary_file(_filepath_public_key, public_key, strlen(public_key));
        free(public_key);
    }
}


int rsa_set_crypt_param_private(rsa_crypt_param* _param, unsigned char* _key)
{
    if (_param->bio != NULL) {
        fprintf(stderr, "Set bio for private key already\n");
        return ERR_ALREADY_SET_PRIVATE_BIO;
    }
    if (_param->rsa != NULL) {
        fprintf(stderr, "Set rsa for private key already\n");
        return ERR_ALREADY_SET_PRIVATE_RSA;
    }

    _param->bio = BIO_new_mem_buf(_key, -1);
    if (_param->bio == NULL) {
        fprintf(stderr, "Failed to create private key BIO\n");
        return ERR_FAIL_TO_SET_PRIVATE_BIO;
    }

    _param->rsa = PEM_read_bio_RSAPrivateKey(_param->bio, &_param->rsa, NULL, NULL);
    if (_param->rsa == NULL) {
        fprintf(stderr, "Failed to create private RSA\n");
        return ERR_FAIL_TO_SET_PRIVATE_RSA;
    }

    _param->padding = RSA_PKCS1_PADDING;

    return ERR_SUCCESS;
}

int rsa_set_crypt_param_public(rsa_crypt_param* _param, unsigned char* _key)
{
    if (_param->bio != NULL) {
        fprintf(stderr, "Set bio for public key already\n");
        return ERR_ALREADY_SET_PUBLIC_BIO;
    }
    if (_param->rsa != NULL) {
        fprintf(stderr, "Set rsa for public key already\n");
        return ERR_ALREADY_SET_PUBLIC_RSA;
    }

    _param->bio = BIO_new_mem_buf(_key, -1);
    if (_param->bio == NULL) {
        fprintf(stderr, "Failed to create public key BIO\n");
        return ERR_FAIL_TO_SET_PUBLIC_BIO;
    }

    _param->rsa = PEM_read_bio_RSA_PUBKEY(_param->bio, &_param->rsa, NULL, NULL);
    if (_param->rsa == NULL) {
        fprintf(stderr, "Failed to create public RSA\n");
        return ERR_FAIL_TO_SET_PUBLIC_RSA;
    }

    _param->padding = RSA_PKCS1_PADDING;

    return ERR_SUCCESS;
}

void rsa_free_crypt_param(rsa_crypt_param _param)
{
    if (_param.rsa != NULL) {
        RSA_free(_param.rsa);
    }
    if (_param.bio != NULL) {
        BIO_free_all(_param.bio);
    }
}


int rsa_encrypt_plain_to_binary_with_public_key(unsigned char* _crypt, unsigned char* _plain, int _length, unsigned char* _key)
{
    rsa_crypt_param param = { 0 };
    if (rsa_set_crypt_param_public(&param, _key) < 0) {
        rsa_free_crypt_param(param);
        return -1;
    }

    int size = RSA_public_encrypt(_length, _plain, _crypt, param.rsa, param.padding);
    rsa_free_crypt_param(param);

    return size;
}

int rsa_decrypt_binary_to_plain_with_private_key(unsigned char* _plain, unsigned char* _crypt, int _length, unsigned char* _key)
{
    rsa_crypt_param param = { 0 };
    if (rsa_set_crypt_param_private(&param, _key) < 0) {
        rsa_free_crypt_param(param);
        return -1;
    }

    int size = RSA_private_decrypt(_length, _crypt, _plain, param.rsa, param.padding);
    rsa_free_crypt_param(param);

    return size;
}

int rsa_encrypt_plain_to_binary_with_private_key(unsigned char* _crypt, unsigned char* _plain, int _length, unsigned char* _key)
{
    rsa_crypt_param param = { 0 };
    if (rsa_set_crypt_param_private(&param, _key) < 0) {
        rsa_free_crypt_param(param);
        return -1;
    }

    int size = RSA_private_encrypt(_length, _plain, _crypt, param.rsa, param.padding);
    rsa_free_crypt_param(param);

    return size;
}

int rsa_decrypt_binary_to_plain_with_public_key(unsigned char* _plain, unsigned char* _crypt, int _length, unsigned char* _key)
{
    rsa_crypt_param param = { 0 };
    if (rsa_set_crypt_param_public(&param, _key) < 0) {
        rsa_free_crypt_param(param);
        return -1;
    }

    int size = RSA_public_decrypt(_length, _crypt, _plain, param.rsa, param.padding);
    rsa_free_crypt_param(param);

    return size;
}


const static char table_encoding[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

const static unsigned char table_decoding[] = {
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   62,  0,   0,   0,   63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  0,   0,   0,   0,   0,   0,
    0,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  0,   0,   0,   0,   0,
    0,   26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0
};

int base64_encode(char* _target, const unsigned char* _source, int _length)
{
    if (_target == NULL) {
        return ERR_MUST_BE_NOT_NULL;
    }

    int mod_table[] = { 0, 2, 1 };
    int length = 4 * ((_length + 2) / 3);

    for (int ii = 0, jj = 0; ii < _length;) {

        uint32_t octet_a = ii < _length ? (unsigned char)_source[ii++] : 0;
        uint32_t octet_b = ii < _length ? (unsigned char)_source[ii++] : 0;
        uint32_t octet_c = ii < _length ? (unsigned char)_source[ii++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        _target[jj++] = table_encoding[(triple >> 3 * 6) & 0x3F];
        _target[jj++] = table_encoding[(triple >> 2 * 6) & 0x3F];
        _target[jj++] = table_encoding[(triple >> 1 * 6) & 0x3F];
        _target[jj++] = table_encoding[(triple >> 0 * 6) & 0x3F];
    }

    for (int ii = 0; ii < mod_table[_length % 3]; ++ii)
        _target[length - 1 - ii] = '=';

    return length;
}

int base64_decode(unsigned char* _target, const char* _source, int _length)
{
    if (_target == NULL) {
        return ERR_MUST_BE_NOT_NULL;
    }
    if (_length % 4 != 0) {
        return ERR_MUST_BE_MULTIPLES_OF_4;
    }
    for (int ii = 0; ii < _length; ++ii) {
        if ('A' <= _source[ii] && _source[ii] <= 'Z') continue;
        if ('a' <= _source[ii] && _source[ii] <= 'z') continue;
        if ('0' <= _source[ii] && _source[ii] <= '9') continue;
        if (_source[ii] == table_encoding[62] || _source[ii] == table_encoding[63]) continue;
        if (_source[ii] == '=' && (ii == _length - 2 || ii == _length - 1)) continue;
        return ERR_MUST_BE_BASE64;
    }

    int length = _length / 4 * 3;
    if (_source[_length - 1] == '=') length--;
    if (_source[_length - 2] == '=') length--;

    for (int ii = 0, jj = 0; ii < _length;) {
        uint32_t sextet_a = _source[ii] == '=' ? 0 & ii++ : table_decoding[_source[ii++]];
        uint32_t sextet_b = _source[ii] == '=' ? 0 & ii++ : table_decoding[_source[ii++]];
        uint32_t sextet_c = _source[ii] == '=' ? 0 & ii++ : table_decoding[_source[ii++]];
        uint32_t sextet_d = _source[ii] == '=' ? 0 & ii++ : table_decoding[_source[ii++]];

        uint32_t triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (jj < length) _target[jj++] = (triple >> 2 * 8) & 0xFF;
        if (jj < length) _target[jj++] = (triple >> 1 * 8) & 0xFF;
        if (jj < length) _target[jj++] = (triple >> 0 * 8) & 0xFF;
    }

    return length;
}


int mm_rsa_encrypt_public_with_key_string(unsigned char* _crypt, unsigned char* _plain, unsigned char* _key, int _bits)
{
    if (_bits <= 0) {
        fprintf(stderr, "Bits must be positive\n");
        return ERR_BITS_MUST_BE_POSITIVE;
    }

    unsigned char* crypt_binary = (unsigned char*)malloc(_bits);
    if (crypt_binary == NULL) {
        fprintf(stderr, "Crypt binary must be not null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    memset(crypt_binary, 0x00, _bits);

    int length = rsa_encrypt_plain_to_binary_with_public_key(crypt_binary, _plain, (int)strlen(_plain), _key);
    if (length > 0) {
        length = base64_encode(_crypt, crypt_binary, length);
    }
    free(crypt_binary);

    return length;
}

int mm_rsa_decrypt_private_with_key_string(unsigned char* _plain, unsigned char* _crypt, unsigned char* _key, int _bits)
{
    if (_bits <= 0) {
        fprintf(stderr, "Bits must be positive\n");
        return ERR_BITS_MUST_BE_POSITIVE;
    }

    unsigned char* crypt_binary = (unsigned char*)malloc(_bits);
    if (crypt_binary == NULL) {
        fprintf(stderr, "Crypt binary must be not null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    memset(crypt_binary, 0x00, _bits);

    int length = base64_decode(crypt_binary, _crypt, (int)strlen(_crypt));
    if (length > 0) {
        length = rsa_decrypt_binary_to_plain_with_private_key(_plain, crypt_binary, length, _key);
    }
    free(crypt_binary);

    return length;
}

int mm_rsa_encrypt_private_with_key_string(unsigned char* _crypt, unsigned char* _plain, unsigned char* _key, int _bits)
{
    if (_bits <= 0) {
        fprintf(stderr, "Bits must be positive\n");
        return ERR_BITS_MUST_BE_POSITIVE;
    }

    unsigned char* crypt_binary = (unsigned char*)malloc(_bits);
    if (crypt_binary == NULL) {
        fprintf(stderr, "Crypt binary must be not null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    memset(crypt_binary, 0x00, _bits);

    int length = rsa_encrypt_plain_to_binary_with_private_key(crypt_binary, _plain, (int)strlen(_plain), _key);
    if (length > 0) {
        length = base64_encode(_crypt, crypt_binary, length);
    }
    free(crypt_binary);

    return length;
}

int mm_rsa_decrypt_public_with_key_string(unsigned char* _plain, unsigned char* _crypt, unsigned char* _key, int _bits)
{
    if (_bits <= 0) {
        fprintf(stderr, "Bits must be positive\n");
        return ERR_BITS_MUST_BE_POSITIVE;
    }

    unsigned char* crypt_binary = (unsigned char*)malloc(_bits);
    if (crypt_binary == NULL) {
        fprintf(stderr, "Crypt binary must be not null\n");
        return ERR_MUST_BE_NOT_NULL;
    }
    memset(crypt_binary, 0x00, _bits);

    int length = base64_decode(crypt_binary, _crypt, (int)strlen(_crypt));
    if (length > 0) {
        length = rsa_decrypt_binary_to_plain_with_public_key(_plain, crypt_binary, length, _key);
    }
    free(crypt_binary);

    return length;
}

int mm_rsa_encrypt_public_with_key_file(unsigned char* _crypt, unsigned char* _plain, const char* _filepath_key, int _bits)
{
    unsigned char* key = (unsigned char*)malloc(_bits);
    int rv = mm_read_binary_file(key, _bits, _filepath_key);
    if (rv < ERR_SUCCESS) {
        return rv;
    }
    rv = mm_rsa_encrypt_public_with_key_string(_crypt, _plain, key, _bits);
    free(key);

    return rv;
}

int mm_rsa_decrypt_private_with_key_file(unsigned char* _plain, unsigned char* _crypt, const char* _filepath_key, int _bits)
{
    unsigned char* key = (unsigned char*)malloc(_bits);
    int rv = mm_read_binary_file(key, _bits, _filepath_key);
    if (rv < ERR_SUCCESS) {
        return rv;
    }
    rv = mm_rsa_decrypt_private_with_key_string(_plain, _crypt, key, _bits);
    free(key);

    return rv;
}

int mm_rsa_encrypt_private_with_key_file(unsigned char* _crypt, unsigned char* _plain, const char* _filepath_key, int _bits)
{
    unsigned char* key = (unsigned char*)malloc(_bits);
    int rv = mm_read_binary_file(key, _bits, _filepath_key);
    if (rv < ERR_SUCCESS) {
        return rv;
    }
    rv = mm_rsa_encrypt_private_with_key_string(_crypt, _plain, key, _bits);
    free(key);

    return rv;
}

int mm_rsa_decrypt_public_with_key_file(unsigned char* _plain, unsigned char* _crypt, const char* _filepath_key, int _bits)
{
    unsigned char* key = (unsigned char*)malloc(_bits);
    int rv = mm_read_binary_file(key, _bits, _filepath_key);
    if (rv < ERR_SUCCESS) {
        return rv;
    }
    rv = mm_rsa_decrypt_public_with_key_string(_plain, _crypt, key, _bits);
    free(key);

    return rv;
}


void mm_print_last_error(const char* _msg)
{
    char* err = malloc(ERR_LENGTH_OF_STRING);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr, "[%s] ERROR: [%s]\n", _msg, err);
    free(err);
}
