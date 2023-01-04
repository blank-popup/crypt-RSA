#include <stdio.h>

#include "crypt.h"


#define GENERATE_KEY_PAIR       "generate_key_pair"
#define ENCRYPT_PUBLIC          "encrypt_public"
#define DECRYPT_PRIVATE         "decrypt_private"
#define ENCRYPT_PRIVATE         "encrypt_private"
#define DECRYPT_PUBLIC          "decrypt_public"


void print_usage()
{
    fprintf(stdout, "Usage) cryptc.exe generate_key_pair 2048 private.pem public.pem\n");
    fprintf(stdout, "       cryptc.exe encrypt_public 2048 public.pem plain\n");
    fprintf(stdout, "       cryptc.exe decrypt_private 2048 private.pem crypt\n");
    fprintf(stdout, "       cryptc.exe encrypt_private 2048 private.pem plain\n");
    fprintf(stdout, "       cryptc.exe decrypt_public 2048 public.pem crypt\n");
}


int main(int argc, char* argv[])
{
    if (argc != 5) {
        print_usage();
    }

    for (int ii = 0; ii < (int)strlen(argv[2]); ++ii) {
        if ((argv[2][ii] < '0') || (argv[2][ii] > '9')) {
            fprintf(stderr, "Second parameter, count of bit must be integer. Ex) 1024, 2048\n");
            print_usage();
            return -1;
        }
    }

    int bits = atoi(argv[2]);
    int limit_length = bits / 8 - 11;

    for (int ii = 1; ii < argc; ++ii) {
        fprintf(stdout, "Parameter[%d]: [%s]\n", ii, argv[ii]);
    }

    unsigned char* crypt = malloc(bits);
    unsigned char* plain = malloc(bits);

    if (strcmp(GENERATE_KEY_PAIR, argv[1]) == 0) {
        mm_rsa_generate_pair_key_in_file(argv[3], argv[4], bits);
    }
    else if (strcmp(ENCRYPT_PUBLIC, argv[1]) == 0) {
        if ((int)strlen(argv[4]) > limit_length) {
            fprintf(stderr, "Length of fourth parameter, plain must be equal or less than %d\n", limit_length);
            free(crypt);
            free(plain);
            return -2;
        }
        if (crypt != NULL) {
            memset(crypt, 0x00, bits);
            if (mm_rsa_encrypt_public_with_key_file(crypt, argv[4], argv[3], bits) < 0) {
                mm_print_last_error("Failed to encrypt using public key");
            }
            fprintf(stdout, "Output: [%s], [%zu]\n", crypt, strlen(crypt));
        }
    }
    else if (strcmp(DECRYPT_PRIVATE, argv[1]) == 0) {
        if (plain != NULL) {
            memset(plain, 0x00, bits);
            if (mm_rsa_decrypt_private_with_key_file(plain, argv[4], argv[3], bits) < 0) {
                mm_print_last_error("Failed to decrypt using private key");
            }
            fprintf(stdout, "Output: [%s], [%zu]\n", plain, strlen(plain));
        }
    }
    else if (strcmp(ENCRYPT_PRIVATE, argv[1]) == 0) {
        if ((int)strlen(argv[4]) > limit_length) {
            fprintf(stderr, "Length of fourth parameter, plain must be equal or less than %d\n", limit_length);
            free(crypt);
            free(plain);
            return -3;
        }
        if (crypt != NULL) {
            memset(crypt, 0x00, bits);
            if (mm_rsa_encrypt_private_with_key_file(crypt, argv[4], argv[3], bits) < 0) {
                mm_print_last_error("Failed to encrypt using private key");
            }
            fprintf(stdout, "Output: [%s], [%zu]\n", crypt, strlen(crypt));
        }
    }
    else if (strcmp(DECRYPT_PUBLIC, argv[1]) == 0) {
        if (plain != NULL) {
            memset(plain, 0x00, bits);
            if (mm_rsa_decrypt_public_with_key_file(plain, argv[4], argv[3], bits) < 0) {
                mm_print_last_error("Failed to decrypt using public key");
            }
            fprintf(stdout, "Output: [%s], [%zu]\n", plain, strlen(plain));
        }
    }

    free(crypt);
    free(plain);

    return 0;
}
