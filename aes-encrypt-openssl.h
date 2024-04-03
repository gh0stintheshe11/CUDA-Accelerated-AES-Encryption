// To build and run:
// nvcc aes-encrypt-openssl.c utils.c -o aes-encrypt-openssl -lcrypto -lssl &&
// ./aes-encrypt-openssl
#ifndef _AES_ENCRYPT_OPENSSL_H
#define _AES_ENCRYPT_OPENSSL_H 1

#include "utils.h"
#include <openssl/evp.h>
#include <string.h>

double aes_encrypt_openssl(unsigned char *plaintext, int plaintext_len,
                           unsigned char *key, unsigned char *ivec,
                           unsigned char *ciphertext);

#endif // _AES_ENCRYPT_OPENSSL_H