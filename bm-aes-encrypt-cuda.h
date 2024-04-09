#ifndef _AES_ENCRYPT_CUDA_H
#define _AES_ENCRYPT_CUDA_H

#include <stdlib.h>
#include <utility>

std::pair<double, double> aes_encrypt_cuda_v0(unsigned char *plaintext,
                                              size_t dataSize,
                                              unsigned char *key,
                                              unsigned char *iv,
                                              unsigned char *ciphertext);

std::pair<double, double> aes_encrypt_cuda_v1(unsigned char *plaintext,
                                              size_t dataSize,
                                              unsigned char *key,
                                              unsigned char *iv,
                                              unsigned char *ciphertext);

std::pair<double, double> aes_encrypt_cuda_v2(unsigned char *plaintext,
                                              size_t dataSize,
                                              unsigned char *key,
                                              unsigned char *iv,
                                              unsigned char *ciphertext);

std::pair<double, double> aes_encrypt_cuda_v3_1(unsigned char *plaintext,
                                                size_t dataSize,
                                                unsigned char *key,
                                                unsigned char *iv,
                                                unsigned char *ciphertext);

std::pair<double, double> aes_encrypt_cuda_v3_2(unsigned char *plaintext,
                                                size_t dataSize,
                                                unsigned char *key,
                                                unsigned char *iv,
                                                unsigned char *ciphertext);

#endif // _AES_ENCRYPT_CUDA_H