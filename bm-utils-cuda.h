#ifndef UTILS_CUDA_H
#define UTILS_CUDA_H

#include <cstddef>
#include <cuda_runtime.h>
#include <iostream>
#include <string>

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

extern unsigned char h_sbox[256];
extern unsigned char h_rcon[11];

// Function to read key or IV from a file
void read_key_or_iv(unsigned char *data, size_t size, const char *filename);

// Function to read plaintext from a file
void read_file_as_binary(unsigned char **data, size_t *size, const char *filename);

void read_file_as_binary_v2(unsigned char **data, size_t *size, const char *filename);

// Function to write ciphertext to a file
void write_encrypted(const unsigned char *ciphertext, size_t size, const char *filename);

void write_encrypted_v2(unsigned char* ciphertext, size_t size, const char* filename);

void write_encrypted_multithreading(const unsigned char *ciphertext, size_t size, const char *filename); 

size_t preprocess(const char *filename, size_t chunkSize, unsigned char ***chunks, size_t **chunkSizes);

std::string getFileExtension(const std::string& filename);

void appendFileExtension(const std::string& filename, const std::string& extension);

void KeyExpansionHost(unsigned char *key, unsigned char *expandedKey);

__device__ void increment_counter(unsigned char *counter, int increment);

__device__ void aes_encrypt_block(unsigned char *input, unsigned char *output,
                                  unsigned char *expandedKey,
                                  unsigned char *d_sbox);

__device__ void aes_encrypt_block_v2(unsigned char *input, unsigned char *output,
                                  unsigned char *expandedKey,
                                  unsigned char *d_sbox);

#endif // UTILS_CUDA_H