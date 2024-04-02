#ifndef UTILS_CUDA_H
#define UTILS_CUDA_H

#include <cstddef>

extern unsigned char h_sbox[256];
extern unsigned char h_rcon[11];

// Function to read key or IV from a file
void read_key_or_iv(unsigned char *data, size_t size, const char *filename);

// Function to read plaintext from a file
void read_file_as_binary(unsigned char **data, size_t *size, const char *filename);

// Function to write ciphertext to a file
void write_encrypted(const unsigned char *ciphertext, size_t size, const char *filename);

void write_encrypted_multithreading(const unsigned char *ciphertext, size_t size, const char *filename);

size_t preprocess(const char *filename, size_t chunkSize, unsigned char ***chunks, size_t **chunkSizes);

#endif // UTILS_CUDA_H