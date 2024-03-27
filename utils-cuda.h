#ifndef UTILS_CUDA_H
#define UTILS_CUDA_H

#include <cstddef>

extern unsigned char h_sbox[256];
extern unsigned char h_rcon[11];

// Print bytes in hexadecimal format
void print_hex(unsigned char *bytes, size_t length);

// Function to read key or IV from a file
void read_key_or_iv(unsigned char *data, size_t size, const char *filename);

// Function to read plaintext from a file
void read_plaintext(unsigned char **plaintext, size_t *size, const char *filename);

// Function to write ciphertext to a file
void write_ciphertext(const unsigned char *ciphertext, size_t size, const char *filename);

#endif // UTILS_CUDA_H