#ifndef _UTILS_H
#define _UTILS_H 1

#include <stdio.h>

// Function to read key or IV from a file
void read_key_or_iv(unsigned char *data, size_t size, const char *filename);

// Function to read plaintext from a file
void read_plaintext(unsigned char *plaintext, size_t size,
                    const char *filename);

// Function to write ciphertext to a file
void write_ciphertext(const unsigned char *ciphertext, size_t size,
                      const char *filename);

#endif // _UTILS_H