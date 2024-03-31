#ifndef _UTILS_H
#define _UTILS_H 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

// Print bytes in hexadecimal format.
void print_hex(unsigned char *bytes, size_t length);

// Function to read key or IV from a file.
void read_key_or_iv(unsigned char *data, size_t size, const char *filename);

// Function to read binary from a file.
void read_file_as_binary(unsigned char **data, size_t *size, const char *filename);

// Function to write ciphertext to a file.
void write_ciphertext(const unsigned char *ciphertext, size_t size, const char *filename);

// Used in benchmarks.
double getTimeStampMs();

#endif // _UTILS_H