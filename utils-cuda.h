#ifndef UTILS_CUDA_H
#define UTILS_CUDA_H

#include <cuda_runtime.h>

// Used by cuda v0, v1, v2, v3.
extern unsigned char h_sbox[256];
extern unsigned char h_rcon[11];

// Used by cuda v0, v1, v2.
void KeyExpansionHost(unsigned char *key, unsigned char *expandedKey);

// Used by cuda v3.
void KeyExpansionHost_v2(unsigned char *key, unsigned char *expandedKey);

// Used by cuda v0, v1, v2.
__device__ void aes_encrypt_block(unsigned char *input, unsigned char *output,
                                  unsigned char *expandedKey,
                                  unsigned char *d_sbox);

// Used by cuda v3.
__device__ void aes_encrypt_block_v2(unsigned char *input, unsigned char *output,
                                  unsigned char *expandedKey,
                                  unsigned char *d_sbox);

// Host function to copy the IV and expanded key to constant memory
// Used by cuda v1, v2, v3.
void copyToConstantMemory(unsigned char *constantIv, unsigned char *iv,
                          unsigned char *constantExpandedKey,
                          unsigned char *expandedKey);

#endif // UTILS_CUDA_H