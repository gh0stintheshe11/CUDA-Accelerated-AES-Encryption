#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>
#include <string.h>

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

// Expected output: 
// 0a 85 29 86 05 3b 96 32 79 5a 3e e3 0a 8e 04 a5

// Define plaintext: 
// 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
unsigned char plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

// Define key for AES-128: 
// 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
unsigned char key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Define IV for AES-CTR: 
// 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
unsigned char iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Print bytes in hexadecimal format
void print_hex(unsigned char *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

unsigned char h_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned char h_rcon[11] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

__constant__ unsigned char d_sbox[256];
__constant__ unsigned char d_rcon[11];

__device__ unsigned char mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char high_bit_mask = 0x80;
    unsigned char high_bit = 0;
    unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }

        high_bit = a & high_bit_mask;
        a <<= 1;
        if (high_bit) {
            a ^= modulo;
        }
        b >>= 1;
    }

    return p;
}

void KeyExpansionHost(unsigned char* key, unsigned char* expandedKey) {
    int i = 0;
    while (i < 4) {
        for (int j = 0; j < 4; j++) {
            expandedKey[i * 4 + j] = key[i * 4 + j];
        }
        i++;
    }

    int rconIteration = 1;
    unsigned char temp[4];

    while (i < 44) {
        for (int j = 0; j < 4; j++) {
            temp[j] = expandedKey[(i - 1) * 4 + j];
        }

        if (i % 4 == 0) {
            unsigned char k = temp[0];
            for (int j = 0; j < 3; j++) {
                temp[j] = temp[j + 1];
            }
            temp[3] = k;

            for (int j = 0; j < 4; j++) {
                // Use the host-accessible arrays
                temp[j] = h_sbox[temp[j]] ^ (j == 0 ? h_rcon[rconIteration++] : 0);
            }
        }

        for (int j = 0; j < 4; j++) {
            expandedKey[i * 4 + j] = expandedKey[(i - 4) * 4 + j] ^ temp[j];
        }
        i++;
    }
}

__device__ void SubBytes(unsigned char *state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = d_sbox[state[i]];
    }
}

__device__ void ShiftRows(unsigned char *state) {
    unsigned char tmp[16];

    /* Column 1 */
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];
    /* Column 2 */
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];
    /* Column 3 */
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];
    /* Column 4 */
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    memcpy(state, tmp, 16);
}

__device__ void MixColumns(unsigned char *state) {
    unsigned char tmp[16];

    for (int i = 0; i < 4; ++i) {
        tmp[i*4] = (unsigned char)(mul(0x02, state[i*4]) ^ mul(0x03, state[i*4+1]) ^ state[i*4+2] ^ state[i*4+3]);
        tmp[i*4+1] = (unsigned char)(state[i*4] ^ mul(0x02, state[i*4+1]) ^ mul(0x03, state[i*4+2]) ^ state[i*4+3]);
        tmp[i*4+2] = (unsigned char)(state[i*4] ^ state[i*4+1] ^ mul(0x02, state[i*4+2]) ^ mul(0x03, state[i*4+3]));
        tmp[i*4+3] = (unsigned char)(mul(0x03, state[i*4]) ^ state[i*4+1] ^ state[i*4+2] ^ mul(0x02, state[i*4+3]));
    }

    memcpy(state, tmp, 16);
}

__device__ void AddRoundKey(unsigned char *state, const unsigned char *roundKey) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= roundKey[i];
    }
}

__global__ void aes_ctr_encrypt_kernel(unsigned char *input, unsigned char *output, unsigned char *expandedKey, unsigned char *iv, unsigned long long nonceCounter) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Assuming each thread processes one block of data
    if (idx < AES_BLOCK_SIZE) { // This condition seems off; you'd typically compare idx against the total number of blocks or data size
        unsigned char state[16];
        unsigned long long int counter = nonceCounter + idx; // Increment counter for each block

        // Copy IV to the state and apply the counter value
        memcpy(state, iv, AES_BLOCK_SIZE); // Assuming the first 8 bytes of IV are constant for this example
        for (int i = 0; i < 8; ++i) { // This part needs to handle the counter correctly; consider the entire 128-bit block
            state[8 + i] = ((unsigned char*)&counter)[i];
        }

        // Encrypt the counter block
        for (int round = 0; round < 10; ++round) {
            SubBytes(state);
            ShiftRows(state);
            if (round < 9) MixColumns(state);
            AddRoundKey(state, expandedKey + round * AES_BLOCK_SIZE); // Ensure expandedKey is correctly prepared
        }

        // XOR with plaintext to produce ciphertext
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ state[i];
        }
    }
}

int main() {
    unsigned char *d_plaintext, *d_ciphertext, *d_iv;
    unsigned long long int *d_nonceCounter; // Device pointer for nonce counter
    unsigned long long int nonceCounterValue = 0; 
    size_t dataSize = 16; // set the actual data size;
    unsigned char *d_expandedKey;


    // Copy S-box and rcon to device constant memory
    cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox));
    cudaMemcpyToSymbol(d_rcon, h_rcon, sizeof(h_rcon));

    // Call the host function to expand the key
    unsigned char expandedKey[176];
    KeyExpansionHost(key, expandedKey);

    // Calculate the number of AES blocks needed
    size_t numBlocks = (dataSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    // Define the size of the grid and the blocks
    dim3 threadsPerBlock(AES_BLOCK_SIZE, AES_BLOCK_SIZE, 1);
    dim3 blocksPerGrid((numBlocks + threadsPerBlock.x - 1) / threadsPerBlock.x,
                    (numBlocks + threadsPerBlock.y - 1) / threadsPerBlock.y,
                    (numBlocks + threadsPerBlock.z - 1) / threadsPerBlock.z);

    //dim3 threadsPerBlock(1, 1, 1);
    //dim3 blocksPerGrid(1, 1, 1);

   // Allocate device memory
    cudaMalloc((void **)&d_plaintext, AES_BLOCK_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_ciphertext, AES_BLOCK_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_nonceCounter, sizeof(unsigned long long int));
    cudaMalloc((void **)&d_iv, AES_BLOCK_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_expandedKey, 176); // Expanded key size for AES-128

    // Copy host memory to device
    cudaMemcpy(d_plaintext, plaintext, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_nonceCounter, &nonceCounterValue, sizeof(unsigned long long int), cudaMemcpyHostToDevice); 
    cudaMemcpy(d_iv, iv, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_expandedKey, expandedKey, 176, cudaMemcpyHostToDevice); // Copy expanded key

    // Launch AES-CTR encryption kernel
    aes_ctr_encrypt_kernel<<<blocksPerGrid, threadsPerBlock>>>(d_plaintext, d_ciphertext, d_expandedKey, d_iv, nonceCounterValue);

    // Copy device ciphertext back to host
    unsigned char ciphertext[AES_BLOCK_SIZE];
    cudaMemcpy(ciphertext, d_ciphertext, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    print_hex(ciphertext, AES_BLOCK_SIZE);

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    cudaFree(d_nonceCounter);
    cudaFree(d_iv);
    return 0;
}