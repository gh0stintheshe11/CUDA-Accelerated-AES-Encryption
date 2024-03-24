#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>
#include <string.h>
#include "utils-cuda.h"

/*
    Memory targeted optimizations:
        - Add shared memory for data with in SM -> slightly improve kernel throughput
        - Add constant memory for expanded key and IV -> slightly improve kernel throughput
        - Add stream for GPU kernel -> transfer data still waste time
        - Add stream for CPU data transfer + GPU kernel computation -> CPU pass file in gpu serially, which leads to serial stream and serial kernel excution -> waste time (basically back to v0 level...)
*/

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

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

__device__ void aes_encrypt_block(unsigned char *input, unsigned char *output, unsigned char *expandedKey) {
    unsigned char state[16];

    // Copy the input to the state array
    for (int i = 0; i < 16; ++i) {
        state[i] = input[i];
    }

    // Add the round key to the state
    AddRoundKey(state, expandedKey);

    // Perform 9 rounds of substitutions, shifts, mixes, and round key additions
    for (int round = 1; round < 10; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + round * 16);
    }

    // Perform the final round (without MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + 10 * 16);

    // Copy the state to the output
    for (int i = 0; i < 16; ++i) {
        output[i] = state[i];
    }
}

// Declare constant memory variables for the IV and expanded key
__constant__ unsigned char constantIv[AES_BLOCK_SIZE];
__constant__ unsigned char constantExpandedKey[176];

// Host function to copy the IV and expanded key to constant memory
void copyToConstantMemory(unsigned char *iv, unsigned char *expandedKey) {
    cudaMemcpyToSymbol(constantIv, iv, AES_BLOCK_SIZE);
    cudaMemcpyToSymbol(constantExpandedKey, expandedKey, 176);
}

__global__ void aes_ctr_encrypt_kernel(unsigned char *plaintext, unsigned char *ciphertext, int numBlocks) {
    // Calculate the global thread ID
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    // Declare shared memory for the IV
    __shared__ unsigned char sharedIv[AES_BLOCK_SIZE];

    // Load the IV into shared memory
    if (threadIdx.x < AES_BLOCK_SIZE) {
        sharedIv[threadIdx.x] = constantIv[threadIdx.x];
    }

    // Synchronize to make sure the data is loaded before proceeding
    __syncthreads();

    // Check if the thread is within the number of blocks
    if (tid < numBlocks) {
        // Copy the IV to a local array
        unsigned char localIv[AES_BLOCK_SIZE];
        memcpy(localIv, sharedIv, AES_BLOCK_SIZE);

        // Increment the counter in the local IV
        localIv[15] += tid;

        // Perform the AES encryption
        unsigned char block[AES_BLOCK_SIZE];
        aes_encrypt_block(localIv, block, constantExpandedKey);  // Use constantExpandedKey here

        // XOR the plaintext with the encrypted block
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            ciphertext[tid * AES_BLOCK_SIZE + i] = plaintext[tid * AES_BLOCK_SIZE + i] ^ block[i];
        }
    }
}

int main() {

    // Read the key and IV
    unsigned char key[16];
    unsigned char iv[16];
    read_key_or_iv(key, sizeof(key), "key.txt");
    read_key_or_iv(iv, sizeof(iv), "iv.txt");

    // Determine the size of the file and read the plaintext
    size_t dataSize;
    unsigned char* plaintext;
    read_plaintext(&plaintext, &dataSize, "plaintext.txt"); 

    unsigned char *d_plaintext, *d_ciphertext;

    // Copy S-box and rcon to device constant memory
    cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox));
    cudaMemcpyToSymbol(d_rcon, h_rcon, sizeof(h_rcon));

    // Call the host function to expand the key
    unsigned char expandedKey[176];
    KeyExpansionHost(key, expandedKey);

    // Copy the IV and expanded key to constant memory
    copyToConstantMemory(iv, expandedKey);

    // Calculate the number of AES blocks needed
    size_t numBlocks = (dataSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    // Define the size of the grid and the blocks
    dim3 threadsPerBlock(256); // Use a reasonable number of threads per block
    dim3 blocksPerGrid((numBlocks + threadsPerBlock.x - 1) / threadsPerBlock.x);

    // Pad the plaintext with zeros
    unsigned char *paddedPlaintext = new unsigned char[numBlocks * AES_BLOCK_SIZE];
    memcpy(paddedPlaintext, plaintext, dataSize);
    memset(paddedPlaintext + dataSize, 0, numBlocks * AES_BLOCK_SIZE - dataSize);

    // Allocate device memory
    cudaMalloc((void **)&d_plaintext, numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_ciphertext, numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));

    // Determine the number of streams based on the number of SMs
    int numStreams = 16;  // Use full 82 will decrese performance, best at 8 and 16

    // Create the streams
    cudaStream_t *streams = new cudaStream_t[numStreams];
    for (int i = 0; i < numStreams; ++i) {
        cudaStreamCreate(&streams[i]);
    }

    // Calculate the number of blocks per stream
    size_t blocksPerStream = (numBlocks + numStreams - 1) / numStreams;

    // Allocate host memory for the ciphertext
    unsigned char* ciphertext = new unsigned char[numBlocks * AES_BLOCK_SIZE];

    // Inside the loop over the streams
    for (int i = 0; i < numStreams; ++i) {
        // Calculate the start and end indices for this stream
        size_t start = i * blocksPerStream;
        size_t end = min((i + 1) * blocksPerStream, numBlocks);

        // Calculate the actual size of the data processed by this stream
        size_t actualChunkSize = (end - start) * AES_BLOCK_SIZE;

        // Calculate the actual number of blocks for this stream
        size_t actualBlocks = end - start;

        // Copy a chunk of the plaintext from the CPU to the GPU
        cudaMemcpyAsync(&d_plaintext[start * AES_BLOCK_SIZE], &paddedPlaintext[start * AES_BLOCK_SIZE], actualChunkSize, cudaMemcpyHostToDevice, streams[i]);


        // Launch the kernel on the GPU
        aes_ctr_encrypt_kernel<<<actualBlocks, threadsPerBlock, 0, streams[i]>>>(d_plaintext + start * AES_BLOCK_SIZE, d_ciphertext + start * AES_BLOCK_SIZE, actualBlocks);

        // Copy the processed data back from the GPU to the CPU
        cudaMemcpyAsync(&ciphertext[start * AES_BLOCK_SIZE], &d_ciphertext[start * AES_BLOCK_SIZE], actualChunkSize, cudaMemcpyDeviceToHost, streams[i]);
    }

    // Wait for all streams to finish
    for (int i = 0; i < numStreams; ++i) {
        cudaStreamSynchronize(streams[i]);
    }

    // Output encoded text to a file
    write_ciphertext(ciphertext, dataSize, "ciphertext.txt");

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    delete[] streams;
    delete[] paddedPlaintext;
    delete[] plaintext; 

    return 0;
}