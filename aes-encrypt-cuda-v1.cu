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
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; --i) {
            unsigned char old = localIv[i];
            localIv[i] += tid;
            if (localIv[i] >= old) break;  // Break if there's no carry
        }

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
    unsigned char *plaintext;
    read_file_as_binary(&plaintext, &dataSize, "plaintext.txt"); 

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

    // Allocate device memory
    cudaMalloc((void **)&d_plaintext, numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_ciphertext, numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));

    // Allocate memory for the ciphertext on the host
    unsigned char *ciphertext = new unsigned char[numBlocks * AES_BLOCK_SIZE];

    // Copy host memory to device
    cudaMemcpy(d_plaintext, plaintext, dataSize * sizeof(unsigned char), cudaMemcpyHostToDevice);

    // Determine the number of streams based on the number of SMs
    int numStreams = 16;  // Use full 82 will decrese performance, best at 8 and 16

    // Create the streams
    cudaStream_t *streams = new cudaStream_t[numStreams];
    for (int i = 0; i < numStreams; ++i) {
        cudaStreamCreate(&streams[i]);
    }

    // Calculate the number of blocks per stream
    size_t blocksPerStream = (numBlocks + numStreams - 1) / numStreams;

    // Loop over the streams
    for (int i = 0; i < numStreams; ++i) {
        // Calculate the start and end block for this stream
        size_t startBlock = i * blocksPerStream;
        size_t endBlock = min(startBlock + blocksPerStream, numBlocks);

        // Check if there are any blocks for this stream
        if (startBlock < endBlock) {
            // Calculate the number of blocks and threads for this stream
            dim3 blocks(endBlock - startBlock);
            dim3 threads(AES_BLOCK_SIZE);

            // Launch the kernel in this stream
            aes_ctr_encrypt_kernel<<<blocks, threads, 0, streams[i]>>>(d_plaintext + startBlock * AES_BLOCK_SIZE, d_ciphertext + startBlock * AES_BLOCK_SIZE, endBlock - startBlock);
        }
    }

    // Wait for all streams to finish
    for (int i = 0; i < numStreams; ++i) {
        cudaStreamSynchronize(streams[i]);
    }

    // Clean up
    for (int i = 0; i < numStreams; ++i) {
        cudaStreamDestroy(streams[i]);
    }
    delete[] streams;

    // Copy device ciphertext back to host
    cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    // Output encoded text to a file
    write_ciphertext(ciphertext, dataSize, "ciphertext.bin");

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    delete[] ciphertext;
    delete[] plaintext; 

    return 0;
}