#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <chrono>
#include <cuda_runtime.h>
#include <string.h>
#include "utils-cuda.h"

/*
    Optimization:
        -v1 Constant Memory: S box
        -v1 Shared Memory: IV and expanded key
        -v2 Coalesced Memory Access: In previous code, each thread is accessing a different block of the plaintext and ciphertext arrays. If the blocks are not contiguous in memory, this could slow down the program. This code rearrange the data so that the blocks accessed by threads in the same warp are contiguous in memory.
        -v3 Divergence Avoidance: 
            -v3.1 aes_ctr_encrypt_kernel(): In the original function, the divergence is caused by the conditional statement if (blockId < numBlocks). This divergence can be avoided by ensuring that the number of threads is a multiple of the number of blocks, which means padding the data to a multiple of the block size.
            -v3.2 mul(): In this modified version, the if (b & 1) and if (high_bit) conditions are replaced with arithmetic operations. This ensures all threads in a warp take the same execution path, avoiding divergence.
        -v4 Stream: bitch.

*/

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

// Declare fixed data in constant memory
__constant__ unsigned char d_sbox[256];

__device__ unsigned char mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char high_bit_mask = 0x80;
    unsigned char high_bit = 0;
    unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

    for (int i = 0; i < 8; i++) {
        p ^= a * (b & 1);  // Use arithmetic instead of conditional

        high_bit = a & high_bit_mask;
        a <<= 1;
        a ^= modulo * (high_bit >> 7);  // Use arithmetic instead of conditional
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

__device__ void increment_counter(unsigned char *counter, int increment) {
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; --i) {
        int sum = counter[i] + (increment & 0xFF);
        counter[i] = sum & 0xFF;
        increment >>= 8;
        if (increment == 0) {
            break;
        }
    }
}

__global__ void aes_ctr_encrypt_kernel(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *expandedKey, unsigned char *iv, int numBlocks, int dataSize, int streamId, int blocksPerStream) {
    // Calculate the unique thread ID within the grid
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    // Define the counter and initialize it with the IV
    unsigned char counter[AES_BLOCK_SIZE];

    // Calculate the number of blocks processed by each thread
    int blocksPerThread = (numBlocks + gridDim.x * blockDim.x - 1) / (gridDim.x * blockDim.x);

    // Process multiple blocks of plaintext/ciphertext
    for (int block = 0; block < blocksPerThread; ++block) {
        int blockId = tid + block * gridDim.x * blockDim.x;

        // Calculate the global block ID
        int globalBlockId = blockId + blocksPerStream * streamId;

        // Skip the iteration if the globalBlockId is out of range
        if (globalBlockId >= numBlocks) {
            continue;
        }

        // Copy the IV to the counter
        memcpy(counter, iv, AES_BLOCK_SIZE);

        // Increment the counter by the block ID (not the global block ID)
        increment_counter(counter, blockId);

        // Encrypt the counter to get the ciphertext block
        unsigned char ciphertextBlock[AES_BLOCK_SIZE];
        aes_encrypt_block(counter, ciphertextBlock, expandedKey);

        // XOR the plaintext with the ciphertext block
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            int index = globalBlockId * AES_BLOCK_SIZE + i;
            if (index < dataSize) {
                ciphertext[index] = plaintext[index] ^ ciphertextBlock[i];
            }
        }
    }
}

int main(int argc, char* argv[]) {
    // Check if filename is provided
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const int numStreams = 8;

    // Get the file extension
    std::string extension = getFileExtension(argv[1]);

    // Get the start time
    auto start = std::chrono::high_resolution_clock::now();

    // Read the key and IV
    unsigned char key[16];
    unsigned char iv[16];
    read_key_or_iv(key, sizeof(key), "key.txt");
    read_key_or_iv(iv, sizeof(iv), "iv.txt");

    size_t dataSize;
    unsigned char* plaintext;
    unsigned char *ciphertext;  
    unsigned char *d_plaintext, *d_ciphertext;
    unsigned char *d_iv[numStreams];
    unsigned char *d_expandedKey[numStreams];
    // Determine the size of the file and read the plaintext
    read_file_as_binary_v2(&plaintext, &dataSize, argv[1]);

    // Call the host function to expand the key
    unsigned char expandedKey[176];
    KeyExpansionHost(key, expandedKey);

    // Calculate the number of AES blocks needed
    size_t numBlocks = (dataSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    // Define the size of the grid and the blocks
    dim3 threadsPerBlock(256); // Use a reasonable number of threads per block
    dim3 blocksPerGrid((numBlocks + threadsPerBlock.x - 1) / threadsPerBlock.x);

    // Allocate device memory
    cudaMalloc((void **)&d_plaintext, dataSize * sizeof(unsigned char));
    cudaMalloc((void **)&d_ciphertext, dataSize * sizeof(unsigned char));
    cudaMallocHost((void**)&ciphertext, dataSize * sizeof(unsigned char));

    for(int i = 0; i < numStreams; i++) {
        cudaMalloc((void **)&d_iv[i], AES_BLOCK_SIZE * sizeof(unsigned char));
        cudaMalloc((void **)&d_expandedKey[i], 176);
        cudaMemcpy(d_iv[i], iv, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
        cudaMemcpy(d_expandedKey[i], expandedKey, 176, cudaMemcpyHostToDevice);
    }

    // Copy S-box to device constant memory
    cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox));

    cudaStream_t streams[numStreams];
    for(int i = 0; i < numStreams; i++) {
        cudaStreamCreate(&streams[i]);
    }

    // Calculate the number of blocks processed by each stream
    int blocksPerStream = (numBlocks + numStreams - 1) / numStreams;

    for(int i = 0; i < numStreams; i++) {
        int offset = i * blocksPerStream * AES_BLOCK_SIZE;
        int blocks = min(blocksPerStream, static_cast<int>(numBlocks - i * blocksPerStream));
        int size = blocks * AES_BLOCK_SIZE;

        // Copy the plaintext to the device
        cudaMemcpyAsync(&d_plaintext[offset], &plaintext[offset], size, cudaMemcpyHostToDevice, streams[i]);

        // Launch the kernel
        aes_ctr_encrypt_kernel<<<blocks, threadsPerBlock, 0, streams[i]>>>(&d_plaintext[offset], &d_ciphertext[offset], d_expandedKey[i], d_iv[i], blocks, size, i, blocksPerStream);

        // Add a synchronization point after each kernel launch
        cudaStreamSynchronize(streams[i]);

        // Copy the ciphertext back to the host
        cudaMemcpyAsync(&ciphertext[offset], &d_ciphertext[offset], size, cudaMemcpyDeviceToHost, streams[i]);
    }

    for(int i = 0; i < numStreams; i++) {
        cudaStreamSynchronize(streams[i]);
        cudaStreamDestroy(streams[i]);
    }

    // Synchronize device
    cudaDeviceSynchronize();

    // Output encoded text to a file
    write_encrypted(ciphertext, dataSize, "encrypted.bin");

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    for(int i = 0; i < numStreams; i++) {
        cudaFree(d_iv[i]);
        cudaFree(d_expandedKey[i]);
    }
    cudaFreeHost(ciphertext);
    cudaFreeHost(plaintext); 

    // Get the stop time
    auto stop = std::chrono::high_resolution_clock::now();

    // Calculate the elapsed time and print
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    std::cout << "IKO time: " << duration.count() << " ms\n";

    // After encrypting, append the file extension to the encrypted data
    appendFileExtension("encrypted.bin", extension);
    
    return 0;
}