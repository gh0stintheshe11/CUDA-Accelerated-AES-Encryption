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
        -v1 Pinned Memory: plaintext and ciphertext
        -v2 Coalesced Memory Access
            In previous code, each thread is accessing a different block of the plaintext and ciphertext arrays. If the blocks are not contiguous in memory, this could slow down the program. This code rearrange the data so that the blocks accessed by threads in the same warp are contiguous in memory.
        -v3 Divergence Avoidance: 
            -v3.1 aes_ctr_encrypt_kernel(): In the original function, the divergence is caused by the conditional statement if (blockId < numBlocks). This divergence can be avoided by ensuring that the number of threads is a multiple of the number of blocks, which means padding the data to a multiple of the block size.
            -v3.2 mul(): In this modified version, the if (b & 1) and if (high_bit) conditions are replaced with arithmetic operations. This ensures all threads in a warp take the same execution path, avoiding divergence.
        -v4 Loop Unrolling and Intrinsic function
            1. Loop Unrolling: add loop unrolling to small(eliminating loop control overhead)/compute-focused(allow for more instruction-level parallelism) loops not large(increasing the register pressure)/memory-focused(lead to instruction cache misses) loops. mul(), SubBytes(), MixColumns(), AddRoundKey(), aes_encrypt_block(): 9_rounds and state_to_output, aes_ctr_encrypt_kernel(): XOR.
            2. Intrinsic Function: use fast build-in function __ldg() to load and cache expanded key.
        -v5 Stream
            added stream for kernel. However due to host side increment variable code excution between kernel lunches, the kernel stream are not really excuting in parallel but in serial. The increment code is used to calculate unique IV for every stream/data chunks, but since it is a host side function, which natruelly excute in serial, the code actually block the next kernel lunch until it is finished.
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

    #pragma unroll
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
    #pragma unroll
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
    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        tmp[i*4] = (unsigned char)(mul(0x02, state[i*4]) ^ mul(0x03, state[i*4+1]) ^ state[i*4+2] ^ state[i*4+3]);
        tmp[i*4+1] = (unsigned char)(state[i*4] ^ mul(0x02, state[i*4+1]) ^ mul(0x03, state[i*4+2]) ^ state[i*4+3]);
        tmp[i*4+2] = (unsigned char)(state[i*4] ^ state[i*4+1] ^ mul(0x02, state[i*4+2]) ^ mul(0x03, state[i*4+3]));
        tmp[i*4+3] = (unsigned char)(mul(0x03, state[i*4]) ^ state[i*4+1] ^ state[i*4+2] ^ mul(0x02, state[i*4+3]));
    }
    memcpy(state, tmp, 16);
}

__device__ void AddRoundKey(unsigned char *state, const unsigned char *roundKey) {
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        state[i] ^= roundKey[i];
    }
}

__device__ void aes_encrypt_block(unsigned char *input, unsigned char *output, unsigned char *expandedKey) {
    __shared__ unsigned char state[16];

    // Copy the input to the state array (loop unroll)
    state[0] = input[0]; state[1] = input[1]; state[2] = input[2]; state[3] = input[3];
    state[4] = input[4]; state[5] = input[5]; state[6] = input[6]; state[7] = input[7];
    state[8] = input[8]; state[9] = input[9]; state[10] = input[10]; state[11] = input[11];
    state[12] = input[12]; state[13] = input[13]; state[14] = input[14]; state[15] = input[15];

    // Add the round key to the state
    AddRoundKey(state, expandedKey);

    // Perform 9 rounds of substitutions, shifts, mixes, and round key additions
    #pragma unroll
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
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        output[i] = state[i];
    }
}

__device__ void increment_counter(unsigned char *counter, int increment) {
    int carry = increment;
    int sum;
    sum = counter[15] + carry; counter[15] = sum & 0xFF; carry = sum >> 8;
    if (carry != 0) {
        sum = counter[14] + carry; counter[14] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[13] + carry; counter[13] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[12] + carry; counter[12] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[11] + carry; counter[11] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[10] + carry; counter[10] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[9] + carry; counter[9] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[8] + carry; counter[8] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[7] + carry; counter[7] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[6] + carry; counter[6] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[5] + carry; counter[5] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[4] + carry; counter[4] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[3] + carry; counter[3] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[2] + carry; counter[2] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[1] + carry; counter[1] = sum & 0xFF; carry = sum >> 8;
    }
    if (carry != 0) {
        sum = counter[0] + carry; counter[0] = sum & 0xFF; carry = sum >> 8;
    }
}

__global__ void aes_ctr_encrypt_kernel(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *expandedKey, unsigned char *iv, int numBlocks, int dataSize, size_t totalBlocks) {
    // Calculate the unique thread ID within the grid
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    // Create shared memory arrays for the IV and expanded key
    __shared__ unsigned char shared_iv[AES_BLOCK_SIZE];
    __shared__ unsigned char shared_expandedKey[176];

    // Copy the IV and expanded key to shared memory
    if (threadIdx.x < AES_BLOCK_SIZE) {
        shared_iv[threadIdx.x] = iv[threadIdx.x];
    }
    if (threadIdx.x < 176) {
        shared_expandedKey[threadIdx.x] =  __ldg(&expandedKey[threadIdx.x]);
    }

    __syncthreads(); // Ensure IV and key are fully loaded

    // Define the counter and initialize it with the IV
    unsigned char counter[AES_BLOCK_SIZE];

    // Calculate the number of blocks processed by each thread
    int blocksPerThread = (numBlocks + gridDim.x * blockDim.x - 1) / (gridDim.x * blockDim.x);

    // Process multiple blocks of plaintext/ciphertext
    for (int block = 0; block < blocksPerThread; ++block) {
        // Calculate the actual number of blocks processed by all previous threads, blocks, and streams
        int blockId = tid + block * gridDim.x * blockDim.x;

        memcpy(counter, shared_iv, AES_BLOCK_SIZE);

        // Increment the counter by the actual number of blocks
        increment_counter(counter, blockId); // Increment by blockId instead of blockId - totalBlocks

        // Calculate the block size
        int blockSize = AES_BLOCK_SIZE;

        // Encrypt the counter to get the ciphertext block
        unsigned char ciphertextBlock[AES_BLOCK_SIZE];
        aes_encrypt_block(counter, ciphertextBlock, shared_expandedKey);

        // XOR the plaintext with the ciphertext block
        #pragma unroll
        for (int i = 0; i < blockSize; ++i) {
            if (blockId * AES_BLOCK_SIZE + i < dataSize) { // Ensure that only the correct number of bytes are included in the final ciphertext
                ciphertext[blockId * AES_BLOCK_SIZE + i] = plaintext[blockId * AES_BLOCK_SIZE + i] ^ ciphertextBlock[i];
            }
        }
    }
}

// Function to increment the IV
void increment_iv(unsigned char* iv, size_t increment) {
    size_t i = AES_BLOCK_SIZE - 1;
    while (increment > 0) {
        size_t sum = iv[i] + (increment & 0xFF); // Add the least significant byte of increment to iv[i]
        iv[i] = sum & 0xFF; // Store the least significant byte of the sum in iv[i]
        increment = (increment >> 8) | (sum >> 8); // Carry the overflow to the next byte
        --i;
    }
}

int main(int argc, char* argv[]) {
    // Check if filename is provided
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    int numStream = 16;

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

    // Copy S-box to device constant memory
    cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox));

    // Allocate device memory for each stream
    unsigned char *d_iv[numStream];
    unsigned char *d_expandedKey[numStream];
    for (int i = 0; i < numStream; ++i) {
        cudaMalloc((void **)&d_iv[i], AES_BLOCK_SIZE * sizeof(unsigned char));
        cudaMalloc((void **)&d_expandedKey[i], 176);
        cudaMemcpy(d_iv[i], iv, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
        cudaMemcpy(d_expandedKey[i], expandedKey, 176, cudaMemcpyHostToDevice);
    }
    
    // Copy data to GPU without using streams
    cudaMemcpy(d_plaintext, plaintext, dataSize * sizeof(unsigned char), cudaMemcpyHostToDevice);

    // Define four CUDA streams
    cudaStream_t stream[numStream];
    for (int i = 0; i < numStream; ++i) {
        cudaStreamCreate(&stream[i]);
    }

    // Divide the data into four parts
    size_t partSize = (numBlocks + numStream - 1) / numStream * AES_BLOCK_SIZE;
    
    // Execute the kernel using streams
    size_t totalBlocks = 0; // Total number of blocks processed by all previous streams
    for (int i = 0; i < numStream; ++i) {
        size_t start = i * partSize;
        size_t end = min((i + 1) * partSize, dataSize);
        size_t size = end - start;
        size_t numBlocks = size / AES_BLOCK_SIZE;
        dim3 blocksPerGrid((numBlocks + threadsPerBlock.x - 1) / threadsPerBlock.x);

        // Increment the IV for this stream
        unsigned char iv_for_this_stream[AES_BLOCK_SIZE];
        memcpy(iv_for_this_stream, iv, AES_BLOCK_SIZE);
        increment_iv(iv_for_this_stream, totalBlocks); // Increment by the total number of blocks
        cudaMemcpy(d_iv[i], iv_for_this_stream, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);

        aes_ctr_encrypt_kernel<<<blocksPerGrid, threadsPerBlock, 0, stream[i]>>>(d_plaintext + start, d_ciphertext + start, d_expandedKey[i], d_iv[i], numBlocks, size, totalBlocks);

        totalBlocks += numBlocks; // Update the total number of blocks after the kernel launch
    }

    // Synchronize each stream individually, but after all streams have been launched
    for (int i = 0; i < numStream; ++i) {
        cudaStreamSynchronize(stream[i]);
    }

    // Copy data back to CPU without using streams
    cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    // Output encoded text to a file
    write_encrypted(ciphertext, dataSize, "encrypted.bin");

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    // Cleanup
    for (int i = 0; i < numStream; ++i) {
        cudaFree(d_iv[i]);
        cudaFree(d_expandedKey[i]);
    }
    cudaFreeHost(ciphertext);
    cudaFreeHost(plaintext);

    // Get the stop time
    auto stop = std::chrono::high_resolution_clock::now();

    // Calculate the elapsed time and print
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    std::cout << "time: " << duration.count() << " ms\n";

    // After encrypting, append the file extension to the encrypted data
    appendFileExtension("encrypted.bin", extension);
    
    return 0;
}