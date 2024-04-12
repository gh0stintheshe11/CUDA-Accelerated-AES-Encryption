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
        -v5.1 Stream and Others
            1. Stream
            Modify the code to precalculate all nessaray variables before lunchun kernel, whcih makes every stream truly independent.
            2. Others
            Modify the mul() and merge aes-encrypt-block() with kernel to reduce local variable use to reduce register use. This optimization is based on Nsight Compute report. Since register's are shared between warps, use limted register allows the program to achieve max warp occupency.
*/

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define NUM_STREAMS 16

// Declare fixed data in constant memory
__constant__ unsigned char d_sbox[256];

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


__device__ unsigned char mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char high_bit_mask = 0x80;
    unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        // Use arithmetic instead of conditional
        p ^= a * (b & 1);  
        a = (a << 1) ^ (modulo * ((a & high_bit_mask) >> 7));  
        b >>= 1;
    }
    return p;
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

__device__ void increment_counter(unsigned char *counter, int increment) {
    int carry = increment;
    #pragma unroll
    for (int i = 15; i >= 0 && carry != 0; --i) {
        int sum = counter[i] + carry;
        counter[i] = sum & 0xFF;
        carry = sum >> 8;
    }
}

__global__ void aes_ctr_encrypt_kernel(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *expandedKey, unsigned char *iv, int numBlocks, int dataSize) {
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

    // Calculate the actual number of blocks processed by all previous threads, blocks, and streams
    int blockId = tid;

    memcpy(counter, shared_iv, AES_BLOCK_SIZE);

    // Increment the counter by the actual number of blocks
    increment_counter(counter, blockId); // Increment by blockId instead of blockId - totalBlocks

    // Calculate the block size
    int blockSize = AES_BLOCK_SIZE;

    // Encrypt the counter to get the ciphertext block
    unsigned char ciphertextBlock[AES_BLOCK_SIZE];

    // aes_encrypt_block(counter, ciphertextBlock, shared_expandedKey);
    // Merged aes_encrypt_block function
    {
        __shared__ unsigned char state[16];

        // Copy the counter to the state array (loop unroll)
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            state[i] = counter[i];
        }

        // Add the round key to the state
        AddRoundKey(state, shared_expandedKey);

        // Perform 9 rounds of substitutions, shifts, mixes, and round key additions
        #pragma unroll
        for (int round = 1; round < 10; ++round) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, shared_expandedKey + round * 16);
        }

        // Perform the final round (without MixColumns)
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, shared_expandedKey + 10 * 16);

        // Copy the state to the ciphertextBlock
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            ciphertextBlock[i] = state[i];
        }
    }

    // XOR the plaintext with the ciphertext block
    #pragma unroll
    for (int i = 0; i < blockSize; ++i) {
        if (blockId * AES_BLOCK_SIZE + i < dataSize) { // Ensure that only the correct number of bytes are included in the final ciphertext
            ciphertext[blockId * AES_BLOCK_SIZE + i] = plaintext[blockId * AES_BLOCK_SIZE + i] ^ ciphertextBlock[i];
        }
    }
}

int main(int argc, char* argv[]) {
    // Check if filename is provided
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

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
    unsigned char *plaintext;
    unsigned char *ciphertext;
    // Determine the size of the file and read the plaintext
    read_file_as_binary_v2(&plaintext, &dataSize, argv[1]); 

    // Call the host function to expand the key
    unsigned char expandedKey[176];
    KeyExpansionHost(key, expandedKey);
    // Allocate device memory for expanded key
    unsigned char *d_expandedKey;
    cudaMalloc((void **)&d_expandedKey, 176 * sizeof(unsigned char));
    cudaMemcpy(d_expandedKey, expandedKey, 176 * sizeof(unsigned char), cudaMemcpyHostToDevice);

    // Calculate the number of AES blocks needed
    size_t numBlocks = (dataSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    // Define the size of the grid and the blocks
    dim3 threadsPerBlock(256); 

    // Allocate device memory
    cudaMallocHost((void**)&ciphertext, dataSize * sizeof(unsigned char));

    // Copy S-box to device constant memory
    cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox));

    // Define four CUDA streams
    cudaStream_t stream[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; ++i) {
        cudaStreamCreate(&stream[i]);
    }

    // Pre-calculate the values for each stream
    size_t partSize = (numBlocks + NUM_STREAMS - 1) / NUM_STREAMS * AES_BLOCK_SIZE;
    size_t starts[NUM_STREAMS], ends[NUM_STREAMS], sizes[NUM_STREAMS], numBlocksPerStream[NUM_STREAMS];
    unsigned char* d_plaintexts[NUM_STREAMS];
    unsigned char* d_ciphertexts[NUM_STREAMS];
    unsigned char* d_ivs[NUM_STREAMS];

    for (int i = 0; i < NUM_STREAMS; ++i) {
        starts[i] = i * partSize;
        ends[i] = min((i + 1) * partSize, dataSize);
        sizes[i] = ends[i] - starts[i];
        numBlocksPerStream[i] = sizes[i] / AES_BLOCK_SIZE;

        cudaMalloc((void **)&d_plaintexts[i], sizes[i] * sizeof(unsigned char));
        cudaMalloc((void **)&d_ciphertexts[i], sizes[i] * sizeof(unsigned char));
        cudaMalloc((void **)&d_ivs[i], AES_BLOCK_SIZE * sizeof(unsigned char));
        unsigned char iv_for_this_stream[AES_BLOCK_SIZE];
        memcpy(iv_for_this_stream, iv, AES_BLOCK_SIZE);
        increment_iv(iv_for_this_stream, i * partSize / AES_BLOCK_SIZE); // Increment by the number of blocks for each stream
        cudaMemcpy(d_ivs[i], iv_for_this_stream, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
    }

    // Execute the kernel using streams
    for (int i = 0; i < NUM_STREAMS; ++i) {
        int numMultiprocessors = 82;
        dim3 blocksPerGrid(max((numBlocksPerStream[i] + threadsPerBlock.x - 1) / threadsPerBlock.x, (unsigned long)numMultiprocessors));
        
        cudaMemcpyAsync(d_plaintexts[i], plaintext + starts[i], sizes[i] * sizeof(unsigned char), cudaMemcpyHostToDevice, stream[i]);
        
        aes_ctr_encrypt_kernel<<<blocksPerGrid, threadsPerBlock, 0, stream[i]>>>(d_plaintexts[i], d_ciphertexts[i], d_expandedKey, d_ivs[i], numBlocksPerStream[i], sizes[i]);

        cudaMemcpyAsync(ciphertext + starts[i], d_ciphertexts[i], sizes[i] * sizeof(unsigned char), cudaMemcpyDeviceToHost, stream[i]);
    }

    // Output encoded text to a file
    write_encrypted(ciphertext, dataSize, "encrypted.bin");

    // Cleanup
    for (int i = 0; i < NUM_STREAMS; ++i) {
        cudaFree(d_ivs[i]);
    }
    cudaFree(d_expandedKey);
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