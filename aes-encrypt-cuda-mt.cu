#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cuda_runtime.h>
#include <string.h>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <chrono>
#include <condition_variable>
#include "utils-cuda.h"

/*
    DEAD END, do not use.
    CPU multithreading (MT) + GPU stream version
    I can't get this goddamn piece of shit working!
    also maybe too slow: guessing a big transfer is better than multiple small transfer?
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

__device__ void increment_counter(unsigned char *counter, int increment) {
    int carry = increment;
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        int sum = counter[i] + carry;
        counter[i] = sum & 0xFF;
        carry = sum >> 8;
        if (carry == 0) {
            break;
        }
    }
}

__global__ void aes_ctr_encrypt_kernel(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *expandedKey, unsigned char *iv, int numBlocks, int dataSize) {
    // Calculate the global block ID
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    // Check if the block is within the number of blocks
    if (tid < numBlocks) {
        // Create a counter array
        unsigned char counter[AES_BLOCK_SIZE];

        // Copy the IV to the counter
        memcpy(counter, iv, AES_BLOCK_SIZE);

        // Increment the counter by the block ID
        increment_counter(counter, tid);

        // Calculate the block size
        int blockSize = (tid == numBlocks - 1 && dataSize % AES_BLOCK_SIZE != 0) ? dataSize % AES_BLOCK_SIZE : AES_BLOCK_SIZE;

        // Encrypt the counter to get the ciphertext block
        unsigned char ciphertextBlock[AES_BLOCK_SIZE];
        aes_encrypt_block(counter, ciphertextBlock, expandedKey);

        // XOR the plaintext with the ciphertext block
        for (int i = 0; i < blockSize; ++i) {
            ciphertext[tid * AES_BLOCK_SIZE + i] = plaintext[tid * AES_BLOCK_SIZE + i] ^ ciphertextBlock[i];
        }
    }
}

std::queue<size_t> workQueue;
std::mutex queueMutex;
std::condition_variable queueCondVar;

bool allChunksProcessed = false;

unsigned char** chunks;
size_t numChunks;
size_t* chunkSizes;

struct Chunk {
    size_t number;
    unsigned char* data;
    size_t size;
};

// Create a std::deque to hold the chunks to be written to the file
std::deque<Chunk> writeQueue;
std::mutex writeMutex;
std::condition_variable writeCondVar;

void writeThread(const char* filename) {
    while (true) {
        Chunk chunk;

        {
            std::unique_lock<std::mutex> lock(writeMutex);
            writeCondVar.wait(lock, []{ return !writeQueue.empty(); });

            if (!writeQueue.empty()) {
                // Get the next processed chunk from the queue
                chunk = writeQueue.front();
                writeQueue.pop_front();
                std::cout << "WriteThread: Got chunk " << chunk.number << std::endl;

                // Write the processed chunk to the output file
                write_encrypted_multithreading(chunk.data, chunk.size, filename);
                std::cout << "WriteThread: Writing chunk " << chunk.number << " to file " << filename << std::endl;
            }

            if (writeQueue.empty() && allChunksProcessed) {
                std::cout << "WriteThread: All chunks processed, exiting" << std::endl;
                break;
            }
        }
    }
}

void processChunk(size_t i, unsigned char** chunks, unsigned char** ciphertexts, size_t* chunkSizes, unsigned char* expandedKey, unsigned char* iv, cudaStream_t* streams, unsigned char** d_chunks, unsigned char** d_ciphertexts) {
    std::cout << "Processing chunk " << i << std::endl;
    cudaStreamCreate(&streams[i]);

    // Allocate memory on the GPU
    cudaMalloc(&d_chunks[i], chunkSizes[i]);
    cudaMalloc(&d_ciphertexts[i], chunkSizes[i]);

    // Allocate memory for iv on the GPU
    unsigned char* d_iv;
    cudaMalloc(&d_iv, AES_BLOCK_SIZE);
    cudaMemcpy(d_iv, iv, AES_BLOCK_SIZE, cudaMemcpyHostToDevice);

    // Copy the chunk to the GPU
    cudaMemcpyAsync(d_chunks[i], chunks[i], chunkSizes[i], cudaMemcpyHostToDevice, streams[i]);

    // Launch the kernel
    dim3 numThreadsPerBlock(256);
    dim3 numBlocksPerGrid((chunkSizes[i] + numThreadsPerBlock.x - 1) / numThreadsPerBlock.x);
    aes_ctr_encrypt_kernel<<<numBlocksPerGrid, numThreadsPerBlock>>>(d_chunks[i], d_ciphertexts[i], expandedKey, d_iv, numBlocksPerGrid.x, chunkSizes[i]);

    // Copy the processed data back to the CPU
    cudaMemcpyAsync(ciphertexts[i], d_ciphertexts[i], chunkSizes[i], cudaMemcpyDeviceToHost, streams[i]);

    // Wait for the copy to finish
    cudaStreamSynchronize(streams[i]);

    cudaFree(d_chunks[i]);
    cudaFree(d_ciphertexts[i]);
    cudaFree(d_iv);
    cudaStreamDestroy(streams[i]);

    // After the copy is finished, add the chunk to the writeQueue
    {
        std::lock_guard<std::mutex> lock(writeMutex);
        writeQueue.push_back({i, ciphertexts[i], chunkSizes[i]});
        writeCondVar.notify_one();
    }
    std::cout << "Finished processing chunk " << i << std::endl;
}

void workerThread(unsigned char** chunks, unsigned char** ciphertexts, size_t* chunkSizes, unsigned char expandedKey[176], unsigned char iv[16], cudaStream_t* streams, unsigned char** d_chunks, unsigned char** d_ciphertexts) {
    while (true) {
        size_t i;
        // Get a chunk from the workQueue
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            while (workQueue.empty()) {
                if (allChunksProcessed) {
                    return;
                }
                queueCondVar.wait(lock);
            }
            // Get the next chunk number from the queue
            i = workQueue.front();
            workQueue.pop();
        }
        // Process the chunk
        processChunk(i, chunks, ciphertexts, chunkSizes, expandedKey, iv, streams, d_chunks, d_ciphertexts);

        // After the chunk is processed, add it to the writeQueue
        {
            std::lock_guard<std::mutex> lock(writeMutex);
            unsigned char* ciphertextCopy = new unsigned char[chunkSizes[i]];
            memcpy(ciphertextCopy, ciphertexts[i], chunkSizes[i]);
            writeQueue.push_back({i, ciphertextCopy, chunkSizes[i]});
            writeCondVar.notify_one();
        }

        // Delete the original ciphertexts[i] after it's copied and added to the writeQueue
        delete[] ciphertexts[i];
    }
}

int main(int argc, char* argv[]) {
    // Check if filename is provided
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // Get the start time
    auto start = std::chrono::high_resolution_clock::now();

    // Read the key and IV
    unsigned char key[16];
    unsigned char iv[16];
    read_key_or_iv(key, sizeof(key), "key.txt");
    read_key_or_iv(iv, sizeof(iv), "iv.txt");

    unsigned char** ciphertexts = new unsigned char*[numChunks];
    for (size_t i = 0; i < numChunks; i++) {
        ciphertexts[i] = new unsigned char[chunkSizes[i]];
    }

    // Call the host function to expand the key
    unsigned char expandedKey[176];
    KeyExpansionHost(key, expandedKey);

    // Preprocess the data into chunks
    numChunks = preprocess(argv[1], AES_BLOCK_SIZE, &chunks, &chunkSizes);

    // Create a pool of CUDA streams
    cudaStream_t* streams = new cudaStream_t[numChunks];
    unsigned char** d_chunks = new unsigned char*[numChunks];
    unsigned char** d_ciphertexts = new unsigned char*[numChunks];

    // Create the worker threads
    std::thread workerThreads[8];
    for (int i = 0; i < 8; i++) {
        workerThreads[i] = std::thread(workerThread, chunks, ciphertexts, chunkSizes, expandedKey, iv, streams, d_chunks, d_ciphertexts);
    }

    // Create the write thread
    std::thread writeThreadInstance(writeThread, "encrypted.bin");

    // Add the chunks to the work queue
    for (size_t i = 0; i < numChunks; i++) {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            workQueue.push(i);
        }
        queueCondVar.notify_one();
        std::cout << "Added chunk " << i << " to work queue" << std::endl;
    }

    // Notify all waiting threads that all chunks have been processed
    queueCondVar.notify_all();

    // Wait for all threads to finish
    for (int i = 0; i < 8; i++) {
        workerThreads[i].join();
    }

    // Set allChunksProcessed to true after all chunks have been processed
    allChunksProcessed = true;
    std::cout << "WorkerThread: All chunks processed, exiting" << std::endl;

    writeCondVar.notify_all();

    // Wait for the write thread to finish
    writeThreadInstance.join();

    delete[] chunks;
    delete[] chunkSizes;
    delete[] streams;
    delete[] d_chunks;
    delete[] d_ciphertexts;

    // Get the stop time
    auto stop = std::chrono::high_resolution_clock::now();

    // Calculate the elapsed time and print
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    std::cout << "Elapsed time: " << duration.count() << " ms\n";

    return 0;
}