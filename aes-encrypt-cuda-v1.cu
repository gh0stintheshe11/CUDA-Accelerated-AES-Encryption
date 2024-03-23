#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>
#include <string.h>

/*
    Memory targeted optimizations:
        - Add shared memory for data with in SM -> slightly improve kernel throughput
        - Add constant memory for expanded key and IV -> slightly improve kernel throughput
        - Add stream for GPU kernel -> transfer data still waste time
*/

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

// Print bytes in hexadecimal format
void print_hex(unsigned char *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

// Function to read key or IV from a file
void read_key_or_iv(unsigned char *data, size_t size, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }
    for (size_t i = 0; i < size; i++) {
        char buffer[3];
        if (fread(buffer, 1, 2, file) != 2) {
            fprintf(stderr, "Cannot read value from file: %s\n", filename);
            exit(1);
        }
        buffer[2] = '\0'; // Null-terminate the buffer
        data[i] = (unsigned char)strtol(buffer, NULL, 16); // Convert the buffer to a hexadecimal value
    }
    fclose(file);
}

void read_plaintext(unsigned char **plaintext, size_t *size, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate the buffer
    *plaintext = new unsigned char[*size];

    size_t bytesRead = fread(*plaintext, 1, *size, file);
    if (bytesRead != *size) {
        fprintf(stderr, "Failed to read the entire file: %s\n", filename);
        exit(1);
    }

    fclose(file);
}

// Function to write ciphertext to a file
void write_ciphertext(const unsigned char *ciphertext, size_t size, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }
    for (size_t i = 0; i < size; i++) {
        fprintf(file, "%02x", ciphertext[i]);
    }
    fprintf(file, "\n"); 
    fclose(file);
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
    0x00, // not used
    0x01, 0x02, 0x04, 0x08, 0x10, 
    0x20, 0x40, 0x80, 0x1B, 0x36
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
    unsigned char *plaintext;
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

    // Allocate device memory
    cudaMalloc((void **)&d_plaintext, numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_ciphertext, numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));

    // Allocate memory for the ciphertext on the host
    unsigned char *ciphertext = new unsigned char[dataSize];

    // Copy host memory to device
    cudaMemcpy(d_plaintext, plaintext, dataSize * sizeof(unsigned char), cudaMemcpyHostToDevice);

    // Set the rest of d_plaintext to zero
    cudaMemset(d_plaintext + dataSize, 0, numBlocks * AES_BLOCK_SIZE - dataSize);

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
    write_ciphertext(ciphertext, dataSize, "ciphertext.txt");

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    delete[] ciphertext;
    delete[] plaintext; 
    return 0;
}