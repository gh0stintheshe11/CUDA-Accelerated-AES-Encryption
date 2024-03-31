#include "utils.h"
#include "utils-cuda.h"

/*
    Base version of CUDA implementation, no special optimization
*/

__constant__ unsigned char d_sbox[256];
__constant__ unsigned char d_rcon[11];

__global__ void aes_ctr_encrypt_kernel(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *expandedKey, unsigned char *iv, int numBlocks) {
    // Calculate the global thread ID
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    // Check if the thread is within the number of blocks
    if (tid < numBlocks) {
        // Copy the IV to a local array
        unsigned char localIv[AES_BLOCK_SIZE];
        memcpy(localIv, iv, AES_BLOCK_SIZE);

        // Increment the counter in the local IV
        localIv[15] += tid;

        // Perform the AES encryption
        unsigned char block[AES_BLOCK_SIZE];
        aes_encrypt_block(localIv, block, expandedKey, d_sbox);

        // XOR the plaintext with the encrypted block
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            ciphertext[tid * AES_BLOCK_SIZE + i] = plaintext[tid * AES_BLOCK_SIZE + i] ^ block[i];
        }
    }
}

double aes_encrypt_cuda_v0(unsigned char *plaintext, size_t dataSize,
                        unsigned char *key, unsigned char *iv,
                        unsigned char *ciphertext) {
  double start_time = getTimeStampMs();

  unsigned char *d_plaintext, *d_ciphertext, *d_iv;
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
  dim3 threadsPerBlock(256); // Use a reasonable number of threads per block
  dim3 blocksPerGrid((numBlocks + threadsPerBlock.x - 1) / threadsPerBlock.x);
  // Pad the plaintext with zeros
  unsigned char *paddedPlaintext =
      new unsigned char[numBlocks * AES_BLOCK_SIZE];
  memcpy(paddedPlaintext, plaintext, dataSize);
  memset(paddedPlaintext + dataSize, 0, numBlocks * AES_BLOCK_SIZE - dataSize);

  // Allocate device memory
  cudaMalloc((void **)&d_iv, AES_BLOCK_SIZE * sizeof(unsigned char));
  cudaMalloc((void **)&d_expandedKey, 176);
  cudaMalloc((void **)&d_plaintext,
             numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));
  cudaMalloc((void **)&d_ciphertext,
             numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));

  // Copy host memory to device
  cudaMemcpy(d_plaintext, paddedPlaintext,
             numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char),
             cudaMemcpyHostToDevice);
  cudaMemcpy(d_iv, iv, AES_BLOCK_SIZE * sizeof(unsigned char),
             cudaMemcpyHostToDevice);
  cudaMemcpy(d_expandedKey, expandedKey, 176, cudaMemcpyHostToDevice);

  // Launch AES-CTR encryption kernel
  aes_ctr_encrypt_kernel<<<blocksPerGrid, threadsPerBlock>>>(
      d_plaintext, d_ciphertext, d_expandedKey, d_iv, numBlocks);

  // Copy device ciphertext back to host
  cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char),
             cudaMemcpyDeviceToHost);

  double end_time = getTimeStampMs();

  // Cleanup
  cudaFree(d_plaintext);
  cudaFree(d_ciphertext);
  cudaFree(d_iv);
  cudaFree(d_expandedKey);
  return end_time - start_time;
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
    read_file_as_binary(&plaintext, &dataSize, "plaintext.txt");

    // Allocate memory, transfer data and run kernel.
    unsigned char *ciphertext = new unsigned char[dataSize];
    aes_encrypt_cuda_v0(plaintext, dataSize, key, iv, ciphertext);

    // Output encoded text to a file
    write_ciphertext(ciphertext, dataSize, "ciphertext.txt");

    // Cleanup
    delete[] ciphertext;
    delete[] plaintext; 
    return 0;
}