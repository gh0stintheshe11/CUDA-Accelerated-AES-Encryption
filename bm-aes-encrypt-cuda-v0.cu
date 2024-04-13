#include "bm-utils-cuda.h"
#include <chrono>
#include <cuda_runtime.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
    Base version of CUDA implementation, no special optimization
*/

__global__ void
aes_ctr_encrypt_kernel_v0(unsigned char *plaintext, unsigned char *ciphertext,
                          unsigned char *expandedKey, unsigned char *iv,
                          unsigned char *d_sbox_v0, int numBlocks, int dataSize) {
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
    int blockSize = (tid == numBlocks - 1 && dataSize % AES_BLOCK_SIZE != 0)
                        ? dataSize % AES_BLOCK_SIZE
                        : AES_BLOCK_SIZE;

    // Encrypt the counter to get the ciphertext block
    unsigned char ciphertextBlock[AES_BLOCK_SIZE];
    aes_encrypt_block(counter, ciphertextBlock, expandedKey, d_sbox_v0);

    // XOR the plaintext with the ciphertext block
    for (int i = 0; i < blockSize; ++i) {
      ciphertext[tid * AES_BLOCK_SIZE + i] =
          plaintext[tid * AES_BLOCK_SIZE + i] ^ ciphertextBlock[i];
    }
  }
}

std::pair<double, double> aes_encrypt_cuda_v0(unsigned char *plaintext,
                                              size_t dataSize,
                                              unsigned char *key,
                                              unsigned char *iv,
                                              unsigned char *ciphertext) {
  auto start = std::chrono::high_resolution_clock::now();

  unsigned char *d_plaintext, *d_ciphertext, *d_iv;
  unsigned char *d_expandedKey;
  unsigned char *d_sbox_v0;

  // Call the host function to expand the key
  unsigned char expandedKey[176];
  KeyExpansionHost(key, expandedKey);

  // Calculate the number of AES blocks needed
  size_t numBlocks = (dataSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

  // Define the size of the grid and the blocks
  dim3 threadsPerBlock(256); // Use a reasonable number of threads per block
  dim3 blocksPerGrid((numBlocks + threadsPerBlock.x - 1) / threadsPerBlock.x);

  // Allocate device memory
  cudaMalloc((void **)&d_iv, AES_BLOCK_SIZE * sizeof(unsigned char));
  cudaMalloc((void **)&d_expandedKey, 176);
  cudaMalloc((void **)&d_plaintext, dataSize * sizeof(unsigned char));
  cudaMalloc((void **)&d_ciphertext, dataSize * sizeof(unsigned char));
  cudaMalloc((void **)&d_sbox_v0, 256 * sizeof(unsigned char));

  // Copy host memory to device
  cudaMemcpy(d_plaintext, plaintext, dataSize * sizeof(unsigned char),
             cudaMemcpyHostToDevice);
  cudaMemcpy(d_iv, iv, AES_BLOCK_SIZE * sizeof(unsigned char),
             cudaMemcpyHostToDevice);
  cudaMemcpy(d_expandedKey, expandedKey, 176, cudaMemcpyHostToDevice);
  cudaMemcpy(d_sbox_v0, h_sbox, sizeof(h_sbox), cudaMemcpyHostToDevice);

  // Launch AES-CTR encryption kernel
  auto kernel_start = std::chrono::high_resolution_clock::now();
  aes_ctr_encrypt_kernel_v0<<<blocksPerGrid, threadsPerBlock>>>(
      d_plaintext, d_ciphertext, d_expandedKey, d_iv, d_sbox_v0, numBlocks,
      dataSize);

  // Synchronize device
  cudaDeviceSynchronize();
  auto kernel_stop = std::chrono::high_resolution_clock::now();

  // Copy device ciphertext back to host
  cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char),
             cudaMemcpyDeviceToHost);

  // Get the stop time
  auto stop = std::chrono::high_resolution_clock::now();

  // Cleanup
  cudaFree(d_plaintext);
  cudaFree(d_ciphertext);
  cudaFree(d_iv);
  cudaFree(d_expandedKey);
  cudaFree(d_sbox_v0);

  // Calculate the elapsed time and print
  return std::make_pair(
      std::chrono::duration_cast<std::chrono::microseconds>(stop - start)
          .count(),
      std::chrono::duration_cast<std::chrono::microseconds>(kernel_stop -
                                                            kernel_start)
          .count());
}

// int main(int argc, char* argv[]) {
//     // Check if filename is provided
//     if (argc < 2) {
//         printf("Usage: %s <filename>\n", argv[0]);
//         return 1;
//     }

//     // Get the file extension
//     std::string extension = getFileExtension(argv[1]);

//     // Read the key and IV
//     unsigned char key[16];
//     unsigned char iv[16];
//     read_key_or_iv(key, sizeof(key), "key.txt");
//     read_key_or_iv(iv, sizeof(iv), "iv.txt");

//     // Determine the size of the file and read the plaintext
//     size_t dataSize;
//     unsigned char* plaintext;
//     read_file_as_binary(&plaintext, &dataSize, argv[1]);

//     // Allocate buffer for ciphertext
//     unsigned char *ciphertext = new unsigned char[dataSize];

//     // Calculate the elapsed time and print
//     auto duration = aes_encrypt_cuda_v0(plaintext, dataSize, key, iv,
//     ciphertext); std::cout << "Elapsed time: " << duration.first << " ms\n";

//     // Output encoded text to a file
//     write_encrypted(ciphertext, dataSize, "encrypted.bin");

//     // After encrypting, append the file extension to the encrypted data
//     appendFileExtension("encrypted.bin", extension);

//     delete[] plaintext;
//     delete[] ciphertext;

//     return 0;
// }