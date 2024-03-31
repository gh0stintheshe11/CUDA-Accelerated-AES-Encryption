#include "utils.h"
#include "utils-cuda.h"

/*
    Memory targeted optimizations:
        - Add shared memory for data with in SM -> slightly improve kernel throughput
        - Add constant memory for expanded key and IV -> slightly improve kernel throughput
        - Add stream for GPU kernel -> transfer data still waste time
*/

__constant__ unsigned char d_sbox[256];
__constant__ unsigned char d_rcon[11];

// Declare constant memory variables for the IV and expanded key
__constant__ unsigned char constantIv[AES_BLOCK_SIZE];
__constant__ unsigned char constantExpandedKey[176];

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
        aes_encrypt_block(localIv, block, constantExpandedKey, d_sbox);  // Use constantExpandedKey here

        // XOR the plaintext with the encrypted block
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            ciphertext[tid * AES_BLOCK_SIZE + i] = plaintext[tid * AES_BLOCK_SIZE + i] ^ block[i];
        }
    }
}

double aes_encrypt_cuda_v1(unsigned char *plaintext, size_t dataSize,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *ciphertext) {
  double start_time = getTimeStampMs();

  unsigned char *d_plaintext, *d_ciphertext;

  // Copy S-box and rcon to device constant memory
  cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox));
  cudaMemcpyToSymbol(d_rcon, h_rcon, sizeof(h_rcon));

  // Call the host function to expand the key
  unsigned char expandedKey[176];
  KeyExpansionHost(key, expandedKey);

  // Copy the IV and expanded key to constant memory
  copyToConstantMemory(constantIv, iv, constantExpandedKey, expandedKey);

  // Calculate the number of AES blocks needed
  size_t numBlocks = (dataSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

  // Define the size of the grid and the blocks
  dim3 threadsPerBlock(256); // Use a reasonable number of threads per block
  dim3 blocksPerGrid((numBlocks + threadsPerBlock.x - 1) / threadsPerBlock.x);

  // Pad the plaintext with zeros
  unsigned char *paddedPlaintext =
      new unsigned char[numBlocks * AES_BLOCK_SIZE];
  memcpy(paddedPlaintext, plaintext, dataSize);

  // Allocate device memory
  cudaMalloc((void **)&d_plaintext,
             numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));
  cudaMalloc((void **)&d_ciphertext,
             numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));

  // Copy host memory to device
  cudaMemcpy(d_plaintext, plaintext, dataSize * sizeof(unsigned char),
             cudaMemcpyHostToDevice);

  // Set the rest of d_plaintext to zero
  cudaMemset(d_plaintext + dataSize, 0, numBlocks * AES_BLOCK_SIZE - dataSize);

  // Determine the number of streams based on the number of SMs
  int numStreams = 16; // Use full 82 will decrese performance, best at 8 and 16

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
      aes_ctr_encrypt_kernel<<<blocks, threads, 0, streams[i]>>>(
          d_plaintext + startBlock * AES_BLOCK_SIZE,
          d_ciphertext + startBlock * AES_BLOCK_SIZE, endBlock - startBlock);
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
  cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char),
             cudaMemcpyDeviceToHost);

  double end_time = getTimeStampMs();

  // Cleanup
  cudaFree(d_plaintext);
  cudaFree(d_ciphertext);
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
  unsigned char *plaintext;
  read_file_as_binary(&plaintext, &dataSize, "plaintext.txt");

  // Allocate memory, transfer data and run kernel.
  unsigned char *ciphertext = new unsigned char[dataSize];
  aes_encrypt_cuda_v1(plaintext, dataSize, key, iv, ciphertext);

  // Output encoded text to a file
  write_ciphertext(ciphertext, dataSize, "ciphertext.txt");

  // Cleanup
  delete[] ciphertext;
  delete[] plaintext;
  return 0;
}