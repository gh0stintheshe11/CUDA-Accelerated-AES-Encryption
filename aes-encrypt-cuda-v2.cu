#include "utils.h"
#include "utils-cuda.h"

/*
    Memory targeted optimizations:
        - Add shared memory for data with in SM -> slightly improve kernel throughput
        - Add constant memory for expanded key and IV -> slightly improve kernel throughput
        - Add stream for GPU kernel -> transfer data still waste time
        - Add stream for CPU data transfer + GPU kernel computation -> CPU load file in buffer serially, which leads to serial stream and serial kernel excution -> waste time (basically back to v0 level...)
*/

__constant__ unsigned char d_sbox_v2[256];
__constant__ unsigned char d_rcon_v2[11];

// Declare constant memory variables for the IV and expanded key
__constant__ unsigned char constantIv_v2[AES_BLOCK_SIZE];
__constant__ unsigned char constantExpandedKey_v2[176];

__global__ void aes_ctr_encrypt_kernel_v2(unsigned char *plaintext, unsigned char *ciphertext, int numBlocks) {
    // Calculate the global thread ID
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    // Declare shared memory for the IV
    __shared__ unsigned char sharedIv[AES_BLOCK_SIZE];

    // Load the IV into shared memory
    if (threadIdx.x < AES_BLOCK_SIZE) {
        sharedIv[threadIdx.x] = constantIv_v2[threadIdx.x];
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
        aes_encrypt_block(localIv, block, constantExpandedKey_v2, d_sbox_v2);  // Use constantExpandedKey_v2 here

        // XOR the plaintext with the encrypted block
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            ciphertext[tid * AES_BLOCK_SIZE + i] = plaintext[tid * AES_BLOCK_SIZE + i] ^ block[i];
        }
    }
}

double aes_encrypt_cuda_v2(unsigned char *plaintext, size_t dataSize,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *ciphertext) {
  double start_time = getTimeStampMs();

  unsigned char *d_plaintext, *d_ciphertext;

  // Copy S-box and rcon to device constant memory
  cudaMemcpyToSymbol(d_sbox_v2, h_sbox, sizeof(h_sbox));
  cudaMemcpyToSymbol(d_rcon_v2, h_rcon, sizeof(h_rcon));

  // Call the host function to expand the key
  unsigned char expandedKey[176];
  KeyExpansionHost(key, expandedKey);

  // Copy the IV and expanded key to constant memory
  copyToConstantMemory(constantIv_v2, iv, constantExpandedKey_v2, expandedKey);

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
  cudaMalloc((void **)&d_plaintext,
             numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));
  cudaMalloc((void **)&d_ciphertext,
             numBlocks * AES_BLOCK_SIZE * sizeof(unsigned char));

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
    // Calculate the start and end indices for this stream
    size_t start = i * blocksPerStream;
    size_t end = min((i + 1) * blocksPerStream, numBlocks);

    // Calculate the actual size of the data processed by this stream
    size_t actualChunkSize = (end - start) * AES_BLOCK_SIZE;

    // Calculate the actual number of blocks for this stream
    size_t actualBlocks = end - start;

    // Copy a chunk of the plaintext from the CPU to the GPU
    cudaMemcpyAsync(&d_plaintext[start * AES_BLOCK_SIZE],
                    &paddedPlaintext[start * AES_BLOCK_SIZE], actualChunkSize,
                    cudaMemcpyHostToDevice, streams[i]);

    // Launch the kernel on the GPU
    aes_ctr_encrypt_kernel_v2<<<actualBlocks, threadsPerBlock, 0, streams[i]>>>(
        d_plaintext + start * AES_BLOCK_SIZE,
        d_ciphertext + start * AES_BLOCK_SIZE, actualBlocks);

    // Copy the processed data back from the GPU to the CPU
    cudaMemcpyAsync(&ciphertext[start * AES_BLOCK_SIZE],
                    &d_ciphertext[start * AES_BLOCK_SIZE], actualChunkSize,
                    cudaMemcpyDeviceToHost, streams[i]);
  }

  // Wait for all streams to finish
  for (int i = 0; i < numStreams; ++i) {
    cudaStreamSynchronize(streams[i]);
  }

  double end_time = getTimeStampMs();

  // Cleanup
  cudaFree(d_plaintext);
  cudaFree(d_ciphertext);
  delete[] streams;
  delete[] paddedPlaintext;
  return end_time - start_time;
}

// Comment below if run in benchmarks.
// int main() {
//   // Read the key and IV
//   unsigned char key[16];
//   unsigned char iv[16];
//   read_key_or_iv(key, sizeof(key), "key.txt");
//   read_key_or_iv(iv, sizeof(iv), "iv.txt");

//   // Determine the size of the file and read the plaintext
//   size_t dataSize;
//   unsigned char *plaintext;
//   read_file_as_binary(&plaintext, &dataSize, "plaintext.txt");

//   // Allocate memory, transfer data and run kernel.
//   unsigned char *ciphertext = new unsigned char[dataSize];
//   aes_encrypt_cuda_v2(plaintext, dataSize, key, iv, ciphertext);

//   // Output encoded text to a file
//   write_ciphertext(ciphertext, dataSize, "ciphertext.txt");

//   // Cleanup
//   delete[] plaintext;

//   return 0;
// }