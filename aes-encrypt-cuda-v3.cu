#include "utils.h"
#include "utils-cuda.h"

/*
    Memory optimizations:
        - Add shared memory for data with in SM -> slightly improve kernel throughput
        - Add constant memory for expanded key and IV -> slightly improve kernel throughput
        - Add stream for GPU kernel -> transfer data still waste time

    Kernel optimization:
        - CUDA intrinsic function (fast build-in functions): use __byte_perm in the ShiftRow(), use __mul24 in the mul(), __shfl_sync in kernel()
        - 
*/

__constant__ unsigned char d_sbox_v3[256];
__constant__ unsigned char d_rcon_v3[11];

// Declare constant memory variables for the IV and expanded key
__constant__ unsigned char constantIv_v3[AES_BLOCK_SIZE];
__constant__ unsigned char constantExpandedKey_v3[176];

__global__ void aes_ctr_encrypt_kernel_v3(unsigned char *plaintext, unsigned char *ciphertext, int numBlocks) {
    // Calculate the global thread ID
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    // Declare shared memory for the IV
    __shared__ unsigned char sharedIv[AES_BLOCK_SIZE];

    // Load the IV into shared memory
    if (threadIdx.x < AES_BLOCK_SIZE) {
        sharedIv[threadIdx.x] = constantIv_v3[threadIdx.x];
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
        aes_encrypt_block_v2(localIv, block, constantExpandedKey_v3, d_sbox_v3);  // Use constantExpandedKey_v3 here

        // XOR the plaintext with the encrypted block
        // __shfl_sync is used to exchange the block array between the threads in a warp. The 0xffffffff mask indicates that all threads in the warp participate in the shuffle operation. The block[i] is the value to be shuffled, and threadIdx.x is the source lane.
        #pragma unroll
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            unsigned char block_i = __shfl_sync(0xffffffff, block[i], threadIdx.x);
            ciphertext[tid * AES_BLOCK_SIZE + i] = plaintext[tid * AES_BLOCK_SIZE + i] ^ block_i;
        }
    }
}

double aes_encrypt_cuda_v3(unsigned char *plaintext, size_t dataSize,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *ciphertext) {
  double start_time = getTimeStampMs();

  unsigned char *d_plaintext, *d_ciphertext;

  // Copy S-box and rcon to device constant memory
  cudaMemcpyToSymbol(d_sbox_v3, h_sbox, sizeof(h_sbox));
  cudaMemcpyToSymbol(d_rcon_v3, h_rcon, sizeof(h_rcon));

  // Call the host function to expand the key
  unsigned char expandedKey[176];
  KeyExpansionHost_v2(key, expandedKey);

  // Copy the IV and expanded key to constant memory
  copyToConstantMemory(constantIv_v3, iv, constantExpandedKey_v3, expandedKey);

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
      aes_ctr_encrypt_kernel_v3<<<blocks, threads, 0, streams[i]>>>(
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

  // Copy device ciphertext back to host
  cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char),
             cudaMemcpyDeviceToHost);

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
//   aes_encrypt_cuda_v3(plaintext, dataSize, key, iv, ciphertext);

//   // Output encoded text to a file
//   write_ciphertext(ciphertext, dataSize, "ciphertext.txt");

//   // Cleanup
//   delete[] ciphertext;
//   delete[] plaintext;
//   return 0;
// }
