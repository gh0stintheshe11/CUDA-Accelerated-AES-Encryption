#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>

int main() {
    unsigned char *plaintext;  // Host plaintext
    unsigned char *ciphertext; // Host ciphertext
    unsigned char *d_plaintext, *d_ciphertext, *d_key;
    unsigned long long int *d_nonceCounter;
    int dataSize = 1024; // Example data size, adjust as needed
    unsigned char key[AES_KEY_SIZE]; // AESi key, ensure AES_KEY_SIZE is defined
    unsigned long long int nonceCounter = 0; // Example nonceCounter, initialize appropriately

    // Allocate host memory
    plaintext = (unsigned char*)malloc(dataSize * sizeof(unsigned char));
    ciphertext = (unsigned char*)malloc(dataSize * sizeof(unsigned char));

    // Initialize plaintext and key as needed

    // Allocate device memory
    cudaMalloc((void **)&d_plaintext, dataSize * sizeof(unsigned char));
    cudaMalloc((void **)&d_ciphertext, dataSize * sizeof(unsigned char));
    cudaMalloc((void **)&d_key, AES_KEY_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_nonceCounter, sizeof(unsigned long long int));

    // Copy host memory to device
    cudaMemcpy(d_plaintext, plaintext, dataSize * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_key, key, AES_KEY_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_nonceCounter, &nonceCounter, sizeof(unsigned long long int), cudaMemcpyHostToDevice);

    // Define block and grid sizes
    int blockSize = 256; // Example, can be optimized
    int numBlocks = (dataSize + blockSize - 1) / blockSize;

    // Launch AES-CTR encryption kernel
    aes_ctr_encrypt_kernel<<<numBlocks, blockSize>>>(d_plaintext, d_ciphertext, d_key, d_nonceCounter, dataSize);

    // Copy device ciphertext back to host
    cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    cudaFree(d_key);
    cudaFree(d_nonceCounter);
    free(plaintext);
    free(ciphertext);

    return 0;
}
int main() {
    unsigned char *plaintext;  // Host plaintext
    unsigned char *ciphertext; // Host ciphertext
    unsigned char *d_plaintext, *d_ciphertext, *d_key;
    unsigned long long int *d_nonceCounter;
    int dataSize = 1024; // Example data size, adjust as needed
    unsigned char key[AES_KEY_SIZE]; // AESi key, ensure AES_KEY_SIZE is defined
    unsigned long long int nonceCounter = 0; // Example nonceCounter, initialize appropriately

    // Allocate host memory
    plaintext = (unsigned char*)malloc(dataSize * sizeof(unsigned char));
    ciphertext = (unsigned char*)malloc(dataSize * sizeof(unsigned char));

    // Initialize plaintext and key as needed

    // Allocate device memory
    cudaMalloc((void **)&d_plaintext, dataSize * sizeof(unsigned char));
    cudaMalloc((void **)&d_ciphertext, dataSize * sizeof(unsigned char));
    cudaMalloc((void **)&d_key, AES_KEY_SIZE * sizeof(unsigned char));
    cudaMalloc((void **)&d_nonceCounter, sizeof(unsigned long long int));

    // Copy host memory to device
    cudaMemcpy(d_plaintext, plaintext, dataSize * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_key, key, AES_KEY_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_nonceCounter, &nonceCounter, sizeof(unsigned long long int), cudaMemcpyHostToDevice);

    // Define block and grid sizes
    int blockSize = 256; // Example, can be optimized
    int numBlocks = (dataSize + blockSize - 1) / blockSize;

    // Launch AES-CTR encryption kernel
    aes_ctr_encrypt_kernel<<<numBlocks, blockSize>>>(d_plaintext, d_ciphertext, d_key, d_nonceCounter, dataSize);

    // Copy device ciphertext back to host
    cudaMemcpy(ciphertext, d_ciphertext, dataSize * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    // Cleanup
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    cudaFree(d_key);
    cudaFree(d_nonceCounter);
    free(plaintext);
    free(ciphertext);

    return 0;
}
