/*
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

    // Preprocess the data into chunks
    unsigned char **chunks;
    size_t *chunkSizes;
    size_t chunkSize = 50*1024*1024; // Set chunks size to n MB
    printf("Preprocessing...\n");
    size_t numChunks = preprocess(argv[1], chunkSize, &chunks, &chunkSizes);
    printf("Preprocessing done. Number of chunks: %zu\n", numChunks);

    // Call the host function to expand the key
    unsigned char expandedKey[176];
    KeyExpansionHost(key, expandedKey);

    // Define the size of the grid and the blocks
    dim3 threadsPerBlock(256); // Use a reasonable number of threads per block
    dim3 blocksPerGrid((numChunks + threadsPerBlock.x - 1) / threadsPerBlock.x);

    // Allocate device memory
    unsigned char *d_expandedKey;
    cudaMalloc((void **)&d_expandedKey, 176); 

    unsigned char *d_iv;
    cudaMalloc((void **)&d_iv, AES_BLOCK_SIZE * sizeof(unsigned char));
    cudaMemcpy(d_iv, iv, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);

    // Copy S-box to device constant memory
    cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox));

    // Process each chunk
    printf("Processing chunks...\n");
    size_t totalSize = 0;

    // Define the number of streams
    const int numStreams = 4;
    cudaStream_t streams[numStreams];
    for (int i = 0; i < numStreams; i++) {
        cudaStreamCreate(&streams[i]);
    }

    // Calculate the counter increment for each chunk
    unsigned int counterIncrement = (chunkSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    for (size_t i = 0; i < numChunks; i++) {
        printf("Processing chunk %zu...\n", i);
        // Calculate the number of AES blocks needed for the current chunk
        size_t numBlocks = (chunkSizes[i] + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
        unsigned char *d_plaintext, *d_ciphertext, *d_iv;
        cudaMalloc((void **)&d_iv, AES_BLOCK_SIZE * sizeof(unsigned char));
        cudaMalloc((void **)&d_plaintext, chunkSizes[i] * sizeof(unsigned char));
        cudaMalloc((void **)&d_ciphertext, chunkSizes[i] * sizeof(unsigned char));

        // Choose a stream
        cudaStream_t stream = streams[i % numStreams];

        // Copy the current chunk to device memory
        cudaMemcpyAsync(d_plaintext, chunks[i], chunkSizes[i] * sizeof(unsigned char), cudaMemcpyHostToDevice, stream);

        // Update the counter in the IV
        unsigned int* counter = (unsigned int*)(iv + AES_BLOCK_SIZE - 4);
        *counter += i * counterIncrement;

        // Copy the updated IV to device memory
        cudaMemcpyAsync(d_iv, iv, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice, stream);

        // Copy the updated IV to device memory
        cudaMemcpy(d_iv, iv, AES_BLOCK_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);

        // Call the encryption kernel
        aes_ctr_encrypt_kernel<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_plaintext, d_ciphertext, d_expandedKey, d_iv, numBlocks, chunkSizes[i]);

        // Copy the encrypted data back to host memory
        cudaMemcpyAsync(chunks[i], d_ciphertext, chunkSizes[i] * sizeof(unsigned char), cudaMemcpyDeviceToHost, stream);

        // Free the device memory for the current chunk
        cudaFree(d_plaintext);
        cudaFree(d_ciphertext);
        cudaFree(d_iv);
        printf("Chunk %zu processed. Size: %zu bytes\n", i, chunkSizes[i]);
        totalSize += chunkSizes[i];
    }
    printf("All chunks processed. Total size: %zu bytes\n", totalSize);

    // Wait for all streams to finish
    for (int i = 0; i < numStreams; i++) {
        cudaStreamSynchronize(streams[i]);
    }

    // Output encoded text to a file
    printf("Writing encrypted data...\n");
    for (size_t i = 0; i < numChunks; i++) {
        write_encrypted_v2(chunks[i], chunkSizes[i], "encrypted.bin");
    }
    printf("Encrypted data written.\n");

    // Cleanup
    cudaFree(d_expandedKey);
    for (size_t i = 0; i < numChunks; i++) {
        cudaFreeHost(chunks[i]);
    }
    cudaFreeHost(chunks);
    cudaFreeHost(chunkSizes);
    // Destroy the streams
    for (int i = 0; i < numStreams; i++) {
        cudaStreamDestroy(streams[i]);
    }

    // Get the stop time
    auto stop = std::chrono::high_resolution_clock::now();

    // Calculate the elapsed time and print
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    std::cout << "time: " << duration.count() << " ms\n";

    // After encrypting, append the file extension to the encrypted data
    appendFileExtension("encrypted.bin", extension);
    
    return 0;
}
*/