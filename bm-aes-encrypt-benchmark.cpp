// To build and run:
// make && ./aes-encrypt-benchmark

#include "aes-cpu.h"
#include "aes-encrypt-cuda.h"
#include "aes-encrypt-openssl.h"
#include <chrono>

#define RUN_FOR_AVERAGE_RUNTIME 1000

void run_benchmark(const char *sourceFile, const char *keyFile,
                   const char *ivFile, const char *outputFile, bool skipCpu) {
  printf("Running benchmark with source file %s, key file %s, IV file %s, "
         "output file %s.\n",
         sourceFile, ivFile, keyFile, outputFile);

  auto read_files_start = std::chrono::high_resolution_clock::now();
  // Read the key and IV.
  unsigned char key[16];
  unsigned char iv[16];
  read_key_or_iv(key, sizeof(key), keyFile);
  // printf("\nEncypt key is : \n");
  // BIO_dump_fp(stdout, (const char *)key, AES_KEY_SIZE);
  read_key_or_iv(iv, sizeof(iv), ivFile);
  // printf("\nEncypt iv is:\n");
  // BIO_dump_fp(stdout, (const char *)iv, AES_BLOCK_SIZE);

  // Read the plaintext from a file.
  size_t dataSize;
  unsigned char *plaintext;
  read_file_as_binary(&plaintext, &dataSize, sourceFile);
  // printf("\nPlain text is:\n");
  // BIO_dump_fp(stdout, (const char *)plaintext, dataSize);

  auto read_files_stop = std::chrono::high_resolution_clock::now();
  double read_files_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             read_files_stop - read_files_start)
                             .count();

  // Encrypt text.
  unsigned char *ciphertext =
      (unsigned char *)malloc(dataSize * sizeof(unsigned char));
  double openssl_time = 0;
  for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
    openssl_time +=
        aes_encrypt_openssl(plaintext, dataSize, key, iv, ciphertext);
  }
  openssl_time /= RUN_FOR_AVERAGE_RUNTIME;
  printf("Openssl runtime is %lf us.\n", openssl_time);

  double cuda_v0_time = 0;
  double cuda_v0_kernel_time = 0;
  for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
    auto time_pair =
        aes_encrypt_cuda_v0(plaintext, dataSize, key, iv, ciphertext);
    cuda_v0_time += time_pair.first;
    cuda_v0_kernel_time += time_pair.second;
  }
  cuda_v0_time /= RUN_FOR_AVERAGE_RUNTIME;
  cuda_v0_kernel_time /= RUN_FOR_AVERAGE_RUNTIME;
  printf("Cuda v0 total runtime is %lf ms, kernel runtime is %lf us.\n",
         cuda_v0_time, cuda_v0_kernel_time);

  // double cuda_v1_time = 0;
  // for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
  //   cuda_v1_time +=
  //       aes_encrypt_cuda_v1(plaintext, dataSize, key, iv, ciphertext);
  // }
  // cuda_v1_time /= RUN_FOR_AVERAGE_RUNTIME;
  // printf("\nCuda v1 runtime is: %lf ms\n", cuda_v1_time);

  // double cuda_v2_time = 0;
  // for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
  //   cuda_v2_time +=
  //       aes_encrypt_cuda_v2(plaintext, dataSize, key, iv, ciphertext);
  // }
  // cuda_v2_time /= RUN_FOR_AVERAGE_RUNTIME;
  // printf("\nCuda v2 runtime is: %lf ms\n", cuda_v2_time);

  // double cuda_v3_time = 0;
  // for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
  //   cuda_v3_time +=
  //       aes_encrypt_cuda_v3(plaintext, dataSize, key, iv, ciphertext);
  // }
  // cuda_v3_time /= RUN_FOR_AVERAGE_RUNTIME;
  // printf("\nCuda v3 runtime is: %lf ms\n", cuda_v3_time);

  // Output encoded text to a file.
  auto write_file_start = std::chrono::high_resolution_clock::now();
  write_encrypted(ciphertext, dataSize, outputFile);
  // printf("\nCiphertext is:\n");
  // BIO_dump_fp(stdout, (const char *)ciphertext, dataSize);
  auto write_file_stop = std::chrono::high_resolution_clock::now();
  double write_file_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             write_file_stop - write_file_start)
                             .count();

  // Cleanup.
  free(plaintext);
  free(ciphertext);

  if (skipCpu)
    return;
  // CPU implementation reads/writes files chunk by chunk, so pure runtime
  // cannot be calculated. Offset the time using read/write file time for
  // OpenSSL and CUDA implementation for a fair comparision.
  double cpu_time_total =
      AESCTREncFile(sourceFile, ivFile, keyFile, outputFile);
  printf("CPU runtime is %lf ms.\n\n",
         cpu_time_total - read_files_ms - write_file_ms);
}

int main(int argc, char *argv[]) {
  run_benchmark("small.txt", "key.txt", "iv.txt", "small.txt.encrypted", false);
  run_benchmark("big.txt", "key.txt", "iv.txt", "big.txt.encrypted", false);
  return 0;
}