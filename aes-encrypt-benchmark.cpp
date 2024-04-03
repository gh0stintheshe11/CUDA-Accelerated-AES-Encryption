// To build and run:
// make && ./aes-encrypt-benchmark

#include "aes-encrypt-openssl.h"
#include "aes-encrypt-cuda.h"

#define RUN_FOR_AVERAGE_RUNTIME 1000

int main(int argc, char *argv[]) {
  // Read the key and IV.
  unsigned char key[16];
  unsigned char iv[16];
  read_key_or_iv(key, sizeof(key), "key.txt");
  printf("\nEncypt key is : \n");
  BIO_dump_fp(stdout, (const char *)key, AES_KEY_SIZE);
  read_key_or_iv(iv, sizeof(iv), "iv.txt");
  printf("\nEncypt iv is:\n");
  BIO_dump_fp(stdout, (const char *)iv, AES_BLOCK_SIZE);

  // Read the plaintext from a file.
  size_t dataSize;
  unsigned char *plaintext;
  if (argc >= 2) {
    // Use the filename from commmand line.
    read_file_as_binary(&plaintext, &dataSize, argv[1]);

  } else {
    // Default case: plaintext.txt
    read_file_as_binary(&plaintext, &dataSize, "plaintext.txt");
    printf("\nPlain text is:\n");
    BIO_dump_fp(stdout, (const char *)plaintext, dataSize);
  }

  // Encrypt text.
  unsigned char *ciphertext =
      (unsigned char *)malloc(dataSize * sizeof(unsigned char));
  double openssl_time = 0;
  for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
    openssl_time +=
        aes_encrypt_openssl(plaintext, dataSize, key, iv, ciphertext);
  }
  openssl_time /= RUN_FOR_AVERAGE_RUNTIME;
  printf("\nOpenssl runtime is: %lf ms\n", openssl_time);

  double cuda_v0_time = 0;
  for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
    cuda_v0_time +=
        aes_encrypt_openssl(plaintext, dataSize, key, iv, ciphertext);
  }
  cuda_v0_time /= RUN_FOR_AVERAGE_RUNTIME;
  printf("\nCuda v0 runtime is: %lf ms\n", cuda_v0_time);

  double cuda_v1_time = 0;
  for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
    cuda_v1_time +=
        aes_encrypt_cuda_v1(plaintext, dataSize, key, iv, ciphertext);
  }
  cuda_v1_time /= RUN_FOR_AVERAGE_RUNTIME;
  printf("\nCuda v1 runtime is: %lf ms\n", cuda_v1_time);

  double cuda_v2_time = 0;
  for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
    cuda_v2_time +=
        aes_encrypt_cuda_v2(plaintext, dataSize, key, iv, ciphertext);
  }
  cuda_v2_time /= RUN_FOR_AVERAGE_RUNTIME;
  printf("\nCuda v2 runtime is: %lf ms\n", cuda_v2_time);

  double cuda_v3_time = 0;
  for (int i = 0; i < RUN_FOR_AVERAGE_RUNTIME; i++) {
    cuda_v3_time +=
        aes_encrypt_cuda_v3(plaintext, dataSize, key, iv, ciphertext);
  }
  cuda_v3_time /= RUN_FOR_AVERAGE_RUNTIME;
  printf("\nCuda v3 runtime is: %lf ms\n", cuda_v3_time);

  // Output encoded text to a file.
  write_ciphertext(ciphertext, dataSize, "ciphertext.txt");
  // printf("\nCiphertext is:\n");
  // BIO_dump_fp(stdout, (const char *)ciphertext, dataSize);

  // Cleanup.
  free(plaintext);
  free(ciphertext);
  return 0;
}