// To build and run:
// nvcc aes-encrypt-benchmark.cpp aes-encrypt-openssl.cpp utils.cpp -o benchmark -lcrypto -lssl && ./benchmark

#include "aes-encrypt-openssl.h"

int main() {
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
  read_file_as_binary(&plaintext, &dataSize, "plaintext.txt");
  printf("\nPlain text is:\n");
  BIO_dump_fp(stdout, (const char *)plaintext, dataSize);

  // Encrypt text.
  unsigned char *ciphertext =
      (unsigned char *)malloc(dataSize * sizeof(unsigned char));
  double openssl_time =
      aes_encrypt_openssl(plaintext, dataSize, key, iv, ciphertext);
  printf("\nOpenssl runtime is: %lf ms\n", openssl_time);

  // Output encoded text to a file.
  write_ciphertext(ciphertext, dataSize, "ciphertext.txt");
  printf("\nCiphertext is:\n");
  BIO_dump_fp(stdout, (const char *)ciphertext, dataSize);

  // Cleanup.
  free(ciphertext);
  return 0;
}