// To build and run:
// nvcc aes-encrypt-openssl.c utils.c -o aes-encrypt-openssl -lcrypto -lssl && ./aes-encrypt-openssl

#include "aes-encrypt-openssl.h"
#include <chrono>

double aes_encrypt_openssl(unsigned char *plaintext, int plaintext_len,
                           unsigned char *key, unsigned char *ivec,
                           unsigned char *ciphertext) {
  // Initialize the library.
  auto start_time = std::chrono::high_resolution_clock::now();
  OpenSSL_add_all_algorithms();

  // Create and initialize the context.
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  // Initialize the encryption operation.
  EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, ivec);

  // Disable padding.
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  // Provide the message to be encrypted, and obtain the encrypted output.
  // EVP_EncryptUpdate can be called multiple times if necessary.
  int len;
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

  // Finalize the encryption.
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  auto end_time = std::chrono::high_resolution_clock::now();

  // Clean up.
  EVP_CIPHER_CTX_free(ctx);

  return std::chrono::duration_cast<std::chrono::microseconds>(end_time -
                                                               start_time)
      .count();
}

// Comment below if run in benchmarks.
// int main() {
//   // Read the key and IV.
//   unsigned char key[16];
//   unsigned char iv[16];
//   read_key_or_iv(key, sizeof(key), "key.txt");
//   printf("\nEncypt key is : \n");
//   BIO_dump_fp(stdout, (const char *)key, AES_KEY_SIZE);
//   read_key_or_iv(iv, sizeof(iv), "iv.txt");
//   printf("\nEncypt iv is:\n");
//   BIO_dump_fp(stdout, (const char *)iv, AES_BLOCK_SIZE);

//   // Read the plaintext from a file.
//   size_t dataSize;
//   unsigned char *plaintext;
//   read_file_as_binary(&plaintext, &dataSize, "big.txt");
//   // printf("\nPlain text is:\n");
//   // BIO_dump_fp(stdout, (const char *)plaintext, dataSize);

//   // Encrypt text.
//   unsigned char *ciphertext =
//       (unsigned char *)malloc(dataSize * sizeof(unsigned char));
//   aes_encrypt_openssl(plaintext, dataSize, key, iv, ciphertext);

//   // Output encoded text to a file.
//   write_encrypted(ciphertext, dataSize, "encrypted.bin");
//   // printf("\nCiphertext is:\n");
//   // BIO_dump_fp(stdout, (const char *)ciphertext, dataSize);

//   // Cleanup.
//   free(ciphertext);
//   return 0;
// }