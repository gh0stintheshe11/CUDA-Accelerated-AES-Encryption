// To build and run:
// nvcc aes-encrypt-openssl.c utils.c -o aes-encrypt-openssl -lcrypto -lssl && ./aes-encrypt-openssl

#include "utils.h"
#include <openssl/evp.h>
#include <string.h>

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *ivec, unsigned char *ciphertext) {
  // Initialize the library.
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
  int ciphertext_len;
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  ciphertext_len = len;

  // Finalize the encryption.
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  ciphertext_len += len;

  // Clean up.
  EVP_CIPHER_CTX_free(ctx);

  // Debug prints.
  printf("\nEncypt key is : \n");
  BIO_dump_fp(stdout, (const char *)key, AES_KEY_SIZE);

  printf("\nEncypt ivec is:\n");
  BIO_dump_fp(stdout, (const char *)ivec, 16); // 16 bytes

  printf("\nPlain text is:\n");
  BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);

  printf("\nCiphertext is:\n");
  BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

  return ciphertext_len;
}

int main() {
  // Read the key and IV.
  unsigned char key[16];
  unsigned char iv[16];
  read_key_or_iv(key, sizeof(key), "key.txt");
  read_key_or_iv(iv, sizeof(iv), "iv.txt");

  // Read the plaintext from a file.
  unsigned char plaintext[1024]; // Buffer to hold the plaintext
  read_plaintext(plaintext, sizeof(plaintext), "plaintext.txt");
  size_t dataSize = strlen((char *)plaintext); // Get the size of the plaintext

  // Encrypt text.
  unsigned char *ciphertext =
      (unsigned char *)malloc(dataSize * sizeof(unsigned char));
  aes_encrypt(plaintext, dataSize, key, iv, ciphertext);

  // Output encoded text to a file.
  write_ciphertext(ciphertext, dataSize, "ciphertext.txt");

  // Cleanup.
  free(ciphertext);
  return 0;
}