#include "bm-utils-cuda.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <iostream>

unsigned char h_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned char h_rcon[11] = {
    0x00, // not used
    0x01, 0x02, 0x04, 0x08, 0x10, 
    0x20, 0x40, 0x80, 0x1B, 0x36
};

// Function to read key or IV from a file
void read_key_or_iv(unsigned char *data, size_t size, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }
    for (size_t i = 0; i < size; i++) {
        char buffer[3];
        if (fread(buffer, 1, 2, file) != 2) {
            fprintf(stderr, "Cannot read value from file: %s\n", filename);
            exit(1);
        }
        buffer[2] = '\0'; // Null-terminate the buffer
        data[i] = (unsigned char)strtol(buffer, NULL, 16); // Convert the buffer to a hexadecimal value
    }
    fclose(file);
}

void read_file_as_binary(unsigned char **data, size_t *size, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate the buffer
    *data = new unsigned char[*size];

    size_t bytesRead = fread(*data, 1, *size, file);
    if (bytesRead != *size) {
        fprintf(stderr, "Failed to read the entire file: %s\n", filename);
        exit(1);
    }

    fclose(file);
}

// Add pinned memory allocation
void read_file_as_binary_v2(unsigned char **data, size_t *size, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate pinned memory for data
    cudaMallocHost((void**)data, *size * sizeof(unsigned char));

    // Read the file into data
    if (fread(*data, 1, *size, file) != *size) {
        fprintf(stderr, "Cannot read file: %s\n", filename);
        exit(1);
    }

    fclose(file);
}

size_t preprocess(const char *filename, size_t chunkSize, unsigned char ***chunks, size_t **chunkSizes) {
    // Read the file into a buffer
    unsigned char *buffer;
    size_t bufferSize;
    read_file_as_binary_v2(&buffer, &bufferSize, filename);

    // Calculate the number of chunks
    size_t numChunks = (bufferSize + chunkSize - 1) / chunkSize;

    // Allocate pinned memory for the chunks and their sizes
    cudaMallocHost((void***)chunks, numChunks * sizeof(unsigned char*));
    cudaMallocHost((void**)chunkSizes, numChunks * sizeof(size_t));

    // Split the buffer into chunks
    for (size_t i = 0; i < numChunks; i++) {
        // Calculate the size of the current chunk
        size_t currentChunkSize = (i < numChunks - 1) ? chunkSize : (bufferSize % chunkSize);

        // Allocate pinned memory for the current chunk
        cudaMallocHost((void**)&(*chunks)[i], currentChunkSize * sizeof(unsigned char));

        printf("Chunk %zu address: %p\n", i, (*chunks)[i]);  // Print the address of the current chunk

        // Copy the data from the buffer to the current chunk
        memcpy((*chunks)[i], buffer + i * chunkSize, currentChunkSize);

        // Save the size of the current chunk
        (*chunkSizes)[i] = currentChunkSize;
    }

    // Free the buffer
    cudaFreeHost(buffer);

    return numChunks;
}

void write_encrypted(const unsigned char *ciphertext, size_t size, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }
    if (fwrite(ciphertext, 1, size, file) != size) {
        fprintf(stderr, "Error writing to file: %s\n", filename);
        exit(1);
    }
    fclose(file);
}

void write_encrypted_v2(unsigned char* ciphertext, size_t size, const char* filename) {
    FILE* file = fopen(filename, "ab");
    if (file == NULL) {
        printf("Error opening file: %s\n", filename);
        return;
    }
    if (fwrite(ciphertext, 1, size, file) != size) {
        fprintf(stderr, "Error writing to file: %s\n", filename);
        exit(1);
    }
    fclose(file);
}

std::mutex fileMutex;
void write_encrypted_multithreading(const unsigned char *ciphertext, size_t size, const char *filename) {
    std::lock_guard<std::mutex> lock(fileMutex);

    // Open the file in append mode
    FILE *file = fopen(filename, "ab");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        exit(1);
    }

    // Write the data to the file
    size_t written = fwrite(ciphertext, 1, size, file);
    if (written != size) {
        fprintf(stderr, "Failed to write to file: %s\n", filename);
        exit(1);
    }

    fclose(file);
}

std::string getFileExtension(const std::string& filename) {
    size_t pos = filename.rfind('.');
    return (pos == std::string::npos) ? "" : filename.substr(pos);
}

void appendFileExtension(const std::string& filename, const std::string& extension) {
    FILE* file = fopen(filename.c_str(), "ab");
    if (file != NULL) {
        fwrite(extension.c_str(), 1, extension.size() + 1, file);  // +1 to include null terminator
        fclose(file);
    } else {
        std::cerr << "Failed to open file: " << filename << std::endl;
    }
}

__device__ unsigned char mul(unsigned char a, unsigned char b) {
  unsigned char p = 0;
  unsigned char high_bit_mask = 0x80;
  unsigned char high_bit = 0;
  unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

  for (int i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }

    high_bit = a & high_bit_mask;
    a <<= 1;
    if (high_bit) {
      a ^= modulo;
    }
    b >>= 1;
  }

  return p;
}

void KeyExpansionHost(unsigned char *key, unsigned char *expandedKey) {
  int i = 0;
  while (i < 4) {
    for (int j = 0; j < 4; j++) {
      expandedKey[i * 4 + j] = key[i * 4 + j];
    }
    i++;
  }

  int rconIteration = 1;
  unsigned char temp[4];

  while (i < 44) {
    for (int j = 0; j < 4; j++) {
      temp[j] = expandedKey[(i - 1) * 4 + j];
    }

    if (i % 4 == 0) {
      unsigned char k = temp[0];
      for (int j = 0; j < 3; j++) {
        temp[j] = temp[j + 1];
      }
      temp[3] = k;

      for (int j = 0; j < 4; j++) {
        // Use the host-accessible arrays
        temp[j] = h_sbox[temp[j]] ^ (j == 0 ? h_rcon[rconIteration++] : 0);
      }
    }

    for (int j = 0; j < 4; j++) {
      expandedKey[i * 4 + j] = expandedKey[(i - 4) * 4 + j] ^ temp[j];
    }
    i++;
  }
}

__device__ void SubBytes(unsigned char *state, unsigned char *d_sbox) {
  for (int i = 0; i < 16; ++i) {
    state[i] = d_sbox[state[i]];
  }
}

__device__ void ShiftRows(unsigned char *state) {
  unsigned char tmp[16];

  /* Column 1 */
  tmp[0] = state[0];
  tmp[1] = state[5];
  tmp[2] = state[10];
  tmp[3] = state[15];
  /* Column 2 */
  tmp[4] = state[4];
  tmp[5] = state[9];
  tmp[6] = state[14];
  tmp[7] = state[3];
  /* Column 3 */
  tmp[8] = state[8];
  tmp[9] = state[13];
  tmp[10] = state[2];
  tmp[11] = state[7];
  /* Column 4 */
  tmp[12] = state[12];
  tmp[13] = state[1];
  tmp[14] = state[6];
  tmp[15] = state[11];

  memcpy(state, tmp, 16);
}

__device__ void MixColumns(unsigned char *state) {
  unsigned char tmp[16];

  for (int i = 0; i < 4; ++i) {
    tmp[i * 4] =
        (unsigned char)(mul(0x02, state[i * 4]) ^ mul(0x03, state[i * 4 + 1]) ^
                        state[i * 4 + 2] ^ state[i * 4 + 3]);
    tmp[i * 4 + 1] =
        (unsigned char)(state[i * 4] ^ mul(0x02, state[i * 4 + 1]) ^
                        mul(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3]);
    tmp[i * 4 + 2] = (unsigned char)(state[i * 4] ^ state[i * 4 + 1] ^
                                     mul(0x02, state[i * 4 + 2]) ^
                                     mul(0x03, state[i * 4 + 3]));
    tmp[i * 4 + 3] =
        (unsigned char)(mul(0x03, state[i * 4]) ^ state[i * 4 + 1] ^
                        state[i * 4 + 2] ^ mul(0x02, state[i * 4 + 3]));
  }

  memcpy(state, tmp, 16);
}

__device__ void AddRoundKey(unsigned char *state,
                            const unsigned char *roundKey) {
  for (int i = 0; i < 16; ++i) {
    state[i] ^= roundKey[i];
  }
}

__device__ void aes_encrypt_block(unsigned char *input, unsigned char *output,
                                  unsigned char *expandedKey,
                                  unsigned char *d_sbox) {
  unsigned char state[16];

  // Copy the input to the state array
  for (int i = 0; i < 16; ++i) {
    state[i] = input[i];
  }

  // Add the round key to the state
  AddRoundKey(state, expandedKey);

  // Perform 9 rounds of substitutions, shifts, mixes, and round key additions
  for (int round = 1; round < 10; ++round) {
    SubBytes(state, d_sbox);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, expandedKey + round * 16);
  }

  // Perform the final round (without MixColumns)
  SubBytes(state, d_sbox);
  ShiftRows(state);
  AddRoundKey(state, expandedKey + 10 * 16);

  // Copy the state to the output
  for (int i = 0; i < 16; ++i) {
    output[i] = state[i];
  }
}

__device__ void increment_counter(unsigned char *counter, int increment) {
  int carry = increment;
  for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
    int sum = counter[i] + carry;
    counter[i] = sum & 0xFF;
    carry = sum >> 8;
    if (carry == 0) {
      break;
    }
  }
}

__device__ unsigned char mul_v2(unsigned char a, unsigned char b) {
  unsigned char p = 0;
  unsigned char high_bit_mask = 0x80;
  unsigned char high_bit = 0;
  unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

  for (int i = 0; i < 8; i++) {
    p ^= a * (b & 1); // Use arithmetic instead of conditional

    high_bit = a & high_bit_mask;
    a <<= 1;
    a ^= modulo * (high_bit >> 7); // Use arithmetic instead of conditional
    b >>= 1;
  }

  return p;
}

__device__ void MixColumns_v2(unsigned char *state) {
  unsigned char tmp[16];

  for (int i = 0; i < 4; ++i) {
    tmp[i * 4] = (unsigned char)(mul_v2(0x02, state[i * 4]) ^
                                 mul_v2(0x03, state[i * 4 + 1]) ^
                                 state[i * 4 + 2] ^ state[i * 4 + 3]);
    tmp[i * 4 + 1] =
        (unsigned char)(state[i * 4] ^ mul_v2(0x02, state[i * 4 + 1]) ^
                        mul_v2(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3]);
    tmp[i * 4 + 2] = (unsigned char)(state[i * 4] ^ state[i * 4 + 1] ^
                                     mul_v2(0x02, state[i * 4 + 2]) ^
                                     mul_v2(0x03, state[i * 4 + 3]));
    tmp[i * 4 + 3] =
        (unsigned char)(mul_v2(0x03, state[i * 4]) ^ state[i * 4 + 1] ^
                        state[i * 4 + 2] ^ mul_v2(0x02, state[i * 4 + 3]));
  }

  memcpy(state, tmp, 16);
}

__device__ void aes_encrypt_block_v2(unsigned char *input,
                                     unsigned char *output,
                                     unsigned char *expandedKey,
                                     unsigned char *d_sbox) {
  unsigned char state[16];

  // Copy the input to the state array
  for (int i = 0; i < 16; ++i) {
    state[i] = input[i];
  }

  // Add the round key to the state
  AddRoundKey(state, expandedKey);

  // Perform 9 rounds of substitutions, shifts, mixes, and round key additions
  for (int round = 1; round < 10; ++round) {
    SubBytes(state, d_sbox);
    ShiftRows(state);
    MixColumns_v2(state);
    AddRoundKey(state, expandedKey + round * 16);
  }

  // Perform the final round (without MixColumns_v2)
  SubBytes(state, d_sbox);
  ShiftRows(state);
  AddRoundKey(state, expandedKey + 10 * 16);

  // Copy the state to the output
  for (int i = 0; i < 16; ++i) {
    output[i] = state[i];
  }
}