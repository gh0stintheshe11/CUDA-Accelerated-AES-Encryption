#include "utils.h"

// Print bytes in hexadecimal format
void print_hex(unsigned char *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    printf("%02x", bytes[i]);
  }
  printf("\n");
}

// Function to read key or IV from a file.
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
    data[i] = (unsigned char)strtol(
        buffer, NULL, 16); // Convert the buffer to a hexadecimal value
  }
  fclose(file);
}

// Function to read binary from a file.
void read_file_as_binary(unsigned char **data, size_t *size,
                         const char *filename) {
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

// Function to write ciphertext to a file
void write_ciphertext(const unsigned char *ciphertext, size_t size,
                      const char *filename) {
  FILE *file = fopen(filename, "w");
  if (file == NULL) {
    fprintf(stderr, "Cannot open file: %s\n", filename);
    exit(1);
  }
  for (size_t i = 0; i < size; i++) {
    fprintf(file, "%02x", ciphertext[i]);
  }
  fprintf(file, "\n");
  fclose(file);
}

double getTimeStampMs() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_usec / 1000 + tv.tv_sec * 1000;
}