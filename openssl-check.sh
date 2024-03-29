#!/bin/bash

# Check if input, key, and IV files are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <plaintext file> <key file> <IV file>"
    exit 1
fi

# Assign arguments to variables
plaintext_file=$1
key_file=$2
iv_file=$3

# Read key and IV from files, removing any newlines
key=$(tr -d '\n' < "$key_file")
iv=$(tr -d '\n' < "$iv_file")

# Perform the encryption
openssl enc -aes-128-ctr -in "$plaintext_file" -out openssl_ciphertext.bin -K "$key" -iv "$iv" -nosalt

echo "OpenSSL encryption complete."

# Compare CUDA encrypted text and OpenSSL encrypted text
diff_output=$(cmp -l ciphertext.bin openssl_ciphertext.bin | wc -l)
if [ $diff_output -eq 0 ]; then
    echo "No differences"
else
    echo "$diff_output bytes are different"
fi