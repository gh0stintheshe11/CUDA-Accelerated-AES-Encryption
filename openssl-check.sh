#!/bin/bash

# Check if input, key, and IV files are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <data file> <key file> <IV file>"
    exit 1
fi

# Assign arguments to variables
data_file=$1
key_file=$2
iv_file=$3

# Read key and IV from files, removing any newlines
key=$(tr -d '\n' < "$key_file")
iv=$(tr -d '\n' < "$iv_file")

# Perform the encryption
openssl enc -aes-128-ctr -in "$data_file" -out openssl_encrypted.bin -K "$key" -iv "$iv" -nosalt
echo "OpenSSL encryption complete."

# Print the size of the files
ls -l openssl_encrypted.bin encrypted.bin

# Show difference between CUDA encrypted data and OpenSSL encrypted data
diff_output=$(cmp -l openssl_encrypted.bin encrypted.bin | wc -l)
if [ $diff_output -eq 0 ]; then
    echo "No differences"
else
    echo "$diff_output bytes are different"
fi