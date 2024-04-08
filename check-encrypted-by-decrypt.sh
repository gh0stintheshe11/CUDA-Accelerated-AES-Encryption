#!/bin/bash

# Check if source file, key file, IV file, and encrypted file are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <source file> <key file> <IV file> <encrypted file>"
    exit 1
fi

# Assign arguments to variables
source_file=$1
key_file=$2
iv_file=$3
encrypted_file=$4

# Read key and IV from files, removing any newlines
key=$(tr -d '\n' < "$key_file")
iv=$(tr -d '\n' < "$iv_file")

# Perform the decryption
output_file=${source_file%.*}-from-decryption.${source_file##*.}
openssl enc -aes-128-ctr -d -in "$encrypted_file" -out "$output_file" -K "$key" -iv "$iv" -nosalt

# Show difference between CUDA encrypted data and OpenSSL encrypted data
diff_output=$(cmp -l $source_file $output_file | wc -l)
if [ $diff_output -eq 0 ]; then
    echo "No differences"
else
    echo "$diff_output bytes are different"
fi