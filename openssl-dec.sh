#!/bin/bash

# Check if input, key, IV files, and output file name are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <encrypted file> <key file> <IV file> <output file>"
    exit 1
fi

# Assign arguments to variables
encrypted_file=$1
key_file=$2
iv_file=$3
output_file=$4

# Read key and IV from files, removing any newlines
key=$(tr -d '\n' < "$key_file")
iv=$(tr -d '\n' < "$iv_file")

# Read the file extension from the end of the encrypted file
extension=$(strings "$encrypted_file" | grep -oE "\.[a-zA-Z0-9]*$" | tail -n 1)

# Perform the decryption
openssl enc -aes-128-ctr -d -in "$encrypted_file" -out "$output_file$extension" -K "$key" -iv "$iv" -nosalt
echo "Decryption complete. Decrypted file written in $output_file$extension"