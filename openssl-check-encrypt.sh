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

# Get the extension of the data file
data_file_extension="${data_file##*.}"

# Read key and IV from files, removing any newlines
key=$(tr -d '\n' < "$key_file")
iv=$(tr -d '\n' < "$iv_file")

# Perform the encryption
openssl enc -aes-128-ctr -in "$data_file" -out openssl_encrypted_original.bin -K "$key" -iv "$iv" -nosalt
echo "OpenSSL encryption complete."

# Write the data file extension and a null terminator to a separate file
echo -n ".$data_file_extension" > extension.bin
echo -ne '\0' >> extension.bin

# Concatenate the files together
cat openssl_encrypted_original.bin extension.bin > openssl_encrypted.bin
rm openssl_encrypted_original.bin 
rm extension.bin

# Print the size of the files
ls -l openssl_encrypted.bin encrypted.bin

# Show difference between CUDA encrypted data and OpenSSL encrypted data
diff_output=$(cmp -l openssl_encrypted.bin encrypted.bin | wc -l)
if [ $diff_output -eq 0 ]; then
    echo "No differences"
else
    echo "$diff_output bytes are different"
fi