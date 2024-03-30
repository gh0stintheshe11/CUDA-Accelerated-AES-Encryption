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

# Print the size of the files
ls -l openssl_ciphertext.bin ciphertext.bin

# Show difference between CUDA encrypted text and OpenSSL encrypted text
diff_output=$(cmp -l openssl_ciphertext.bin ciphertext.bin | wc -l)
if [ $diff_output -eq 0 ]; then
    echo "No differences"
else
    echo "$diff_output bytes are different"
fi

# Convert binary ciphertext to hexadecimal format
xxd -p openssl_ciphertext.bin > openssl_temp.txt
xxd -p ciphertext.bin > cuda_temp.txt

# Remove all newlines and spaces
tr -d '\n ' < openssl_temp.txt > openssl_ciphertext.txt
tr -d '\n ' < cuda_temp.txt > ciphertext.txt

# Clean up temp files
rm openssl_temp.txt
rm cuda_temp.txt

# Print the size of the files
ls -l openssl_ciphertext.txt ciphertext.txt

# Show difference between CUDA encrypted text and OpenSSL encrypted text
diff_output=$(diff -y --suppress-common-lines ciphertext.txt openssl_ciphertext.txt | wc -l)
if [ $diff_output -eq 0 ]; then
    echo "No differences"
else
    echo "$diff_output lines are different"
fi