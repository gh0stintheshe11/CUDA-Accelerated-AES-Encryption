#!/bin/bash

# openssl-dec.sh: Decrypt data file with openssl. Make sure input is
# in binary. (not ascii encoded binaray...) Stolen from openssl-check.sh

if [ "$#" -ne 4 ]; then
	echo "Usage: $0 <data file> <key file> <IV file> <output file>"
	exit 1
fi

data_file=$1
key_file=$2
iv_file=$3
output_file=$4

key=$(tr -d '\n' < "$key_file")
iv=$(tr -d '\n' < "$iv_file")

openssl enc -aes-128-ctr -d -in "$data_file" -out "$output_file" -K "$key" -iv "$iv" -nosalt
echo "result written in $output_file"
