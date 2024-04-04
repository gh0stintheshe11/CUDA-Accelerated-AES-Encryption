# ECE1782 Project: CUDA Accelerated AES Encryption


- aes-encrypt-cuda-v0 
    - vanilla version : no special optimization
    - pass openssl encrypt/decrypt check

- aes-encrypt-cuda-mt
    - CPU multithreading + GPU stream version: I was hoping this can optimize the data transfer and kernel excution, but I was too naive.
    - I can't get this PIECE OF SHIT to work, so I'm droping this idea.

- aes-encrypt-cuda-v1
    - memory optimization : in progress

- aes-encrypt-cuda-v2
    - memory + kernel optimization : in progress

- aes-cpu
    - CPU side AES CTR encryption implementation from scratch.


## Complie and run aes-encrypt-cuda

:boom: All file type supported

:exclamation: IV and Key can be changed in txt file.

Complie: 
```
nvcc utils-cuda.cu aes-encrypt-cuda-<version>.cu -o excutable
```
Run: 
```
./excutable <filename.type>
```
The output will contain the full run time ( not din/kernel/dout time )
```
Elapsed time: 64 ms
```
and a newly created ```encrypted.bin``` will be the encrypted data.

## Compile and run aes-cpu
```
gcc aes-cpu.c aes-cpu-main.c && ./a.out
```
Usage:
```
./a.out [input file name] [key file name] [iv file name] [output file name]
```
aes-cpu.h provides the following function:
```
void AESCTREncFile(char* in, char* iv, char* key, char* out);
```
where
```
in  - input file name
iv  - iv file name
key - key file name
out - output file name
```
note: all input/output files are read/written as binary.

## Check encryption correctness 

Run varification script:
```
./openssl-check.sh <filename.type>  key.txt iv.txt
```
The output will be similar to this:
```
OpenSSL encryption complete.
-rw-rw-r-- 1 xavia xavia 134 Apr  2 22:37 encrypted.bin
-rw-rw-r-- 1 xavia xavia 134 Apr  2 22:37 openssl_encrypted.bin
No differences
```
outputing the encryption status, relevent file status and varification results.

## Build and run the benchmark
Use a big plaintext file:
```
wget https://norvig.com/big.txt
make && ./aes-encrypt-benchmark big.txt
```
or use the default plaintext.txt:
```
make && ./aes-encrypt-benchmark
```


