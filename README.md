# ECE1782 Project: CUDA Accelerated AES Encryption


- aes-encrypt-openssl
    - Reference implementation using OpenSSL APIs running on 4 CPU threads

- aes-cpu
    - CPU side AES CTR encryption single-thread naive implementation from scratch.

- aes-encrypt-cuda-v0 
    - vanilla version: no special optimization
    - pass openssl encrypt/decrypt check

- aes-encrypt-cuda-v1
    - v0 + memory optimizations:
        - Constant Memory: S box
        - Shared Memory: IV and expanded key    
        - Pinned Memory: plaintext and ciphertext 

- aes-encrypt-cuda-v2
    - v1 + coalesced memory access: in previous code, each thread is accessing
        a different block of the plaintext and ciphertext arrays. If the blocks are
        not contiguous in memory, this could slow down the program. This code
        rearrange the data so that the blocks accessed by threads in the same warp
        are contiguous in memory.

- aes-encrypt-cuda-v3.1
    - v2 + divergence avoidance: in the original kernel function, the divergence is caused by the conditional statement if (blockId < numBlocks). This divergence can be avoided by ensuring that the number of threads is a multiple of the number of blocks, which means padding the data to a multiple of the block size.

- aes-encrypt-cuda-v3.2
    - v3.1 + more divergence avoidance: In this modified version, the if (b & 1) and if (high_bit) conditions in mul function are replaced with arithmetic operations. This ensures all threads in a warp take the same execution path, avoiding divergence.

- aes-encrypt-cuda-v4
    - v3.1 + Loop Unrolling and Intrinsic function
        - Loop Unrolling: add loop unrolling to small(eliminating loop control overhead)/compute-focused(allow for more instruction-level parallelism) loops not large(increasing the register pressure)/memory-focused(lead to instruction cache misses) loops. mul(), SubBytes(), MixColumns(), AddRoundKey(), aes_encrypt_block(): 9_rounds and state_to_output, aes_ctr_encrypt_kernel(): XOR.
        - Intrinsic Function: use fast build-in function __ldg() to load and cache iv and expandedkey.

- aes-encrypt-cuda-v5
    - v4 + Stream: add stream for kernel. However due to host side increment variable code excution between kernel lunches, the kernel stream are not really excuting in parallel but in serial. The increment code is used to calculate unique IV for every stream/data chunks, but since it is a host side function, which natruelly excute in serial, the code actually block the next kernel lunch until it is finished.

- aes-encrypt-cuda-v5.1
    - v5 + improved stream and more:
        - Modify the code to precalculate all nessaray variables before lunchun kernel, whcih makes every stream truly independent.
        - Modify the mul() and merge aes-encrypt-block() with kernel to reduce local variable use to reduce register use. This optimization is based on Nsight Compute report. Since register's are shared between warps, use limted register allows the program to achieve max warp occupency.



## Build and run the benchmark
```
wget https://norvig.com/big.txt && make && ./aes-encrypt-benchmark
```
It will printout the runtime for OpenSSL, CPU version and different CUDA verisons.

## Complie and run each aes-encrypt-cuda version individually

:boom: All file type supported

:exclamation: IV and Key can be changed in `iv.txt` and `key.txt`.

Complie (check Makefile for more options):
```
make cuda_v5_1
```
Run: 
```
./aes-encrypt-cuda-v5-1 [filename_to_encrypt]
```
The output will contain the full run time (not din/kernel/dout time) and a newly created ```encrypted.bin``` will be the encrypted data.

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
:musical_note: note: all input/output files are read/written as binary.

## Check encryption correctness 

Run varification script:
```
./check-encrypted-by-decrypt.sh <source file> <key file> <IV file> <encrypted file>
```
This script will decrypt `<encrypted file>` using OpenSSL CLI and compare with `<source file>`.
Thie output will be "No differences" or "* bytes are different".