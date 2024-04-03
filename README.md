# ECE1782 Project: CUDA Accelerated AES Encryption

## Build and run the benchmark ##
Use a big plaintext file:
```
wget https://norvig.com/big.txt
make && ./aes-encrypt-benchmark big.txt
```
or use the default plaintext.txt:
```
make && ./aes-encrypt-benchmark
```

## Build a single version of aes-encrypt-cuda ##
For example, for v0:
1. Uncomment main function in `aes-encrypt-cuda-v0.cu`.
2. `make cuda_v0`
3. `./aes-encrypt-cuda-v0`

## Check encryption correctness ##
Use a custom plaintext file:
```
chmod +x openssl-check.sh
./openssl-check.sh <plaintext file> key.txt iv.txt
```
or use the default plaintext.txt:
```
chmod +x openssl-check.sh
./openssl-check.sh
```