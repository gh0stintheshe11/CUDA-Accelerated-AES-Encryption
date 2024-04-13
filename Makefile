objects = bm-aes-encrypt-benchmark.o aes-encrypt-openssl.o aes-cpu.o bm-aes-encrypt-cuda-v0.o bm-aes-encrypt-cuda-v1.o bm-aes-encrypt-cuda-v2.o bm-aes-encrypt-cuda-v3.1.o bm-aes-encrypt-cuda-v3.2.o bm-utils-cuda.o
all: $(objects)
	nvcc $(objects) -o aes-encrypt-benchmark -lcrypto -lssl -rdc=true

cuda_v0_objects = aes-encrypt-cuda-v0.o utils-cuda.o
cuda_v0: $(cuda_v0_objects)
	nvcc $(cuda_v0_objects) -o aes-encrypt-cuda-v0

cuda_v1_objects = aes-encrypt-cuda-v1.o utils-cuda.o
cuda_v1: $(cuda_v1_objects)
	nvcc $(cuda_v1_objects) -o aes-encrypt-cuda-v1

cuda_v2_objects = aes-encrypt-cuda-v2.o utils-cuda.o
cuda_v2: $(cuda_v2_objects)
	nvcc $(cuda_v2_objects) -o aes-encrypt-cuda-v2

cuda_v3_1_objects = aes-encrypt-cuda-v3.1.o utils-cuda.o
cuda_v3_1: $(cuda_v3_1_objects)
	nvcc $(cuda_v3_1_objects) -o aes-encrypt-cuda-v3-1

cuda_v3_2_objects = aes-encrypt-cuda-v3.2.o utils-cuda.o
cuda_v3_2: $(cuda_v3_2_objects)
	nvcc $(cuda_v3_2_objects) -o aes-encrypt-cuda-v3-2

cuda_v4_objects = aes-encrypt-cuda-v4.o utils-cuda.o
cuda_v4: $(cuda_v4_objects)
	nvcc $(cuda_v4_objects) -o aes-encrypt-cuda-v4

cuda_v5_objects = aes-encrypt-cuda-v5.o utils-cuda.o
cuda_v5: $(cuda_v5_objects)
	nvcc $(cuda_v5_objects) -o aes-encrypt-cuda-v5

cuda_v5_1_objects = aes-encrypt-cuda-v5.1.o utils-cuda.o
cuda_v5_1: $(cuda_v5_1_objects)
	nvcc $(cuda_v5_1_objects) -o aes-encrypt-cuda-v5-1

openssl_objects = aes-encrypt-openssl.o utils.o
openssl: $(openssl_objects)
	nvcc $(openssl_objects) -o aes-encrypt-openssl -lcrypto -lssl

aes-encrypt-cuda-%.o: aes-encrypt-cuda-%.cu
	nvcc -dc $< -o $@

bm-aes-encrypt-cuda-%.o: bm-aes-encrypt-cuda-%.cu
	nvcc -dc $< -o $@

aes-encrypt-openssl.o: aes-encrypt-openssl.cpp
	nvcc -dc $< -o $@

aes-cpu.o: aes-cpu.cpp
	nvcc -dc $< -o $@

bm-aes-encrypt-benchmark.o: bm-aes-encrypt-benchmark.cpp
	nvcc -dc $< -o $@

bm-utils-cuda.o: bm-utils-cuda.cu
	nvcc -dc $< -o $@

utils-cuda.o: utils-cuda.cu
	nvcc -dc $< -o $@

utils.o: utils.cpp
	nvcc -dc $< -o $@

clean:
	rm -f *.o aes-encrypt-benchmark aes-encrypt-openssl aes-encrypt-cuda-v0 aes-encrypt-cuda-v1 aes-encrypt-cuda-v2 aes-encrypt-cuda-v3