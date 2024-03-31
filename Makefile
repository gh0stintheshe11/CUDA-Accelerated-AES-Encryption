# objects = aes-encrypt-cuda-v0.o utils.o utils-cuda.o
# all: $(objects)
# 	nvcc $(objects) -o aes-encrypt-cuda-v0

cuda_v0_objects = aes-encrypt-cuda-v0.o utils.o utils-cuda.o
cuda_v0: $(cuda_v0_objects)
	nvcc $(cuda_v0_objects) -o aes-encrypt-cuda-v0

cuda_v1_objects = aes-encrypt-cuda-v1.o utils.o utils-cuda.o
cuda_v1: $(cuda_v1_objects)
	nvcc $(cuda_v1_objects) -o aes-encrypt-cuda-v1

cuda_v2_objects = aes-encrypt-cuda-v2.o utils.o utils-cuda.o
cuda_v2: $(cuda_v2_objects)
	nvcc $(cuda_v2_objects) -o aes-encrypt-cuda-v2

cuda_v3_objects = aes-encrypt-cuda-v3.o utils.o utils-cuda.o
cuda_v3: $(cuda_v3_objects)
	nvcc $(cuda_v3_objects) -o aes-encrypt-cuda-v3

aes-encrypt-cuda-%.o: aes-encrypt-cuda-%.cu
	nvcc -dc $< -o $@

utils-cuda.o: utils-cuda.cu
	nvcc -dc $< -o $@

utils.o: utils.cpp
	nvcc -dc $< -o $@ -lcrypto -lssl

clean:
	rm -f *.o aes-encrypt-cuda-v0