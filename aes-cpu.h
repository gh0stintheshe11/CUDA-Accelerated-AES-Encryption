/*
 *
 * Implements AES CTR.
 * To compile and run:
 * 	gcc aes-cpu.c && ./a.out
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


#define KEY_SIZE 128
#define N_ROUND 10

#define DEBUG 0

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

typedef struct CipherBlock
{
	uint64_t lo;
	uint64_t hi;

} CBlock_t;   /* 16-byte fixed size block */


static uint8_t* sbox;
/* Manages CTR states */
static CBlock_t* nonce;


/* use this */
void AESCTREncFile(char* filename, char* ivname, char* keyname, char* outname);









