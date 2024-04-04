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


/* use this:
 * filename - plain text input file name
 * ivname   - file name of iv text file that contains 16 byte hex
 * keyname  - file name of key text file that contains 16 byte hex
 * outname  - file name of output file
 */
void AESCTREncFile(char* filename, char* ivname, char* keyname, char* outname);









