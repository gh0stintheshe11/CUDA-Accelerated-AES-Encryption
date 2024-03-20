#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


#define KEY_SIZE 128
#define N_ROUND 10


#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

typedef struct CipherBlock
{
	uint64_t lo;
	uint64_t hi;

} CBlock_t;   /* 16-byte fixed size block */

static uint8_t* sbox;

/* Rijndael Forward S-box */
void initSbox(uint8_t* sbox)
{
	uint8_t p = 1, q = 1;

	do
	{
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		uint8_t xformed = q ^ ROTL8(q,1) ^ ROTL8(q,2) ^ ROTL8(q,3) ^ ROTL8(q,4);

		sbox[p] = xformed ^ 0x63;
	} while(p != 1);

	sbox[0] = 0x63;
}


uint8_t subByte(uint8_t in)
{
	return sbox[in];
}


void subBytesBlock(CBlock_t* in)
{
	uint8_t byte;
  	uint64_t mask;	
	for(int i = 0; i < 8; i++)
	{
		/* select */
		mask = (uint64_t) 0xff << (8 * i);
		byte = (uint8_t) (  ( in->lo & mask  ) >> (8 * i)  );
		/* clear */
		in->lo &=  ~( (uint64_t) 0xff << (8 * i) ); 
		/* set */
		byte = subByte(byte);
		in->lo |= ( (uint64_t) byte ) << (8 * i);
	}
	
	for(int i = 0; i < 8; i++)
	{
		/* select */
		mask = (uint64_t) 0xff << (8 * i);
		byte = (uint8_t) (  ( in->hi & mask  ) >> (8 * i)  );
		/* clear */
		in->hi &= ~( (uint64_t) 0xff << (8 * i) ); 
		/* set */
		byte = subByte(byte);
		in->hi |= ( (uint64_t) byte ) << (8 * i);
	}
}

/* https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf page 4
 * B0 B4 B8  B12
 * B1 B5 B9  B13
 * B2 B6 B10 B14
 * B3 B7 B11 B15
 * To shift rows of the state array, we need to fit the 128-bit input state
 * into 4x4 block, where each cell is a Byte. The above shows the ordering of
 * the bytes of the 128-bit block.
 * lo: B7  B6  B5  B4  | B3  B2  B1 B0
 * hi: B15 B14 B13 B12 | B11 B10 B9 B8
 */


/* t = B1, B1 = B5, B5 = B9, B9 = B13, B13 = t
 * t = B2, B2 = B6, B6 = B10, B10 = B14, B14 = t
 * t = B3, B3 = B7, B7 = B11, B11 = B15, B15 = t
 */


void shiftRows(CBlock_t* in)
{
	uint8_t tempByte = 0;
	uint8_t byte = 0;
	uint64_t mask = 0;
	/* no change to first row */
	
	/* second row shift 1 */
	tempByte = (uint8_t) ( ( in->lo & ((uint64_t)0xff << ( 8 * 1 )) ) >> 8 * 1); // t = B1
	
	// B1 = B5
	/* read B5 */
	mask = (uint64_t) 0xff << (8 * 5);
	byte = (uint8_t) (  ( in->lo & mask  ) >> (8 * 5)  ); // B5
	/* write to B1 */
	in->lo &=  ~( (uint64_t) 0xff << (8 * 1) ); // clear
	in->lo |= ( (uint64_t) byte ) << (8 * 1); // write

	// B5 = B9
	/* read B9 */
	mask = (uint64_t) 0xff << (8 * 1);
	byte = (uint8_t) (  ( in->hi & mask  ) >> (8 * 1)  ); // B9
	/* write to B5 */
	in->lo &=  ~( (uint64_t) 0xff << (8 * 5) ); // clear
	in->lo |= ( (uint64_t) byte ) << (8 * 5); // write

	// B9 = B13
	/* read B13 */
	mask = (uint64_t) 0xff << (8 * 5);
	byte = (uint8_t) (  ( in->hi & mask  ) >> (8 * 5)  ); // B13
	/* write to B9 */
	in->hi &=  ~( (uint64_t) 0xff << (8 * 1) ); // clear
	in->hi |= ( (uint64_t) byte ) << (8 * 1); // write

	// B13 = tempByte
	/* write to B13 */
	in->hi &=  ~( (uint64_t) 0xff << (8 * 5) ); // clear
	in->hi |= ( (uint64_t) tempByte ) << (8 * 5); // write



	/* third row shift 2 */
	for(int i = 0; i < 2; i++)
	{
		tempByte = (uint8_t) ( ( in->lo & ((uint64_t)0xff << ( 8 * 2 )) ) >> 8 * 2); // t = B2
		
		// B2 = B6
		/* read B6 */
		mask = (uint64_t) 0xff << (8 * 6);
		byte = (uint8_t) (  ( in->lo & mask  ) >> (8 * 6)  ); // B6
		/* write to B2 */
		in->lo &=  ~( (uint64_t) 0xff << (8 * 2) ); // clear
		in->lo |= ( (uint64_t) byte ) << (8 * 2); // write
	
		// B6 = B10
		/* read B10 */
		mask = (uint64_t) 0xff << (8 * 2);
		byte = (uint8_t) (  ( in->hi & mask  ) >> (8 * 2)  ); // B10
		/* write to B6 */
		in->lo &=  ~( (uint64_t) 0xff << (8 * 6) ); // clear
		in->lo |= ( (uint64_t) byte ) << (8 * 6); // write
	
		// B10 = B14
		/* read B14 */
		mask = (uint64_t) 0xff << (8 * 6);
		byte = (uint8_t) (  ( in->hi & mask  ) >> (8 * 6)  ); // B14
		/* write to B10 */
		in->hi &=  ~( (uint64_t) 0xff << (8 * 2) ); // clear
		in->hi |= ( (uint64_t) byte ) << (8 * 2); // write
	
		// B14 = tempByte
		/* write to B14 */
		in->hi &=  ~( (uint64_t) 0xff << (8 * 6) ); // clear
		in->hi |= ( (uint64_t) tempByte ) << (8 * 6); // write
	}
	

	/* fourth row shift 3 */
	for(int i = 0; i < 3; i++)
	{
		tempByte = (uint8_t) ( ( in->lo & ((uint64_t)0xff << ( 8 * 3 )) ) >> 8 * 3); // t = B3
		
		// B3 = B7
		/* read B7 */
		mask = (uint64_t) 0xff << (8 * 7);
		byte = (uint8_t) (  ( in->lo & mask  ) >> (8 * 7)  ); // B7
		/* write to B3 */
		in->lo &=  ~( (uint64_t) 0xff << (8 * 3) ); // clear
		in->lo |= ( (uint64_t) byte ) << (8 * 3); // write
	
		// B7 = B11
		/* read B11 */
		mask = (uint64_t) 0xff << (8 * 3);
		byte = (uint8_t) (  ( in->hi & mask  ) >> (8 * 3)  ); // B11
		/* write to B7 */
		in->lo &=  ~( (uint64_t) 0xff << (8 * 7) ); // clear
		in->lo |= ( (uint64_t) byte ) << (8 * 7); // write
	
		// B11 = B15
		/* read B15 */
		mask = (uint64_t) 0xff << (8 * 7);
		byte = (uint8_t) (  ( in->hi & mask  ) >> (8 * 7)  ); // B15
		/* write to B11 */
		in->hi &=  ~( (uint64_t) 0xff << (8 * 3) ); // clear
		in->hi |= ( (uint64_t) byte ) << (8 * 3); // write
	
		// B15 = tempByte
		/* write to B15 */
		in->hi &=  ~( (uint64_t) 0xff << (8 * 7) ); // clear
		in->hi |= ( (uint64_t) tempByte ) << (8 * 7); // write
	}
	



}



void test_subByte()
{
	for (int i  = 0; i< 16; i++)
	{
		for(int j = 0; j < 16; j++)
		{
			printf("%02x ", sbox[i*16 + j]);
		}
		printf("\n");
	}
	
	uint8_t test[] = {0x9a, 0x00, 0x13, 0xc1};

	for(int i = 0; i < 4; i++)
	{
		printf("%02x => %02x ", test[i], subByte(test[i]));
	}
	printf("\n");
}

void test_subBytesBlock()
{
	CBlock_t* input;
	input = (CBlock_t*) malloc(sizeof(CBlock_t));
	input->lo = 0xa158d1c8bc9dc1c9;
	input->hi = 0x8e9ff1c64ddce1c7;


	printf("IN  %lx_%lx\n", input->hi, input->lo);

	subBytesBlock(input);

	printf("OUT %lx_%lx\n", input->hi, input->lo);
	
	free(input);

}


void printStateBlock(CBlock_t* in)
{
	for(int i = 0; i< 4; i++)
	{
		uint64_t lswMask = (uint64_t) 0xff << (8 * i);
		uint64_t mswMask = (uint64_t) 0xff << (8 * (i+4));

		uint8_t lswLoByte = (uint8_t) ((in->lo & lswMask) >> (8 *   i   ));
		uint8_t mswLoByte = (uint8_t) ((in->lo & mswMask) >> (8 * (i+4) ));
		uint8_t lswHiByte = (uint8_t) ((in->hi & lswMask) >> (8 *   i   ));
		uint8_t mswHiByte = (uint8_t) ((in->hi & mswMask) >> (8 * (i+4) ));
		
		printf("0x %02x %02x %02x %02x\n", lswLoByte, mswLoByte, lswHiByte, mswHiByte);

	}
}


void test_shiftRows()
{
	CBlock_t* input;
	input = (CBlock_t*) malloc(sizeof(CBlock_t));
	input->lo = 0x9d58dc9fbca14d8e;
	input->hi = 0xc6c6c6c601010101;
	
	printf("Input State\n");
	printStateBlock(input);

	shiftRows(input);

	printf("Output State\n");
	printStateBlock(input);

}


int main(int argc, char** argv)
{
	sbox = (uint8_t*) malloc(sizeof(uint8_t) * 16 * 16);
	initSbox(sbox);
	

	
	//test_subBytesBlock();
	test_shiftRows();


	free(sbox);

	return 0;
}















