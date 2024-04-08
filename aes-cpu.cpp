#include "aes-cpu.h"
#include <chrono>

void printStateBlock(CBlock_t*);

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
 *
 * Actually need:
 * B15 B11 B7 B3 
 * B14 B10 B6 B2
 * B13 B9  B5 B1
 * B12 B8  B4 B0
 *
 * So to fix this, for input
 * B0 B1 B2 B3 ... B15
 * lo should be 
 * B8 B9 B10 B11 | B12 B13 B14 B15
 * hi should be
 * B0 B1 B2 B3 | B4 B5 B6 B7
 *
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




void printBits(uint8_t a)
{
	printf("0b");
	for(int i = 7; i >= 0; i--)
	{
		if(a & (1<<i))
			printf("1");
		else
			printf("0");
		if(i == 4)
			printf("_");
	}
}

/* implementing multiplication under the finite 
 * galois field GF(2^8). Used by mixColumns. Uses
 * the irreducible polynomial specified by the 
 * NIST AES paper for modulo:
 * m(x) = x^8 + x^4 + x^3 + x + 1
 */
uint8_t _gfMul(uint8_t, uint8_t, int);
uint8_t gfMul(uint8_t a, uint8_t b)
{
	return _gfMul(a, b, DEBUG);
}

uint8_t _gfMul(uint8_t a, uint8_t b, int print)
{
	if(print)
	{
		printf("a = %02x; b = %02x\n", a, b);	
		printf("a = "); printBits(a);printf("; b = ");printBits(b);printf("\n");
	}

	uint8_t result = 0;

	/* GF(2^8) has max degree of x^7. The corresponding m(x) has max degree of x^8. */
	uint8_t coeff[16] = {0}; /* max power is 14 (7+7) so 16 should be enough. */
	
	/* go through every bit of a */
	for(int i = 0; i < 8; i++)
	{
		if(a & (1 << i))
		{
			/* go thru every bit of b */
			for(int j = 0; j < 8; j++)
			{
				if(b & (1 << j))
				{
					coeff[i+j]++;
				}
			}
		}
	}
		
	for(int i = 0; i < 16; i++)
	{
		coeff[i] = (coeff[i] % 2 == 0) ? 0 : 1;
	}


	if(print)
	{
		printf(" ");
		for(int i = 15; i>=0; i--)
			printf("%d", coeff[i]);
		printf("\n");
	}

	/* modulo m(x) */
	while(coeff[15]+coeff[14]+coeff[13]+coeff[12]+coeff[11]+coeff[10]+coeff[9]+coeff[8] != 0)
	{
		int pos = 0;
		for(int i = 15; i >= 0; i--)
		{
			if(coeff[i])
			{
				pos = i;
				break;
			}
		}
	
		coeff[pos] ^= 1; // x^8
		coeff[pos-4] ^= 1; // x^4
		coeff[pos-5] ^= 1; // x^3
		coeff[pos-7] ^= 1; // x^1
		coeff[pos-8] ^= 1; // 1		

		
		if(print)
		{
			printf("^");
			for(int i = 1; i < pos; i++)
				printf(" ");
			for(int i = 0; i < 9; i++)
			{
				if(i == 0 || i == 4 || i == 5 || i == 7 || i ==8)
				{
					printf("1");
				}
				else
				{
					printf("0");
				}
			}
			printf("\n");
			printf(" ");
			for(int i = 15; i>=0; i--)
				printf("%d", coeff[i]);
			printf("\n");
		}


	}


	/* convert coeff to byte */
	for(int i = 0; i < 16; i++)
	{
		if(i == 0)
			result += coeff[i];
		else
			result += (2 << (i-1)) * coeff[i];
	}

	if(print)
		printf("result = %02x\n", result);

	return result;	
}

/* mixColumns: take each column of the stack block, mul by the following 4x4 matrix
 * 2 3 1 1 
 * 1 2 3 1
 * 1 1 2 3
 * 3 1 1 2
 */

void mixColumns(CBlock_t* in)
{

	/* 1st column */

	/* save the column first bc we are overwriting */
	uint8_t col[4] = {0};
	uint8_t res[4] = {0};
	col[0] = in->lo & (uint64_t)0xff;
	col[1] = (in->lo & (uint64_t)0xff << (8)) >> (8);
	col[2] = (in->lo & (uint64_t)0xff << (8*2)) >> (8*2);
	col[3] = (in->lo & (uint64_t)0xff << (8*3)) >> (8*3);

	res[0] = gfMul(col[0], 2) ^ gfMul(col[1], 3) ^ gfMul(col[2], 1) ^ gfMul(col[3], 1);
	res[1] = gfMul(col[0], 1) ^ gfMul(col[1], 2) ^ gfMul(col[2], 3) ^ gfMul(col[3], 1);
	res[2] = gfMul(col[0], 1) ^ gfMul(col[1], 1) ^ gfMul(col[2], 2) ^ gfMul(col[3], 3);
	res[3] = gfMul(col[0], 3) ^ gfMul(col[1], 1) ^ gfMul(col[2], 1) ^ gfMul(col[3], 2);

	/* write to state */
	for(int i = 0; i<4; i++)
	{
		in->lo &=  ~( (uint64_t) 0xff << (8 * i) ); // clear
		in->lo |= ( (uint64_t) res[i] ) << (8 * i); // write
	}


	/* 2nd column */

	/* save the column first bc we are overwriting */
	col[0] = (in->lo & (uint64_t)0xff << (8*4)) >> (8*4);
	col[1] = (in->lo & (uint64_t)0xff << (8*5)) >> (8*5);
	col[2] = (in->lo & (uint64_t)0xff << (8*6)) >> (8*6);
	col[3] = (in->lo & (uint64_t)0xff << (8*7)) >> (8*7);

	res[0] = gfMul(col[0], 2) ^ gfMul(col[1], 3) ^ gfMul(col[2], 1) ^ gfMul(col[3], 1);
	res[1] = gfMul(col[0], 1) ^ gfMul(col[1], 2) ^ gfMul(col[2], 3) ^ gfMul(col[3], 1);
	res[2] = gfMul(col[0], 1) ^ gfMul(col[1], 1) ^ gfMul(col[2], 2) ^ gfMul(col[3], 3);
	res[3] = gfMul(col[0], 3) ^ gfMul(col[1], 1) ^ gfMul(col[2], 1) ^ gfMul(col[3], 2);

	/* write to state */
	for(int i = 0; i<4; i++)
	{
		in->lo &=  ~( (uint64_t) 0xff << (8 * (i+4)) ); // clear
		in->lo |= ( (uint64_t) res[i] ) << (8 * (i+4)); // write
	}


	/* 3rd column */

	/* save the column first bc we are overwriting */
	col[0] = in->hi & (uint64_t)0xff;
	col[1] = (in->hi & (uint64_t)0xff << (8)) >> (8);
	col[2] = (in->hi & (uint64_t)0xff << (8*2)) >> (8*2);
	col[3] = (in->hi & (uint64_t)0xff << (8*3)) >> (8*3);

	res[0] = gfMul(col[0], 2) ^ gfMul(col[1], 3) ^ gfMul(col[2], 1) ^ gfMul(col[3], 1);
	res[1] = gfMul(col[0], 1) ^ gfMul(col[1], 2) ^ gfMul(col[2], 3) ^ gfMul(col[3], 1);
	res[2] = gfMul(col[0], 1) ^ gfMul(col[1], 1) ^ gfMul(col[2], 2) ^ gfMul(col[3], 3);
	res[3] = gfMul(col[0], 3) ^ gfMul(col[1], 1) ^ gfMul(col[2], 1) ^ gfMul(col[3], 2);

	/* write to state */
	for(int i = 0; i<4; i++)
	{
		in->hi &=  ~( (uint64_t) 0xff << (8 * i) ); // clear
		in->hi |= ( (uint64_t) res[i] ) << (8 * i); // write
	}


	/* 4th column */

	/* save the column first bc we are overwriting */
	col[0] = (in->hi & (uint64_t)0xff << (8*4)) >> (8*4);
	col[1] = (in->hi & (uint64_t)0xff << (8*5)) >> (8*5);
	col[2] = (in->hi & (uint64_t)0xff << (8*6)) >> (8*6);
	col[3] = (in->hi & (uint64_t)0xff << (8*7)) >> (8*7);

	res[0] = gfMul(col[0], 2) ^ gfMul(col[1], 3) ^ gfMul(col[2], 1) ^ gfMul(col[3], 1);
	res[1] = gfMul(col[0], 1) ^ gfMul(col[1], 2) ^ gfMul(col[2], 3) ^ gfMul(col[3], 1);
	res[2] = gfMul(col[0], 1) ^ gfMul(col[1], 1) ^ gfMul(col[2], 2) ^ gfMul(col[3], 3);
	res[3] = gfMul(col[0], 3) ^ gfMul(col[1], 1) ^ gfMul(col[2], 1) ^ gfMul(col[3], 2);

	/* write to state */
	for(int i = 0; i<4; i++)
	{
		in->hi &=  ~( (uint64_t) 0xff << (8 * (i+4)) ); // clear
		in->hi |= ( (uint64_t) res[i] ) << (8 * (i+4)); // write
	}

}


/* 
 * Calculate the round key given last round key and current round number.
 * Assume 128-bit key size.
 * 
 */
void keySchedule(CBlock_t* rk, int round)
{
	if(DEBUG)
	{
		printf("Begin: Round Key generation for round %d\nInput RK:\n", round);
		printStateBlock(rk);	
	}

	/* round 0 uses encrypt key itself */
	if(round == 0)
		return;
	/* Round constant lookup */
	const uint8_t rc[10] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

	/* Save 4th column (right most) before performing rot+sub */
	uint32_t rightMostCol = (uint32_t) ( (rk->hi & ((uint64_t)0xffffffff << 32)) >> 32 );

	/* RotWord on right most column then subByte():
	 * B12		sbox(B13)
	 * B13		sbox(B14)
	 * B14   ===>	sbox(B15)
	 * B15		sbox(B12)
	 */
	uint8_t tempByte; // holds B12
	uint8_t byte;
	uint64_t mask;

	/* read B12 */
	mask = (uint64_t) 0xff << (8 * 4);
	tempByte = (uint8_t) (  ( rk->hi & mask  ) >> (8 * 4)  );
	
	// B12 = B13
	/* read B13 */
	mask = (uint64_t) 0xff << (8 * 5);
	byte = (uint8_t) (  ( rk->hi & mask  ) >> (8 * 5)  ); // B13
	/* write to B12 */
	rk->hi &=  ~( (uint64_t) 0xff << (8 * 4) ); // clear
	rk->hi |= ( (uint64_t) subByte(byte) ) << (8 * 4); // write
	
	// B13 = B14
	/* read B14 */
	mask = (uint64_t) 0xff << (8 * 6);
	byte = (uint8_t) (  ( rk->hi & mask  ) >> (8 * 6)  ); // B14
	/* write to B13 */
	rk->hi &=  ~( (uint64_t) 0xff << (8 * 5) ); // clear
	rk->hi |= ( (uint64_t) subByte(byte) ) << (8 * 5); // write

	// B14 = B15
	/* read B15 */
	mask = (uint64_t) 0xff << (8 * 7);
	byte = (uint8_t) (  ( rk->hi & mask  ) >> (8 * 7)  ); // B15
	/* write to B14 */
	rk->hi &=  ~( (uint64_t) 0xff << (8 * 6) ); // clear
	rk->hi |= ( (uint64_t) subByte(byte) ) << (8 * 6); // write

	// B15 = tempByte
	/* write to B15 */
	rk->hi &=  ~( (uint64_t) 0xff << (8 * 7) ); // clear
	rk->hi |= ( (uint64_t) subByte(tempByte) ) << (8 * 7); // write
	
	
	if(DEBUG)
	{
		printf("4th col rot+sub:\n");
		printStateBlock(rk);
	}
	

	/* left most column xor right most column xor round constant */

	for(int i = 0; i < 4; i++)
	{
		/* read B0 */
		mask = (uint64_t) 0xff << (8 * i);
		byte = (uint8_t) (  ( rk->lo & mask  ) >> (8 * i)  ); // B0
		/* read B12 */
		mask = (uint64_t) 0xff << (8 * (i+4));
		tempByte = (uint8_t) (  ( rk->hi & mask  ) >> (8 * (i+4))  ); // B12
		/* calc byte */
		byte = byte ^ tempByte ^ (  (i==0) ? rc[round - 1] : 0  );
		/* write to B0 */
		rk->lo &=  ~( (uint64_t) 0xff << (8 * i) ); // clear
		rk->lo |= ( (uint64_t) byte ) << (8 * i); // write
	}
	
	if(DEBUG)
	{
		printf("1st col done:\n");
		printStateBlock(rk);
	}
	
	uint32_t col, lcol;

	
	/* COL 2 */
	/* read col 1,2 */
	mask = (uint64_t) 0xffffffff << (32);
	col = (uint32_t) ( (rk->lo & mask) >> (32) ); // col 2
	mask = (uint64_t) 0xffffffff << (0);
	lcol = (uint32_t) ( (rk->lo & mask) >> (0) ); // col 1
	/* calc new col 2 */
	col = col ^ lcol;
	/* write back to col 2 */
	mask = (uint64_t) 0xffffffff << (32);
	rk->lo &= ~mask; // clear
	rk->lo |= ((uint64_t) col) << (32); // write

	
	if(DEBUG)
	{
		printf("2nd col done:\n");
		printStateBlock(rk);
	}

	
	/* COL 3 */
	/* read col 2,3 */
	mask = (uint64_t) 0xffffffff << (0);
	col = (uint32_t) ( (rk->hi & mask) >> (0) ); // col 3
	mask = (uint64_t) 0xffffffff << (32);
	lcol = (uint32_t) ( (rk->lo & mask) >> (32) ); // col 2
	/* calc new col 3 */
	col = col ^ lcol;
	/* write back to col 3 */
	mask = (uint64_t) 0xffffffff << (0);
	rk->hi &= ~mask; // clear
	rk->hi |= ((uint64_t) col) << (0); // write

	if(DEBUG)
	{
		printf("3rd col done:\n");
		printStateBlock(rk);
	}

	
	/* COL 4: use saved col 4 */
	/* read col 3 */
	mask = (uint64_t) 0xffffffff << (0);
	lcol = (uint32_t) ( (rk->hi & mask) >> (0) ); // col 3
	/* calc new col 4 */
	col = rightMostCol ^ lcol;
	/* write back to col 4 */
	mask = (uint64_t) 0xffffffff << (32);
	rk->hi &= ~mask; // clear
	rk->hi |= ((uint64_t) col) << (32); // write

	if(DEBUG)
	{
		printf("4th col done:\n");
		printStateBlock(rk);
	}
	

}


/*
 * addRoundKey: xor state block with current round key
 */
void addRoundKey(CBlock_t* in, CBlock_t* rk)
{
	uint32_t stateCol, rkCol;
	uint64_t mask;
	
	/* COL1 */
	mask = (uint64_t) 0xffffffff << 0;
	stateCol = (uint32_t) ((in->lo & mask) >> (0));
	rkCol = (uint32_t) ((rk->lo & mask) >> (0));
	in->lo &= ~mask; // clear
	in->lo |= ((uint64_t) (stateCol ^ rkCol)) << (0); // write

	/* COL2 */
	mask = (uint64_t) 0xffffffff << 32;
	stateCol = (uint32_t) ((in->lo & mask) >> (32));
	rkCol = (uint32_t) ((rk->lo & mask) >> (32));
	in->lo &= ~mask; // clear
	in->lo |= ((uint64_t) (stateCol ^ rkCol)) << (32); // write

	/* COL3 */
	mask = (uint64_t) 0xffffffff << 0;
	stateCol = (uint32_t) ((in->hi & mask) >> (0));
	rkCol = (uint32_t) ((rk->hi & mask) >> (0));
	in->hi &= ~mask; // clear
	in->hi |= ((uint64_t) (stateCol ^ rkCol)) << (0); // write

	/* COL4 */
	mask = (uint64_t) 0xffffffff << 32;
	stateCol = (uint32_t) ((in->hi & mask) >> (32));
	rkCol = (uint32_t) ((rk->hi & mask) >> (32));
	in->hi &= ~mask; // clear
	in->hi |= ((uint64_t) (stateCol ^ rkCol)) << (32); // write
}



/*
 * Encrypt a block. Same as openssl, iv is 128-bit
 */
void blockEncrypt(CBlock_t* in, CBlock_t* key)
{
	/* Round 0: addRoundKey with og key */
	addRoundKey(in, key);

	/* 9 main rounds */
	for(int i = 0; i < 9; i++)
	{
		keySchedule(key, i+1); // get round key: starts at round 1 goes to round 9
		subBytesBlock(in);
		shiftRows(in);
		mixColumns(in);
		addRoundKey(in, key);
	}

	/* Last Round: 10th. No mixColumns() */
	keySchedule(key, 10);
	subBytesBlock(in);
	shiftRows(in);
	addRoundKey(in, key);
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

/*
 * Reformat the input. For 128b/64B input 
 * B0 B1 B2 B3 ... B12 B13 B14 B15
 * Parameter hi contains: B0 B1 .. B7
 * Parameter lo contains: B8 B9 .. B15
 * This function construct the correct state/block
 */
void setBlock(CBlock_t* in, uint64_t hi, uint64_t lo)
{
	in->lo = 0;
	in->hi = 0;
	for(int i = 0; i < 8; i++)
	{
		uint64_t mask = (uint64_t) 0xff << (8 * i);
		uint8_t hByte = (uint8_t) ((hi & mask) >> (8 * i));
		uint8_t lByte = (uint8_t) ((lo & mask) >> (8 * i));
		in->lo |= ((uint64_t) hByte) << (8 * (7-i));
		in->hi |= ((uint64_t) lByte) << (8 * (7-i));
	}
}

void getBlock(CBlock_t* in, uint64_t* hi, uint64_t* lo)
{
	*lo = 0;
	*hi = 0;
	for(int i = 0; i < 8; i++)
	{
		uint64_t mask = (uint64_t) 0xff << (8 * i);
		uint8_t hByte = (uint8_t) ((in->hi & mask) >> (8 * i));
		uint8_t lByte = (uint8_t) ((in->lo & mask) >> (8 * i));
		*lo |= ((uint64_t) hByte) << (8 * (7-i));
		*hi |= ((uint64_t) lByte) << (8 * (7-i));
	}
}


/* Manages CTR states */
void AESCTRinit(CBlock_t* iv)
{
	uint64_t hi, lo;
	sbox = (uint8_t*) malloc(sizeof(uint8_t) * 16 * 16);
	initSbox(sbox);
	
	nonce = (CBlock_t*) malloc(sizeof(CBlock_t));
	

	getBlock(iv, &hi, &lo);

	//printf("IV init'ed to:");
	//printf("%016lx_%016lx\n", hi, lo);

	setBlock(nonce, hi, lo);	
}

void AESCTRenc(CBlock_t* data, CBlock_t* key)
{
	/* Assume nonce is ready */
	CBlock_t* n = (CBlock_t*) malloc(sizeof(CBlock_t));
	n->lo = nonce->lo; n->hi = nonce->hi;

	blockEncrypt(n, key);

	/* xor */
	data->hi ^= n->hi;
	data->lo ^= n->lo;


	free(n);

	/* incr nonce */
	uint64_t nHi, nLo, resHi, resLo;
	getBlock(nonce, &nHi, &nLo);
	resLo = nLo + 1;
	resHi = nHi + ((resLo < nLo) ? 1 : 0);
	setBlock(nonce, resHi, resLo);
	//printf("Counter:\n\t%016lx_%016lx  =>  %016lx_%016lx\n", nHi, nLo, resHi, resLo);

}

void AESCTRcleanup()
{
	free(nonce);
	free(sbox);
}


/* Some file operation Utils...  */

/* return 1 on EOF */
int fileReadBlock(CBlock_t* data, FILE* handle, int* bytesRead)
{
	uint64_t hi = 0;
	uint64_t lo = 0;
	uint8_t byte = 0;
	*bytesRead = 0;

	for(int i = 0; i < 8; i++) // read hi 8 byte
	{
		if(!fread(&byte, 1, 1, handle)) // read 1B
		{
			//printf("EOF!\n");
			hi |= ((uint64_t) byte) << (8 * ( 7 - i));
			setBlock(data, hi, lo);
			return 1;
		}
		else
		{
			*bytesRead = *bytesRead + 1;
			hi |= ((uint64_t) byte) << (8 * (7 - i));
		}
	}
	for(int i = 0; i < 8; i++) // read lo 8 byte
	{
		if(!fread(&byte, 1, 1, handle)) // read 1B
		{
			//printf("EOF!\n");
			lo |= ((uint64_t) byte) << (8 * (7 - i));
			setBlock(data, hi, lo);
			return 1;
		}
		else
		{
			*bytesRead = *bytesRead + 1;
			lo |= ((uint64_t) byte) << (8 * (7 - i));
		}
	}
	setBlock(data, hi, lo);
	return 0;
}


/* interprets file content as ascii encoded hex data */
void fileReadKey(CBlock_t* data, const char* name)
{
	uint64_t hi = 0;
	uint64_t lo = 0;
	uint8_t byte = 0;
	char buffer[3];
	buffer[2] = '\0';
	
	FILE* handle = fopen(name, "r");

	for(int i = 0; i < 8; i++) // read hi 8 byte
	{
		if(fread(buffer, 1, 2, handle) != 2) // read 2 char
		{
			printf("Wrong file format: reached EOF!\n");
			return;
		}
		else
		{
			byte = (uint8_t) strtol(buffer, NULL, 16);
			hi |= ((uint64_t) byte) << (8 * (7 - i));
		}
	}
	for(int i = 0; i < 8; i++) // read lo 8 byte
	{
		if(fread(buffer, 1, 2, handle) != 2) // read 2 char
		{
			printf("Wrong file format: reached EOF!\n");
			return;
		}
		else
		{
			byte = (uint8_t) strtol(buffer, NULL, 16);
			lo |= ((uint64_t) byte) << (8 * (7 - i));
		}
	}
	setBlock(data, hi, lo);
	fclose(handle);
}



void fileWriteBlock(CBlock_t* data, FILE* handle, int bytesToWrite)
{
	uint64_t hi = 0;
	uint64_t lo = 0;
	uint8_t byte;
	int written = 0;

	getBlock(data, &hi, &lo);

	for(int i = 0; i < 8; i++)
	{
		if(written == bytesToWrite)
			return;
		byte = (uint8_t) (  (hi & ( (uint64_t)0xff << (8 * (7 - i)) )) >> (8 * (7 - i))  );
		fwrite(&byte, 1, 1, handle);
		written++;
	}

	for(int i = 0; i < 8; i++)
	{
		if(written == bytesToWrite)
			return;
		byte = (uint8_t) (  (lo & ( (uint64_t)0xff << (8 * (7 - i)) )) >> (8 * (7 - i))  );
		fwrite(&byte, 1, 1, handle);
		written++;
	}


}

/// This is it.
double AESCTREncFile(const char *filename, const char *ivname,
                     const char *keyname, const char *outname) {
  auto start = std::chrono::high_resolution_clock::now();

  uint64_t hi, lo;
  FILE *in, *out;
  int numBytes = 0;

  CBlock_t *data = (CBlock_t *)malloc(sizeof(CBlock_t));
  CBlock_t *iv = (CBlock_t *)malloc(sizeof(CBlock_t));
  CBlock_t *key = (CBlock_t *)malloc(sizeof(CBlock_t));
  CBlock_t *blockKey = (CBlock_t *)malloc(sizeof(CBlock_t));

  fileReadKey(iv, ivname);
  fileReadKey(key, keyname);

  getBlock(iv, &hi, &lo);
  // printf("iv:\n%016lx_%016lx\n", hi, lo);

  getBlock(key, &hi, &lo);
  // printf("key:\n%016lx_%016lx\n", hi, lo);

  AESCTRinit(iv);

  in = fopen(filename, "rb");
  out = fopen(outname, "wb");

  while (fileReadBlock(data, in, &numBytes) != 1) {
    // reset key
    blockKey->lo = key->lo;
    blockKey->hi = key->hi;
    getBlock(data, &hi, &lo);
    // printf("Block Data:\n%016lx_%016lx\n", hi, lo);
    AESCTRenc(data, blockKey);
    fileWriteBlock(data, out, numBytes);
  }
  blockKey->lo = key->lo;
  blockKey->hi = key->hi;
  getBlock(data, &hi, &lo);
  // printf("Block Data:\n%016lx_%016lx\n", hi, lo);
  AESCTRenc(data, blockKey);
  fileWriteBlock(data, out, numBytes);

  // printf("Input reached EOF.\n");

  fclose(in);
  fclose(out);

  auto stop = std::chrono::high_resolution_clock::now();

  free(data);
  free(key);
  free(iv);
  free(blockKey);

  AESCTRcleanup();

  return std::chrono::duration_cast<std::chrono::milliseconds>(stop - start)
      .count();
}

/* Some tests */

void test_fileReadBlock()
{
	AESCTREncFile("aaa", "iv.txt", "key.txt", "testout.bin");
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

	free(input);
}


void test_gfMul()
{
	gfMul(0xbf, 0x03); // expected: 0xb3
	gfMul(0xd4, 0x02); // expected: 0xda
	gfMul(0x5d, 0x01); // expected: 0x5d
	gfMul(0x30, 0x01); // expected: 0x30

}

void test_mixColumns()
{
	CBlock_t* input;
	input = (CBlock_t*) malloc(sizeof(CBlock_t));
	input->lo = 0x8f26136eedbc1985;
	input->hi = 0xc2ea823cf685e061;
	


	printf("Input State\n");
	printStateBlock(input);

	mixColumns(input);

	printf("Output State\n");
	printStateBlock(input);

	free(input);
}


void test_keySchedule()
{
	CBlock_t* input;
	input = (CBlock_t*) malloc(sizeof(CBlock_t));
	input->lo = 0xa6d2ae2816157e2b;
	input->hi = 0x3c4fcf098815f7ab;
	


	printf("Input Key\n");
	printStateBlock(input);

	keySchedule(input, 1);

	printf("Round 1 RoundKey\n");
	printStateBlock(input);


	keySchedule(input, 2);

	printf("Round 2 RoundKey\n");
	printStateBlock(input);


	free(input);
}


void test_addRoundKey()
{
	CBlock_t *input, *rk;
	input = (CBlock_t*) malloc(sizeof(CBlock_t));
	rk = (CBlock_t*) malloc(sizeof(CBlock_t));
	
	input->lo = 0x82bbad40f0d3856b;
	input->hi = 0xb32cc4cd3191d88a;
	
	rk->lo = 0xb12c548817fefaa0;
	rk->hi = 0x05766c2a3939a323;


	printf("Input State\n");
	printStateBlock(input);
	printf("RK\n");
	printStateBlock(rk);

	addRoundKey(input, rk);

	printf("Output State\n");
	printStateBlock(input);


	free(input);
	free(rk);

}


void test_blockEncrypt()
{
	CBlock_t *input, *key;
	input = (CBlock_t*) malloc(sizeof(CBlock_t));
	key = (CBlock_t*) malloc(sizeof(CBlock_t));
	
	setBlock(input, 0x4c6f72656d206970, 0x73756d20646f6c6f);
	setBlock(key, 0x0001020304050607, 0x08090a0b0c0d0e0f);

	printStateBlock(input);
	printStateBlock(key);
	blockEncrypt(input, key);

	uint64_t readHi, readLo;
	getBlock(input, &readHi, &readLo);
		
	printf("Output:\n%016lx%016lx\n", readHi, readLo);


	free(input);
	free(key);


}











