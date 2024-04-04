#include "aes-cpu.h"



int main(int argc, char** argv)
{

	if(argc != 5)
	{
		printf("Usage:\n\t%s [input file] [key] [iv] [output file]\n", argv[0]);
		return 0;
	}

	printf("Input file: %s\nKey file: %s\n IV file: %s\nOutput file: %s\n", argv[1], argv[2], argv[3], argv[4]);

	AESCTREncFile(argv[1], argv[3], argv[2], argv[4]);
	
	return 0;
}
