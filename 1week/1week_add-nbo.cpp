#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stddef.h>

int main(int argc, char* argv[]){
	//ntohl(uint32_t)
	
	FILE *fp1, *fp2;

	fp1 = fopen(argv[1],"r");
	fp2 = fopen(argv[2],"r");

	uint32_t x,y;

	fread(&x,sizeof(uint32_t),1,fp1);
	fread(&y,sizeof(uint32_t),1,fp2);

	x = ntohl(x);
	y = ntohl(y);

	printf("%d(0x%x)+%d(0x%x)=%d(0x%x)\n",x,x,y,y,x+y,x+y);

	fclose(fp1);
	fclose(fp2);

	return 0;
}


