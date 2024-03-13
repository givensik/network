#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void dump(void *p, size_t n){
	uint8_t* u8=static_cast<uint8_t*>(p);
	size_t i =0;
	while(1){
		printf("%02X", *u8++);
		if(++i>=n) break;
		if(i%8==0) printf(" ");
		if(i%16 == 0) printf("\n");
	}
	printf("\n");
}

void write_4660(){
	uint16_t port=4660;
	printf(" port number : %d\n",port);
	dump(&port, sizeof(port));
}

uint16_t my_htons(uint16_t a){
	return (a<<8)|(a>>8);
}

void write_0x1234(){
	uint8_t network_buffer[] = {0x12, 0x34};
	uint16_t* p =reinterpret_cast<uint16_t*>(network_buffer);
//	uint16_t n =*p;
	uint16_t n = my_htons(*p);//

	printf("16 bit number = 0x%x\n",n);
}
//void write_0x12345678(){
//	unit8_t n =
//}

int main(){
	write_4660();
	write_0x1234();
}
