#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>

#define SIZE 4096
int main() {
	
	char * scode = valloc(SIZE);
	//make scode executable on 64-bit
	if (mprotect((void*)scode,  sizeof(scode), PROT_READ | PROT_WRITE | PROT_EXEC)) {
		perror("mprotect");
	}
	//0xffff is an illegal instruction on both PPC and Intel.
	memset((void*)scode,0xff,SIZE);
	void  (*fp)() = (void(*)())scode;
	(*fp) ();
}