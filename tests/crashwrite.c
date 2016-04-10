#include <stdio.h>

int main () {
    printf("crashwrite\n");
	char * ptr = (char*) 0x61616161;
	ptr[0]=0;
}