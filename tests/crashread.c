#include <stdio.h>
int main() {
    printf("crashread\n");
	char * ptr = (char*)0x41414141;
	char c = ptr[0];
}