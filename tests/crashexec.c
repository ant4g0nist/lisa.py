#include <stdio.h>
int main() {
    printf("crashexec\n");
	void (*fp)() = (void(*)())0x51515151;
	(*fp)();
	
}