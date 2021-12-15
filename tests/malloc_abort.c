#include <stdlib.h>

int main() {
//	setenv("MallocErrorAbort", "1", 1);
	
	char * buf = malloc(10);
	free(buf);
	free(buf);
}