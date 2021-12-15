#include <stdlib.h>

int main() {
    setenv("MallocScribble", "1", 1);
    
    long ** buf = (long**)malloc(12);
    long * ptr = buf[0];
    long l = ptr[0];
    
}