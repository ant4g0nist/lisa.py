#include <stdio.h>

int main() {
    printf("nullderef\n");
    char * ptr = 0;
    ptr[0]=0;
}