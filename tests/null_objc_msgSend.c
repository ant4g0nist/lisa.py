#include <stdio.h>

//NULL derefs in objc_msgSend should not be exploitable.
void objc_msgSend() {
    char * ptr = 0;
    ptr[0]= 0;
}
int main() {
    printf("null_objc_msgSend");
    objc_msgSend();
}