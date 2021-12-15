
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <err.h>
#include <fcntl.h>



//If we crash with something like rep/movsl	(%esi),(%edi)
//we need to determine if we crashed accessing esi or edi. 
//and determine exploitability accordingly.

//This test is only relevant on Intel.

int main (int argc, char ** argv) {
#if defined (__x86_64__) || defined (__i386)
    //In practice it always seems to crash reading esi, which is what we want
    __asm__("movl $0x88888888, %esi\n\t"
            "movl $0x40000000, %edi\n\t"
            "movl $10, %ecx\n\t"
            "rep/movsl");
#endif

}