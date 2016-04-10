#include <stdio.h>

int main() {
    printf("bad_func_call\n");    
#if defined (__ppc__) || defined (__ppc64__)
    return 0;
#elif defined (__i386__) 
    __asm__("mov $0x77777777, %eax\n\t"
            "call *%eax"
    );
#elif defined (__x86_64__)
    __asm__("mov $0x7777777777777777, %rax\n\t"
        "call *%rax"
    );
#elif defined (__arm__)
    //on ARM, this test doesn't make as much sense because it will crash
    //executing 0x77777777, not on the blx instruction.
    __asm__("movw	r0, #30583\n\t" //0x7777
            "movt	r0, #30583\n\t" //0x7777
            "blx     r0"
            );
    /*%r0, #0x77777777\n\t"
     "bl %r0"*/
#elif defined (__arm64__)
//for now just do nothing
#else
#error Unknown architecture
#endif
}