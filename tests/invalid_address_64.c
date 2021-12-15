//cause a crash writing to an invalid address where the address is not valid in the 64-bit ABI.
//NOTE:  when the address would be invalid in the 64-bit ABI, we get a EXC_I386_GPFLT and 
//the access address shows up as 0.  That shouldn't count as a null deref.
//(0x0000800000000000 to 0xFFFF800000000000 is not addressable, 0xFFFF800000000000 and up is reserved for future kernel use)
#include <stdio.h>
int main () {
    printf("invalid_address_64\n");
#if defined (__x86_64__)
	char * ptr = (char*) 0x1111111111111111;
	ptr[0]=0;
#else
    //just cause a write crash, the outcome of this doesn't matter since this test is only for x86_64.
    char * ptr = (char*)0x11111111;
    ptr[0]=0;
#endif
}