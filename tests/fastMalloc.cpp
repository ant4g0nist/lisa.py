//WebCore fast*alloc functions call CRASH() which writes to 0xbbadbeef if
//the amount to allocate was too big.  That shouldn't be considered exploitable.


#include <stdio.h>
//as defined in wtf/Assertions.h

#define CRASH() do { \
    *(int *)(unsigned int*)0xbbadbeef = 0; \
     ((void(*)())0)(); /* More reliable, but doesn't say BBADBEEF */ \
} while(false)


//#include <JavaScriptCore/JavaScriptCore.h>
//#include <JavaScriptCore/FastMalloc.h>
int main() {
 //   void * buf = WTF::fastMalloc(-1);
    CRASH();
    printf("Should have crashed by now\n");
    
}

