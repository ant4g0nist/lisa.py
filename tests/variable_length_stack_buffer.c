

#define SIZE (1 << 30)
int main() {
    
    char buf[SIZE];
    //even a read from this buffer should be considered exploitable 
    //because the stack pointer is pointing outside of the stack boundaries, 
    //some evil stuff is possible.
    char c = buf[0]; 
    
}