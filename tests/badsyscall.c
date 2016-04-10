#include <sys/syscall.h>
#include <unistd.h>
int main() {
	syscall(0x41414141);
}