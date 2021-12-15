

void foo1(int stuff) {
	char * ptr = (char*)0x44444444;
	ptr[0] =0 ;
}
int main() {
	foo1(0);
}