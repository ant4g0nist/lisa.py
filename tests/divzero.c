int main() {
	int foo = 0; //trick the compiler into actually doing a div by zero
	if (! foo) { 
		foo = foo / foo;
	}
}