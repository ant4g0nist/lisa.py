build:
	$(shell mkdir binaries)
	clang -o binaries/abort abort.c
	clang -o binaries/bad_func_call bad_func_call.c
	clang -o binaries/badsyscall badsyscall.c
	clang -o binaries/cfrelease_null -framework Foundation cfrelease_null.c
	clang -o binaries/cpp_crash cpp_crash.cpp
	clang -o binaries/crashexec crashexec.c
	clang -o binaries/crashread crashread.c
	clang -o binaries/crashwrite crashwrite.c
	clang -o binaries/divzero divzero.c
	clang -o binaries/exploitable_jit exploitable_jit.c
	clang -o binaries/fastMalloc fastMalloc.cpp
	clang -o binaries/illegal_libdispatch illegal_libdispatch.c
	clang -o binaries/illegalinstruction illegalinstruction.c
	clang -o binaries/invalid_address_64 invalid_address_64.c
	clang -o binaries/malloc_abort malloc_abort.c
	clang -o binaries/nocrash nocrash.c
	clang -o binaries/null_objc_msgSend null_objc_msgSend.c
	clang -o binaries/nullderef nullderef.c
	clang -o binaries/objc_crash -framework Foundation objc_crash.m
	clang -o binaries/read_and_write_instruction read_and_write_instruction.c
	clang -o binaries/recursion recursion.c
	clang -o binaries/recursive_write recursive_write.c
	clang -o binaries/stack_buffer_overflow stack_buffer_overflow.c
	clang -o binaries/uninit_heap uninit_heap.c
	clang -o binaries/variable_length_stack_buffer variable_length_stack_buffer.c

test:
	./bin/crashmon ./examples/binaries/abort abort.c
	./bin/crashmon ./examples/binaries/bad_func_call bad_func_call.c
	./bin/crashmon ./examples/binaries/badsyscall badsyscall.c
	./bin/crashmon ./examples/binaries/cfrelease_null -framework Foundation cfrelease_null.c
	./bin/crashmon ./examples/binaries/cpp_crash cpp_crash.cpp
	./bin/crashmon ./examples/binaries/crashexec crashexec.c
	./bin/crashmon ./examples/binaries/crashread crashread.c
	./bin/crashmon ./examples/binaries/crashwrite crashwrite.c
	./bin/crashmon ./examples/binaries/divzero divzero.c
	./bin/crashmon ./examples/binaries/exploitable_jit exploitable_jit.c
	./bin/crashmon ./examples/binaries/fastMalloc fastMalloc.cpp
	./bin/crashmon ./examples/binaries/illegal_libdispatch illegal_libdispatch.c
	./bin/crashmon ./examples/binaries/illegalinstruction illegalinstruction.c
	./bin/crashmon ./examples/binaries/invalid_address_64 invalid_address_64.c
	./bin/crashmon ./examples/binaries/malloc_abort malloc_abort.c
	./bin/crashmon ./examples/binaries/nocrash nocrash.c
	./bin/crashmon ./examples/binaries/null_objc_msgSend null_objc_msgSend.c
	./bin/crashmon ./examples/binaries/nullderef nullderef.c
	./bin/crashmon ./examples/binaries/objc_crash -framework Foundation objc_crash.m
	./bin/crashmon ./examples/binaries/read_and_write_instruction read_and_write_instruction.c
	./bin/crashmon ./examples/binaries/recursion recursion.c
	./bin/crashmon ./examples/binaries/recursive_write recursive_write.c
	./bin/crashmon ./examples/binaries/stack_buffer_overflow stack_buffer_overflow.c
	./bin/crashmon ./examples/binaries/uninit_heap uninit_heap.c
	./bin/crashmon ./examples/binaries/variable_length_stack_buffer variable_length_stack_buffer.c