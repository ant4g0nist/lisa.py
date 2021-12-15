
rtests:
	cd tests && make
	lldb -s tests/cmds.s ./tests/binaries/abort
	lldb -s tests/cmds.s ./tests/binaries/bad_func_call
	lldb -s tests/cmds.s ./tests/binaries/badsyscall
	lldb -s tests/cmds.s ./tests/binaries/cfrelease_null
	lldb -s tests/cmds.s ./tests/binaries/cpp_crash
	lldb -s tests/cmds.s ./tests/binaries/crashexec
	lldb -s tests/cmds.s ./tests/binaries/crashread
	lldb -s tests/cmds.s ./tests/binaries/crashwrite
	lldb -s tests/cmds.s ./tests/binaries/divzero
	lldb -s tests/cmds.s ./tests/binaries/exploitable_jit
	lldb -s tests/cmds.s ./tests/binaries/fastMalloc
	lldb -s tests/cmds.s ./tests/binaries/illegal_libdispatch
	lldb -s tests/cmds.s ./tests/binaries/illegalinstruction
	lldb -s tests/cmds.s ./tests/binaries/invalid_address_64
	lldb -s tests/cmds.s ./tests/binaries/malloc_abort
	lldb -s tests/cmds.s ./tests/binaries/nocrash
	lldb -s tests/cmds.s ./tests/binaries/null_objc_msgSend
	lldb -s tests/cmds.s ./tests/binaries/nullderef
	lldb -s tests/cmds.s ./tests/binaries/objc_crash
	lldb -s tests/cmds.s ./tests/binaries/read_and_write_instruction
	lldb -s tests/cmds.s ./tests/binaries/recursive_write
	lldb -s tests/cmds.s ./tests/binaries/stack_buffer_overflow
	lldb -s tests/cmds.s ./tests/binaries/uninit_heap
	lldb -s tests/cmds.s ./tests/binaries/variable_length_stack_buffer
