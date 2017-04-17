# lisa.py
-An Exploit Dev Swiss Army Knife. 

# Installation
Copy lisa.py and .lldbinit to ~/ 
Use the following commands:

	ant4g0nist$ cp lisa.py ~/lisa.py

	ant4g0nist$ cp lldbinit ~/.lldbinit

	<!-- this installs requests and capstone libraries -->
	ant4g0nist$ sudo pip install -r requirements.txt

	ant4g0nist$ lldb
        
        lllllll   iiii
        l:::::l  i::::i
        l:::::l   iiii
        l:::::l
        l::::l iiiiiii     ssssssssss     aaaaaaaaaaaaa
        l::::l i:::::i   ss::::::::::s    a::::::::::::a
        l::::l  i::::i ss:::::::::::::s   aaaaaaaaa:::::a
        l::::l  i::::i s::::::ssss:::::s           a::::a
        l::::l  i::::i  s:::::s  ssssss     aaaaaaa:::::a
        l::::l  i::::i    s::::::s        aa::::::::::::a
        l::::l  i::::i       s::::::s    a::::aaaa::::::a
        l::::l  i::::i ssssss   s:::::s a::::a    a:::::a
        l::::::li::::::is:::::ssss::::::sa::::a    a:::::a
        l::::::li::::::is::::::::::::::s a:::::aaaa::::::a
        l::::::li::::::i s:::::::::::ss   a::::::::::aa:::a
        lllllllliiiiiiii  sssssssssss      aaaaaaaaaa  aaaa
        
		-An Exploit Dev Swiss Army Knife. Version: v-ni

	(lisa)target create tests/binaries/abort
	(lisa)process launch -s
	Process 1660 stopped
	* thread #1: tid = 0x10801, 0x00007fff5fc01000 dyld`_dyld_start, stop reason = signal SIGSTOP
	    frame #0: 0x00007fff5fc01000 dyld`_dyld_start
	dyld`_dyld_start:
	->  0x7fff5fc01000 <+0>: pop    rdi
	    0x7fff5fc01001 <+1>: push   0x0
	    0x7fff5fc01003 <+3>: mov    rbp, rsp
	    0x7fff5fc01006 <+6>: and    rsp, -0x10
	Process 1660 launched: '/Users/v0id/Documents/Research/lisa.py/tests/binaries/abort' (x86_64)

# Commands Available:
	
	
	**exploitable** : checks if the crash is exploitable
		<!-- run this when the process stops cause of an exception -->

		(lisa)exploitable

	**shellcode**: Searches shell-storm for shellcode

		(lisa)shellcode 
		Syntax:   shellcode <option> <arg>

		Options:  -search <keyword>
		          -display <shellcode id>
		          -save <shellcode id>
		(lisa)shellcode -search osx
		Connecting to shell-storm.org...
		Found 17 shellcodes
		ScId	Size Title
		[312]	300  Osx/ppc - Bind Shell PORT TCP/8000 - encoder OSXPPCLongXOR - 300 bytes
		[127]	222  Osx/ppc - add inetd backdoor - 222 bytes
		[128]	219  Osx/ppc - Add user r00t - 219 bytes
		[761]	131  Osx/x86-64 - reverse tcp shellcode - 131 bytes
		[126]	122  Osx/ppc - create /tmp/suid - 122 bytes
		[129]	72   Osx/ppc - execve(/bin/sh,[/bin/sh],NULL)& exit() - 72 bytes
		[736]	51   Osx/x86-64 - setuid shell x86_64 - 51 bytes
		[130]	32   Osx/ppc - sync(), reboot() - 32 bytes
		[692]	24   Osx/x86 - execve(/bin/sh) - 24 byte
		[121]	n/a  Osx/ppc - remote findsock by recv() key shellcode
		[122]	n/a  Osx/ppc - Single Reverse TCP
		[123]	n/a  Osx/ppc - stager sock find peek
		[124]	n/a  Osx/ppc - stager sock find
		[125]	n/a  Osx/ppc - stager sock reverse
		[120]	n/a  Osx/ppc - shellcode execve(/bin/sh)
		[777]	n/a  Osx/x86-64 - universal ROP shellcode
		[786]	n/a  Osx/x86-64 - universal OSX dyld ROP shellcode	


	**launch**: launch the process from /Applications folder given process name:

			(lisa) launch safari
			Current executable set to '/Applications/Safari.app' (x86_64).
			Shall i run /Applications/Safari.app?y/n : n
			
	**extract**: Extract a given architecture from a Universal binary

		(lisa)extract
		Syntax: extract x86_64 /usr/lib/system/libsystem_kernel.dylib ./libsystem_kernel.dylib
		(lisa)extract x86_64 /usr/lib/system/libsystem_kernel.dylib ./libsystem_kernel.dylib
		(lisa)

	**patterncreate**: Creates a cyclic pattern of given length

		(lisa)patterncreate 100
		Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

	**patternoffset**: Finds the offset of a given pattern in cyclic pattern of n length

		(lisa)patternoffset 100 Ad2A
		Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
		offsets: [96]
		(lisa)

	**ct**: Prints the context of execution

		(lisa)ct
			[disassembly]
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			->  0x1000e30b5 <+21>: je     0x1000e30c2               ; <+34>
			    0x1000e30b7 <+23>: nop    word ptr [rax + rax]
			    0x1000e30c0 <+32>: jmp    0x1000e30c0               ; <+32>
			    0x1000e30c2 <+34>: lea    rbx, [rip + 0xcef7d7]     ; __asan::asan_flags_dont_use_directly

			[/disassembly]
			[jump]
			Jumping to  0x1000e30c2
			disassembly at  0x1000e30c2
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			    0x1000e30c2 <+34>: lea    rbx, [rip + 0xcef7d7]     ; __asan::asan_flags_dont_use_directly
			    0x1000e30c9 <+41>: mov    esi, dword ptr [rbx + 0x34]

			[/jump]
			[registers]
				 rax = 0x0000000000000000
				 rbx = 0x00000001032bd000
				 rcx = 0x0000000000000000
				 rdx = 0x00007fff5fbfed8a
				 rdi = 0x00000001005c2178  libclang_rt.asan_osx_dynamic.dylib`crashreporter_info_mutex
				 rsi = 0x00007fff5fbfed70
				 rbp = 0x00007fff5fbff010
				 rsp = 0x00007fff5fbff000
				 r8 = 0x00000001005b2a3c  libclang_rt.asan_osx_dynamic.dylib`__crashreporter_info_buff__ + 2332
				 r9 = 0x0000000000000012
				 r10 = 0x0000000000000012
				 r11 = 0x0000000000000003
				 r12 = 0x0000000100108624  "\e[1m\e[0m"
				 r13 = 0x00007fff5fbff9a0
				 r14 = 0x00007fff5fbff960
				 r15 = 0x0000000100361120  libclang_rt.asan_osx_dynamic.dylib`__asan::error_message_buf_mutex
				 rip = 0x00000001000e30b5  libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie() + 21
				 rflags = 0x0000000000000246
				 cs = 0x000000000000002b
				 fs = 0x0000000000000000
				 gs = 0x0000000000000000
			[/registers]
		(lisa)

	**s**: thread step-in

		(lisa)s
			[disassembly]
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			->  0x1000e30c2 <+34>: lea    rbx, [rip + 0xcef7d7]     ; __asan::asan_flags_dont_use_directly
			    0x1000e30c9 <+41>: mov    esi, dword ptr [rbx + 0x34]
			    0x1000e30cc <+44>: test   esi, esi
			    0x1000e30ce <+46>: je     0x1000e30e6               ; <+70>

			[/disassembly]
			[registers]
				 rax = 0x0000000000000000
				 rbx = 0x00000001032bd000
				 rcx = 0x0000000000000000
				 rdx = 0x00007fff5fbfed8a
				 rdi = 0x00000001005c2178  libclang_rt.asan_osx_dynamic.dylib`crashreporter_info_mutex
				 rsi = 0x00007fff5fbfed70
				 rbp = 0x00007fff5fbff010
				 rsp = 0x00007fff5fbff000
				 r8 = 0x00000001005b2a3c  libclang_rt.asan_osx_dynamic.dylib`__crashreporter_info_buff__ + 2332
				 r9 = 0x0000000000000012
				 r10 = 0x0000000000000012
				 r11 = 0x0000000000000003
				 r12 = 0x0000000100108624  "\e[1m\e[0m"
				 r13 = 0x00007fff5fbff9a0
				 r14 = 0x00007fff5fbff960
				 r15 = 0x0000000100361120  libclang_rt.asan_osx_dynamic.dylib`__asan::error_message_buf_mutex
				 rip = 0x00000001000e30c2  libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie() + 34
				 rflags = 0x0000000000000246
				 cs = 0x000000000000002b
				 fs = 0x0000000000000000
				 gs = 0x0000000000000000
			[/registers]

	**si**: thread step-into

		(lisa)si
			[disassembly]
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			->  0x1000e30c9 <+41>: mov    esi, dword ptr [rbx + 0x34]
			    0x1000e30cc <+44>: test   esi, esi
			    0x1000e30ce <+46>: je     0x1000e30e6               ; <+70>
			    0x1000e30d0 <+48>: lea    rdi, [rip + 0x261a3]      ; "Sleeping for %d second(s)\n"

			[/disassembly]
			[registers]
				 rax = 0x0000000000000000
				 rbx = 0x0000000100dd28a0  libclang_rt.asan_osx_dynamic.dylib`__asan::asan_flags_dont_use_directly
				 rcx = 0x0000000000000000
				 rdx = 0x00007fff5fbfed8a
				 rdi = 0x00000001005c2178  libclang_rt.asan_osx_dynamic.dylib`crashreporter_info_mutex
				 rsi = 0x00007fff5fbfed70
				 rbp = 0x00007fff5fbff010
				 rsp = 0x00007fff5fbff000
				 r8 = 0x00000001005b2a3c  libclang_rt.asan_osx_dynamic.dylib`__crashreporter_info_buff__ + 2332
				 r9 = 0x0000000000000012
				 r10 = 0x0000000000000012
				 r11 = 0x0000000000000003
				 r12 = 0x0000000100108624  "\e[1m\e[0m"
				 r13 = 0x00007fff5fbff9a0
				 r14 = 0x00007fff5fbff960
				 r15 = 0x0000000100361120  libclang_rt.asan_osx_dynamic.dylib`__asan::error_message_buf_mutex
				 rip = 0x00000001000e30c9  libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie() + 41
				 rflags = 0x0000000000000246
				 cs = 0x000000000000002b
				 fs = 0x0000000000000000
				 gs = 0x0000000000000000
			[/registers]

	**so**: thread step-over
		
		(lisa)so
			[disassembly]
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			->  0x1000e30cc <+44>: test   esi, esi
			    0x1000e30ce <+46>: je     0x1000e30e6               ; <+70>
			    0x1000e30d0 <+48>: lea    rdi, [rip + 0x261a3]      ; "Sleeping for %d second(s)\n"
			    0x1000e30d7 <+55>: xor    eax, eax

			[/disassembly]
			[registers]
				 rax = 0x0000000000000000
				 rbx = 0x0000000100dd28a0  libclang_rt.asan_osx_dynamic.dylib`__asan::asan_flags_dont_use_directly
				 rcx = 0x0000000000000000
				 rdx = 0x00007fff5fbfed8a
				 rdi = 0x00000001005c2178  libclang_rt.asan_osx_dynamic.dylib`crashreporter_info_mutex
				 rsi = 0x0000000000000000
				 rbp = 0x00007fff5fbff010
				 rsp = 0x00007fff5fbff000
				 r8 = 0x00000001005b2a3c  libclang_rt.asan_osx_dynamic.dylib`__crashreporter_info_buff__ + 2332
				 r9 = 0x0000000000000012
				 r10 = 0x0000000000000012
				 r11 = 0x0000000000000003
				 r12 = 0x0000000100108624  "\e[1m\e[0m"
				 r13 = 0x00007fff5fbff9a0
				 r14 = 0x00007fff5fbff960
				 r15 = 0x0000000100361120  libclang_rt.asan_osx_dynamic.dylib`__asan::error_message_buf_mutex
				 rip = 0x00000001000e30cc  libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie() + 44
				 rflags = 0x0000000000000246
				 cs = 0x000000000000002b
				 fs = 0x0000000000000000
				 gs = 0x0000000000000000
			[/registers]


	**sf**: thread step-in 'n' number of times
		(lisa)sf 2
			[disassembly]
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			->  0x1000e30ce <+46>: je     0x1000e30e6               ; <+70>
			    0x1000e30d0 <+48>: lea    rdi, [rip + 0x261a3]      ; "Sleeping for %d second(s)\n"
			    0x1000e30d7 <+55>: xor    eax, eax
			    0x1000e30d9 <+57>: call   0x1000f2180               ; __sanitizer::Report(char const*, ...)

			[/disassembly]
			[jump]
			Jumping to  0x1000e30e6
			disassembly at  0x1000e30e6
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			    0x1000e30e6 <+70>: cmp    byte ptr [rbx + 0x39], 0x0
			    0x1000e30ea <+74>: je     0x1000e3134               ; <+148>

			[/jump]
			[registers]
				 rax = 0x0000000000000000
				 rbx = 0x0000000100dd28a0  libclang_rt.asan_osx_dynamic.dylib`__asan::asan_flags_dont_use_directly
				 rcx = 0x0000000000000000
				 rdx = 0x00007fff5fbfed8a
				 rdi = 0x00000001005c2178  libclang_rt.asan_osx_dynamic.dylib`crashreporter_info_mutex
				 rsi = 0x0000000000000000
				 rbp = 0x00007fff5fbff010
				 rsp = 0x00007fff5fbff000
				 r8 = 0x00000001005b2a3c  libclang_rt.asan_osx_dynamic.dylib`__crashreporter_info_buff__ + 2332
				 r9 = 0x0000000000000012
				 r10 = 0x0000000000000012
				 r11 = 0x0000000000000003
				 r12 = 0x0000000100108624  "\e[1m\e[0m"
				 r13 = 0x00007fff5fbff9a0
				 r14 = 0x00007fff5fbff960
				 r15 = 0x0000000100361120  libclang_rt.asan_osx_dynamic.dylib`__asan::error_message_buf_mutex
				 rip = 0x00000001000e30ce  libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie() + 46
				 rflags = 0x0000000000000246
				 cs = 0x000000000000002b
				 fs = 0x0000000000000000
				 gs = 0x0000000000000000
			[/registers]
			[disassembly]
			libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
			->  0x1000e30e6 <+70>: cmp    byte ptr [rbx + 0x39], 0x0
			    0x1000e30ea <+74>: je     0x1000e3134               ; <+148>
			    0x1000e30ec <+76>: movabs rbx, 0x100000000000
			    0x1000e30f6 <+86>: mov    rsi, qword ptr [rip + 0xcf0203] ; __asan::kMidMemBeg

			[/disassembly]
			[registers]
				 rax = 0x0000000000000000
				 rbx = 0x0000000100dd28a0  libclang_rt.asan_osx_dynamic.dylib`__asan::asan_flags_dont_use_directly
				 rcx = 0x0000000000000000
				 rdx = 0x00007fff5fbfed8a
				 rdi = 0x00000001005c2178  libclang_rt.asan_osx_dynamic.dylib`crashreporter_info_mutex
				 rsi = 0x0000000000000000
				 rbp = 0x00007fff5fbff010
				 rsp = 0x00007fff5fbff000
				 r8 = 0x00000001005b2a3c  libclang_rt.asan_osx_dynamic.dylib`__crashreporter_info_buff__ + 2332
				 r9 = 0x0000000000000012
				 r10 = 0x0000000000000012
				 r11 = 0x0000000000000003
				 r12 = 0x0000000100108624  "\e[1m\e[0m"
				 r13 = 0x00007fff5fbff9a0
				 r14 = 0x00007fff5fbff960
				 r15 = 0x0000000100361120  libclang_rt.asan_osx_dynamic.dylib`__asan::error_message_buf_mutex
				 rip = 0x00000001000e30e6  libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie() + 70
				 rflags = 0x0000000000000246
				 cs = 0x000000000000002b
				 fs = 0x0000000000000000
				 gs = 0x0000000000000000
			[/registers]


	**pbt**: pretty backtrace of current thread
		(lisa) bt
		* thread #1: tid = 0x708bf, 0x00000001000e30a0 libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie(), queue = 'com.apple.main-thread', stop reason = Use of deallocated memory detected
		  * frame #0: 0x00000001000e30a0 libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie()
		    frame #1: 0x00000001000e8198 libclang_rt.asan_osx_dynamic.dylib`__sanitizer::Die() + 88
		    frame #2: 0x00000001000e0a29 libclang_rt.asan_osx_dynamic.dylib`__asan::ScopedInErrorReport::~ScopedInErrorReport() + 249
		    frame #3: 0x00000001000e0151 libclang_rt.asan_osx_dynamic.dylib`__asan::ReportGenericError(unsigned long, unsigned long, unsigned long, unsigned long, bool, unsigned long, unsigned int, bool) + 3953
		    frame #4: 0x00000001000e0e26 libclang_rt.asan_osx_dynamic.dylib`__asan_report_load1 + 54
		    frame #5: 0x0000000100000ee4 a.out`main + 116 at a.c:5
		    frame #6: 0x00007fff8e2b9255 libdyld.dylib`start + 1
		    frame #7: 0x00007fff8e2b9255 libdyld.dylib`start + 1

		(lisa) pbt
		* thread #1: tid = 0x708bf, 0x00000001000e30a0 libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie(), queue = 'com.apple.main-thread', stop reason = Use of deallocated memory detected
		  * frame #0: 0x00000001000e30a0 libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie()
			[disassembly]
				libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
				->  0x1000e30a0 <+0>: push   rbp
				    0x1000e30a1 <+1>: mov    rbp, rsp
				    0x1000e30a4 <+4>: push   rbx
				    0x1000e30a5 <+5>: push   rax

			[/disassembly]
		    frame #1: 0x00000001000e8198 libclang_rt.asan_osx_dynamic.dylib`__sanitizer::Die() + 88
		    frame #2: 0x00000001000e0a29 libclang_rt.asan_osx_dynamic.dylib`__asan::ScopedInErrorReport::~ScopedInErrorReport() + 249
		    frame #3: 0x00000001000e0151 libclang_rt.asan_osx_dynamic.dylib`__asan::ReportGenericError(unsigned long, unsigned long, unsigned long, unsigned long, bool, unsigned long, unsigned int, bool) + 3953
		    frame #4: 0x00000001000e0e26 libclang_rt.asan_osx_dynamic.dylib`__asan_report_load1 + 54
		    frame #5: 0x0000000100000ee4 a.out`main + 116 at a.c:5
		    frame #6: 0x00007fff8e2b9255 libdyld.dylib`start + 1
		    frame #7: 0x00007fff8e2b9255 libdyld.dylib`start + 1


	**dump**: Dump Memory of the process in a given address range
		(lisa) dump -h
		usage: dump memory in the memory given range [-h] -s START -e END [-o OUTFILE]
		                                             [-f FORCE]

		optional arguments:
		  -h, --help            show this help message and exit
		  -s START, --start START
		                        start address
		  -e END, --end END     end address
		  -o OUTFILE, --outfile OUTFILE
		                        file to save the dump to
		  -f FORCE, --force FORCE
		                        dump will not read over 1024 bytes of data. To
		                        overwride this use -f. 0(false) or 1(true)


	**coredump**: Dump entire process memory
		(lldb) coredump
		mach_header: 0xfeedfacf 0x01000007 0x00000003 0x00000004 0x0001c0ac 0x007e30e8 0x00000000 0x00000000
		0x00000019 0x00000048 [0x0000000100000000 - 0x0000000100001000) [0x00000000007e4000 0x0000000000001000) 0x00000005 0x00000005 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100001000 - 0x0000000100002000) [0x00000000007e5000 0x0000000000001000) 0x00000003 0x00000003 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100002000 - 0x0000000100003000) [0x00000000007e6000 0x0000000000001000) 0x00000001 0x00000001 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100003000 - 0x0000000100011000) [0x00000000007e7000 0x000000000000e000) 0x00000005 0x00000005 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100011000 - 0x0000000100012000) [0x00000000007f5000 0x0000000000001000) 0x00000005 0x00000005 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100012000 - 0x0000000100041000) [0x00000000007f6000 0x000000000002f000) 0x00000005 0x00000005 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100041000 - 0x0000000100044000) [0x0000000000825000 0x0000000000003000) 0x00000003 0x00000003 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100044000 - 0x0000000100078000) [0x0000000000828000 0x0000000000034000) 0x00000003 0x00000003 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100078000 - 0x000000010008e000) [0x000000000085c000 0x0000000000016000) 0x00000001 0x00000001 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x000000010008e000 - 0x00000001000e3000) [0x0000000000872000 0x0000000000055000) 0x00000005 0x00000005 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x00000001000e3000 - 0x00000001000e4000) [0x00000000008c7000 0x0000000000001000) 0x00000005 0x00000005 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x00000001000e4000 - 0x000000010011e000) [0x00000000008c8000 0x000000000003a000) 0x00000005 0x00000005 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x000000010011e000 - 0x0000000100123000) [0x0000000000902000 0x0000000000005000) 0x00000003 0x00000003 0x00000000 0x00000000]
		0x00000019 0x00000048 [0x0000000100123000 - 0x0000000100dd4000) [0x0000000000907000 0x0000000000cb1000) 0x00000003 0x00000003 0x00000000 0x00000000]
		....


	***rop***:
		  rop(ROPgadget) lets you search your gadgets on a binary. It supports several 
		  file formats and architectures and uses the Capstone disassembler for
		  the search engine.

		(lisa)rop
			description:
			  ROPgadget lets you search your gadgets on a binary. It supports several 
			  file formats and architectures and uses the Capstone disassembler for
			  the search engine.

			formats supported: 
			  - ELF
			  - PE
			  - Mach-O
			  - Raw

			architectures supported:
			  - x86
			  - x86-64
			  - ARM
			  - ARM64
			  - MIPS
			  - PowerPC
			  - Sparc
			  epilog=examples:
			  rop --binary ./test-suite-binaries/elf-Linux-x86 
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --ropchain
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --depth 3
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --string "main"
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --string "m..n"
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --opcode c9c3
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|ret"
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|pop|xor|ret"
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --filter "xchg|add|sub"
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --norop --nosys
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --range 0x08041000-0x08042000
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --string main --range 0x080c9aaa-0x080c9aba
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --memstr "/bin/sh"
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --console
			  rop --binary ./test-suite-binaries/elf-Linux-x86 --badbytes "00|7f|42"
			  rop --binary ./test-suite-binaries/Linux_lib64.so --offset 0xdeadbeef00000000
			  rop --binary ./test-suite-binaries/elf-ARMv7-ls --depth 5
			  rop --binary ./test-suite-binaries/elf-ARM64-bash --depth 5
			  rop --binary ./test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32		


		**vtable**: dump vtable for all modules
			(lisa) vtable
			11 symbols match the regular expression 'vtable for' in /usr/lib/dyld:
			        Address: dyld[0x000000000003e6b0] (dyld.__DATA.__const + 1360)
			        Summary: dyld`vtable for ImageLoader
			         Module: file = "/usr/lib/dyld", arch = "x86_64"
			         Symbol: id = {0x00000418}, range = [0x00000001000416b0-0x00000001000419d0), name="vtable for ImageLoader", mangled="_ZTV11ImageLoader"
			        Address: dyld[0x000000000003e9d0] (dyld.__DATA.__const + 2160)
			        Summary: dyld`vtable for ImageLoaderMachO
			         Module: file = "/usr/lib/dyld", arch = "x86_64"
			         Symbol: id = {0x00000419}, range = [0x00000001000419d0-0x0000000100041d60), name="vtable for ImageLoaderMachO", mangled="_ZTV16ImageLoaderMachO"
			        Address: dyld[0x000000000003ed60] (dyld.__DATA.__const + 3072)
			        Summary: dyld`vtable for ImageLoaderMachOClassic
			         Module: file = "/usr/lib/dyld", arch = "x86_64"
			         Symbol: id = {0x0000041a}, range = [0x0000000100041d60-0x00000001000420f0), name="vtable for ImageLoaderMachOClassic", mangled="_ZTV23ImageLoaderMachOClassic"
			        Address: dyld[0x000000000003f0f0] (dyld.__DATA.__const + 3984)
			        Summary: dyld`vtable for ImageLoaderMachOCompressed
			        ....


		**symbol**: search and dump modules of given symbol
			(lisa) symbol printf
			libclang_rt.asan_osx_dynamic.dylib`id = {0x00000769}, value = 0x0000000000000000, name="printf"
			libcache.dylib`id = {0x00000051}, range = [0x0000000000003590-0x0000000000003596), name="printf"
			libcommonCrypto.dylib`id = {0x0000026f}, range = [0x000000000000ae10-0x000000000000ae16), name="printf"
			libsystem_c.dylib`id = {0x0000065e}, range = [0x0000000000044180-0x0000000000044261), name="printf"
			libsystem_malloc.dylib`id = {0x000001b9}, range = [0x000000000001a336-0x000000000001a33c), name="printf"
			libsystem_symptoms.dylib`id = {0x0000006a}, range = [0x00000000000064be-0x00000000000064c4), name="printf"
			libsystem_trace.dylib`id = {0x00000338}, range = [0x000000000001bbb2-0x000000000001bbb8), name="printf"
			libobjc.A.dylib`id = {0x0000051b}, range = [0x0000000000021732-0x0000000000021738), name="printf"
		
		**shell**: run shell commands
			(lisa) shell ps aux|grep -i lldb|grep -v grep
				v0id             40432   0.0  0.5  2643564  85956 s001  S+   10:01pm   0:00.84 /Applications/Xcode.app/Contents/Developer/usr/bin/lldb
				v0id             40435   0.0  0.1  2468372   8404 s001  S    10:01pm   0:00.04 /Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Resources/debugserver --native-regs --setsid --reverse-connect 127.0.0.1:64148


		

![alt tag](https://raw.githubusercontent.com/ant4g0nist/lisa.py/master/context.png)

![alt tag](https://raw.githubusercontent.com/ant4g0nist/lisa.py/master/pbt.png)


You can test lisa.py against CrashWranglers's test cases

	ant4g0nist$ cp lisa.py ~/lisa.py

	ant4g0nist$ cp lldbinit ~/.lldbinit

	ant4g0nist$ python test.py


Thanks:

	- Mona.py : https://github.com/corelan/mona

	- Crashwrangler : https://developer.apple.com/library/mac/technotes/tn2334/_index.html

	- Metasploit : https://github.com/rapid7/metasploit-framework
	
	- PEDA :	https://github.com/longld/peda
	
	- Phillips : https://www.phillips321.co.uk/2013/04/02/recreating-pattern_create-rb-in-python/

	- Jonathan Salwan : http://shell-storm.org/shellcode/
	
	- Capstone : http://www.capstone-engine.org

TODO:
	add support for macho in ropmaker
	