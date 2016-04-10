# lisa.py
-An Exploit Dev Swiss Army Knife. 

![alt tag](https://raw.githubusercontent.com/ant4g0nist/lisa.py/master/lisa.png)


#Installation
Copy lisa.py and .lldbinit to ~/ 
Use the following commands:

	ant4g0nist$ cp lisa.py ~/lisa.py

	ant4g0nist$ cp lldbinit ~/.lldbinit

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

#Commands Available:
	
	
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

	**extract**: Extract a given architecture from a Universal binary

		(lisa)extract
		Syntax: extract x86_64 /usr/lib/system/libsystem_kernel.dylib ./libsystem_kernel.dylib
		(lisa)extract x86_64 /usr/lib/system/libsystem_kernel.dylib ./libsystem_kernel.dylib
		(lisa)

	**pattern_create**: Creates a cyclic pattern of given length

		(lisa)pattern_create 100
		Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

	**pattern_offset**: Finds the offset of a given pattern in cyclic pattern of n length

		(lisa)pattern_offset 100 Ad2A
		Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
		offsets: [96]
		(lisa)

	**ct**: Prints the context of execution

		(lisa)ct
		[*] Disassembly :

		libsystem_kernel.dylib`__pthread_kill:
		->  0x7fff8f6a4f06 <+10>: jae    0x7fff8f6a4f10            ; <+20>
		    0x7fff8f6a4f08 <+12>: mov    rdi, rax

		[*] Stack :

		0x7fff5fbff788: 0x8d36b4ec 0x00007fff 0x00000000 0x00000000
		0x7fff5fbff798: 0x5fbff7d0 0x00000307 0x5fbff7d0 0x00007fff
		0x7fff5fbff7a8: 0x00000000 0x00000000

		[*] Registers	:
		       rax = 0x0000000000000000
		       rbx = 0x0000000000000006
		       rcx = 0x00007fff5fbff788
		       rdx = 0x0000000000000000
		       rdi = 0x0000000000000307
		       rsi = 0x0000000000000006
		       rbp = 0x00007fff5fbff7b0
		       rsp = 0x00007fff5fbff788
		        r8 = 0x0000000000000000
		        r9 = 0x00007fff782e90c8  atexit_mutex + 24
		       r10 = 0x0000000008000000
		       r11 = 0x0000000000000206
		       r12 = 0x0000000000000000
		       r13 = 0x0000000000000000
		       r14 = 0x00007fff76fb8000  libsystem_pthread.dylib`_thread
		       r15 = 0x0000000000000000
		       rip = 0x00007fff8f6a4f06  libsystem_kernel.dylib`__pthread_kill + 10
		    rflags = 0x0000000000000206
		        cs = 0x0000000000000007
		        fs = 0x0000000000000000
		        gs = 0x0000000000000000


		[*] Jumping to	:0x7fff8f6a4f10
		(lisa)

	**s**: thread step-in

		(lisa)s
		[*] Disassembly :

		dyld`_dyld_start:
		->  0x7fff5fc0102d <+45>: lea    r9, [rbp - 0x8]
		    0x7fff5fc01031 <+49>: call   0x7fff5fc01076            ; dyldbootstrap::start(macho_header const*, int, char const**, long, macho_header const*, unsigned long*)

		[*] Stack :

		0x7fff5fbff800: 0x00000000 0x00000000 0x00000000 0x00000000
		0x7fff5fbff810: 0x00000000 0x00000000 0x00000001 0x00000000
		0x7fff5fbff820: 0x5fbff9f8 0x00007fff

		[*] Registers	:
		       rax = 0x0000000000000000
		       rbx = 0x0000000000000000
		       rcx = 0x0000000000000000
		       rdx = 0x00007fff5fbff820
		       rdi = 0x0000000100000000
		       rsi = 0x0000000000000001
		       rbp = 0x00007fff5fbff810
		       rsp = 0x00007fff5fbff800
		        r8 = 0x00007fff5fc00000  
		        r9 = 0x0000000000000000
		       r10 = 0x0000000000000000
		       r11 = 0x0000000000000000
		       r12 = 0x0000000000000000
		       r13 = 0x0000000000000000
		       r14 = 0x0000000000000000
		       r15 = 0x0000000000000000
		       rip = 0x00007fff5fc0102d  dyld`_dyld_start + 45
		    rflags = 0x0000000000000246
		        cs = 0x000000000000002b
		        fs = 0x0000000000000000
		        gs = 0x0000000000000000

	**si**: thread step-into

		(lisa)si
		[*] Disassembly :

		dyld`_dyld_start:
		->  0x7fff5fc01031 <+49>: call   0x7fff5fc01076            ; dyldbootstrap::start(macho_header const*, int, char const**, long, macho_header const*, unsigned long*)
		    0x7fff5fc01036 <+54>: mov    rdi, qword ptr [rbp - 0x8]

		[*] Stack :

		0x7fff5fbff800: 0x00000000 0x00000000 0x00000000 0x00000000
		0x7fff5fbff810: 0x00000000 0x00000000 0x00000001 0x00000000
		0x7fff5fbff820: 0x5fbff9f8 0x00007fff

		[*] Registers	:
		       rax = 0x0000000000000000
		       rbx = 0x0000000000000000
		       rcx = 0x0000000000000000
		       rdx = 0x00007fff5fbff820
		       rdi = 0x0000000100000000
		       rsi = 0x0000000000000001
		       rbp = 0x00007fff5fbff810
		       rsp = 0x00007fff5fbff800
		        r8 = 0x00007fff5fc00000  
		        r9 = 0x00007fff5fbff808
		       r10 = 0x0000000000000000
		       r11 = 0x0000000000000000
		       r12 = 0x0000000000000000
		       r13 = 0x0000000000000000
		       r14 = 0x0000000000000000
		       r15 = 0x0000000000000000
		       rip = 0x00007fff5fc01031  dyld`_dyld_start + 49
		    rflags = 0x0000000000000246
		        cs = 0x000000000000002b
		        fs = 0x0000000000000000
		        gs = 0x0000000000000000

	**so**: thread step-over
		
		(lisa)so
		[*] Disassembly :

		dyld`_dyld_start:
		->  0x7fff5fc01036 <+54>: mov    rdi, qword ptr [rbp - 0x8]
		    0x7fff5fc0103a <+58>: cmp    rdi, 0x0

		[*] Stack :

		0x7fff5fbff800: 0x00000000 0x00000000 0x8e8765ad 0x00007fff
		0x7fff5fbff810: 0x00000000 0x00000000 0x00000001 0x00000000
		0x7fff5fbff820: 0x5fbff9f8 0x00007fff

		[*] Registers	:
		       rax = 0x0000000100000f80  abort`main
		       rbx = 0x0000000000000000
		       rcx = 0x00007fff8e8765ad  libdyld.dylib`start + 1
		       rdx = 0x00007fff5fbff808
		       rdi = 0x00007fff5fc406a8  dyld`initialPoolContent + 2264
		       rsi = 0x0000000000000001
		       rbp = 0x00007fff5fbff810
		       rsp = 0x00007fff5fbff800
		        r8 = 0x00000000fffffffc
		        r9 = 0x00007fff782e90c8  atexit_mutex + 24
		       r10 = 0x00000000ffffffff
		       r11 = 0xffffffff00000000
		       r12 = 0x0000000000000000
		       r13 = 0x0000000000000000
		       r14 = 0x0000000000000000
		       r15 = 0x0000000000000000
		       rip = 0x00007fff5fc01036  dyld`_dyld_start + 54
		    rflags = 0x0000000000000202
		        cs = 0x000000000000002b
		        fs = 0x0000000000000000
		        gs = 0x0000000000000000


	**sf**: thread step-in 'n' number of times

		(lisa)sf 4
		[*] Disassembly :

		dyld`_dyld_start:
		->  0x7fff5fc0100a <+10>: sub    rsp, 0x10
		    0x7fff5fc0100e <+14>: mov    esi, dword ptr [rbp + 0x8]

		[*] Stack :

		0x7fff5fbff810: 0x00000000 0x00000000 0x00000001 0x00000000
		0x7fff5fbff820: 0x5fbff9f8 0x00007fff 0x00000000 0x00000000
		0x7fff5fbff830: 0x5fbffa34 0x00007fff

		[*] Registers	:
		       rax = 0x0000000000000000
		       rbx = 0x0000000000000000
		       rcx = 0x0000000000000000
		       rdx = 0x0000000000000000
		       rdi = 0x0000000100000000
		       rsi = 0x0000000000000000
		       rbp = 0x00007fff5fbff810
		       rsp = 0x00007fff5fbff810
		        r8 = 0x0000000000000000
		        r9 = 0x0000000000000000
		       r10 = 0x0000000000000000
		       r11 = 0x0000000000000000
		       r12 = 0x0000000000000000
		       r13 = 0x0000000000000000
		       r14 = 0x0000000000000000
		       r15 = 0x0000000000000000
		       rip = 0x00007fff5fc0100a  dyld`_dyld_start + 10
		    rflags = 0x0000000000000202
		        cs = 0x000000000000002b
		        fs = 0x0000000000000000
		        gs = 0x0000000000000000


	**dump**: Dump's Memory of the process in a given address range

		(lisa)dump
		Syntax: dump outfile 0x6080000fe680 0x6080000fe680+1000
		(lisa)dump memorydump.bin 0x00007fff8e8765ad 0x00007fff8e8765ad+100
		100 bytes written to 'memorydump.bin'
		(lisa)

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


![alt tag](https://raw.githubusercontent.com/ant4g0nist/lisa.py/master/context.png)


(As of now, commiting exploitable command. Have to test the remaining code.)

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

TODO:
	add support for macho in ropmaker
	