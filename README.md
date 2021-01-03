# lisa.py
	- An Exploit Dev Swiss Army Knife. 

# Commands
* aslr		- View/modify ASLR setting of target.
```
(lisa:>) help aslr
     View/modify ASLR setting of target.  Expects 'raw' input (see 'help raw-input'.)

Syntax: aslr
View/modify ASLR setting of target.

Arguments:
  <on>; Enable ASLR. Usage: aslr on
  <off>; disable ASLR. Usage: aslr off

Syntax: aslr <on> <off>

This command is implemented as ASLRCommand
(lisa:>) aslr on
(lisa:>) aslr 
ASLR : on
(lisa:>) aslr off
(lisa:>) aslr
ASLR : off
(lisa:>) 
```
* checksec	- Display the security properties of an executable
```
(lisa:>) checksec 
Got a Macho-O binary
Parsing arm64 Mach-O
ARC	         : True
PIE	         : True
Stack Canary	 : True
Encrypted	 : False
NX Heap		 : True
NX Stack 	 : True
Restricted 	 : False
(lisa:>) checksec /usr/bin/clang
Got a fat binary
Choose only the host arch: arm64? y/n: y
Parsing arm64 Mach-O
ARC	         : False
PIE	         : True
Stack Canary	 : False
Encrypted	 : False
NX Heap		 : True
NX Stack 	 : True
Restricted 	 : True (Authority=Software Signing)
(lisa:>) 
```