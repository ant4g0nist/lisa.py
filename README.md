# lisa.py
	- An Exploit Dev Swiss Army Knife. 

# Commands
```
  aslr        -- View/modify ASLR setting of target.
  checksec    -- Display the security properties of the current executable
  context     -- Display context of given thread or selected thread by default. Usage: 'context all' or 'context 1'
  csdis       -- Disassemble buffer at a given pointer using Capstone
  pmem        -- Visualize memory at a given address and size
  pstack      -- Visualize stack for a given frame or selected frame by default
  rr          -- Display registers for a given thread and frame or selected thread and selected frame by default
  show_header -- Dump Mach-O headers
  show_lc     -- Dump Load Commands from Mach-O
```

# Commands in Detail
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

### Credits

- [lldb](https://lldb.llvm.org/)
- [chisel](https://github.com/facebook/chisel)
- [gef](https://github.com/hugsy/gef)
- [pixd](https://github.com/moreati/python-pixd)