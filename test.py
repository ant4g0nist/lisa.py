#!/usr/bin/env python
import glob
import commands

try:
	commands.getoutput('mkdir tests/binaries/')
except:
	pass
print "[*]\tCompiling testcases"

for i in glob.glob("tests/*.c"):
	filename = i[:-2].replace("tests/","")
	cmd = "gcc "+i+" -o tests/binaries/"+filename
	print "\t",cmd
	commands.getoutput(cmd)

for i in glob.glob("tests/binaries/*"):
	print commands.getoutput("lldb -s resources/lldb_cmds.s -f "+i)