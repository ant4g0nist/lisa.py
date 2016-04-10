#!/usr/bin/env python

# Copyright 2015 ant4g0nist

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import os
import re
import cmd
import sys
import time
import shlex
import random
import string
import struct
import commands
import datetime
import optparse
import argparse
import platform
import httplib
from struct import *
from sys import version_info
from struct import pack
from binascii   import *
from ctypes import *
import subprocess


#install package
def install(name):
    subprocess.call(['sudo','pip', 'install', name])    

try:
    from capstone import *
except:
    print "[+]\tGonna try installing capstone."
    install('capstone')
    from capstone import *

PYROPGADGET_VERSION = 'ich'

if sys.version_info.major == 3:
    xrange = range

import lldb

#global vars#
lisaversion = 'v-ni'
PAGE_SIZE=4096
MAX_DISTANCE=PAGE_SIZE*10
g_ignore_frame_pointer= False
reportexploitable=""
###################

REGISTERS = {
    8 : ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
    16: ["ax", "bx", "cx", "dx"],
    32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
    64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
}

####################################
#             Misc Utils           #
####################################
def banner(debugger,command,result,dict):
    
    lisa2="""
        
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
        """
    print tty_colors.green()+random.choice([lisa2])+tty_colors.default()
    print tty_colors.red()+"\t-An Exploit Dev Swiss Army Knife. Version: "+lisaversion+tty_colors.default()

#convert to hex
def to_hex(var):
    """
        converts given value to hex
    """
    return hex(var)

#hextoascii
def hex2ascii(debugger,hex,result,dict):
    """
        converts Hex to ascii
        ex: h2a 0x41414141 prints AAAA
    """
    print hex.replace('0x','').decode('hex')

#generate random hex of length between n - m
def urandom(debugger,n,result,dict):
    """
        Generates random hex of given length
    """
    if not n:
        print 'rand command an argument: example: rand 23'
        return
    print open('/dev/urandom','r').read(random.randint(int(n)/2,int(n)/2)).encode('hex')

# run os commands
def shell(debugger,command,result,dict):
    """
        runs shell command and prints output
    """
    try:
        if command:
            os.system(command)
        else:
            print 'Please enter a proper shell command.Eg: shell ls'
            return
    except:
        print 'Please enter a proper shell command.Eg: shell ls'
    return

#term colors
class TerminalColors:
    '''Simple terminal colors class'''
    def __init__(self, enabled = True):
        # TODO: discover terminal type from "file" and disable if
        # it can't handle the color codes
        self.enabled = enabled
    
    def reset(self):
        '''Reset all terminal colors and formatting.'''
        if self.enabled:
            return "\x1b[0m";
        return ''
    
    def bold(self, on = True):
        '''Enable or disable bold depending on the "on" parameter.'''
        if self.enabled:
            if on:
                return "\x1b[1m";
            else:
                return "\x1b[22m";
        return ''
    
    def italics(self, on = True):
        '''Enable or disable italics depending on the "on" parameter.'''
        if self.enabled:
            if on:
                return "\x1b[3m";
            else:
                return "\x1b[23m";
        return ''
    
    def underline(self, on = True):
        '''Enable or disable underline depending on the "on" parameter.'''
        if self.enabled:
            if on:
                return "\x1b[4m";
            else:
                return "\x1b[24m";
        return ''
    
    def inverse(self, on = True):
        '''Enable or disable inverse depending on the "on" parameter.'''
        if self.enabled:
            if on:
                return "\x1b[7m";
            else:
                return "\x1b[27m";
        return ''
    
    def strike(self, on = True):
        '''Enable or disable strike through depending on the "on" parameter.'''
        if self.enabled:
            if on:
                return "\x1b[9m";
            else:
                return "\x1b[29m";
        return ''

    def black(self, fg = True):
        '''Set the foreground or background color to black.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[30m";
            else:
                return "\x1b[40m";
        return ''

    def red(self, fg = True):
        '''Set the foreground or background color to red.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[31m";
            else:
                return "\x1b[41m";
        return ''
    
    def green(self, fg = True):
        '''Set the foreground or background color to green.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[32m";
            else:
                return "\x1b[42m";
        return ''
    
    def yellow(self, fg = True):
        '''Set the foreground or background color to yellow.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[43m";
            else:
                return "\x1b[33m";
        return ''
    
    def blue(self, fg = True):
        '''Set the foreground or background color to blue.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[34m";
            else:
                return "\x1b[44m";
        return ''
    
    def magenta(self, fg = True):
        '''Set the foreground or background color to magenta.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[35m";
            else:
                return "\x1b[45m";
        return ''
    
    def cyan(self, fg = True):
        '''Set the foreground or background color to cyan.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[36m";
            else:
                return "\x1b[46m";
        return ''
    
    def white(self, fg = True):
        '''Set the foreground or background color to white.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[37m";
            else:
                return "\x1b[47m";
        return ''
    
    def default(self, fg = True):
        '''Set the foreground or background color to the default.
            The foreground color will be set if "fg" tests True. The background color will be set if "fg" tests False.'''
        if self.enabled:
            if fg:
                return "\x1b[39m";
            else:
                return "\x1b[49m";
        return ''

####################################
#       LLDB                       #
####################################

#set malloc debugging features
def setMallocDebug(debugger,c,result,dict):
    """sets DYLD_INSERT_LIBRARIES to /usr/lib/libgmalloc.dylib"""
    execute(debugger,'settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib',result,dict)
    return True

#execute given LLDB command
def execute(debugger,lldb_command,result,dict):
    """
        Execute given command and print the outout to stdout
    """
    debugger.HandleCommand(lldb_command)

#execute command and return output
def executeReturnOutput(debugger,lldb_command,result,dict):
    """Execute given command and returns the outout"""
    ci = debugger.GetCommandInterpreter()
    res=lldb.SBCommandReturnObject()
    ci.HandleCommand(lldb_command,res)
    output= res.GetOutput()
    error  = res.GetError()
    return (output,error)

def s(debugger,command,result,dict):
    """step command"""
    executeReturnOutput(debugger,"thread step-in",result,dict)
    context(debugger,command,result,dict)

def si(debugger,command,result,dict):
    """step into command"""
    executeReturnOutput(debugger,"thread step-inst",result,dict)
    context(debugger,command,result,dict)

def so(debugger,command,result,dict):
    """step over"""
    executeReturnOutput(debugger,"thread step-over",result,dict)
    context(debugger,command,result,dict)

def stepnInstructions(debugger,count,result,dict):
    """step-in n time"""
    c=0

    while c<int(count):
        command=""
        executeReturnOutput(debugger,"thread step-in",result,dict)
        c+=1

    context(debugger,command,result,dict)

def testjump(debugger,command,result,dict):
        """
        Test if jump instruction is taken or not
        Returns:
            True if jump is taken or False if not 
        """
        inst=None
        flags = get_eflags(debugger,command,result,dict)
        if not flags:
            return None

        if not inst:
            pc =getregvalue(debugger,"pc",result,dict)

            inst, error = executeReturnOutput(debugger,"x/1i $pc",result,dict)
            if not inst:
                return None

        opcode = inst.split('  ')[2]    

        if opcode == "jmp":
            return (True,inst.split('  ')[4])
        if opcode == "je" and flags["ZF"]:
            print inst.split('  ')[4]
            return (True,inst.split('  ')[4])
        if opcode == "jne" and not flags["ZF"]:
            return (True,inst.split('  ')[4])
        if opcode == "jg" and not flags["ZF"] and (flags["SF"] == flags["OF"]):
            return (True,inst.split('  ')[4])
        if opcode == "jge" and (flags["SF"] == flags["OF"]):
            return (True,inst.split('  ')[4])
        if opcode == "ja" and not flags["CF"] and not flags["ZF"]:
            return (True,inst.split('  ')[4])
        if opcode == "jae" and not flags["CF"]:
            return (True,inst.split('  ')[4])
        if opcode == "jl" and (flags["SF"] != flags["OF"]):
            return (True,inst.split('  ')[4])
        if opcode == "jle" and (flags["ZF"] or (flags["SF"] != flags["OF"])):
            return (True,inst.split('  ')[4])
        if opcode == "jb" and flags["CF"]:
            return (True,inst.split('  ')[4])
        if opcode == "jbe" and (flags["CF"] or flags["ZF"]):
            return (True,inst.split('  ')[4])
        if opcode == "jo" and flags["OF"]:
            return (True,inst.split('  ')[4])
        if opcode == "jno" and not flags["OF"]:
            return (True,inst.split('  ')[4])
        if opcode == "jz" and flags["ZF"]:
            return (True,inst.split('  ')[4])
        if opcode == "jnz" and flags["OF"]:
            return (True,inst.split('  ')[4])

        return (False,None)

def context(debugger,command,result,dict):
    """Prints context of current execution"""
    
    try:
        #disas
        op, error=executeReturnOutput(debugger,"disassemble -c 2 -s $pc",result,dict)
        print tty_colors.red()+"[*] Disassembly :\n"+tty_colors.default()
        print op

        #stack
        op, error=executeReturnOutput(debugger,"x/10x $sp",result,dict)
        print tty_colors.red()+"[*] Stack :\n"+tty_colors.default()
        print tty_colors.blue()+op+tty_colors.default()

        #registers
        op, error=executeReturnOutput(debugger,"register read",result,dict)
        print tty_colors.red()+"[*] Registers\t:"+tty_colors.default()
        print op.split("\n\n")[0].split('General Purpose Registers:\n')[1].split('eflags')[0]
        print '\n'

        #jump
        dis, error=executeReturnOutput(debugger,'disassemble -c 1 -s $pc',result,dict)
        if dis:
            dis = dis.split(': ')[1].split()[0]

            if 'j' in dis:
                jumpto, destination = testjump(debugger,command,result,dict)
                if jumpto==True:
                    print tty_colors.red()+"[*] Jumping to\t:"+destination+tty_colors.default()
                else:
                    print tty_colors.red()+"[*] Jump not taken."+tty_colors.default()
        else:
            print error,

    except Exception as e:
        print 'error running context'

def get_eflags(debugger,command,result,dict):
    """
    Get flags value from EFLAGS register

    Returns:
    - dictionary of named flags
    """

    # Eflags bit masks, source vdb
    EFLAGS_CF = 1 << 0
    EFLAGS_PF = 1 << 2
    EFLAGS_AF = 1 << 4
    EFLAGS_ZF = 1 << 6
    EFLAGS_SF = 1 << 7
    EFLAGS_TF = 1 << 8
    EFLAGS_IF = 1 << 9
    EFLAGS_DF = 1 << 10
    EFLAGS_OF = 1 << 11

    flags = {"CF":0, "PF":0, "AF":0, "ZF":0, "SF":0, "TF":0, "IF":0, "DF":0, "OF":0}
    eflags = getregvalue(debugger,"eflags",result,dict)

    if not eflags:
        eflags = getregvalue(debugger,"rflags",result,dict)
    eflags=int(eflags,16)
    flags["CF"] = bool(eflags & EFLAGS_CF)
    flags["PF"] = bool(eflags & EFLAGS_PF)
    flags["AF"] = bool(eflags & EFLAGS_AF)
    flags["ZF"] = bool(eflags & EFLAGS_ZF)
    flags["SF"] = bool(eflags & EFLAGS_SF)
    flags["TF"] = bool(eflags & EFLAGS_TF)
    flags["IF"] = bool(eflags & EFLAGS_IF)
    flags["DF"] = bool(eflags & EFLAGS_DF)
    flags["OF"] = bool(eflags & EFLAGS_OF)

    return flags


####################################
#         Exploitation             #
####################################


#pattern create and pattern offset
def pattern_create(debugger,size,result,dict):
    """creates a cyclic pattern of given length"""

    try:length=int(size)
    except:print "[+] Usage: pattern_create <length> [set a] [set b] [set c]"
    seta="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    setb="abcdefghijklmnopqrstuvwxyz"
    setc="0123456789"

    string="" ; a=0 ; b=0 ; c=0

    while len(string) < length:
        string += seta[a] + setb[b] + setc[c]
        c+=1
        if c == len(setc):c=0;b+=1
        if b == len(setb):b=0;a+=1
        if a == len(seta):a=0
    
    print tty_colors.red()+ string[:length]+tty_colors.default()

    return string[:length]

#check if given pattern is in cyclic pattern
def check_if_cyclic(debugger,pat,result,dict):
    """check if given pattern is in cyclic pattern"""

    seta="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    setb="abcdefghijklmnopqrstuvwxyz"
    setc="0123456789"
    
    if not pat:
        print '[+] Usage: check_if_cyclic <some string>'
        return

    string=pat ; a=0 ; b=0 ; c=0
    length=len(string)
    i=0
    while i<(length-2):
        if string[i].isalpha():
            if string[i].islower():
                if string[i+1].isupper():
                    if string[i+2].isdigit():
                        pass
                    else:
                        print tty_colors.red()+"Not a cyclic pattern"+tty_colors.default()
                        return False
                else:
                    print tty_colors.red()+"Not a cyclic pattern"+tty_colors.default()
                    return False
        
            elif string[i].isupper():
                if string[i+1].islower():
                    if string[i+2].isdigit():
                        pass
                    else:
                            print tty_colors.red()+"Not a cyclic pattern"+tty_colors.default()
                            return False
                else:
                    print tty_colors.red()+"Not a cyclic pattern"+tty_colors.default()
                    return False

        elif string[i].isdigit():
            if string[i+1].isalpha():
                if string[i+1].isupper():
                    if string[i+2].islower():
                        pass
                    else:
                        print tty_colors.red()+"Not a cyclic pattern"+tty_colors.default()
                        return False
                else:
                    print tty_colors.red()+"Not a cyclic pattern"+tty_colors.default()
                    return False


        i+=3
    print "seems to be a valid pattern"
    return True

#pattern search
def pattern_offset(debugger,sizepat,result,dict):
    """search offset of pattern."""
    
    if len(sizepat.split(' '))==2:
        try:
            size=int(sizepat.split(' ')[0])
            pat=sizepat.split(' ')[1]
            pattern=pattern_create(debugger,size,result,dict)
            if "0x" in pat:
                pat=pat.replace("0x","")
                pat=pat.decode("hex")[::-1]
            try:
                p=int(pat)
                pat=pat.decode('hex')
            except:
                pass
            found=[m.start() for m in re.finditer(pat, pattern)]
            if found!=-1:
                print 'offsets:',found
        except:
            print "please check the syntax"
            print "pattern_offset 250 Aa2A"
                
    elif len(sizepat.split(' '))==1:
        try:
            size=10000
            pat=sizepat.split(' ')[1]
            pattern=pattern_create(debugger,size,result,dict,True)
            if "0x" in pat:
                pat=pat.replace("0x","")
                pat=pat.decode("hex")[::-1]
            try:
                p=int(pat)
                pat=pat.decode('hex')
            except:
                pass
            found=[m.start() for m in re.finditer(pat, pattern)]
            #                found=pattern.find(pat)
            if found!=-1:
                print found
        except:
            print "please check the syntax"
            print "pattern_offset 250 Aa2A"

#return address in register
def getregvalue(debugger,reg,result,dict):
    output,error=executeReturnOutput(debugger,'register read '+reg,result,dict)
    return output.split("= ")[-1].split(" ")[0]

lldb_stop_reasons =  { 'eStateCrashed' : 8, 'eStateDetached' : 9, 'eStateExited' : 10, 'eStateInvalid' : 0,
                      'eStateLaunching' : 4, 'eStateRunning' : 6, 'eStateStepping' : 7,'eStateStopped' : 5,
                      'eStateSuspended' : 11, 'eStopReasonBreakpoint' : 3, 'eStopReasonException' : 6,
                      'eStopReasonExec' : 7, 'eStopReasonInvalid' : 0, 'eStopReasonNone' : 1, 'eStopReasonSignal' : 5,
                      'eStopReasonThreadExiting' : 9, 'eStopReasonTrace' : 2, 'eStopReasonWatchpoint' : 4
                      }

def getexception(exception_description):
    type1  = exception_description
    try:
        exception = re.search("EXC_(.+?) ",type1).group().strip(' ')
    except:
        exception = None
    try:
        code =  re.search("\(code(.+?),",type1).group().split('=')[1].strip(',')
    except:
        try:
            code =  re.search("\(code(.+?)\)",type1).group().split('=')[1].strip(')')
        except:
            code = None
    try:
        address  = re.search(", address(.+?)\)",type1).group().split('=')[1].strip(')')
    except:
        address = None

    return exception,code,address

def getsignal(signal_description):
    return signal_description.split(' ')[1]


def type_for_two_memory(access_address, disassembly):
    first_reg_val = value_for_first_register(disassembly)
    if first_reg_val != access_address:
        return "read"
    else:
        return "write"

def stack_access_crash(access_address, sp_val):
    access_address=int(access_address,0)
    sp_val = int(sp_val,0)
    if ((sp_val - access_address) <= PAGE_SIZE):
        return True
    return False

def getexceptiontype(access_address, disassembly, registers):
    if disassembly!=None:
        last_comma = disassembly.find(',')
        right_paren = disassembly.find(']')

        sp = registers['sp']

        if disassembly[right_paren+1:].find(']')!=-1:
            type_=type_for_two_memory(access_address, disassembly)
            return type_

        elif disassembly.find('call')!=-1:
            if not right_paren or last_comma:
                type_ = "recursion"
            elif stack_access_crash(access_address,sp):
                print 'ohhh'
                type_ = "recursion"
            else:
                type_ = "exec"
            return type_

        elif disassembly.find("cmp")!=-1 or disassembly.find("test")!=-1 or disassembly.find("fld")!=-1:
            type_ = "read"
            return type_

        elif disassembly.find("fst")!=-1:
            type_ = "write"
            return type_

        elif disassembly.find("mov")!=-1:
            if last_comma>right_paren:
                type_ = "read"
            else:
                type_ = "write"
            return type_

        elif disassembly.find('jmp')!=-1:
            type_ = "exec"
            return type_

        elif disassembly.find('push')!=-1:
            if right_paren:
                type_ = "read"
            else:
                type_ = "recursion"
            return type_

        elif disassembly.find('inc')!=-1 or disassembly.find('dec')!=-1:
            type_ = "write"
            return type_

        elif disassembly.find("stos")!=-1:
            type_ = "write"
            return type_

        elif disassembly.find("lods")!=-1:
            type_ = "read"
            return type_

        else:
            type_ = "unknown"
            return type_

        if disassembly.find("st") == 2:
            type_ = "write"
            return type_

        elif disassembly.find("ld") == 2:
            type_ = "read"
            return type_

        elif disassembly.find("push") == 2:
            type_ = "recursion"
            return type_

        else:
            type_ = "unknown"
            return type_

    else:
        type_ = "unknown"
        return type_

def is_stack_suspicious(exc_address, exception, backtrace):
    global reportexploitable
    global is_exploitable

    suspicious_functions = [
            "__chk_fail", "__stack_chk_fail", "szone_error", "CFRelease", "CFRetain", "_CFRelease", "_CFRetain",
           "malloc", "calloc", "realloc", "objc_msgSend",
           "szone_free", "free_small", "tiny_free_list_add_ptr", "tiny_free_list_remove_ptr",
           "small_free_list_add_ptr", "small_free_list_remove_ptr", "large_entries_free_no_lock",
           "large_free_no_lock", "szone_batch_free", "szone_destroy", "free",
           "CSMemDisposeHandle", "CSMemDisposePtr",
           "append_int", "release_file_streams_for_task", "__guard_setup",
           "_CFStringAppendFormatAndArgumentsAux", "WTF::fastFree", "WTF::fastMalloc",
           "WTF::FastCalloc", "WTF::FastRealloc", " WTF::tryFastCalloc", "WTF::tryFastMalloc",
           "WTF::tryFastRealloc", "WTF::TCMalloc_Central_FreeList", "GMfree", "GMmalloc_zone_free",
           "GMrealloc", "GMmalloc_zone_realloc"]

    if exc_address=="0xbbadbeef":
        # WebCore functions call CRASH() in various assertions or if the amount to allocate was too big. CRASH writes a null byte to 0xbbadbeef.
        is_exploitable=False
        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()        
        reportexploitable = "Not exploitable. Seems to be a safe crash. Calls to CRASH() function writes a null byte to 0xbbadbeef"
        print tty_colors.red()+"Not exploitable. Seems to be a safe crash. Calls to CRASH() function writes a null byte to 0xbbadbeef"+tty_colors.default()

        return 

    if "0   ???" in backtrace:
        is_exploitable = True
        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
        print tty_colors.red()+"This crash is suspected to be exploitable because the crashing instruction is outside of a known function, i.e. in dynamically generated code"+tty_colors.default()
        reportexploitable="This crash is suspected to be exploitable because the crashing instruction is outside of a known function, i.e. in dynamically generated code"
        return

    for i in suspicious_functions:
        if i in backtrace:
            if exception == "EXC_BREAKPOINT" and (i=="CFRelease" or i=="CFRetain"):
                is_exploitable = "no"
                return
            elif i=="_CFRelease" or i=="CFRelease" and "CGContextDelegateFinalize" in backtrace:
                return
            elif i=="objc_msgSend" and exc_address<<PAGE_SIZE:
                continue
            else:
                is_exploitable = True
                print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                print tty_colors.red()+"The crash is suspected to be an exploitable issue due to the suspicious function in the stack trace of the crashing thread: "+i+tty_colors.default()
                reportexploitable="The crash is suspected to be an exploitable issue due to the suspicious function in the stack trace of the crashing thread."
                return

#return whether or not the base pointer is far away from the stack pointer.
def bp_inconsistent_with_sp(bp_val,sp_val):
    #define MAX_DISTANCE (PAGE_SIZE * 10)
    #    No check if bp_val > sp_val since bp_val - sp_val may have underflowed.

    if (int(bp_val,0) - int(sp_val,0)) > MAX_DISTANCE:
        return True
    return False

class Lisa:
    def __init__(self, debugger,result,dict):
        
        self.debugger = debugger
        self.target = self.debugger.GetSelectedTarget()
        self.process = self.target.process
        self.thread = self.process.selected_thread
        self.frame = self.thread.GetFrameAtIndex(0)
        self.pc = hex(self.frame.pc)
        self.sp = hex(self.frame.sp)
        self.bp = hex(self.frame.fp)

        disas,disas_error = executeReturnOutput(debugger,"disassemble -c 1 -s $pc",result,dict)

        if disas_error:
            self.pc_disas = None
        else:
            self.pc_disas = re.search("->(.+?)\n",disas).group().split(':')[1]

        self.backtrace, self.backtrace_error = executeReturnOutput(debugger,"bt",result,dict)

        self.crash_reason = self.thread.GetStopReason()
        
        if self.crash_reason == lldb_stop_reasons['eStopReasonException']:
            self.exception = self.thread.GetStopDescription(80)
            self.exception,self.exc_code,self.exc_address = getexception(self.exception)
            self.signal = None

            print tty_colors.red()+"Exception : "+self.exception+tty_colors.default()

        elif self.crash_reason == lldb_stop_reasons['eStopReasonSignal']:
            self.signal = self.thread.GetStopDescription(80)
            self.signal = getsignal(self.signal)
            self.exc_address = None
            self.exception = None

            print tty_colors.red()+"Signal : "+self.signal+tty_colors.default()
            
        else:
            return

        self.gen_registers =  list(self.frame.registers)[0]
        self.registers = {}

        for i in  self.gen_registers.__iter__():
            self.registers[i.name]=i.value

        max_offset = 1024
        if self.exception:
            if self.exception=="EXC_BAD_ACCESS":
                # check pc == access_address
                
                if self.exc_address and int(self.exc_address,0)==int(self.pc,0):
                    # IP over write
                    is_exploitable = True
                    print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                    print tty_colors.red()+"Trying to execute a bad address, this is a potentially exploitable issue"+tty_colors.default()
                    reportexploitable="Trying to execute a bad address, this is a potentially exploitable issue"

                else:
                    self.access_type = getexceptiontype(self.exc_address, self.pc_disas, self.registers)
                    
                    if self.exc_address and int(self.exc_address,16)<int(PAGE_SIZE):
                        is_exploitable=False
                        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                        print tty_colors.blue()+"Null Dereference. Probably not exploitable"+tty_colors.default()
                        reportexploitable="Null Dereference. Probably not exploitable"
                        return

                    elif self.access_type == "recursion":
                        is_exploitable=False

                        stack=self.backtrace
                        MINIMUM_RECURSION_LENGTH = 300
                        stack_length= len(stack.split("\n"))

                        if stack_length>MINIMUM_RECURSION_LENGTH:
                            print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                            print tty_colors.red()+"The crash is suspected to be not exploitable due to unbounded recursion since there were %d stack frames."%stack_length+tty_colors.default()
                            reportexploitable="The crash is suspected to be not exploitable due to unbounded recursion since there were %d stack frames."%stack_length
                            return
                    else:
                        is_exploitable=True

                    if self.access_type == "exec":
                        is_exploitable = True

                    addr = self.exc_address
                    max_offset = 1024

                    if (addr > 0x55555555 - max_offset and addr < 0x55555555 + max_offset):
                        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                        print tty_colors.red()+"The access address indicates the use of freed memory if MallocScribble was used, or uninitialized memory if libgmalloc and MALLOC_FILL_SPACE was used."+tty_colors.default()
                        reportexploitable="The access address indicates the use of freed memory if MallocScribble was used, or uninitialized memory if libgmalloc and MALLOC_FILL_SPACE was used."
                    
                    elif (addr > 0xaaaaaaaa - max_offset and addr < 0xaaaaaaaa + max_offset):
                        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()                        
                        print tty_colors.red()+"The access address indicates that uninitialized memory was being used if MallocScribble was used."+tty_colors.default()
                        reportexploitable="The access address indicates that uninitialized memory was being used if MallocScribble was used."                            

                    elif "EXC_I386_GPFLT" == self.exc_code:
                        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                        print tty_colors.red()+"The exception code indicates that the access address was invalid in the 64-bit ABI (it was > 0x0000800000000000)."+tty_colors.default()
                        reportexploitable="The exception code indicates that the access address was invalid in the 64-bit ABI (it was > 0x0000800000000000)."

                    elif not g_ignore_frame_pointer  and bp_inconsistent_with_sp(self.bp,self.sp):
                        is_exploitable = True
                        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                        print tty_colors.red()+"Presumed exploitable based on the discrepancy between the stack pointer and base pointer registers. "+tty_colors.default()
                        reportexploitable="Presumed exploitable based on the discrepancy between the stack pointer and base pointer registers."

                    else:
                        print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()

                        if self.access_type=="read" or self.access_type=="write":
                            print tty_colors.red()+"Crash "+self.access_type+"'g invalid address."+tty_colors.default()
                            reportexploitable= "Crash "+self.access_type+"'g invalid address."
                        else:
                            print tty_colors.red()+"Crash accessing invalid address."+tty_colors.default()
                            reportexploitable= "Crash accessing invalid address."

            elif self.exception=="EXC_BAD_INSTRUCTION":
                is_exploitable = True
                print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                print tty_colors.blue()+"Illegal instruction at %s, probably a exploitable issue unless the crash was in libdispatch/xpc."%self.pc+tty_colors.default()
                reportexploitable="Illegal instruction at %s, probably a exploitable issue unless the crash was in libdispatch/xpc."%self.pc

            elif self.exception=="EXC_ARITHMETIC":
                is_exploitable = False
                print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                print tty_colors.blue()+"Arithmetic exception at %s, probably not exploitable."%self.pc+tty_colors.default()
                reportexploitable="Arithmetic exception at %s, probably not exploitable."%self.pc

            elif self.exception=="EXC_SOFTWARE":
                is_exploitable=False
                print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                print tty_colors.blue()+"Software exception, probably not exploitable."+tty_colors.default()
                reportexploitable="Software exception, probably not exploitable."

            elif self.exception=="EXC_BREAKPOINT":
                is_exploitable=False
                print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()
                print tty_colors.blue()+"Software breakpoint, probably not exploitable."+tty_colors.default()
                reportexploitable="Software breakpoint, probably not exploitable."
            
            elif self.exc_address=="EXC_CRASH":
                is_exploitable= False
                print tty_colors.red()+"Exploitable = %s"%is_exploitable+tty_colors.default()

        elif self.signal:
            is_stack_suspicious(self.exc_address, self.exception, self.backtrace)
        

def exploitable(debugger,cmd,res,dict):
    """checks if the crash is exploitable"""
    lisa_=Lisa(debugger,res,dict)

class ShellStorm:
    def __init__(self):
        pass

    def searchShellcode(self, keyword):
        try:
            print "Connecting to shell-storm.org..."
            s = httplib.HTTPConnection("shell-storm.org")
            s.request("GET", "/api/?s="+str(keyword))
            res = s.getresponse()
            data_l = res.read().split('\n')
        except:
            print "Cannot connect to shell-storm.org"
            return None

        data_dl = []
        for data in data_l:
            try:
                desc = data.split("::::")
                try:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': int(''.join(x for x in desc[2][-10:-5] if x.isdigit()))
                           }
                except Exception:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': 0
                           }


                data_dl.append(dico)
            except:
                pass

        try:
            return sorted(data_dl, key=lambda x: x['ScSize'], reverse=True)
        except Exception:
            print("Could not sort by size")

        return data_dl

    def displayShellcode(self, shellcodeId):
        if shellcodeId is None:
            return None

        try:
            print "Connecting to shell-storm.org..."
            s = httplib.HTTPConnection("shell-storm.org")
        except:
            print "Cannot connect to shell-storm.org"
            return None

        try:
            s.request("GET", "/shellcode/files/shellcode-"+str(shellcodeId)+".php")
            res = s.getresponse()
            data = res.read().split("<pre>")[1].split("<body>")[0]
        except:
            print "Failed to download shellcode from shell-storm.org"
            return None

        data = data.replace("&quot;", "\"")
        data = data.replace("&amp;", "&")
        data = data.replace("&lt;", "<")
        data = data.replace("&gt;", ">")

        return data

    @staticmethod
    def version():
        print "shell-storm API - v0.1"
        print "Search and display all shellcodes in shell-storm database"
        print "Jonathan Salwan - @JonathanSalwan - 2012"
        print "http://shell-storm.org"
        return

def extract_from_universal_binary(debugger,command,result,dict):
    """Uses lipo to extract a given architecture from a Universal binary
        Syntax: extract x86_64 <input file> <output file>
        Ex: extract x86_64 /usr/lib/system/libsystem_kernel.dylib ./libsystem_kernel.dylib

    """
    args = shlex.split(command)
    if len(args)==3:
        architecture = args[0]
        intputfile = args[1]
        outputfile = args[2]

        commands.getoutput('lipo '+intputfile+' -extract '+architecture+' -output '+outputfile)
    else:
        print "Syntax: extract x86_64 /usr/lib/system/libsystem_kernel.dylib ./libsystem_kernel.dylib"



def shellcode(debugger, command, result, dict):
    """Searches shell-storm for shellcode
       Syntax:shellcode"""
    mod = shlex.split(command)
    if len(mod)!=2:
        print "Syntax:   shellcode <option> <arg>\n"
        print "Options:  -search <keyword>"
        print "          -display <shellcode id>"
        print "          -save <shellcode id>"
        return

    arg = mod[1]
    mod = mod[0]
    if mod != "-search" and mod != "-display" and mod != "-save":
        syntax()
        return

    if mod == "-search":
        api = ShellStorm()
        res_dl = api.searchShellcode(arg)
        if not res_dl:
            print "Shellcode not found"
            sys.exit(0)

        print "Found %d shellcodes" % len(res_dl)
        print "%s\t%s %s" %("ScId", "Size", "Title")
        for data_d in res_dl:
            if data_d['ScSize'] == 0:
                print "[%s]\tn/a  %s - %s"%(data_d['ScId'], data_d['ScArch'], data_d['ScTitle'])
            else:
                print "[%s]\t%s%s - %s"%(data_d['ScId'], str(data_d['ScSize']).ljust(5), data_d['ScArch'], data_d['ScTitle'])

    elif mod == "-display":
        res = ShellStorm().displayShellcode(arg)
        if not res:
            print "Shellcode id not found"
            return
        print tty_colors.red()+res+tty_colors.default()

    elif mod == "-save":
        res = ShellStorm().displayShellcode(arg)

        if not res:
            print "Shellcode id not found"
            return
        f=open('shellcode_'+str(time.time())+'.c','w')
        f.write(res)
        f.close()            
        print tty_colors.red()+"Written to file shellcode_"+str(time.time())+'.c'+tty_colors.default()

    

def dump(debugger,command,result,dict):
    """Dump's Memory of the process in a given address range
       Syntax: dump outfile 0x6080000fe680 0x6080000fe680+1000
            dump will not read over 1024 bytes of data. To overwride this use -f
       Syntax: dump outfile 0x6080000fe680 0x6080000fe680+1000 -f"""

    args = shlex.split(command)
    if len(args)<3:
        print "Syntax: dump outfile 0x6080000fe680 0x6080000fe680+1000"
        return

    outfile = args[0]
    start_range = args[1]
    end_range = args[2]
    force=False
    if len(args)>3:
        force=True

    if force:
        output,error=executeReturnOutput(debugger,"memory read -b --force --outfile "+outfile+' '+start_range+' '+end_range,result,dict)    
    else:
        output,error=executeReturnOutput(debugger,"memory read -b --outfile "+outfile+' '+start_range+' '+end_range,result,dict)

    if not error:
        print output,
    else:
        if "--force" in error:
            print "dump will not read over 1024 bytes of data. To overwride this use -f."
            print "Syntax: dump outfile 0x6080000fe680 0x6080000fe680+1000 -f"
        else:
            print error

class MACH_HEADER(Structure):
    _fields_ = [
                ("magic",           c_uint),
                ("cputype",         c_uint),
                ("cpusubtype",      c_uint),
                ("filetype",        c_uint),
                ("ncmds",           c_uint),
                ("sizeofcmds",      c_uint),
                ("flags",           c_uint)
               ]

class LOAD_COMMAND(Structure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint)
               ]

class SEGMENT_COMMAND(Structure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
                ("segname",         c_ubyte * 16),
                ("vmaddr",          c_uint),
                ("vmsize",          c_uint),
                ("fileoff",         c_uint),
                ("filesize",        c_uint),
                ("maxprot",         c_uint),
                ("initprot",        c_uint),
                ("nsects",          c_uint),
                ("flags",           c_uint)
               ]

class SEGMENT_COMMAND64(Structure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
                ("segname",         c_ubyte * 16),
                ("vmaddr",          c_ulonglong),
                ("vmsize",          c_ulonglong),
                ("fileoff",         c_ulonglong),
                ("filesize",        c_ulonglong),
                ("maxprot",         c_uint),
                ("initprot",        c_uint),
                ("nsects",          c_uint),
                ("flags",           c_uint)
               ]

class SECTION(Structure):
    _fields_ = [
                ("sectname",        c_ubyte * 16),  
                ("segname",         c_ubyte * 16),  
                ("addr",            c_uint),  
                ("size",            c_uint),  
                ("offset",          c_uint),  
                ("align",           c_uint),  
                ("reloff",          c_uint),  
                ("nreloc",          c_uint),  
                ("flags",           c_uint),  
                ("reserved1",       c_uint),  
                ("reserved2",       c_uint)  
               ]
    
class SECTION64(Structure):
    _fields_ = [
                ("sectname",        c_ubyte * 16),  
                ("segname",         c_ubyte * 16),  
                ("addr",            c_ulonglong),  
                ("size",            c_ulonglong),  
                ("offset",          c_uint),  
                ("align",           c_uint),  
                ("reloff",          c_uint),  
                ("nreloc",          c_uint),  
                ("flags",           c_uint),  
                ("reserved1",       c_uint),  
                ("reserved2",       c_uint)  
               ]

class MACHOFlags:
    CPU_TYPE_I386               = 0x7
    CPU_TYPE_X86_64             = (CPU_TYPE_I386 | 0x1000000)
    CPU_TYPE_MIPS               = 0x8
    CPU_TYPE_ARM                = 12
    CPU_TYPE_SPARC              = 14
    CPU_TYPE_POWERPC            = 18
    CPU_TYPE_POWERPC64          = (CPU_TYPE_POWERPC | 0x1000000)
    LC_SEGMENT                  = 0x1
    LC_SEGMENT_64               = 0x19
    S_ATTR_SOME_INSTRUCTIONS    = 0x00000400
    S_ATTR_PURE_INSTRUCTIONS    = 0x80000000

class MachOHeader(Structure):

    _fields_ = [

        ("magic", c_uint),
        ("cputype", c_uint),
        ("cpusubtype", c_uint),
        ("filetype", c_uint),
        ("ncmds", c_uint),
        ("sizeofcmds", c_uint),
        ("flags", c_uint)

    ]

""" This class parses the Mach-O """
class MACHO:
    def __init__(self, binary):
        self.__binary = bytearray(binary)

        self.__machHeader   = None
        self.__rawLoadCmd   = None
        self.__sections_l   = []

        self.__setHeader()
        self.__setLoadCmd()

    def __setHeader(self):
        self.__machHeader = MACH_HEADER.from_buffer_copy(self.__binary)

        if self.getArchMode() == CS_MODE_32:
            self.__rawLoadCmd   = self.__binary[28:28+self.__machHeader.sizeofcmds]

        elif self.getArchMode() == CS_MODE_64:
            self.__rawLoadCmd   = self.__binary[32:32+self.__machHeader.sizeofcmds]

    def __setLoadCmd(self):
        base = self.__rawLoadCmd
        for i in range(self.__machHeader.ncmds):
            command = LOAD_COMMAND.from_buffer_copy(base)

            if command.cmd == MACHOFlags.LC_SEGMENT:
                segment = SEGMENT_COMMAND.from_buffer_copy(base)
                self.__setSections(segment.nsects, base[56:], 32)

            elif command.cmd == MACHOFlags.LC_SEGMENT_64:
                segment = SEGMENT_COMMAND64.from_buffer_copy(base)
                self.__setSections(segment.nsects, base[72:], 64)

            base = base[command.cmdsize:]

    def __setSections(self, sectionsNumber, base, sizeHeader):
        for i in range(sectionsNumber):
            if sizeHeader == 32:
                section = SECTION.from_buffer_copy(base)
                base = base[68:]
                self.__sections_l += [section]
            elif sizeHeader == 64:
                section = SECTION64.from_buffer_copy(base)
                base = base[80:]
                self.__sections_l += [section]

    def getEntryPoint(self):
        
        for section in self.__sections_l:
            if section.sectname[0:6] == "__text":
                return section.addr

    def getExecSections(self):
        ret = []
        for section in self.__sections_l:
            if section.flags & MACHOFlags.S_ATTR_SOME_INSTRUCTIONS or section.flags & MACHOFlags.S_ATTR_PURE_INSTRUCTIONS:
                ret +=  [{
                            "name"    : section.sectname,
                            "offset"  : section.offset,
                            "size"    : section.size,
                            "vaddr"   : section.addr,
                            "opcodes" : bytes(self.__binary[section.offset:section.offset+section.size])
                        }]
        return ret

    def getDataSections(self):
        ret = []
        for section in self.__sections_l:
            if not section.flags & MACHOFlags.S_ATTR_SOME_INSTRUCTIONS and not section.flags & MACHOFlags.S_ATTR_PURE_INSTRUCTIONS:
                ret +=  [{
                            "name"    : section.sectname,
                            "offset"  : section.offset,
                            "size"    : section.size,
                            "vaddr"   : section.addr,
                            "opcodes" : str(self.__binary[section.offset:section.offset+section.size])
                        }]
        return ret

    def getArch(self):
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_I386 or self.__machHeader.cputype == MACHOFlags.CPU_TYPE_X86_64: 
            return CS_ARCH_X86
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_ARM:
            return CS_ARCH_ARM
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_MIPS:
            return CS_ARCH_MIPS
        else:
            print("[Error] MACHO.getArch() - Architecture not supported")
            return None
            
    def getArchMode(self):
        if self.__machHeader.magic == 0xfeedface: 
            return 4
        elif self.__machHeader.magic == 0xfeedfacf:
            return 8
        else:
            print("[Error] MACHO.getArchMode() - Bad Arch size")
            return None
        pass

    def getFormat(self):
        return "Mach-O"

class FAT_HEADER(BigEndianStructure):
    _fields_ = [
                ("magic",           c_uint),
                ("nfat_arch",       c_uint)
               ]

class FAT_ARC(BigEndianStructure):
    _fields_ = [
                ("cputype",         c_uint),
                ("cpusubtype",      c_uint),
                ("offset",          c_uint),
                ("size",            c_uint),
                ("align",           c_uint)
               ]

class MACHOFlags:
    CPU_TYPE_I386               = 0x7
    CPU_TYPE_X86_64             = (CPU_TYPE_I386 | 0x1000000)
    CPU_TYPE_MIPS               = 0x8
    CPU_TYPE_ARM                = 12
    CPU_TYPE_SPARC              = 14
    CPU_TYPE_POWERPC            = 18
    CPU_TYPE_POWERPC64          = (CPU_TYPE_POWERPC | 0x1000000)
    LC_SEGMENT                  = 0x1
    LC_SEGMENT_64               = 0x19
    S_ATTR_SOME_INSTRUCTIONS    = 0x00000400
    S_ATTR_PURE_INSTRUCTIONS    = 0x80000000

""" This class parses the Universal binary """
class UNIVERSAL:
    def __init__(self, binary):
        self.__binary = bytearray(binary)
        self.__machoBinaries = []

        self.__fatHeader    = None
        self.__rawLoadCmd   = None
        self.__sections_l   = []

        self.__setHeader()
        self.__setBinaries()

    def __setHeader(self):
        self.__fatHeader = FAT_HEADER.from_buffer_copy(self.__binary)

    def __setBinaries(self):
        offset = 8
        for i in xrange(self.__fatHeader.nfat_arch):
            header = FAT_ARC.from_buffer_copy(self.__binary[offset:])
            rawBinary = self.__binary[header.offset:header.offset+header.size]
            if rawBinary[:4] == unhexlify(b"cefaedfe") or rawBinary[:4] == unhexlify(b"cffaedfe"):
                self.__machoBinaries.append(MACHO(rawBinary))
            else:
                print("[Error] Binary #"+str(i+1)+" in Universal binary has an unsupported format")
            offset += sizeof(header)

    def getExecSections(self):
        ret = []
        for binary in self.__machoBinaries:
            ret += binary.getExecSections()
        return ret

    def getDataSections(self):
        ret = []
        for binary in self.__machoBinaries:
            ret += binary.getDataSections()
        return ret

    def getFormat(self):
        return "Universal"

    # TODO: These three will just return whatever is in the first binary.
    # Perhaps the rest of ROPgadget should support loading multiple binaries?
    def getEntryPoint(self):
        for binary in self.__machoBinaries:
            return binary.getEntryPoint()

    def getArch(self):
        for binary in self.__machoBinaries:
            return binary.getArch()
            
    def getArchMode(self):
        for binary in self.__machoBinaries:
            return binary.getArchMode()



def deleteDuplicateGadgets(currentGadgets):
    gadgets_content_set = set()
    unique_gadgets = []
    for gadget in currentGadgets:
        gad = gadget["gadget"]
        if gad in gadgets_content_set:
            continue
        gadgets_content_set.add(gad)
        unique_gadgets += [gadget]
    return unique_gadgets

def alphaSortgadgets(currentGadgets):
    return sorted(currentGadgets, key=lambda key : key["gadget"]) 



class Options:
    def __init__(self, options, binary, gadgets):
        self.__options = options
        self.__gadgets = gadgets
        self.__binary  = binary 

        if options.filter:   self.__filterOption()
        if options.only:     self.__onlyOption()
        if options.range:    self.__rangeOption()
        if options.badbytes: self.__deleteBadBytes()

    def __filterOption(self):
        new = []
        if not self.__options.filter:
            return 
        filt = self.__options.filter.split("|")
        if not len(filt):
            return 
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] in filt:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

    def __onlyOption(self):
        new = []
        if not self.__options.only:
            return 
        only = self.__options.only.split("|")
        if not len(only):
            return 
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] not in only:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

    def __rangeOption(self):
        new = []
        rangeS = int(self.__options.range.split('-')[0], 16)
        rangeE = int(self.__options.range.split('-')[1], 16)
        if rangeS == 0 and rangeE == 0:
            return 
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            if vaddr >= rangeS and vaddr <= rangeE:
                new += [gadget]
        self.__gadgets = new

    def __deleteBadBytes(self):
        if not self.__options.badbytes:
            return
        new = []
        #Filter out empty badbytes (i.e if badbytes was set to 00|ff| there's an empty badbyte after the last '|')
        #and convert each one to the corresponding byte
        bbytes = [bb.decode('hex') for bb in self.__options.badbytes.split("|") if bb]
        archMode = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            gadAddr = pack("<L", gadget["vaddr"]) if archMode == CS_MODE_32 else pack("<Q", gadget["vaddr"])
            try:
                for x in bbytes:
                    if x in gadAddr: raise
                new += [gadget]
            except:
                pass
        self.__gadgets = new

    def getGadgets(self):
        return self.__gadgets


class ROPMakerX86:
    def __init__(self, binary, gadgets, liboffset=0x0):
        self.__binary  = binary
        self.__gadgets = gadgets

        # If it's a library, we have the option to add an offset to the addresses
        self.__liboffset = liboffset

        self.__generate()


    def __lookingForWrite4Where(self, gadgetsAlreadyTested):
        for gadget in self.__gadgets:
            if gadget in gadgetsAlreadyTested:
                continue
            f = gadget["gadget"].split(" ; ")[0]
            # regex -> mov dword ptr [r32], r32
            regex = re.search("mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$", f)
            if regex:
                lg = gadget["gadget"].split(" ; ")[1:]
                try:
                    for g in lg:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    print("\t[+] Gadget found: 0x%x %s" %(gadget["vaddr"], gadget["gadget"]))
                    return [gadget, regex.group("dst"), regex.group("src")]
                except:
                    continue
        return None

    def __lookingForSomeThing(self, something):
        for gadget in self.__gadgets:
            lg = gadget["gadget"].split(" ; ")
            if lg[0] == something:
                try:
                    for g in lg[1:]:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    print("\t[+] Gadget found: 0x%x %s" %(gadget["vaddr"], gadget["gadget"]))
                    return gadget
                except:
                    continue
        return None

    def __padding(self, gadget, regAlreadSetted):
        lg = gadget["gadget"].split(" ; ")
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    print("\tp += pack('<I', 0x%08x) # padding without overwrite %s" %(regAlreadSetted[reg], reg))
                except KeyError:
                    print("\tp += pack('<I', 0x41414141) # padding")

    def __buildRopChain(self, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):

        sects = self.__binary.getDataSections()
        dataAddr = None
        for s in sects:
            if s["name"] == ".data":
                dataAddr = s["vaddr"] + self.__liboffset
        if dataAddr == None:
            print("\n[-] Error - Can't find a writable section")
            return

        print("\t#!/usr/bin/env python2")
        print("\t# execve generated by ROPgadget\n" )
        print("\tfrom struct import pack\n")

        print("\t# Padding goes here")
        print("\tp = ''\n")

        print("\tp += pack('<I', 0x%08x) # %s" %(popDst["vaddr"], popDst["gadget"]))
        print("\tp += pack('<I', 0x%08x) # @ .data" %(dataAddr))
        self.__padding(popDst, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(popSrc["vaddr"], popSrc["gadget"]))
        print("\tp += '/bin'")
        self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr}) # Don't overwrite reg dst

        print("\tp += pack('<I', 0x%08x) # %s" %(write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(popDst["vaddr"], popDst["gadget"]))
        print("\tp += pack('<I', 0x%08x) # @ .data + 4" %(dataAddr + 4))
        self.__padding(popDst, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(popSrc["vaddr"], popSrc["gadget"]))
        print("\tp += '//sh'")
        self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr + 4}) # Don't overwrite reg dst

        print("\tp += pack('<I', 0x%08x) # %s" %(write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(popDst["vaddr"], popDst["gadget"]))
        print("\tp += pack('<I', 0x%08x) # @ .data + 8" %(dataAddr + 8))
        self.__padding(popDst, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(xorSrc["vaddr"], xorSrc["gadget"]))
        self.__padding(xorSrc, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(popEbx["vaddr"], popEbx["gadget"]))
        print("\tp += pack('<I', 0x%08x) # @ .data" %(dataAddr))
        self.__padding(popEbx, {})

        print("\tp += pack('<I', 0x%08x) # %s" %(popEcx["vaddr"], popEcx["gadget"]))
        print("\tp += pack('<I', 0x%08x) # @ .data + 8" %(dataAddr + 8))
        self.__padding(popEcx, {"ebx": dataAddr}) # Don't overwrite ebx

        print("\tp += pack('<I', 0x%08x) # %s" %(popEdx["vaddr"], popEdx["gadget"]))
        print("\tp += pack('<I', 0x%08x) # @ .data + 8" %(dataAddr + 8))
        self.__padding(popEdx, {"ebx": dataAddr, "ecx": dataAddr + 8}) # Don't overwrite ebx and ecx

        print("\tp += pack('<I', 0x%08x) # %s" %(xorEax["vaddr"], xorEax["gadget"]))
        self.__padding(xorEax, {"ebx": dataAddr, "ecx": dataAddr + 8}) # Don't overwrite ebx and ecx

        for i in range(11):
            print("\tp += pack('<I', 0x%08x) # %s" %(incEax["vaddr"], incEax["gadget"]))
            self.__padding(incEax, {"ebx": dataAddr, "ecx": dataAddr + 8}) # Don't overwrite ebx and ecx

        print("\tp += pack('<I', 0x%08x) # %s" %(syscall["vaddr"], syscall["gadget"]))

    def __generate(self):

        # To find the smaller gadget
        self.__gadgets.reverse()

        print("\nROP chain generation\n===========================================================")

        print("\n- Step 1 -- Write-what-where gadgets\n")

        gadgetsAlreadyTested = []
        while True:
            write4where = self.__lookingForWrite4Where(gadgetsAlreadyTested)
            if not write4where:
                print("\t[-] Can't find the 'mov dword ptr [r32], r32' gadget")
                return

            popDst = self.__lookingForSomeThing("pop %s" %(write4where[1]))
            if not popDst:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" %(write4where[1]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            popSrc = self.__lookingForSomeThing("pop %s" %(write4where[2]))
            if not popSrc:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" %(write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            xorSrc = self.__lookingForSomeThing("xor %s, %s" %(write4where[2], write4where[2]))
            if not xorSrc:
                print("\t[-] Can't find the 'xor %s, %s' gadget. Try with another 'mov [r], r'\n" %(write4where[2], write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue
            else:
                break

        print("\n- Step 2 -- Init syscall number gadgets\n")

        xorEax = self.__lookingForSomeThing("xor eax, eax")
        if not xorEax:
            print("\t[-] Can't find the 'xor eax, eax' instuction")
            return

        incEax = self.__lookingForSomeThing("inc eax")
        if not incEax:
            print("\t[-] Can't find the 'inc eax' instuction")
            return

        print("\n- Step 3 -- Init syscall arguments gadgets\n")

        popEbx = self.__lookingForSomeThing("pop ebx")
        if not popEbx:
            print("\t[-] Can't find the 'pop ebx' instruction")
            return

        popEcx = self.__lookingForSomeThing("pop ecx")
        if not popEcx:
            print("\t[-] Can't find the 'pop ecx' instruction")
            return

        popEdx = self.__lookingForSomeThing("pop edx")
        if not popEdx:
            print("\t[-] Can't find the 'pop edx' instruction")
            return

        print("\n- Step 4 -- Syscall gadget\n")

        syscall = self.__lookingForSomeThing("int 0x80")
        if not syscall:
            print("\t[-] Can't find the 'syscall' instruction")
            return

        print("\n- Step 5 -- Build the ROP chain\n")

        self.__buildRopChain(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)

class ROPMakerX64:
    def __init__(self, binary, gadgets, liboffset=0x0):
        self.__binary  = binary
        self.__gadgets = gadgets

        # If it's a library, we have the option to add an offset to the addresses
        self.__liboffset = liboffset

        self.__generate()


    def __lookingForWrite4Where(self, gadgetsAlreadyTested):
        for gadget in self.__gadgets:
            if gadget in gadgetsAlreadyTested:
                continue
            f = gadget["gadget"].split(" ; ")[0]
            regex = re.search("mov .* ptr \[(?P<dst>([(rax)|(rbx)|(rcx)|(rdx)|(rsi)|(rdi)|(r9)|(r10)|(r11)|(r12)|(r13)|(r14)|(r15)]{3}))\], (?P<src>([(rax)|(rbx)|(rcx)|(rdx)|(rsi)|(rdi)|(r9)|(r10)|(r11)|(r12)|(r13)|(r14)|(r15)]{3}))$", f)
            if regex:
                lg = gadget["gadget"].split(" ; ")[1:]
                try:
                    for g in lg:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    print("\t[+] Gadget found: 0x%x %s" %(gadget["vaddr"], gadget["gadget"]))
                    return [gadget, regex.group("dst"), regex.group("src")]
                except:
                    continue
        return None

    def __lookingForSomeThing(self, something):
        for gadget in self.__gadgets:
            lg = gadget["gadget"].split(" ; ")
            if lg[0] == something:
                try:
                    for g in lg[1:]:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        if g != "ret":
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    print("\t[+] Gadget found: 0x%x %s" %(gadget["vaddr"], gadget["gadget"]))
                    return gadget
                except:
                    continue
        return None

    def __padding(self, gadget, regAlreadSetted):
        lg = gadget["gadget"].split(" ; ")
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    print("\tp += pack('<Q', 0x%016x) # padding without overwrite %s" %(regAlreadSetted[reg], reg))
                except KeyError:
                    print("\tp += pack('<Q', 0x4141414141414141) # padding")

    def __buildRopChain(self, write4where, popDst, popSrc, xorSrc, xorRax, incRax, popRdi, popRsi, popRdx, syscall):

        sects = self.__binary.getDataSections()
        dataAddr = None
        for s in sects:
            if s["name"] == ".data":
                dataAddr = s["vaddr"] + self.__liboffset
        if dataAddr is None:
            print("\n[-] Error - Can't find a writable section")
            return

        print("\t#!/usr/bin/env python2")
        print("\t# execve generated by ROPgadget\n")
        print("\tfrom struct import pack\n")

        print("\t# Padding goes here")
        print("\tp = ''\n")

        print("\tp += pack('<Q', 0x%016x) # %s" %(popDst["vaddr"], popDst["gadget"]))
        print("\tp += pack('<Q', 0x%016x) # @ .data" %(dataAddr))
        self.__padding(popDst, {})

        print("\tp += pack('<Q', 0x%016x) # %s" %(popSrc["vaddr"], popSrc["gadget"]))
        print("\tp += '/bin//sh'")
        self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr}) # Don't overwrite reg dst

        print("\tp += pack('<Q', 0x%016x) # %s" %(write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("\tp += pack('<Q', 0x%016x) # %s" %(popDst["vaddr"], popDst["gadget"]))
        print("\tp += pack('<Q', 0x%016x) # @ .data + 8" %(dataAddr + 8))
        self.__padding(popDst, {})

        print("\tp += pack('<Q', 0x%016x) # %s" %(xorSrc["vaddr"], xorSrc["gadget"]))
        self.__padding(xorSrc, {})

        print("\tp += pack('<Q', 0x%016x) # %s" %(write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("\tp += pack('<Q', 0x%016x) # %s" %(popRdi["vaddr"], popRdi["gadget"]))
        print("\tp += pack('<Q', 0x%016x) # @ .data" %(dataAddr))
        self.__padding(popRdi, {})

        print("\tp += pack('<Q', 0x%016x) # %s" %(popRsi["vaddr"], popRsi["gadget"]))
        print("\tp += pack('<Q', 0x%016x) # @ .data + 8" %(dataAddr + 8))
        self.__padding(popRsi, {"rdi": dataAddr}) # Don't overwrite rdi

        print("\tp += pack('<Q', 0x%016x) # %s" %(popRdx["vaddr"], popRdx["gadget"]))
        print("\tp += pack('<Q', 0x%016x) # @ .data + 8" %(dataAddr + 8))
        self.__padding(popRdx, {"rdi": dataAddr, "rsi": dataAddr + 8}) # Don't overwrite rdi and rsi

        print("\tp += pack('<Q', 0x%016x) # %s" %(xorRax["vaddr"], xorRax["gadget"]))
        self.__padding(xorRax, {"rdi": dataAddr, "rsi": dataAddr + 8}) # Don't overwrite rdi and rsi

        for i in range(59):
            print("\tp += pack('<Q', 0x%016x) # %s" %(incRax["vaddr"], incRax["gadget"]))
            self.__padding(incRax, {"rdi": dataAddr, "rsi": dataAddr + 8}) # Don't overwrite rdi and rsi

        print("\tp += pack('<Q', 0x%016x) # %s" %(syscall["vaddr"], syscall["gadget"]))

    def __generate(self):

        # To find the smaller gadget
        self.__gadgets.reverse()

        print("\nROP chain generation\n===========================================================")

        print("\n- Step 1 -- Write-what-where gadgets\n")

        gadgetsAlreadyTested = []
        while True:
            write4where = self.__lookingForWrite4Where(gadgetsAlreadyTested)
            if not write4where:
                print("\t[-] Can't find the 'mov qword ptr [r64], r64' gadget")
                return

            popDst = self.__lookingForSomeThing("pop %s" %(write4where[1]))
            if not popDst:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" %(write4where[1]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            popSrc = self.__lookingForSomeThing("pop %s" %(write4where[2]))
            if not popSrc:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" %(write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            xorSrc = self.__lookingForSomeThing("xor %s, %s" %(write4where[2], write4where[2]))
            if not xorSrc:
                print("\t[-] Can't find the 'xor %s, %s' gadget. Try with another 'mov [reg], reg'\n" %(write4where[2], write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue
            else:
                break

        print("\n- Step 2 -- Init syscall number gadgets\n")

        xorRax = self.__lookingForSomeThing("xor rax, rax")
        if not xorRax:
            print("\t[-] Can't find the 'xor rax, rax' instuction")
            return

        incRax = self.__lookingForSomeThing("inc rax")
        incEax = self.__lookingForSomeThing("inc eax")
        incAx = self.__lookingForSomeThing("inc al")
        addRax = self.__lookingForSomeThing("add rax, 1")
        addEax = self.__lookingForSomeThing("add eax, 1")
        addAx = self.__lookingForSomeThing("add al, 1")

        instr = [incRax, incEax, incAx, addRax, addEax, addAx]

        if all(v is None for v in instr):
            print("\t[-] Can't find the 'inc rax' or 'add rax, 1' instuction")
            return

        for i in instr:
            if i is not None:
                incRax = i
                break

        print("\n- Step 3 -- Init syscall arguments gadgets\n")

        popRdi = self.__lookingForSomeThing("pop rdi")
        if not popRdi:
            print("\t[-] Can't find the 'pop rdi' instruction")
            return

        popRsi = self.__lookingForSomeThing("pop rsi")
        if not popRsi:
            print("\t[-] Can't find the 'pop rsi' instruction")
            return

        popRdx = self.__lookingForSomeThing("pop rdx")
        if not popRdx:
            print("\t[-] Can't find the 'pop rdx' instruction")
            return

        print("\n- Step 4 -- Syscall gadget\n")

        syscall = self.__lookingForSomeThing("syscall")
        if not syscall:
            print("\t[-] Can't find the 'syscall' instruction")
            return

        print("\n- Step 5 -- Build the ROP chain\n")

        self.__buildRopChain(write4where[0], popDst, popSrc, xorSrc, xorRax, incRax, popRdi, popRsi, popRdx, syscall)


class ROPMaker:
    def __init__(self, binary, gadgets, offset):
        self.__binary  = binary
        self.__gadgets = gadgets
        self.__offset  = offset

        self.__handlerArch()

    def __handlerArch(self):

        if self.__binary.getArch() == CS_ARCH_X86           \
            and self.__binary.getArchMode() == CS_MODE_32   \
            and self.__binary.getFormat() == "ELF":
            ROPMakerX86(self.__binary, self.__gadgets, self.__offset)

        elif self.__binary.getArch() == CS_ARCH_X86         \
            and self.__binary.getArchMode() == CS_MODE_64   \
            and self.__binary.getFormat() == "ELF":
            ROPMakerX64(self.__binary, self.__gadgets, self.__offset)

        else:
            print("\n[Error] ROPMaker.__handlerArch - Arch not supported yet for the rop chain generation")


class Gadgets:
    def __init__(self, binary, options, offset):
        self.__binary  = binary
        self.__options = options
        self.__offset  = offset


    def __checkInstructionBlackListedX86(self, insts):
        bl = ["db", "int3"]
        for inst in insts:
            for b in bl:
                if inst.split(" ")[0] == b:
                    return True
        return False

    def __checkMultiBr(self, insts, br):
        count = 0
        for inst in insts:
            if inst.split()[0] in br:
                count += 1
        return count

    def __passCleanX86(self, gadgets, multibr=False):
        new = []
        br = ["ret", "retf", "int", "sysenter", "jmp", "call", "syscall"]
        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if self.__checkInstructionBlackListedX86(insts):
                continue
            if not multibr and self.__checkMultiBr(insts, br) > 1:
                continue
            if len([m.start() for m in re.finditer("ret", gadget["gadget"])]) > 1:
                continue
            new += [gadget]
        return new

    def __gadgetsFinding(self, section, gadgets, arch, mode):

        C_OP    = 0
        C_SIZE  = 1
        C_ALIGN = 2

        ret = []
        md = Cs(arch, mode)
        for gad in gadgets:
            
            allRefRet = [m.start() for m in re.finditer(gad[C_OP], section["opcodes"])]
            for ref in allRefRet:
                for i in range(self.__options.depth):
                    if (section["vaddr"]+ref-(i*gad[C_ALIGN])) % gad[C_ALIGN] == 0:
                        off = self.__offset
                        decodes = md.disasm(section["opcodes"][ref-(i*gad[C_ALIGN]):ref+gad[C_SIZE]], section["vaddr"]+ref)
                        gadget = ""
                        for decode in decodes:
                            gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                        if len(gadget) > 0:
                            gadget = gadget[:-3]
                            off = self.__offset
                            ret += [{"vaddr" :  off+section["vaddr"]+ref-(i*gad[C_ALIGN]), "gadget" : gadget, "decodes" : decodes, "bytes": section["opcodes"][ref-(i*gad[C_ALIGN]):ref+gad[C_SIZE]]}]
        return ret

    def addROPGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()

        if arch == CS_ARCH_X86:
            gadgets = [
                            [b"\xc3", 1, 1],               # ret
                            [b"\xc2[\x00-\xff]{2}", 3, 1], # ret <imm>
                            [b"\xcb", 1, 1],               # retf
                            [b"\xca[\x00-\xff]{2}", 3, 1]  # retf <imm>
                       ]

        elif arch == CS_ARCH_MIPS:   gadgets = []            # MIPS doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_PPC:
            gadgets = [
                            [b"\x4e\x80\x00\x20", 4, 4] # blr
                       ]
            arch_mode = arch_mode + CS_MODE_BIG_ENDIAN

        elif arch == CS_ARCH_SPARC:
            gadgets = [
                            [b"\x81\xc3\xe0\x08", 4, 4], # retl
                            [b"\x81\xc7\xe0\x08", 4, 4], # ret
                            [b"\x81\xe8\x00\x00", 4, 4]  # restore
                       ]
            arch_mode = CS_MODE_BIG_ENDIAN

        elif arch == CS_ARCH_ARM:    gadgets = []            # ARM doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_ARM64:
            gadgets =  [
                            [b"\xc0\x03\x5f\xd6", 4, 4] # ret
                       ]
            arch_mode = CS_MODE_ARM

        else:
            print("Gadgets().addROPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return gadgets


    def addJOPGadgets(self, section):
        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()



        if arch  == CS_ARCH_X86:
            gadgets = [
                               [b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                               [b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1]  # call [reg]
                      ]


        elif arch == CS_ARCH_MIPS:
            gadgets = [
                               [b"\x09\xf8\x20\x03[\x00-\xff]{4}", 8, 4], # jrl $t9
                               [b"\x08\x00\x20\x03[\x00-\xff]{4}", 8, 4], # jr  $t9
                               [b"\x08\x00\xe0\x03[\x00-\xff]{4}", 8, 4]  # jr  $ra
                      ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # PPC architecture doesn't contains reg branch instruction
        elif arch == CS_ARCH_SPARC:
            gadgets = [
                               [b"\x81\xc0[\x00\x40\x80\xc0]{1}\x00", 4, 4]  # jmp %g[0-3]
                      ]
            arch_mode = CS_MODE_BIG_ENDIAN
        elif arch == CS_ARCH_ARM64:
            gadgets = [
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00\x02]{1}\x1f\xd6", 4, 4],     # br  reg
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00\x02]{1}\x5C\x3f\xd6", 4, 4]  # blr reg
                      ]
            arch_mode = CS_MODE_ARM
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2], # bx   reg
                               [b"[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2], # blx  reg
                               [b"[\x00-\xff]{1}\xbd", 2, 2]                                     # pop {,pc}
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                               [b"[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                               [b"[\x00-\xff]{1}\x80\xbd\xe8", 4, 4]       # pop {,pc}
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addJOPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return gadgets


    def addSYSGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()

        if   arch == CS_ARCH_X86:
            gadgets = [
                               [b"\xcd\x80", 2, 1],                         # int 0x80
                               [b"\x0f\x34", 2, 1],                         # sysenter
                               [b"\x0f\x05", 2, 1],                         # syscall
                               [b"\x65\xff\x15\x10\x00\x00\x00", 7, 1],     # call DWORD PTR gs:0x10
                               [b"\xcd\x80\xc3", 3, 1],                     # int 0x80 ; ret
                               [b"\x0f\x34\xc3", 3, 1],                     # sysenter ; ret
                               [b"\x0f\x05\xc3", 3, 1],                     # syscall ; ret
                               [b"\x65\xff\x15\x10\x00\x00\x00\xc3", 8, 1], # call DWORD PTR gs:0x10 ; ret
                      ]

        elif arch == CS_ARCH_MIPS:
            gadgets = [
                               [b"\x0c\x00\x00\x00", 4, 4] # syscall
                      ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # TODO (sc inst)
        elif arch == CS_ARCH_SPARC:  gadgets = [] # TODO (ta inst)
        elif arch == CS_ARCH_ARM64:  gadgets = [] # TODO
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"\x00-\xff]{1}\xef", 2, 2] # svc
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"\x00-\xff]{3}\xef", 4, 4] # svc
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addSYSGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return []


    def passClean(self, gadgets, multibr):

        arch = self.__binary.getArch()
        if   arch == CS_ARCH_X86:    return self.__passCleanX86(gadgets, multibr)
        elif arch == CS_ARCH_MIPS:   return gadgets
        elif arch == CS_ARCH_PPC:    return gadgets
        elif arch == CS_ARCH_SPARC:  return gadgets
        elif arch == CS_ARCH_ARM:    return gadgets
        elif arch == CS_ARCH_ARM64:  return gadgets
        else:
            print("Gadgets().passClean() - Architecture not supported")
            return None


class Core(cmd.Cmd):
    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary  = None
        self.__gadgets = []
        self.__offset  = 0
        self.prompt    = '(ROPgadget)> '


    def __checksBeforeManipulations(self):
        if self.__binary == None or self.__binary.getBinary() == None or self.__binary.getArch() == None or self.__binary.getArchMode() == None:
            return False
        return True


    def __getAllgadgets(self):

        if self.__checksBeforeManipulations() == False:
            return False

        G = Gadgets(self.__binary, self.__options, self.__offset)
        execSections = self.__binary.getExecSections()

        # Find ROP/JOP/SYS gadgets
        self.__gadgets = []
        for section in execSections:
            if not self.__options.norop: self.__gadgets += G.addROPGadgets(section)
            if not self.__options.nojop: self.__gadgets += G.addJOPGadgets(section)
            if not self.__options.nosys: self.__gadgets += G.addSYSGadgets(section)

        # Pass clean single instruction and unknown instructions
        self.__gadgets = G.passClean(self.__gadgets, self.__options.multibr)

        # Delete duplicate gadgets
        if not self.__options.all:
            self.__gadgets = deleteDuplicateGadgets(self.__gadgets)

        # Applicate some Options
        self.__gadgets = Options(self.__options, self.__binary, self.__gadgets).getGadgets()

        # Sorted alphabetically
        self.__gadgets = alphaSortgadgets(self.__gadgets)

        return True


    def __lookingForGadgets(self):

        if self.__checksBeforeManipulations() == False:
            return False

        arch = self.__binary.getArchMode()
        print("Gadgets information\n============================================================")
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            bytes = gadget["bytes"]
            bytesStr = " // " + bytes.encode('hex') if self.__options.dump else ""

            print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(insts) + bytesStr)

        print("\nUnique gadgets found: %d" %(len(self.__gadgets)))
        return True


    def __lookingForAString(self, string):

        if self.__checksBeforeManipulations() == False:
            return False

        dataSections = self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print("Strings information\n============================================================")
        for section in dataSections:
            allRef = [m.start() for m in re.finditer(string, section["opcodes"])]
            for ref in allRef:
                vaddr  = self.__offset + section["vaddr"] + ref
                string = section["opcodes"][ref:ref+len(string)]
                rangeS = int(self.__options.range.split('-')[0], 16)
                rangeE = int(self.__options.range.split('-')[1], 16)
                if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                    print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(string))
        return True


    def __lookingForOpcodes(self, opcodes):

        if self.__checksBeforeManipulations() == False:
            return False

        execSections = self.__binary.getExecSections()
        arch = self.__binary.getArchMode()
        print("Opcodes information\n============================================================")
        for section in execSections:
            allRef = [m.start() for m in re.finditer(opcodes.decode("hex"), section["opcodes"])]
            for ref in allRef:
                vaddr  = self.__offset + section["vaddr"] + ref
                rangeS = int(self.__options.range.split('-')[0], 16)
                rangeE = int(self.__options.range.split('-')[1], 16)
                if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                    print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(opcodes))
        return True


    def __lookingForMemStr(self, memstr):

        if self.__checksBeforeManipulations() == False:
            return False

        sections  = self.__binary.getExecSections()
        sections += self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print("Memory bytes information\n=======================================================")
        chars = list(memstr)
        for char in chars:
            try:
                for section in sections:
                    allRef = [m.start() for m in re.finditer(char, section["opcodes"])]
                    for ref in allRef:
                        vaddr  = self.__offset + section["vaddr"] + ref
                        rangeS = int(self.__options.range.split('-')[0], 16)
                        rangeE = int(self.__options.range.split('-')[1], 16)
                        if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                            print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : '%c'" %(char))
                            raise
            except:
                pass
        return True


    def analyze(self):

        try:
            self.__offset = int(self.__options.offset, 16) if self.__options.offset else 0
        except ValueError:
            print("[Error] The offset must be in hexadecimal")
            return False

        if self.__options.console:
            if self.__options.binary:
                self.__binary = Binary(self.__options)
                if self.__checksBeforeManipulations() == False:
                    return False
            self.cmdloop()
            return True

        self.__binary = Binary(self.__options)
        if self.__checksBeforeManipulations() == False:
            return False

        if   self.__options.string:   return self.__lookingForAString(self.__options.string)
        elif self.__options.opcode:   return self.__lookingForOpcodes(self.__options.opcode)
        elif self.__options.memstr:   return self.__lookingForMemStr(self.__options.memstr)
        else: 
            self.__getAllgadgets()
            self.__lookingForGadgets()
            if self.__options.ropchain:
                ROPMaker(self.__binary, self.__gadgets, self.__offset)
            return True


    def gadgets(self):
        return self.__gadgets




    # Console methods  ============================================

    def do_binary(self, s, silent=False):
        # Do not split the filename with spaces since it might contain 
        # whitespaces
        if len(s) == 0:
            if not silent:
                return self.help_binary()
            return False

        binary = s

        self.__options.binary = binary
        self.__binary = Binary(self.__options)
        if self.__checksBeforeManipulations() == False:
            return False

        if not silent:
            print("[+] Binary loaded")


    def help_binary(self):
        print("Syntax: binary <file> -- Load a binary")
        return False


    def do_EOF(self, s, silent=False):
        return self.do_quit(s, silent)

    def do_quit(self, s, silent=False):
        return True


    def help_quit(self):
        print("Syntax: quit -- Terminates the application")
        return False


    def do_load(self, s, silent=False):

        if self.__binary == None:
            if not silent:
                print("[-] No binary loaded.")
            return False

        if not silent:
            print("[+] Loading gadgets, please wait...")
        self.__getAllgadgets()

        if not silent:
            print("[+] Gadgets loaded !")

        
    def help_load(self):
        print("Syntax: load -- Load all gadgets")
        return False


    def do_display(self, s, silent=False):
        self.__lookingForGadgets()


    def help_display(self):
        print("Syntax: display -- Display all gadgets loaded")
        return False


    def do_depth(self, s, silent=False):
        try:
            depth = int(s.split()[0])
        except:
            if not silent:
                return self.help_depth()
            return False
        if depth <= 0:
            if not silent:
                print("[-] The depth value must be > 0")
            return False
        self.__options.depth = int(depth)

        if not silent:
            print("[+] Depth updated. You have to reload gadgets")


    def help_depth(self):
        print("Syntax: depth <value> -- Set the depth search engine")
        return False


    def do_badbytes(self, s, silent=False):
        try:
            bb = s.split()[0]
        except:
            if not silent:
                return self.help_badbytes()
            else:
                return False
        self.__options.badbytes = bb

        if not silent:
            print("[+] Bad bytes updated. You have to reload gadgets")


    def help_badbytes(self):
        print("Syntax: badbytes <badbyte1|badbyte2...> -- ")
        return False


    def __withK(self, listK, gadget):
        if len(listK) == 0:
            return True
        for a in listK:
            if a not in gadget:
                return False
        return True
        
    def __withoutK(self, listK, gadget):
        for a in listK:
            if a in gadget:
                return False
        return True

    def do_search(self, s, silent=False):
        args = s.split()
        if not len(args):
            return self.help_search()
        withK, withoutK = [], []
        for a in args:
            if a[0:1] == "!":
                withoutK += [a[1:]]
            else:
                withK += [a]
        if self.__checksBeforeManipulations() == False:
            if not silent:
                print("[-] You have to load a binary")
            return False
        arch = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            if self.__withK(withK, insts) and self.__withoutK(withoutK, insts):
                # What to do if silent = True?
                print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(insts))


    def help_search(self):
        print("Syntax: search <keyword1 keyword2 keyword3...> -- Filter with or without keywords")
        print("keyword  = with")
        print("!keyword = witout")
        return False


    def count(self):
        return len(self.__gadgets)

    def do_count(self, s, silent=False):
        if not silent:
            print("[+] %d loaded gadgets." % self.count())


    def help_count(self):
        print("Shows the number of loaded gadgets.")
        return False


    def do_filter(self, s, silent=False):
        try:
            self.__options.filter = s.split()[0]
        except:
            if not silent:
                return self.help_filter()
            return False

        if not silent:
            print("[+] Filter setted. You have to reload gadgets")


    def help_filter(self):
        print("Syntax: filter <filter1|filter2|...> - Suppress specific instructions")
        return False


    def do_only(self, s, silent=False):
        try:
            self.__options.only = s.split()[0]
        except:
            if not silent:
                return self.help_only()
            return False

        if not silent:
            print("[+] Only setted. You have to reload gadgets")


    def help_only(self):
        print("Syntax: only <only1|only2|...> - Only show specific instructions")
        return False


    def do_range(self, s, silent=False):
            try:
                rangeS = int(s.split('-')[0], 16)
                rangeE = int(s.split('-')[1], 16)
                self.__options.range = s.split()[0]
            except:
                if not silent:
                    return self.help_range()
                return False

            if rangeS > rangeE:
                if not silent:
                    print("[-] The start value must be greater than the end value")
                return False

            if not silent:
                print("[+] Range setted. You have to reload gadgets")


    def help_range(self):
        print("Syntax: range <start-and> - Search between two addresses (0x...-0x...)")
        return False


    def do_settings(self, s, silent=False):
        print("All:         %s" %(self.__options.all))
        print("Badbytes:    %s" %(self.__options.badbytes))
        print("Binary:      %s" %(self.__options.binary))
        print("Depth:       %s" %(self.__options.depth))
        print("Filter:      %s" %(self.__options.filter))
        print("Memstr:      %s" %(self.__options.memstr))
        print("MultiBr:     %s" %(self.__options.multibr))
        print("NoJOP:       %s" %(self.__options.nojop))
        print("NoROP:       %s" %(self.__options.norop))
        print("NoSYS:       %s" %(self.__options.nosys))
        print("Offset:      %s" %(self.__options.offset))
        print("Only:        %s" %(self.__options.only))
        print("Opcode:      %s" %(self.__options.opcode))
        print("ROPchain:    %s" %(self.__options.ropchain))
        print("Range:       %s" %(self.__options.range))
        print("RawArch:     %s" %(self.__options.rawArch))
        print("RawMode:     %s" %(self.__options.rawMode))
        print("String:      %s" %(self.__options.string))
        print("Thumb:       %s" %(self.__options.thumb))

    def help_settings(self):
        print("Display setting's environment")
        return False


    def do_nojop(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_nojop()

        if arg == "enable":
            self.__options.nojop = True
            if not silent:
                print("[+] NoJOP enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.nojop = False
            if not silent:
                print("[+] NoJOP disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_nojop()
            return False


    def help_nojop(self):
        print("Syntax: nojop <enable|disable> - Disable JOP search engin")
        return False


    def do_norop(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_norop()

        if arg == "enable":
            self.__options.norop = True
            if not silent:
                print("[+] NoROP enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.norop = False
            if not silent:
                print("[+] NoROP disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_norop()
            return False


    def help_norop(self):
        print("Syntax: norop <enable|disable> - Disable ROP search engin")
        return False


    def do_nosys(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_nosys()

        if arg == "enable":
            self.__options.nosys = True
            if not silent:
                print("[+] NoSYS enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.nosys = False
            if not silent:
                print("[+] NoSYS disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_nosys()

            return False


    def help_nosys(self):
        print("Syntax: nosys <enable|disable> - Disable SYS search engin")
        return False


    def do_thumb(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_thumb()

        if arg == "enable":
            self.__options.thumb = True
            if not silent:
                print("[+] Thumb enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.thumb = False
            if not silent:
                print("[+] Thumb disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_thumb()
            return False


    def help_thumb(self):
        print("Syntax: thumb <enable|disable> - Use the thumb mode for the search engine (ARM only)")
        return False


    def do_all(self, s, silent=False):
        if s == "enable":
            self.__options.all = True
            if not silent:
                print("[+] Showing all gadgets enabled. You have to reload gadgets")

        elif s == "disable":
            self.__options.all = False
            if not silent:
                print("[+] Showing all gadgets disabled. You have to reload gadgets")

        else:
            if not silent:
                return self.help_all()

            return False


    def help_multibr(self):
        print("Syntax: multibr <enable|disable> - Enable/Disable multiple branch gadgets")
        return False


    def do_multibr(self, s, silent=False):
        if s == "enable":
            self.__options.multibr = True
            if not silent:
                print("[+] Multiple branch gadgets enabled. You have to reload gadgets")

        elif s == "disable":
            self.__options.multibr = False
            if not silent:
                print("[+] Multiple branch gadgets disabled. You have to reload gadgets")

        else:
            if not silent:
                return self.help_all()

            return False


    def help_all(self):
        print("Syntax: all <enable|disable - Show all gadgets (disable removing duplice gadgets)")
        return False

class Binary:
    def __init__(self, options):
        self.__fileName  = options.binary
        self.__rawBinary = None
        self.__binary    = None

        try:
            fd = open(self.__fileName, "rb")
            self.__rawBinary = fd.read()
            fd.close()
        except:
            print("[Error] Can't open the binary or binary not found")
            return None 

        if self.__rawBinary[:4] == unhexlify(b"cafebabe"):
             self.__binary = UNIVERSAL(self.__rawBinary)
        elif self.__rawBinary[:4] == unhexlify(b"cefaedfe") or self.__rawBinary[:4] == unhexlify(b"cffaedfe"):
             self.__binary = MACHO(self.__rawBinary)

    def getFileName(self):
        return self.__fileName

    def getRawBinary(self):
        return self.__rawBinary

    def getBinary(self):
        return self.__binary

    def getEntryPoint(self):
        return self.__binary.getEntryPoint()

    def getDataSections(self):
        return self.__binary.getDataSections()

    def getExecSections(self):
        return self.__binary.getExecSections()

    def getArch(self):
        return self.__binary.getArch()

    def getArchMode(self):
        return self.__binary.getArchMode()

    def getFormat(self):
        return self.__binary.getFormat()
class Args:
    def __init__(self, arguments=None):
        self.__args = None
        custom_arguments_provided = True

        # If no custom arguments are provided, use the program arguments
        if not arguments:
          arguments = args
          custom_arguments_provided = False

        sys.argv=arguments
        self.__parse(arguments, custom_arguments_provided)

    def __parse(self, arguments, custom_arguments_provided=False):
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                         description="""description:
  rop(ROPgadget) lets you search your gadgets on a binary. It supports several 
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
""",
  epilog="""examples:
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
  rop --binary ./test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32""")

        parser.add_argument("--binary",             type=str, metavar="<binary>",     help="Specify a binary filename to analyze")
        parser.add_argument("--opcode",             type=str, metavar="<opcodes>",    help="Search opcode in executable segment")
        parser.add_argument("--string",             type=str, metavar="<string>",     help="Search string in readable segment")
        parser.add_argument("--memstr",             type=str, metavar="<string>",     help="Search each byte in all readable segment")
        parser.add_argument("--depth",              type=int, metavar="<nbyte>",      default=10, help="Depth for search engine (default 10)")
        parser.add_argument("--only",               type=str, metavar="<key>",        help="Only show specific instructions")
        parser.add_argument("--filter",             type=str, metavar="<key>",        help="Suppress specific instructions")
        parser.add_argument("--range",              type=str, metavar="<start-end>",  default="0x0-0x0", help="Search between two addresses (0x...-0x...)")
        parser.add_argument("--badbytes",           type=str, metavar="<byte>",       help="Rejects specific bytes in the gadget's address")
        parser.add_argument("--rawArch",            type=str, metavar="<arch>",       help="Specify an arch for a raw file")
        parser.add_argument("--rawMode",            type=str, metavar="<mode>",       help="Specify a mode for a raw file")
        parser.add_argument("--offset",             type=str, metavar="<hexaddr>",    help="Specify an offset for gadget addresses")
        parser.add_argument("--ropchain",           action="store_true",              help="Enable the ROP chain generation")
        parser.add_argument("--thumb"  ,            action="store_true",              help="Use the thumb mode for the search engine (ARM only)")
        parser.add_argument("--console",            action="store_true",              help="Use an interactive console for search engine")
        parser.add_argument("--norop",              action="store_true",              help="Disable ROP search engine")
        parser.add_argument("--nojop",              action="store_true",              help="Disable JOP search engine")
        parser.add_argument("--nosys",              action="store_true",              help="Disable SYS search engine")
        parser.add_argument("--multibr",            action="store_true",              help="Enable multiple branch gadgets")
        parser.add_argument("--all",                action="store_true",              help="Disables the removal of duplicate gadgets")
        parser.add_argument("--dump",               action="store_true",              help="Outputs the gadget bytes")
        
        self.__args = parser.parse_args(arguments)

        if self.__args.depth < 2:
            print("[Error] The depth must be >= 2")
            sys.exit(-1)

        elif not custom_arguments_provided and not self.__args.binary and not self.__args.console:
            print("[Error] Need a binary filename (--binary/--console or --help)")
            sys.exit(-1)

        elif self.__args.range:
            try:
                rangeS = int(self.__args.range.split('-')[0], 16)
                rangeE = int(self.__args.range.split('-')[1], 16)
            except:
                print("[Error] A range must be set in hexadecimal. Ex: 0x08041000-0x08042000")
                sys.exit(-1)
            if rangeS > rangeE:
                print("[Error] The start value must be greater than end value")
                sys.exit(-1)

    def __printVersion(self):
        print("Version:        %s" %(PYROPGADGET_VERSION))
        print("Author:         Jonathan Salwan" )
        print("Author page:    https://twitter.com/JonathanSalwan" )
        print("Project page:   http://shell-storm.org/project/ROPgadget/" )

    def getArgs(self):
        return self.__args

def rop(debugger,args,result,dict):
    args=shlex.split(args)
    
    if args:
        Core(Args(arguments=args).getArgs()).analyze()
    else:
        print """description:
  rop(ROPgadget) lets you search your gadgets on a binary. It supports several 
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
  rop --binary ./test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32"""

def __lldb_init_module(debugger, dict):
    
    debugger.HandleCommand('command script add --function lisa.exploitable exploitable')
    debugger.HandleCommand('command script add --function lisa.pattern_create pattern_create')
    debugger.HandleCommand('command script add --function lisa.pattern_offset pattern_offset')
    debugger.HandleCommand('command script add --function lisa.check_if_cyclic check_if_cyclic')
    debugger.HandleCommand('command script add --function lisa.stepnInstructions sf')
    debugger.HandleCommand('command script add --function lisa.context ct')
    debugger.HandleCommand('command script add --function lisa.s s')
    debugger.HandleCommand('command script add --function lisa.si si')
    debugger.HandleCommand('command script add --function lisa.so so')
    debugger.HandleCommand('command script add --function lisa.banner banner')
    debugger.HandleCommand('command script add --function lisa.exploitable exploitable')
    debugger.HandleCommand('command script add -function lisa.setMallocDebug setmalloc')
    debugger.HandleCommand('command script add -function lisa.shellcode shellcode')
    debugger.HandleCommand('command script add -function lisa.extract_from_universal_binary extract')
    debugger.HandleCommand('command script add --function lisa.dump dump')
    debugger.HandleCommand('command script add --function lisa.rop rop')

tty_colors = TerminalColors (True)
