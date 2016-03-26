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
import sys
import time
import shlex
import random
import string
import struct
import commands
import datetime
import optparse
import platform
from struct import *
from sys import version_info
import httplib

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

def syntax():
    print "Syntax:   shellcode <option> <arg>\n"
    print "Options:  -search <keyword>"
    print "          -display <shellcode id>"
    print "          -save <shellcode id>"

def shellcode(debugger, command, result, dict):
    mod = shlex.split(command)
    if len(mod)!=2:
        syntax()
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

tty_colors = TerminalColors (True)
