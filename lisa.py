#!/usr/bin/env python

import os
import re
import sys
import lldb
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

lisaversion = 'v-ichi'
PAGE_SIZE=4096
MAX_DISTANCE=PAGE_SIZE*10
g_ignore_frame_pointer= True
g_exploitable_jit = True
reportexploitable=""

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

def banner():
    
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
#step,stepinto functions for these like in lisa

#set malloc debugging features
def setMallocDebug(debugger,c,result,dict):
    """
       sets DYLD_INSERT_LIBRARIES to /usr/lib/libgmalloc.dylib
    """
    execute(debugger,'settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib',result,dict)
    return True


#execute given LLDB command
def execute(debugger,lldb_command,result,dict):
    """
        Execute given command and print the outout to stdout
    """
    debugger=lldb.debugger
    debugger.HandleCommand(lldb_command)

#execute command and return output
def executeReturnOutput(debugger,lldb_command,result,dict):
    """
        Execute given command and returns the outout
    """
    ci = debugger.GetCommandInterpreter()
    res=lldb.SBCommandReturnObject()
    ci.HandleCommand(lldb_command,res)
    output=res.GetOutput()
    return output

def s(debugger,command,result,dict):
    """step command"""
    execute(debugger,"ct",result,dict)
    execute(debugger,"thread step-in",result,dict)

def si(debugger,command,result,dict):
    """step into command"""
    execute(debugger,"ct",result,dict)
    execute(debugger,"thread step-inst",result,dict)

def so(debugger,command,result,dict):
    """step over"""
    execute(debugger,"ct",result,dict)
    execute(debugger,"thread step-over",result,dict)

def testjump(self, inst=None):
        """
        Test if jump instruction is taken or not
        Returns:
            - (status, address of target jumped instruction)
        """

        flags = self.get_eflags()
        if not flags:
            return None

        if not inst:
            pc = getregvalue("pc")
            inst = self.execute_redirect("x/i 0x%x" % pc)
            if not inst:
                return None

        opcode = inst.split(":")[1].split()[0]
        next_addr = self.eval_target(inst)
        if next_addr is None:
            next_addr = 0

        if opcode == "jmp":
            return next_addr
        if opcode == "je" and flags["ZF"]:
            return next_addr
        if opcode == "jne" and not flags["ZF"]:
            return next_addr
        if opcode == "jg" and not flags["ZF"] and (flags["SF"] == flags["OF"]):
            return next_addr
        if opcode == "jge" and (flags["SF"] == flags["OF"]):
            return next_addr
        if opcode == "ja" and not flags["CF"] and not flags["ZF"]:
            return next_addr
        if opcode == "jae" and not flags["CF"]:
            return next_addr
        if opcode == "jl" and (flags["SF"] != flags["OF"]):
            return next_addr
        if opcode == "jle" and (flags["ZF"] or (flags["SF"] != flags["OF"])):
            return next_addr
        if opcode == "jb" and flags["CF"]:
            return next_addr
        if opcode == "jbe" and (flags["CF"] or flags["ZF"]):
            return next_addr
        if opcode == "jo" and flags["OF"]:
            return next_addr
        if opcode == "jno" and not flags["OF"]:
            return next_addr
        if opcode == "jz" and flags["ZF"]:
            return next_addr
        if opcode == "jnz" and flags["OF"]:
            return next_addr

        return None

def context(debugger,command,result,dict):
    """
        Prints context of current execution context
        Usage:
            ct
    """


    #stack
    op=executeReturnOutput(debugger,"x/10x $sp",result,dict)
    print tty_colors.red()+"[*] Stack :\n"+tty_colors.default()
    print tty_colors.blue()+op+tty_colors.default()
    #registers
    op=executeReturnOutput(debugger,"register read",result,dict)
    print tty_colors.red()+"[*] Registers\t:"+tty_colors.default()
    print op.split("\n\n")[0].split('General Purpose Registers:\n')[1].split('eflags')[0]
    
    print "[*] Elfags\t:"

    eflags=get_eflags(debugger,command,result,dict)
    if eflags!=None:
        for i in eflags.keys():
            print eflags[i]


# def stepnInstructions(debugger, n, result, internal_dict):
#     """
#         Steps n number of instructions
        
#         Usage Eg: sf 12

#         Output: prints registers before n after running n instructions
#     """

#     try:
#         n=int(n)
#         thread = debugger.GetSelectedTarget().GetProcess().GetSelectedThread()
#         start_num_frames = thread.GetNumFrames()
#         if start_num_frames == 0:
#             return
#         execute(debugger,'register read',result,internal_dict)
#         thread.StepInstruction(n)
#         execute(debugger,'register read',result,internal_dict)
#     except:
#         print 'Usage Eg: sf 12'

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
#create html report
def report(debugger, command, result, dict):
    
    filename=lldb.target.executable.basename+"_"+str(lldb.process.id)+"_"+str(int(time.time()))+".html"
    description='''Export the state of current target into a crashlog file'''
    
    out_file = open(filename, 'w')
    if not out_file:
        result.PutCString ("error: failed to open file '%s' for writing...", args[0]);
        return
    out_file.write("<html><title>LISA eXploit Report</title>\n")
    
    if lldb.target:
        out_file.write("<body><p>")
        identifier = lldb.target.executable.basename
        if lldb.process:
            pid = lldb.process.id
            if pid != lldb.LLDB_INVALID_PROCESS_ID:
                out_file.write('Process:         %s [%u]</br>' % (identifier, pid))
        out_file.write('Path:            %s</br>' % (lldb.target.executable.fullpath))
        out_file.write('Identifier:      %s</br>' % (identifier))
        out_file.write('\nDate/Time:       %s</br>' % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        out_file.write('OS Version:      Mac OS X %s (%s)</br>' % (platform.mac_ver()[0], commands.getoutput('sysctl -n kern.osversion')));
        out_file.write('Report Version:  9</br>')
        out_file.write('Exploitable: '+reportexploitable+'</br>')
        for thread_idx in range(lldb.process.num_threads):
            thread = lldb.process.thread[thread_idx]
            out_file.write('\nThread %u:\n</br>' % (thread_idx))
            for (frame_idx, frame) in enumerate(thread.frames):
                frame_pc = frame.pc
                frame_offset = 0
                if frame.function:
                    block = frame.GetFrameBlock()
                    block_range = block.range[frame.addr]
                    if block_range:
                        block_start_addr = block_range[0]
                        frame_offset = frame_pc - block_start_addr.load_addr
                    else:
                        frame_offset = frame_pc - frame.function.addr.load_addr
                elif frame.symbol:
                    frame_offset = frame_pc - frame.symbol.addr.load_addr
                out_file.write('%-3u %-32s 0x%16.16x %s</br>' % (frame_idx, frame.module.file.basename, frame_pc, frame.name))
                if frame_offset > 0:
                    out_file.write(' + %u</br>' % (frame_offset))
                line_entry = frame.line_entry
                if line_entry:
                    if options.verbose:
                        # This will output the fullpath + line + column
                        out_file.write(' %s</br>' % (line_entry))
                    else:
                        out_file.write(' %s:%u</br>' % (line_entry.file.basename, line_entry.line))
                        column = line_entry.column
                        if column:
                            out_file.write(':%u</br>' % (column))
                out_file.write('\n</br>')

        out_file.write('\nBinary Images:\n</br>')
        for module in lldb.target.modules:
                text_segment = module.section['__TEXT']
                if text_segment:
                        text_segment_load_addr = text_segment.GetLoadAddress(lldb.target)
                        if text_segment_load_addr != lldb.LLDB_INVALID_ADDRESS:
                            text_segment_end_load_addr = text_segment_load_addr + text_segment.size
                            identifier = module.file.basename
                            module_version = '???'
                            module_version_array = module.GetVersion()
                            if module_version_array:
                                module_version = '.'.join(map(str,module_version_array))
                            out_file.write ('    0x%16.16x - 0x%16.16x  %s (%s - ???) <%s> %s\n</br>' % (text_segment_load_addr, text_segment_end_load_addr, identifier, module_version, module.GetUUIDString(), module.file.fullpath))
        out_file.write("</p></body></html>")
        out_file.close()
    else:
        result.PutCString ("error: invalid target");

####################################
#   Exploitation                   #
####################################


#pattern create and pattern offset
def pattern_create(debugger,size,result,dict,returnv=False):
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
    if not returnv:
        print tty_colors.red()+ string[:length]+tty_colors.default()

    if returnv:
        return string[:length]

#check if given pattern is in cyclic pattern
def check_if_cyclic(debugger,pat,result,dict,ret=False):
    seta="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    setb="abcdefghijklmnopqrstuvwxyz"
    setc="0123456789"
    
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
    if ret==True:
        return True

#pattern search
def pattern_offset(debugger,sizepat,result,dict):
    """[*] search offset of pattern."""
    
    if len(sizepat.split(' '))==2:
        try:
            size=int(sizepat.split(' ')[0])
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
    output=executeReturnOutput(debugger,'register read '+reg,result,dict)
    return output.split("= ")[-1].split(" ")[0]


#return whether or not the base pointer is far away from the stack pointer.
def bp_inconsistent_with_sp(debugger,command,result,dict):
    #define MAX_DISTANCE (PAGE_SIZE * 10)
    bp_val = getregvalue(debugger,"bp",result,dict);
    sp_val = getregvalue(debugger,"sp",result,dict);
    #    No check if bp_val > sp_val since bp_val - sp_val may have underflowed.
    if (bp_val - sp_val) > MAX_DISTANCE:
        return True
    return False
def is_stack_suspicious(access_address):
    if access_address=="0xbbadbeef":
        is_exploitable="no"
        return
    if exception=="EXC_BREAKPOINT":
        return
    suspicious_functions = [
            " __stack_chk_fail ", " szone_error ", " CFRelease ", " CFRetain ", " _CFRelease ", " _CFRetain",
            " malloc ", " calloc ", " realloc ",  " objc_msgSend",
            " szone_free ", " free_small ", " tiny_free_list_add_ptr ", " tiny_free_list_remove_ptr ",
            " small_free_list_add_ptr ", " small_free_list_remove_ptr ", " large_entries_free_no_lock ",
            " large_free_no_lock ", " szone_batch_free ", " szone_destroy ", " free ",
            " CSMemDisposeHandle ",  " CSMemDisposePtr ",
            " append_int ", " release_file_streams_for_task ", " __guard_setup ",
            " _CFStringAppendFormatAndArgumentsAux ", " WTF::fastFree ", " WTF::fastMalloc ",
            " WTF::FastCalloc ", " WTF::FastRealloc ", "  WTF::tryFastCalloc ", " WTF::tryFastMalloc ",
            " WTF::tryFastRealloc ", " WTF::TCMalloc_Central_FreeList ", " GMfree ", " GMmalloc_zone_free ",
            " GMrealloc ", " GMmalloc_zone_realloc "]
    stack=executeReturnOutput("bt")
    if "0   ???" in stack:
        print tty_colors.red()+"This crash is suspected to be exploitable because the crashing instruction is outside of a known function, i.e. in dynamically generated code"+tty_colors.default()
        reportexploitable="This crash is suspected to be exploitable because the crashing instruction is outside of a known function, i.e. in dynamically generated code"
        is_exploitable = "yes"
        return
    MINIMUM_RECURSION_LENGTH = 300
    stack_length= len(stack.split("\n"))
    if stack_length>MINIMUM_RECURSION_LENGTH:
        print tty_colors.red()+"The crash is suspected to be not exploitable due to unbounded recursion since there were %d stack frames."+tty_colors.default()
        reportexploitable="The crash is suspected to be not exploitable due to unbounded recursion since there were %d stack frames."
        is_exploitable = "no"
        return
    for i in suspicious_functions:
        if i in stack:
            if exception == "EXC_BREAKPOINT" and (i==" CFRelease " or i==" CFRetain "):
                is_exploitable = "no"
                return
            elif i==" _CFRelease " or i==" CFRelease " and "CGContextDelegateFinalize" in stack:
                return
            elif i==" objc_msgSend" and access_address<<PAGE_SIZE:
                continue
            else:
                print tty_colors.red()+"The crash is suspected to be an exploitable issue due to the suspicious function in the stack trace of the crashing thread"%i+tty_colors.default()
                reportexploitable="The crash is suspected to be an exploitable issue due to the suspicious function in the stack trace of the crashing thread."
                is_exploitable = "yes"
                return
    return


#get disassembly
def getdisassembly(debugger,c,result,dict):
    disas=executeReturnOutput(debugger,"disassemble -c 1 -s $pc",result,dict).split('\n')[1].split(':')[1]
    return disas

#get exception
def getexception(debugger,c,result,dict):
    output=executeReturnOutput(debugger,"process status",result,dict)
    s1=output.find("stop reason =")
    s2=output[s1:].find("(")
    return output[s1:s1+s2].replace("stop reason =",'')

#get exception address
def getexceptionaddr(debugger,c,result,dict):
    output=executeReturnOutput(debugger,"process status",result,dict)
    s1=output.find("address=")
    s2=output[s1:].find(")")
    return output[s1:s1+s2].replace("address=",'')

#reg should be a 2 character string like ax, di, dx, not necessarily null terminated.
def value_for_register(debugger,reg,result,dict):
    if reg[1:]=="ax":
        return getregvalue(debugger,'rax',result,dict)
    elif reg[1:]=="bx":
        return getregvalue(debugger,'rbx',result,dict);
    elif reg[1:]=="cx":
        return getregvalue(debugger,'rcx',result,dict)
    elif reg[1:]=="dx":
        return getregvalue(debugger,'rdx',result,dict)
    elif reg[1:]=="di":
        return getregvalue(debugger,'rdi',result,dict)
    elif reg[1:]=="si":
        return getregvalue(debugger,'rsi',result,dict)
    elif reg[1:]=="sp":
        return getregvalue(debugger,'rsp',result,dict)
    elif reg[1:]=="bp":
        return getregvalue(debugger,'rbp',result,dict)
    else:
        print "ERROR: unexpected register %s\n"%reg
        sys.exit()

def stack_access_crash(debugger, access_address,result,dict):
    access_address=int(access_address,0)
    sp_val = int(getregvalue(debugger,"sp",result,dict),0)
    if ((sp_val - access_address) <= PAGE_SIZE):
        return True
    return False

def value_for_first_register(debugger, disassembly,result,dict):
    first_left_paren = disassembly.find('[')
    first_reg = disassembly[first_left_paren+1:first_left_paren+4];

    return value_for_register(debugger, first_reg,result,dict)


def type_for_two_memory(debugger,disassembly,access_address,result,dict):
    first_reg_val = value_for_first_register(debugger,disassembly,result,dict)
    if first_reg_val != access_address:
        return "read"
    else:
        return "write"


#get exception type
def getexceptiontype(debugger,disassembly,result,dict):
    last_comma = disassembly.find(',')
    right_paren = disassembly.find(']')

    access_address=getexceptionaddr(debugger,"",result,dict)
    if disassembly[right_paren+1:].find(']')!=-1:
        type=type_for_two_memory(debugger,disassembly, access_address,result,dict)
        return type
    elif disassembly.find('call')!=-1:
        if not right_paren or last_comma:
            type = "recursion"
        elif stack_access_crash(debugger,access_address,result,dict):
            type = "recursion"
        else:
            type = "exec"
        return type
    elif disassembly.find("cmp")!=-1 or disassembly.find("test")!=-1 or disassembly.find("fld")!=-1:
        type = "read"
        return type
    elif disassembly.find("fst")!=-1:
        type = "write"
        return type
    elif disassembly.find("mov")!=-1:
        if getregvalue(debugger, disassembly[last_comma-3:last_comma],result,dict)!=access_address:
            type = "read"
        else:
            type = "write"
        return type
    elif disassembly.find('jmp')!=-1:
        type = "exec"
        return type
    elif disassembly.find('push')!=-1:
        if right_paren:
            type = "read"
        else:
            type = "recursion"
        return type
    elif disassembly.find('inc')!=-1 or disassembly.find('dec')!=-1:
        type = "write"
        return type
    elif disassembly.find("stos")!=-1:
        type = "write"
        return type
    elif disassembly.find("lods")!=-1:
        type = "read"
        return type
    else:
        type = "unknown"
        return type
    if disassembly.find("st") == 2:
        type = "write"
        return type
    elif disassembly.find("ld") == 2:
        type = "read"
        return type
    elif disassembly.find("push") == 2:
        type = "recursion"
        return type
    else:
        type = "unknown"
        return type



#eStateAttaching = 3
#eStateConnected = 2
#eStateCrashed = 8
#eStateDetached = 9
#eStateExited = 10
#eStateInvalid = 0
#eStateLaunching = 4
#eStateRunning = 6
#eStateStepping = 7
#eStateStopped = 5
#eStateSuspended = 11
#eStateUnloaded = 1
#eStopReasonBreakpoint = 3
#eStopReasonException = 6
#eStopReasonExec = 7
#eStopReasonInvalid = 0
#eStopReasonNone = 1
#eStopReasonPlanComplete = 8
#eStopReasonSignal = 5
#eStopReasonThreadExiting = 9
#eStopReasonTrace = 2
#eStopReasonWatchpoint = 4

#check if exploitable or not

def exploitable(debugger,command,result,dict):
    """[*] checks if the crash is exploitable"""
    global reportexploitable
    disassembly=None
    access_type=None
    
    stopreason=lldb.thread.stop_reason
    if stopreason==lldb.eStopReasonSignal:
        signal=lldb.thread.GetStopDescription(30)
        if "SIGABRT" in signal:
            bt=executeReturnOutput(debugger,"bt",result,dict)
            if "__stack_chk_fail" in bt:
                print tty_colors.red()+"Seems like a stack overflow. Found suspicious function '"+bt[bt.find("__stack_chk_fail"):bt.find("__stack_chk_fail")+len("__stack_chk_fail")]+"' in the execution stack"+tty_colors.default()
                reportexploitable="Seems like a stack overflow. Found suspicious function "+bt[bt.find("__stack_chk_fail"):bt.find("__stack_chk_fail")+len("__stack_chk_fail")]+" in the execution stack"
                return
    if stopreason==lldb.eStopReasonException:
        rip=getregvalue(debugger,"$rip",result,dict)
        exception=getexception(debugger,"",result,dict).strip(' ')
        disassembly=getdisassembly(debugger,"",result,dict)
        access_type= getexceptiontype(debugger,disassembly,result,dict)
        access_address=getexceptionaddr(debugger,"",result,dict)
            
        """case 1: accessing invalid address"""
        if access_address==getregvalue(debugger, "pc",result,dict):
            print tty_colors.red()+"Trying to execute a bad address, this is a potentially exploitable issue\n"+tty_colors.default()
            print tty_colors.red()+"exploitable = yes"+tty_colors.default()
            reportexploitable="Trying to execute a bad address, this is a potentially exploitable issue\nexploitable = yes"
            access_type = "exec"

        elif exception=="EXC_BAD_ACCESS":
            if access_type=="exec":
                is_exploitable = "yes"
                addr = access_address
                max_offset = 1024
                if (addr > 0x55555555 - max_offset and addr < 0x55555555 + max_offset):
                    print tty_colors.red()+"The access address indicates the use of freed memory if MallocScribble was used, or uninitialized memory if libgmalloc and MALLOC_FILL_SPACE was used."+tty_colors.default()
                    reportexploitable="The access address indicates the use of freed memory if MallocScribble was used, or uninitialized memory if libgmalloc and MALLOC_FILL_SPACE was used."
                if (addr > 0xaaaaaaaa - max_offset and addr < 0xaaaaaaaa + max_offset):
                    print tty_colors.red()+"The access address indicates that uninitialized memory was being used if MallocScribble was used.\n"+tty_colors.default()
                    reportexploitable="The access address indicates that uninitialized memory was being used if MallocScribble was used.\n"
                
                elif access_type=="recursion":
                    is_exploitable = "no"
                else:
                    is_exploitable="yes"
            if exception == "EXC_I386_GPFLT":
                print tty_colors.red()+"The exception code indicates that the access address was invalid in the 64-bit ABI (it was > 0x0000800000000000).\n"+tty_colors.default()
                reportexploitable="The exception code indicates that the access address was invalid in the 64-bit ABI (it was > 0x0000800000000000).\n"
            if access_address<PAGE_SIZE:
                print tty_colors.blue()+"Null Dereference. Probably not exploitable"+tty_colors.default()
                reportexploitable="Null Dereference. Probably not exploitable"
            else:
                is_exploitable="yes"
                print tty_colors.red()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
                print tty_colors.red()+"Crash accessing invalid address. "+tty_colors.default()
                reportexploitable= "Crash accessing invalid address.\nexploitable = yes"
        elif exception=="EXC_BAD_INSTRUCTION":
            is_exploitable = "yes"
            print tty_colors.red()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
            print tty_colors.blue()+"Illegal instruction at 0x%016qx, probably a exploitable issue unless the crash was in libdispatch/xpc."+tty_colors.default()
            reportexploitable="Illegal instruction at 0x%016qx, probably a exploitable issue unless the crash was in libdispatch/xpc.\nexploitable = yes"
        elif exception=="EXC_ARITHMETIC":
            is_exploitable = "no"
            print tty_colors.blue()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
            print tty_colors.blue()+"Arithmetic exception at 0x%016qx, probably not exploitable."+tty_colors.default()
            reportexploitable="Arithmetic exception at 0x%016qx, probably not exploitable."
        elif exception=="EXC_SOFTWARE":
            is_exploitable = "no"
            print tty_colors.blue()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
            print tty_colors.blue()+"Software exception.\n"+tty_colors.default()
            reportexploitable="Software exception, probably not exploitable.\n"
        elif exception=="EXC_BREAKPOINT":
            is_exploitable = "no"
            print tty_colors.blue()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
        elif exception=="EXC_CRASH":
            is_exploitable= "no"
            print tty_colors.blue()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
        else:
            print tty_colors.red()+"Unknown exception number %d\n"%exception+tty_colors.default()
            is_exploitable = "yes"
            print tty_colors.red()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
        if not g_ignore_frame_pointer and exception=="EXC_BAD_ACCESS" and bp_inconsistent_with_sp(debugger,command,result,dict):
            is_exploitable = "yes"
            print tty_colors.red()+"is_exploitable = %s"%is_exploitable+tty_colors.default()
            print tty_colors.red()+"Presumed exploitable based on the discrepancy between the stack pointer and base pointer registers. If -fomit-frame-pointer was used to build the code, set the CW_IGNORE_FRAME_POINTER env variable."+tty_colors.default()
            reportexploitable="Presumed exploitable based on the discrepancy between the stack pointer and base pointer registers. If -fomit-frame-pointer was used to build the code, set the CW_IGNORE_FRAME_POINTER env variable.\nexploitable = yes"


#Vulnerbility Classfication
#have to code

def alias(debugger,commands,result,dict):
    banner()
    execute(debugger,'command script add --function lisa.exploitable exploitable',result,dict)
    execute(debugger,'command script add --function lisa.pattern_create pattern_create',result,dict)
    execute(debugger,'command script add --function lisa.pattern_offset pattern_offset',result,dict)
    execute(debugger,'command script add --function lisa.check_if_cyclic check_if_cyclic',result,dict)
    execute(debugger,'command script add --function lisa.stepnInstructions sf',result,dict)
    execute(debugger,'command script add --function lisa.context ct',result,dict)
    execute(debugger,'command script add --function lisa.s s',result,dict)
    execute(debugger,'command script add --function lisa.si si',result,dict)
    execute(debugger,'command script add --function lisa.so so',result,dict)
tty_colors = TerminalColors (True)
