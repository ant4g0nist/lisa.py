import os
import re
import abc
import sys
import lldb
import stat
import shlex
import struct
import fnmatch
import platform
import subprocess
from ctypes import *
from optparse import OptionParser

BLK = "\033[30m"
RED = "\033[31m"
GRN = "\033[32m"
YEL = "\033[33m"
BLU = "\033[34m"
MAG = "\033[35m"
CYN = "\033[36m"
WHT = "\033[37m"
RST = "\033[0m"

__prompt__ = f"'(lisa:>) '"

# cpu types
CPU_TYPE_I386   = 7
CPU_ARCH_ABI64  = 0x1000000
CPU_TYPE_X86_64 = CPU_TYPE_I386 | CPU_ARCH_ABI64

CPU_TYPE_ARM	= 12
CPU_TYPE_ARM64  = CPU_TYPE_ARM | CPU_ARCH_ABI64

dlog    = lambda msg: print(f"{GRN}{msg}{RST}")
warnlog	= lambda msg: print(f"{YEL}{msg}{RST}")
errlog	= lambda msg: print(f"{RED}{msg}{RST}")

def get_host_machine():
	return platform.machine()

def get_host_arch():
	if get_host_machine()=="arm64":
		return CPU_TYPE_ARM64

	elif get_host_machine()=="x86_64":
		return CPU_TYPE_X86_64

def cpu_to_string(cpu):
	if cpu == CPU_TYPE_X86_64:
		return "x86_64"
	
	elif cpu == CPU_TYPE_ARM64:
		return "arm64"

def get_target_arch():
	return lldb.debugger.GetSelectedTarget().triple.split('-')[0]

def runShellCommand(command, shell=True):
	return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)

def makeRunCommand(command):
	def runCommand(debugger, input, exe_ctx, result, _):
		command.result = result
		command.context = exe_ctx
		splitInput = command.lex(input)

		# OptionParser will throw in the case where you want just one
		# big long argument and no options and you enter something
		# that starts with '-' in the argument. e.g.:
		#     somecommand -[SomeClass someSelector:]
		# This solves that problem by prepending a '--' so that
		# OptionParser does the right thing.
		options = command.options()
		if len(options) == 0:
			if "--" not in splitInput:
				splitInput.insert(0, "--")

		parser = optionParserForCommand(command)
		(options, args) = parser.parse_args(splitInput)

		# When there are more args than the command has declared, assume
		# the initial args form an expression and combine them into a single arg.
		if len(args) > len(command.args()):
			overhead = len(args) - len(command.args())
			head = args[: overhead + 1]  # Take N+1 and reduce to 1.
			args = [" ".join(head)] + args[-overhead:]

		if validateArgsForCommand(args, command):
			command.run(args, options)

	runCommand.__doc__ = helpForCommand(command)
	return runCommand

def loadCommand(module, command, filename):

	func = makeRunCommand(command)

	name = command.name()

	key = filename + "_" + name

	helpText = (
		command.description().strip().splitlines()[0]
	)  # first line of description

	module._loadedFunctions[key] = func

	functionName = "__" + key

	lldb.debugger.HandleCommand(
		"script "
		+ functionName
		+ " = sys.modules['"
		+ module.__name__
		+ "']._loadedFunctions['"
		+ key
		+ "']"
	)

	lldb.debugger.HandleCommand(
		'command script add --help "{help}" --function {function} {name}'.format(
			help=helpText.replace('"', '\\"'),  # escape quotes
			function=functionName,
			name=name,
		)
	)

def validateArgsForCommand(args, command):
	if len(args) < len(command.args()):
		defaultArgs = [arg.required for arg in command.args()]
		defaultArgsToAppend = defaultArgs[len(args) :]

		index = len(args)
		for defaultArg in defaultArgsToAppend:
			if defaultArg:
				arg = command.args()[index]
				print("Whoops! You are missing the <" + arg.argName + "> argument.")
				print("\nUsage: " + usageForCommand(command))
				return
			index += 1

		args.extend(defaultArgsToAppend)
	return True


def optionParserForCommand(command):
	parser = OptionParser()

	for argument in command.options():
		if argument.boolean:
			parser.add_option(
				argument.shortName,
				argument.longName,
				dest=argument.argName,
				help=argument.help,
				action=("store_false" if argument.default else "store_true"),
			)
		else:
			parser.add_option(
				argument.shortName,
				argument.longName,
				dest=argument.argName,
				help=argument.help,
				default=argument.default,
			)

	return parser


def helpForCommand(command):
	help = command.description()

	argSyntax = ""
	optionSyntax = ""

	if command.args():
		help += "\n\nArguments:"
		for arg in command.args():
			help += "\n  <" + arg.argName + ">; "
			if arg.argType:
				help += "Type: " + arg.argType + "; "
			help += arg.help
			argSyntax += " <" + arg.argName + ">"

	if command.options():
		help += "\n\nOptions:"
		for option in command.options():

			if option.longName and option.shortName:
				optionFlag = option.longName + "/" + option.shortName
			elif option.longName:
				optionFlag = option.longName
			else:
				optionFlag = option.shortName

			help += "\n  " + optionFlag + " "

			if not option.boolean:
				help += "<" + option.argName + ">; Type: " + option.argType

			help += "; " + option.help

			optionSyntax += " [{name}{arg}]".format(
				name=(option.longName or option.shortName),
				arg=("" if option.boolean else ("=" + option.argName)),
			)

	help += "\n\nSyntax: " + command.name() + optionSyntax + argSyntax

	help += "\n\nThis command is implemented as %s" % (
		command.__class__.__name__,
	)

	return help

def usageForCommand(command):
	usage = command.name()
	for arg in command.args():
		if arg.default:
			usage += " [" + arg.argName + "]"
		else:
			usage += " " + arg.argName

	return usage

def runCommand(command):
	lldb.debugger.HandleCommand(command)

class CommandArgument:  # noqa B903
	def __init__(
		self, short="", long="", arg="", type="", help="", default="", boolean=False, required=False
	):
		self.shortName = short
		self.longName = long
		self.argName = arg
		self.argType = type
		self.help = help
		self.default = default
		self.boolean = boolean
		self.required = required

class LLDBCommand:
	def name(self):
		return None

	def options(self):
		return []

	def args(self):
		return []

	def description(self):
		return ""

	def lex(self, commandLine):
		return shlex.split(commandLine)

	def run(self, arguments, option):
		pass

#################################################################################
############################ Mach-O Parser ######################################
#################################################################################
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
				("segname",         c_char * 16),
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
				("sectname",        c_char * 16),  
				("segname",         c_char * 16),  
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
				("sectname",        c_char * 16),  
				("segname",         c_char * 16),  
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
	LC_ENCRYPTION_INFO			= 0x21
	LC_ENCRYPTION_INFO_64		= 0x2C
	LC_CODE_SIGNATURE			= 0x1d
	LC_DYLIB_CODE_SIGN_DRS		= 0x2B
	S_ATTR_SOME_INSTRUCTIONS    = 0x00000400
	S_ATTR_PURE_INSTRUCTIONS    = 0x80000000


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

MH_PIE 						= 0x0020_0000
MH_NO_HEAP_EXECUTION		= 0x0100_0000
MH_ALLOW_STACK_EXECUTION 	= 0x0002_0000

class MachoFile:
	def __init__(self, macho_data, path, debugger):
		self.__executable 	= path
		self.__binary 		= macho_data
		self.__debugger		= debugger
		
		self.__machHeader   = None
		self.__rawLoadCmd   = None
		self.is_encrypted	= False
		self.__sections_l   = []

		self.__setHeader()
		self.__setLoadCmd()

		dlog(f"Parsing {cpu_to_string(self.__machHeader.cputype)} Mach-O")

		macho_stat 	= os.stat(self.__executable)
		self.is_uid 	= stat.S_ISUID & macho_stat.st_mode
		self.is_gid 	= stat.S_ISGID & macho_stat.st_mode

		objc_release, __stack_chk_guard, __stack_chk_fail = self.has_arc_and_strong_stack()

		print(f"ARC	         : {objc_release}")
		print(f"PIE	         : {self.has_pie()}")
		print(f"Stack Canary	 : {__stack_chk_guard and __stack_chk_fail}")
		print(f"Encrypted	 : {self.is_encrypted}")
		print(f"NX Heap		 : {self.has_nx_heap()}")
		print(f"NX Stack 	 : {self.has_nx_stack()}")
		print(f"Restricted 	 : {self.has_restricted()}")

	def get_entropy(self, b):
		"""Calculate byte entropy for given bytes."""
		byte_counts = Counter()

		entropy = 0

		for i in b:
			byte_counts[i] += 1

		total = float(sum(byte_counts.values()))

		for count in byte_counts.values():
			p = float(count) / total
			entropy -= p * log(p, 256)

		return entropy	

	def get_section_entropy(self, section):
		"""Get Entropy of a given section"""
		pass

	def __setHeader(self):
		self.__machHeader = MACH_HEADER.from_buffer_copy(self.__binary)
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

			elif command.cmd == MACHOFlags.LC_ENCRYPTION_INFO:
				cmd, cmdsize, cryptoff, cryptsize, cryptid = struct.unpack('<IIIII', buf)
				self.is_encrypted = bool(cryptid)
			
			elif command.cmd == MACHOFlags.LC_ENCRYPTION_INFO_64:
				cmd, cmdsize, cryptoff, cryptsize, cryptid, padding = struct.unpack('<IIIIII', buf)
				self.is_encrypted = bool(cryptid)

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

	def has_pie(self):
		return bool(self.__machHeader.flags & MH_PIE)

	def has_nx_heap(self):
		#do we need to check this??? I'm gonna return TRUE cause of W^X
		return True if self.__machHeader.flags & MH_NO_HEAP_EXECUTION else True
	
	def has_nx_stack(self):
		return False if self.__machHeader.flags & MH_ALLOW_STACK_EXECUTION else True
	
	def has_restricted(self):
		#3 cases restrictedBySetGUid, restrictedBySegment, restrictedByEntitlements
		codesign = runShellCommand(f"codesign -dvvvv '{self.__executable}'").stderr.decode() #stderr ( :| ) ???
		
		if codesign and "Authority=Apple Root CA" in codesign:
			authority = ""
			for i in codesign.splitlines():
				if "Authority" in i:
					return f"True ({i})"

		#restrictedBySetGUid
		if self.is_uid or self.is_gid:
			msg = "is_uid" if self.is_uid else "gid"
			return f"True ({msg})"

		#restrictedBySegment
		for section in self.__sections_l:
			if section.sectname.decode()=="__restrict":
				return "True (__restrict)"

		return False

	def has_arc_and_strong_stack(self):
		objc_release	  = False
		__stack_chk_guard = False
		__stack_chk_fail  = False

		selected_target = self.__debugger.GetSelectedTarget()

		target = self.__debugger.CreateTarget(self.__executable)
		for module in target.modules:
			if fnmatch.fnmatch(module.file.fullpath.lower(), self.__executable.lower()):

				for i in module.symbols:
					if i.name == "objc_release":
						objc_release =  True
					if i.name == "__stack_chk_guard":
						__stack_chk_guard =  True
					if i.name == "__stack_chk_fail":
						__stack_chk_fail =  True

		self.__debugger.DeleteTarget(target)
		self.__debugger.SetSelectedTarget(selected_target)	# reset back to previously selected target

		return objc_release, __stack_chk_guard, __stack_chk_fail

class MachOBinary:

	MH_MAGIC_64 = 0xfeedfacf
	MH_CIGAM_64 = 0xcffaedfe
	FAT_MAGIC	= 0xcafebabe
	FAT_CIGAM	= 0xbebafeca

	def __init__(self, macho, debugger):
		self.__executable = macho
		self.__debugger   = debugger

		if not os.path.isfile(self.__executable):
			errlog(f"{macho} file not found")
			return

		with open(self.__executable, "rb") as f:
			self.macho_data = f.read()

		self.parse()

	def get_magic(self, data):
		magic = struct.unpack("<L", data[:4])[0]
		return magic

	def is_universal(self, magic):
		"""Check if given file is a Universal Mach-o"""
		if magic in [self.FAT_MAGIC, self.FAT_CIGAM]:
			return True

		return False

	def is_supported(self, magic):
		if magic in [self.MH_CIGAM_64, self.MH_MAGIC_64]:
			return True
		
		return False

	def parse(self):
		magic = self.get_magic(self.macho_data)

		if self.is_universal(magic):
			dlog("Got a fat binary")

			parse_only_host = True

			option 	=	input(f"{RED}Choose only the host arch: {get_host_machine()}? y/n: {RST}")

			if option == "n":
				parse_only_host = False
			
			self.__machoBinaries = []

			offset = 8
			self.__fatHeader    = FAT_HEADER.from_buffer_copy(self.macho_data)

			for i in range(self.__fatHeader.nfat_arch):
				header = FAT_ARC.from_buffer_copy(self.macho_data[offset:])
				rawBinary = self.macho_data[header.offset:header.offset+header.size]
				macho_header = MACH_HEADER.from_buffer_copy(rawBinary)

				if parse_only_host:
					if header.cputype==get_host_arch():
						return self.parse_macho(rawBinary)
				
				self.__machoBinaries.append(rawBinary)

				offset += sizeof(header)

			for i in range(len(self.__machoBinaries)):
				self.parse_macho(self.__machoBinaries[i])

		else:
			dlog("Got a Macho-O binary")
			self.parse_macho(self.macho_data)

	def parse_macho(self, data):
		magic = self.get_magic(data)
		
		if not self.is_supported(magic):
			warnlog("Only 64-bit macho is supported")
			return

		macho = MachoFile(data, self.__executable, self.__debugger)


class CodeSignature:
	def __init__(self, signature):
		self.signature = signature

	# /* code signing attributes of a process */
#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_ADHOC		0x0000002	/* ad hoc signed */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement */
#define CS_INSTALLER		0x0000008	/* has installer entitlement */

#define	CS_HARD			0x0000100	/* don't load invalid pages */
#define	CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION	0x0000400	/* force expiration checking */
#define CS_RESTRICT		0x0000800	/* tell dyld to treat restricted */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
#define CS_REQUIRE_LV		0x0002000	/* require library validation */
#define CS_ENTITLEMENTS_VALIDATED	0x0004000

#################################################################################
############################ COMMANDS ###########################################
#################################################################################
class ASLRCommand(LLDBCommand):
	def name(self):
		return "aslr"
	
	def args(self):
		return [
			CommandArgument(
				arg="on",
				help="Enable ASLR. Usage: aslr on",
			),
			CommandArgument(
				arg="off",
				help="disable ASLR. Usage: aslr off",
			)
		]

	def description(self):
		return "View/modify ASLR setting of target."
	
	def run(self, arguments, option):
		launchInfo = lldb.debugger.GetSelectedTarget().GetLaunchInfo()
		flags 	= launchInfo.GetLaunchFlags()
		
		if arguments[0] == False:
			if flags & lldb.eLaunchFlagDisableASLR:
				print(f"{RED}ASLR{RST} : {GRN}off{RST}")
			else:
				print(f"{RED}ASLR{RST} : {GRN}on{RST}")
		
		else:
			if arguments[0]=="off":
				flags |= (lldb.eLaunchFlagDisableASLR)
				launchInfo.SetLaunchFlags(flags)
				lldb.debugger.GetSelectedTarget().SetLaunchInfo(launchInfo)

			elif arguments[0]=="on":
				flags &= ~(lldb.eLaunchFlagDisableASLR)
				launchInfo.SetLaunchFlags(flags)
				lldb.debugger.GetSelectedTarget().SetLaunchInfo(launchInfo)

class ChecksecCommand(LLDBCommand):
	def name(self):
		return "checksec"
	
	def description(self):
		return "Display the security properties of the current executable"
	
	def args(self):
		return [
			CommandArgument(
				arg="macho",
				type="str",
				help="Path to mach-o binary. Usage: checksec /usr/bin/qlmanage",
			)
		]	
	
	def run(self, arguments, option):
		if arguments[0]==False:
			path = lldb.debugger.GetSelectedTarget().GetExecutable().fullpath
			MachOBinary(path, lldb.debugger)

def exploitable(debugger,cmd,res,dict):
	"""checks if the crash is exploitable"""
	Lisa(debugger)

def __lldb_init_module(debugger, dict):
	dlog(" == lisa == ")

	res = lldb.SBCommandReturnObject()
	command_iterpreter = debugger.GetCommandInterpreter()

	command_iterpreter.HandleCommand(f"settings set prompt {__prompt__}", res)
	command_iterpreter.HandleCommand("settings set stop-disassembly-count 0", res)

	current_module = sys.modules[__name__]
	current_module._loadedFunctions = {}

	loadCommand(current_module, ASLRCommand(), "lisa")
	loadCommand(current_module, ChecksecCommand(), "lisa")
	
