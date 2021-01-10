import io
import os
import re
import abc
import cmd
import sys
import lldb
import stat
import uuid
import fcntl
import shlex
import string
import struct
import fnmatch
import termios
import capstone
import platform
import functools
import subprocess
from capstone import *
from capstone import arm64_const
from capstone import x86_const
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
BASE00 = '#657b83'
Punctuation = BASE00
HORIZONTAL_LINE = "\u2500"
VERTICAL_LINE = "\u2502"

__prompt__ = f"'(lisa:>) '"

# from CW
MINIMUM_RECURSION_LENGTH = 300
NO_CHANGE 				  = 0
CHANGE_TO_EXPLOITABLE	  = 1
CHANGE_TO_NOT_EXPLOITABLE = 2

# cpu types
CPU_TYPE_I386   = 7
CPU_ARCH_ABI64  = 0x1000000
CPU_TYPE_X86_64 = CPU_TYPE_I386 | CPU_ARCH_ABI64

CPU_TYPE_ARM	= 12
CPU_TYPE_ARM64  = CPU_TYPE_ARM | CPU_ARCH_ABI64

dlog    = lambda msg: print(f"{GRN}{msg}{RST}")
warnlog	= lambda msg: print(f"{YEL}{msg}{RST}")
errlog	= lambda msg: print(f"{RED}{msg}{RST}")

tty_rows, tty_columns = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234"))

def context_title(m):
	line_color= YEL
	msg_color = GRN

	if not m:
		print(f"{line_color}{HORIZONTAL_LINE * tty_columns} {line_color}{RST}")
		return

	trail_len = len(m) + 8
	title = ""
	title += line_color+" {:{padd}<{width}} ".format("", width=max(tty_columns - trail_len, 0), padd=HORIZONTAL_LINE)+RST
	title += f"{msg_color}{m}{RST}"
	title += line_color+" {:{padd}<4}".format("", padd=HORIZONTAL_LINE)+RST
	print(title)

def get_host_pagesize():
	host_machine 	= get_host_machine()
	target_arch		= get_target_triple().split('-')[0]

	page_size = 0

	if host_machine == target_arch:
		page_size = run_shell_command('getconf PAGE_SIZE').stdout.rstrip()
	elif host_machine=="arm64" and target_arch=="x86_64":
		page_size = run_shell_command('arch -x86_64 getconf PAGE_SIZE').stdout.rstrip()
	else:
		errlog("get_host_pagesize failed")
		return -1

	return int(page_size)

def get_host_machine():
	return platform.machine()

def get_host_arch():
	if get_host_machine() == "arm64":
		return CPU_TYPE_ARM64

	elif get_host_machine() == "x86_64":
		return CPU_TYPE_X86_64

def cpu_to_string(cpu):
	if cpu == CPU_TYPE_X86_64:
		return "x86_64"
	
	elif cpu == CPU_TYPE_ARM64:
		return "arm64"

def get_target_triple():
	return lldb.debugger.GetSelectedTarget().triple

def get_target_arch():
	arch = lldb.debugger.GetSelectedTarget().triple.split('-')[0]
	if arch == "arm64" or arch=="arm64e":
		return AARCH64()
	elif arch == "x86_64":
		return X8664()
	else:
		errlog(f"Architecture {arch} not supported")

def run_shell_command(command, shell=True):
	return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)

def make_run_command(command):
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

		parser = option_parser_for_command(command)
		(options, args) = parser.parse_args(splitInput)

		# When there are more args than the command has declared, assume
		# the initial args form an expression and combine them into a single arg.
		if len(args) > len(command.args()):
			overhead = len(args) - len(command.args())
			head = args[: overhead + 1]  # Take N+1 and reduce to 1.
			args = [" ".join(head)] + args[-overhead:]

		if validate_args_for_command(args, command):
			command.run(args, options)

	runCommand.__doc__ = help_for_command(command)
	return runCommand

def load_command(module, command, filename):

	func = make_run_command(command)

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

def validate_args_for_command(args, command):
	if len(args) < len(command.args()):
		defaultArgs = [arg.default for arg in command.args()]
		defaultArgsToAppend = defaultArgs[len(args) :]

		index = len(args)
		for defaultArg in defaultArgsToAppend:
			if defaultArg:
				arg = command.args()[index]
				print("Whoops! You are missing the <" + arg.argName + "> argument.")
				print("\nUsage: " + usage_for_command(command))
				return
			index += 1

		args.extend(defaultArgsToAppend)
	return True


def option_parser_for_command(command):
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


def help_for_command(command):
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

def usage_for_command(command):
	usage = command.name()
	for arg in command.args():
		if arg.default:
			usage += " [" + arg.argName + "]"
		else:
			usage += " " + arg.argName

	return usage

class CommandArgument:  # noqa B903
	def __init__(
		self, short="", long="", arg="", type="", help="", default="", boolean=False):
		self.shortName = short
		self.longName = long
		self.argName = arg
		self.argType = type
		self.help = help
		self.default = default
		self.boolean = boolean

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
############################ Utilities  #########################################
#################################################################################


colormap = [
  0x000000, 0x560000, 0x640000, 0x750000, 0x870000, 0x9b0000, 0xb00000, 0xc60000, 0xdd0000, 0xf50000, 0xff0f0f, 0xff2828, 0xff4343, 0xff5e5e, 0xff7979, 0xfe9595,
  0x4c1600, 0x561900, 0x641e00, 0x752300, 0x872800, 0x9b2e00, 0xb03400, 0xc63b00, 0xdd4200, 0xf54900, 0xff570f, 0xff6928, 0xff7b43, 0xff8e5e, 0xffa179, 0xfeb595,
  0x4c3900, 0x564000, 0x644b00, 0x755700, 0x876500, 0x9b7400, 0xb08400, 0xc69400, 0xdda600, 0xf5b800, 0xffc30f, 0xffc928, 0xffd043, 0xffd65e, 0xffdd79, 0xfee495,
  0x4c4c00, 0x565600, 0x646400, 0x757500, 0x878700, 0x9b9b00, 0xb0b000, 0xc6c600, 0xdddd00, 0xf5f500, 0xffff0f, 0xffff28, 0xffff43, 0xffff5e, 0xffff79, 0xfffe95,
  0x324c00, 0x395600, 0x426400, 0x4e7500, 0x5a8700, 0x679b00, 0x75b000, 0x84c600, 0x93dd00, 0xa3f500, 0xafff0f, 0xb7ff28, 0xc0ff43, 0xc9ff5e, 0xd2ff79, 0xdbfe95,
  0x1f4c00, 0x235600, 0x296400, 0x307500, 0x388700, 0x409b00, 0x49b000, 0x52c600, 0x5cdd00, 0x66f500, 0x73ff0f, 0x82ff28, 0x91ff43, 0xa1ff5e, 0xb1ff79, 0xc1fe95,
  0x004c00, 0x005600, 0x006400, 0x007500, 0x008700, 0x009b00, 0x00b000, 0x00c600, 0x00dd00, 0x00f500, 0x0fff0f, 0x28ff28, 0x43ff43, 0x5eff5e, 0x79ff79, 0x95fe95,
  0x004c19, 0x00561c, 0x006421, 0x007527, 0x00872d, 0x009b33, 0x00b03a, 0x00c642, 0x00dd49, 0x00f551, 0x0fff5f, 0x28ff70, 0x43ff81, 0x5eff93, 0x79ffa6, 0x95feb8,
  0x004c4c, 0x005656, 0x006464, 0x007575, 0x008787, 0x009b9b, 0x00b0b0, 0x00c6c6, 0x00dddd, 0x00f5f5, 0x0ffffe, 0x28fffe, 0x43fffe, 0x5efffe, 0x79ffff, 0x95fffe,
  0x00394c, 0x004056, 0x004b64, 0x005775, 0x006587, 0x00749b, 0x0084b0, 0x0094c6, 0x00a6dd, 0x00b8f5, 0x0fc3ff, 0x28c9ff, 0x43d0ff, 0x5ed6ff, 0x79ddff, 0x95e4fe,
  0x00264c, 0x002b56, 0x003264, 0x003a75, 0x004387, 0x004d9b, 0x0058b0, 0x0063c6, 0x006edd, 0x007af5, 0x0f87ff, 0x2893ff, 0x43a1ff, 0x5eaeff, 0x79bcff, 0x95cafe,
  0x00134c, 0x001556, 0x001964, 0x001d75, 0x002187, 0x00269b, 0x002cb0, 0x0031c6, 0x0037dd, 0x003df5, 0x0f4bff, 0x285eff, 0x4372ff, 0x5e86ff, 0x799aff, 0x95b0fe,
  0x19004c, 0x1c0056, 0x210064, 0x270075, 0x2d0087, 0x33009b, 0x3a00b0, 0x4200c6, 0x4900dd, 0x5100f5, 0x5f0fff, 0x7028ff, 0x8143ff, 0x935eff, 0xa679ff, 0xb895fe,
  0x33004c, 0x390056, 0x420064, 0x4e0075, 0x5a0087, 0x67009b, 0x7500b0, 0x8400c6, 0x9300dd, 0xa300f5, 0xaf0fff, 0xb728ff, 0xc043ff, 0xc95eff, 0xd279ff, 0xdb95fe,
  0x4c004c, 0x560056, 0x640064, 0x750075, 0x870087, 0x9b009b, 0xb000b0, 0xc600c6, 0xdd00dd, 0xf500f5, 0xfe0fff, 0xfe28ff, 0xfe43ff, 0xfe5eff, 0xfe79ff, 0xfe95fe,
  0x4c0032, 0x560039, 0x640042, 0x75004e, 0x87005a, 0x9b0067, 0xb00075, 0xc60084, 0xdd0093, 0xf500a3, 0xff0faf, 0xff28b7, 0xff43c0, 0xff5ec9, 0xff79d2, 0xffffff,
]


def expand(v):
	"""Split a 24 bit integer into 3 bytes
	>>> expand(0xff2001)
	(255, 32, 1)
	"""
	return ( ((v)>>16 & 0xFF), ((v)>>8 & 0xFF), ((v)>>0 & 0xFF) )


def format_offset(offset):
	"""Return a right-aligned hexadecimal representation of offset.
	>>> format_offset(128)
	'    0080'
	>>> format_offset(3735928559)
	'deadbeef'
	"""
	return '0x%5x%03x' % (offset >> 12, offset & 0xFFF)

def visual_hexdump(buffer, start=0, end=None, columns=64):
	"""Print a colorful representation of binary data using terminal ESC codes
	"""
	count = (end or -1) - start
	read = 0
	while read != count:
		if end == None:
			to_read = io.DEFAULT_BUFFER_SIZE
		else:
			to_read = min(count - read, io.DEFAULT_BUFFER_SIZE)

		buf =  buffer[read:read+to_read]

		for i in range(0, len(buf), columns*2):
			offset = start + read + i
			print(format_offset(offset), end=' ')

			for j in range(0, columns):
				if i + j >= len(buf):
					break
				elif i + j + columns >= len(buf):
					print('\x1B[0m\x1B[38;2;%d;%d;%dm▀' % expand(colormap[buf[i + j]]), end='')
				else:
					print('\x1B[38;2;%d;%d;%dm\x1B[48;2;%d;%d;%dm▀' % (expand(colormap[buf[i + j]]) + expand(colormap[buf[i + j + columns]])), end='')
			print('\x1B[m')

		read += len(buf)

HEADER = '┌────────────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐'
FOOTER = RST+'└────────────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘'
LINE_FORMATTER = '│' + '' + '{:016x}' + '│ {}' + '│{}'  + '│' + RST

def hexmod(b: int) -> str:
	'''10 -> "0xa" -> "0a"'''
	return hex(b)[2:].rjust(2, '0')

def colored(b: int) -> (str, str):
	ch = chr(b)
	hx = hexmod(b)
	if '\x00' == ch:
		return RST + hx , RST + "."
	elif ch in string.ascii_letters + string.digits + string.punctuation:
		return CYN + hx, CYN + ch
	elif ch in string.whitespace:
		return GRN + hx, ' ' if ' ' == ch else GRN + '_'
	return YEL + hx, YEL + '.'

def hexdump(buf, address):
	cache = {hexmod(b): colored(b) for b in range(256)} #0x00 - 0xff
	cache['  '] = ('  ', ' ')

	print(HEADER)
	cur = 0
	row = address
	line = buf[cur:cur+16]
	while line:
		line_hex = line.hex().ljust(32)

		hexbytes = ''
		printable = ''
		for i in range(0, len(line_hex), 2):
			hbyte, abyte = cache[line_hex[i:i+2]]
			hexbytes += hbyte + ' ' if i != 14 else hbyte + ' ┊ '
			printable += abyte if i != 14 else abyte + '┊'

		print(LINE_FORMATTER.format(row, hexbytes, printable))
		
		row += 0x10
		cur += 0x10
		line = buf[cur:cur+16]
	
	print(FOOTER)

def swap_unpack_char():
	"""Returns the unpack prefix that will for non-native endian-ness."""
	if struct.pack('H', 1).startswith("\x00"):
		return '<'
	return '>'

def dump_hex_bytes(addr, s, bytes_per_line=8):
	i = 0
	line = ''
	for ch in s:
		if (i % bytes_per_line) == 0:
			if line:
				print(line)
			line = '%#8.8x: ' % (addr + i)
		line += "%02x " % ch
		i += 1
	print(line)

def dump_hex_byte_string_diff(addr, a, b, bytes_per_line=16):
	i = 0
	line = ''
	a_len = len(a)
	b_len = len(b)
	if a_len < b_len:
		max_len = b_len
	else:
		max_len = a_len
	tty_colors = TerminalColors(True)
	for i in range(max_len):
		ch = None
		if i < a_len:
			ch_a = a[i]
			ch = ch_a
		else:
			ch_a = None
		if i < b_len:
			ch_b = b[i]
			if not ch:
				ch = ch_b
		else:
			ch_b = None
		mismatch = ch_a != ch_b
		if (i % bytes_per_line) == 0:
			if line:
				print(line)
			line = '%#8.8x: ' % (addr + i)
		if mismatch:
			line += RED
		line += "%02X " % ord(ch)
		if mismatch:
			line += RST
		i += 1

	print(line)

def evaluateInputExpression(expression, printErrors=True):
	# HACK
	frame = (
		lldb.debugger.GetSelectedTarget()
		.GetProcess()
		.GetSelectedThread()
		.GetSelectedFrame()
	)
	options = lldb.SBExpressionOptions()
	options.SetTrapExceptions(False)
	value = frame.EvaluateExpression(expression, options)
	error = value.GetError()

	if printErrors and error.Fail():
		errlog(error)

	return value

class FileExtract:
	'''Decode binary data from a file'''

	def __init__(self, f, b='='):
		'''Initialize with an open binary file and optional byte order'''

		self.file = f
		self.byte_order = b
		self.offsets = list()

	def set_byte_order(self, b):
		'''Set the byte order, valid values are "big", "little", "swap", "native", "<", ">", "@", "="'''
		if b == 'big':
			self.byte_order = '>'
		elif b == 'little':
			self.byte_order = '<'
		elif b == 'swap':
			# swap what ever the current byte order is
			self.byte_order = swap_unpack_char()
		elif b == 'native':
			self.byte_order = '='
		elif b == '<' or b == '>' or b == '@' or b == '=':
			self.byte_order = b
		else:
			print("error: invalid byte order specified: '%s'" % b)

	def is_in_memory(self):
		return False

	def seek(self, offset, whence=0):
		if self.file:
			return self.file.seek(offset, whence)
		raise ValueError

	def tell(self):
		if self.file:
			return self.file.tell()
		raise ValueError

	def read_size(self, byte_size):
		s = self.file.read(byte_size)
		if len(s) != byte_size:
			return None
		return s

	def push_offset_and_seek(self, offset):
		'''Push the current file offset and seek to "offset"'''
		self.offsets.append(self.file.tell())
		self.file.seek(offset, 0)

	def pop_offset_and_seek(self):
		'''Pop a previously pushed file offset, or do nothing if there were no previously pushed offsets'''
		if len(self.offsets) > 0:
			self.file.seek(self.offsets.pop())

	def get_sint8(self, fail_value=0):
		'''Extract a single int8_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(1)
		if s:
			v, = struct.unpack(self.byte_order + 'b', s)
			return v
		else:
			return fail_value

	def get_uint8(self, fail_value=0):
		'''Extract a single uint8_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(1)
		if s:
			v, = struct.unpack(self.byte_order + 'B', s)
			return v
		else:
			return fail_value

	def get_sint16(self, fail_value=0):
		'''Extract a single int16_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(2)
		if s:
			v, = struct.unpack(self.byte_order + 'h', s)
			return v
		else:
			return fail_value

	def get_uint16(self, fail_value=0):
		'''Extract a single uint16_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(2)
		if s:
			v, = struct.unpack(self.byte_order + 'H', s)
			return v
		else:
			return fail_value

	def get_sint32(self, fail_value=0):
		'''Extract a single int32_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(4)
		if s:
			v, = struct.unpack(self.byte_order + 'i', s)
			return v
		else:
			return fail_value

	def get_uint32(self, fail_value=0):
		'''Extract a single uint32_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(4)
		if s:
			v, = struct.unpack(self.byte_order + 'I', s)
			return v
		else:
			return fail_value

	def get_sint64(self, fail_value=0):
		'''Extract a single int64_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(8)
		if s:
			v, = struct.unpack(self.byte_order + 'q', s)
			return v
		else:
			return fail_value

	def get_uint64(self, fail_value=0):
		'''Extract a single uint64_t from the binary file at the current file position, returns a single integer'''
		s = self.read_size(8)
		if s:
			v, = struct.unpack(self.byte_order + 'Q', s)
			return v
		else:
			return fail_value

	def get_fixed_length_c_string(
			self,
			n,
			fail_value='',
			isprint_only_with_space_padding=False):
		'''Extract a single fixed length C string from the binary file at the current file position, returns a single C string'''
		s = self.read_size(n)
		if s:
			cstr, = struct.unpack(self.byte_order + ("%i" % n) + 's', s)
			# Strip trialing NULLs
			cstr = cstr.decode()
			cstr = cstr.strip("\0")
			if isprint_only_with_space_padding:
				for c in cstr:
					if c in string.printable or ord(c) == 0:
						continue
					return fail_value
			return cstr
		else:
			return fail_value

	def get_c_string(self):
		'''Extract a single NULL terminated C string from the binary file at the current file position, returns a single C string'''
		cstr = ''
		byte = self.get_uint8()
		while byte != 0:
			cstr += "%c" % byte
			byte = self.get_uint8()
		return cstr

	def get_n_sint8(self, n, fail_value=0):
		'''Extract "n" int8_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'b', s)
		else:
			return (fail_value,) * n

	def get_n_uint8(self, n, fail_value=0):
		'''Extract "n" uint8_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'B', s)
		else:
			return (fail_value,) * n

	def get_n_sint16(self, n, fail_value=0):
		'''Extract "n" int16_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(2 * n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'h', s)
		else:
			return (fail_value,) * n

	def get_n_uint16(self, n, fail_value=0):
		'''Extract "n" uint16_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(2 * n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'H', s)
		else:
			return (fail_value,) * n

	def get_n_sint32(self, n, fail_value=0):
		'''Extract "n" int32_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(4 * n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'i', s)
		else:
			return (fail_value,) * n

	def get_n_uint32(self, n, fail_value=0):
		'''Extract "n" uint32_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(4 * n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'I', s)
		else:
			return (fail_value,) * n

	def get_n_sint64(self, n, fail_value=0):
		'''Extract "n" int64_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(8 * n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'q', s)
		else:
			return (fail_value,) * n

	def get_n_uint64(self, n, fail_value=0):
		'''Extract "n" uint64_t integers from the binary file at the current file position, returns a list of integers'''
		s = self.read_size(8 * n)
		if s:
			return struct.unpack(self.byte_order + ("%u" % n) + 'Q', s)
		else:
			return (fail_value,) * n


class LookupDictionary(dict):
	"""
	a dictionary which can lookup value by key, or keys by value
	"""

	def __init__(self, items=[]):
		"""items can be a list of pair_lists or a dictionary"""
		dict.__init__(self, items)

	def get_keys_for_value(self, value, fail_value=None):
		"""find the key(s) as a list given a value"""
		list_result = [item[0] for item in self.items() if item[1] == value]
		if len(list_result) > 0:
			return list_result
		return fail_value

	def get_first_key_for_value(self, value, fail_value=None):
		"""return the first key of this dictionary given the value"""
		list_result = [item[0] for item in self.items() if item[1] == value]
		if len(list_result) > 0:
			return list_result[0]
		return fail_value

	def get_value(self, key, fail_value=None):
		"""find the value given a key"""
		if key in self:
			return self[key]
		return fail_value


class Enum(LookupDictionary):

	def __init__(self, initial_value=0, items=[]):
		"""items can be a list of pair_lists or a dictionary"""
		LookupDictionary.__init__(self, items)
		self.value = initial_value

	def set_value(self, v):
		v_typename = typeof(v).__name__
		if v_typename == 'str':
			if str in self:
				v = self[v]
			else:
				v = 0
		else:
			self.value = v

	def get_enum_value(self):
		return self.value

	def get_enum_name(self):
		return self.__str__()

	def __str__(self):
		s = self.get_first_key_for_value(self.value, None)
		if s is None:
			s = "%#8.8x" % self.value
		return s

	def __repr__(self):
		return self.__str__()

#################################################################################
############################ Mach-O Parser ######################################
#################################################################################

# Mach header "magic" constants
MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca

# Mach haeder "filetype" constants
MH_OBJECT = 0x00000001
MH_EXECUTE = 0x00000002
MH_FVMLIB = 0x00000003
MH_CORE = 0x00000004
MH_PRELOAD = 0x00000005
MH_DYLIB = 0x00000006
MH_DYLINKER = 0x00000007
MH_BUNDLE = 0x00000008
MH_DYLIB_STUB = 0x00000009
MH_DSYM = 0x0000000a
MH_KEXT_BUNDLE = 0x0000000b

# Mach haeder "flag" constant bits
MH_NOUNDEFS = 0x00000001
MH_INCRLINK = 0x00000002
MH_DYLDLINK = 0x00000004
MH_BINDATLOAD = 0x00000008
MH_PREBOUND = 0x00000010
MH_SPLIT_SEGS = 0x00000020
MH_LAZY_INIT = 0x00000040
MH_TWOLEVEL = 0x00000080
MH_FORCE_FLAT = 0x00000100
MH_NOMULTIDEFS = 0x00000200
MH_NOFIXPREBINDING = 0x00000400
MH_PREBINDABLE = 0x00000800
MH_ALLMODSBOUND = 0x00001000
MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000
MH_CANONICAL = 0x00004000
MH_WEAK_DEFINES = 0x00008000
MH_BINDS_TO_WEAK = 0x00010000
MH_ALLOW_STACK_EXECUTION = 0x00020000
MH_ROOT_SAFE = 0x00040000
MH_SETUID_SAFE = 0x00080000
MH_NO_REEXPORTED_DYLIBS = 0x00100000
MH_PIE = 0x00200000
MH_DEAD_STRIPPABLE_DYLIB = 0x00400000
MH_HAS_TLV_DESCRIPTORS = 0x00800000
MH_NO_HEAP_EXECUTION = 0x01000000

# Mach load command constants
LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x00000001
LC_SYMTAB = 0x00000002
LC_SYMSEG = 0x00000003
LC_THREAD = 0x00000004
LC_UNIXTHREAD = 0x00000005
LC_LOADFVMLIB = 0x00000006
LC_IDFVMLIB = 0x00000007
LC_IDENT = 0x00000008
LC_FVMFILE = 0x00000009
LC_PREPAGE = 0x0000000a
LC_DYSYMTAB = 0x0000000b
LC_LOAD_DYLIB = 0x0000000c
LC_ID_DYLIB = 0x0000000d
LC_LOAD_DYLINKER = 0x0000000e
LC_ID_DYLINKER = 0x0000000f
LC_PREBOUND_DYLIB = 0x00000010
LC_ROUTINES = 0x00000011
LC_SUB_FRAMEWORK = 0x00000012
LC_SUB_UMBRELLA = 0x00000013
LC_SUB_CLIENT = 0x00000014
LC_SUB_LIBRARY = 0x00000015
LC_TWOLEVEL_HINTS = 0x00000016
LC_PREBIND_CKSUM = 0x00000017
LC_LOAD_WEAK_DYLIB = 0x00000018 | LC_REQ_DYLD
LC_SEGMENT_64 = 0x00000019
LC_ROUTINES_64 = 0x0000001a
LC_UUID = 0x0000001b
LC_RPATH = 0x0000001c | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x0000001d
LC_SEGMENT_SPLIT_INFO = 0x0000001e
LC_REEXPORT_DYLIB = 0x0000001f | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x00000020
LC_ENCRYPTION_INFO = 0x00000021
LC_DYLD_INFO = 0x00000022
LC_DYLD_INFO_ONLY = 0x00000022 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x00000023 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x00000024
LC_VERSION_MIN_IPHONEOS = 0x00000025
LC_FUNCTION_STARTS = 0x00000026
LC_DYLD_ENVIRONMENT = 0x00000027

# Mach CPU constants
CPU_ARCH_MASK = 0xff000000
CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_ANY = 0xffffffff
CPU_TYPE_VAX = 1
CPU_TYPE_MC680x0 = 6
CPU_TYPE_I386 = 7
CPU_TYPE_X86_64 = CPU_TYPE_I386 | CPU_ARCH_ABI64

CPU_TYPE_ARM = 12
CPU_TYPE_ARM64	= CPU_TYPE_ARM | CPU_ARCH_ABI64


# VM protection constants
VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4

# VM protection constants
N_STAB = 0xe0
N_PEXT = 0x10
N_TYPE = 0x0e
N_EXT = 0x01

# Values for nlist N_TYPE bits of the "Mach.NList.type" field.
N_UNDF = 0x0
N_ABS = 0x2
N_SECT = 0xe
N_PBUD = 0xc
N_INDR = 0xa

# Section indexes for the "Mach.NList.sect_idx" fields
NO_SECT = 0
MAX_SECT = 255

# Stab defines
N_GSYM = 0x20
N_FNAME = 0x22
N_FUN = 0x24
N_STSYM = 0x26
N_LCSYM = 0x28
N_BNSYM = 0x2e
N_OPT = 0x3c
N_RSYM = 0x40
N_SLINE = 0x44
N_ENSYM = 0x4e
N_SSYM = 0x60
N_SO = 0x64
N_OSO = 0x66
N_LSYM = 0x80
N_BINCL = 0x82
N_SOL = 0x84
N_PARAMS = 0x86
N_VERSION = 0x88
N_OLEVEL = 0x8A
N_PSYM = 0xa0
N_EINCL = 0xa2
N_ENTRY = 0xa4
N_LBRAC = 0xc0
N_EXCL = 0xc2
N_RBRAC = 0xe0
N_BCOMM = 0xe2
N_ECOMM = 0xe4
N_ECOML = 0xe8
N_LENG = 0xfe

vm_prot_names = ['---', 'r--', '-w-', 'rw-', '--x', 'r-x', '-wx', 'rwx']

class Mach:
	"""Class that does everything mach-o related"""

	class Arch:
		"""Class that implements mach-o architectures"""

		def __init__(self, c=0, s=0):
			self.cpu = c
			self.sub = s

		def set_cpu_type(self, c):
			self.cpu = c

		def set_cpu_subtype(self, s):
			self.sub = s

		def set_arch(self, c, s):
			self.cpu = c
			self.sub = s

		def is_64_bit(self):
			return (self.cpu & CPU_ARCH_ABI64) != 0

		cpu_infos = [
			["arm64", CPU_TYPE_ARM64, 2],
			["x86_64", CPU_TYPE_X86_64, 3],
			["x86_64", CPU_TYPE_X86_64, CPU_TYPE_ANY],
		]

		def __str__(self):
			for info in self.cpu_infos:
				if self.cpu == info[1] and (self.sub & 0x00ffffff) == info[2]:
					return info[0]
			return "{0:x}.{1:x}".format(self.cpu, self.sub)

	class Magic(Enum):

		enum = {
			'MH_MAGIC': MH_MAGIC,
			'MH_CIGAM': MH_CIGAM,
			'MH_MAGIC_64': MH_MAGIC_64,
			'MH_CIGAM_64': MH_CIGAM_64,
			'FAT_MAGIC': FAT_MAGIC,
			'FAT_CIGAM': FAT_CIGAM
		}

		def __init__(self, initial_value=0):
			Enum.__init__(self, initial_value, self.enum)

		def is_skinny_mach_file(self):
			return self.value == MH_MAGIC or self.value == MH_CIGAM or self.value == MH_MAGIC_64 or self.value == MH_CIGAM_64

		def is_universal_mach_file(self):
			return self.value == FAT_MAGIC or self.value == FAT_CIGAM

		def unpack(self, data):
			data.set_byte_order('native')
			self.value = data.get_uint32()

		def get_byte_order(self):
			if self.value == MH_CIGAM or self.value == MH_CIGAM_64 or self.value == FAT_CIGAM:
				return swap_unpack_char()
			else:
				return '='

		def is_64_bit(self):
			return self.value == MH_MAGIC_64 or self.value == MH_CIGAM_64

	def __init__(self, debugger):
		self.magic = Mach.Magic()
		self.content = None
		self.path = None
		self.debugger = debugger

	def extract(self, path, extractor):
		self.path = path
		self.unpack(extractor)

	def parse(self, path):
		self.path = path
		try:
			f = open(self.path, 'rb')
			file_extractor = FileExtract(f, '=')
			self.unpack(file_extractor)
			# f.close()
		except IOError as xxx_todo_changeme:
			(errno, strerror) = xxx_todo_changeme.args
			print("I/O error({0}): {1}".format(errno, strerror))
		except ValueError:
			print("Could not convert data to an integer.")
		except:
			print("Unexpected error:", sys.exc_info()[0])
			raise

	def compare(self, rhs):
		self.content.compare(rhs.content)

	def dump(self, options=None):
		self.content.dump(options)

	def dump_header(self, dump_description=True, options=None):
		self.content.dump_header(dump_description, options)

	def dump_load_commands(self, dump_description=True, options=None):
		self.content.dump_load_commands(dump_description, options)

	def dump_sections(self, dump_description=True, options=None):
		self.content.dump_sections(dump_description, options)

	def dump_section_contents(self, options):
		self.content.dump_section_contents(options)

	def dump_symtab(self, dump_description=True, options=None):
		self.content.dump_symtab(dump_description, options)

	def dump_symbol_names_matching_regex(self, regex, file=None):
		self.content.dump_symbol_names_matching_regex(regex, file)

	def description(self):
		return self.content.description()

	def unpack(self, data):
		self.magic.unpack(data)
		if self.magic.is_skinny_mach_file():
			self.content = Mach.Skinny(self.path, self.debugger)

		elif self.magic.is_universal_mach_file():
			self.content = Mach.Universal(self.path, self.debugger)
		else:
			self.content = None

		if self.content is not None:
			self.content.unpack(data, self.magic)

	def is_valid(self):
		return self.content is not None

	class Universal:

		def __init__(self, path, debugger):
			self.path = path
			self.type = 'universal'
			self.file_off = 0
			self.magic = None
			self.nfat_arch = 0
			self.archs = list()
			self.debugger = debugger

		def description(self):
			s = '%#8.8x: %s (' % (self.file_off, self.path)
			archs_string = ''
			for arch in self.archs:
				if len(archs_string):
					archs_string += ', '
				archs_string += '%s' % arch.arch
			s += archs_string
			s += ')'
			return s

		def unpack(self, data, magic=None):
			self.file_off = data.tell()
			if magic is None:
				self.magic = Mach.Magic()
				self.magic.unpack(data)
			else:
				self.magic = magic
				self.file_off = self.file_off - 4
			# Universal headers are always in big endian
			data.set_byte_order('big')
			self.nfat_arch = data.get_uint32()

			for i in range(self.nfat_arch):
				self.archs.append(Mach.Universal.ArchInfo())
				self.archs[i].unpack(data)

			for i in range(self.nfat_arch):
				self.archs[i].mach = Mach.Skinny(self.path, self.debugger)
				data.seek(self.archs[i].offset, 0)
				skinny_magic = Mach.Magic()
				skinny_magic.unpack(data)
				self.archs[i].mach.unpack(data, skinny_magic)

		def compare(self, rhs):
			print('error: comparing two universal files is not supported yet')
			return False

		def dump(self, options):
			if options.dump_header:
				print()
				print("Universal Mach File: magic = %s, nfat_arch = %u" % (self.magic, self.nfat_arch))
				print()
			if self.nfat_arch > 0:
				if options.dump_header:
					self.archs[0].dump_header(True, options)
					for i in range(self.nfat_arch):
						self.archs[i].dump_flat(options)
				if options.dump_header:
					print()
				for i in range(self.nfat_arch):
					self.archs[i].mach.dump(options)

		def dump_header(self, dump_description=True, options=None):
			if dump_description:
				print(self.description())
			for i in range(self.nfat_arch):
				self.archs[i].mach.dump_header(True, options)
				print()

		def dump_load_commands(self, dump_description=True, options=None):
			if dump_description:
				print(self.description())
			for i in range(self.nfat_arch):
				self.archs[i].mach.dump_load_commands(True, options)
				print()

		def dump_sections(self, dump_description=True, options=None):
			if dump_description:
				print(self.description())
			for i in range(self.nfat_arch):
				self.archs[i].mach.dump_sections(True, options)
				print()

		def dump_section_contents(self, options):
			for i in range(self.nfat_arch):
				self.archs[i].mach.dump_section_contents(options)
				print()

		def dump_symtab(self, dump_description=True, options=None):
			if dump_description:
				print(self.description())
			for i in range(self.nfat_arch):
				self.archs[i].mach.dump_symtab(True, options)
				print()

		def dump_symbol_names_matching_regex(self, regex, file=None):
			for i in range(self.nfat_arch):
				self.archs[i].mach.dump_symbol_names_matching_regex(
					regex, file)

		def checksec(self):
			for i in range(self.nfat_arch):
				if self.archs[i].mach.arch.__str__() == get_host_machine():
					self.archs[i].mach.checksec()

		class ArchInfo:

			def __init__(self):
				self.arch = Mach.Arch(0, 0)
				self.offset = 0
				self.size = 0
				self.align = 0
				self.mach = None

			def unpack(self, data):
				# Universal headers are always in big endian
				data.set_byte_order('big')
				self.arch.cpu, self.arch.sub, self.offset, self.size, self.align = data.get_n_uint32(
					5)

			def dump_header(self, dump_description=True, options=None):
				if options.verbose:
					print("CPU        SUBTYPE    OFFSET     SIZE       ALIGN")
					print("---------- ---------- ---------- ---------- ----------")
				else:
					print("ARCH       FILEOFFSET FILESIZE   ALIGN")
					print("---------- ---------- ---------- ----------")

			def dump_flat(self, options):
				if options.verbose:
					print("%#8.8x %#8.8x %#8.8x %#8.8x %#8.8x" % (self.arch.cpu, self.arch.sub, self.offset, self.size, self.align))
				else:
					print("%-10s %#8.8x %#8.8x %#8.8x" % (self.arch, self.offset, self.size, self.align))

			def dump(self):
				print("   cputype: %#8.8x" % self.arch.cpu)
				print("cpusubtype: %#8.8x" % self.arch.sub)
				print("    offset: %#8.8x" % self.offset)
				print("      size: %#8.8x" % self.size)
				print("     align: %#8.8x" % self.align)

			def __str__(self):
				return "Mach.Universal.ArchInfo: %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x" % (
					self.arch.cpu, self.arch.sub, self.offset, self.size, self.align)

			def __repr__(self):
				return "Mach.Universal.ArchInfo: %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x" % (
					self.arch.cpu, self.arch.sub, self.offset, self.size, self.align)

	class Flags:

		def __init__(self, b):
			self.bits = b

		def __str__(self):
			s = ''
			if self.bits & MH_NOUNDEFS:
				s += 'MH_NOUNDEFS | '
			if self.bits & MH_INCRLINK:
				s += 'MH_INCRLINK | '
			if self.bits & MH_DYLDLINK:
				s += 'MH_DYLDLINK | '
			if self.bits & MH_BINDATLOAD:
				s += 'MH_BINDATLOAD | '
			if self.bits & MH_PREBOUND:
				s += 'MH_PREBOUND | '
			if self.bits & MH_SPLIT_SEGS:
				s += 'MH_SPLIT_SEGS | '
			if self.bits & MH_LAZY_INIT:
				s += 'MH_LAZY_INIT | '
			if self.bits & MH_TWOLEVEL:
				s += 'MH_TWOLEVEL | '
			if self.bits & MH_FORCE_FLAT:
				s += 'MH_FORCE_FLAT | '
			if self.bits & MH_NOMULTIDEFS:
				s += 'MH_NOMULTIDEFS | '
			if self.bits & MH_NOFIXPREBINDING:
				s += 'MH_NOFIXPREBINDING | '
			if self.bits & MH_PREBINDABLE:
				s += 'MH_PREBINDABLE | '
			if self.bits & MH_ALLMODSBOUND:
				s += 'MH_ALLMODSBOUND | '
			if self.bits & MH_SUBSECTIONS_VIA_SYMBOLS:
				s += 'MH_SUBSECTIONS_VIA_SYMBOLS | '
			if self.bits & MH_CANONICAL:
				s += 'MH_CANONICAL | '
			if self.bits & MH_WEAK_DEFINES:
				s += 'MH_WEAK_DEFINES | '
			if self.bits & MH_BINDS_TO_WEAK:
				s += 'MH_BINDS_TO_WEAK | '
			if self.bits & MH_ALLOW_STACK_EXECUTION:
				s += 'MH_ALLOW_STACK_EXECUTION | '
			if self.bits & MH_ROOT_SAFE:
				s += 'MH_ROOT_SAFE | '
			if self.bits & MH_SETUID_SAFE:
				s += 'MH_SETUID_SAFE | '
			if self.bits & MH_NO_REEXPORTED_DYLIBS:
				s += 'MH_NO_REEXPORTED_DYLIBS | '
			if self.bits & MH_PIE:
				s += 'MH_PIE | '
			if self.bits & MH_DEAD_STRIPPABLE_DYLIB:
				s += 'MH_DEAD_STRIPPABLE_DYLIB | '
			if self.bits & MH_HAS_TLV_DESCRIPTORS:
				s += 'MH_HAS_TLV_DESCRIPTORS | '
			if self.bits & MH_NO_HEAP_EXECUTION:
				s += 'MH_NO_HEAP_EXECUTION | '
			# Strip the trailing " |" if we have any flags
			if len(s) > 0:
				s = s[0:-2]
			return s

	class FileType(Enum):

		enum = {
			'MH_OBJECT': MH_OBJECT,
			'MH_EXECUTE': MH_EXECUTE,
			'MH_FVMLIB': MH_FVMLIB,
			'MH_CORE': MH_CORE,
			'MH_PRELOAD': MH_PRELOAD,
			'MH_DYLIB': MH_DYLIB,
			'MH_DYLINKER': MH_DYLINKER,
			'MH_BUNDLE': MH_BUNDLE,
			'MH_DYLIB_STUB': MH_DYLIB_STUB,
			'MH_DSYM': MH_DSYM,
			'MH_KEXT_BUNDLE': MH_KEXT_BUNDLE
		}

		def __init__(self, initial_value=0):
			Enum.__init__(self, initial_value, self.enum)

	class Skinny:

		def __init__(self, path, debugger):
			self.path = path
			self.type = 'skinny'
			self.data = None
			self.file_off = 0
			self.magic = 0
			self.arch = Mach.Arch(0, 0)
			self.filetype = Mach.FileType(0)
			self.ncmds = 0
			self.sizeofcmds = 0
			self.flags = Mach.Flags(0)
			self.uuid = None
			self.commands = list()
			self.segments = list()
			self.sections = list()
			self.symbols = list()
			self.is_encrypted	= False
			self.debugger		= debugger
			self.sections.append(Mach.Section())

		def checksec(self):
			macho_stat 		= os.stat(self.path)
			nx_heap 		= self.has_nx_heap()
			self.has_pie	= bool(self.flags.bits & MH_PIE)
			self.is_uid		= stat.S_ISUID & macho_stat.st_mode
			self.is_gid		= stat.S_ISGID & macho_stat.st_mode

			objc_release, __stack_chk_guard, __stack_chk_fail = self.has_arc_and_strong_stack()

			print(f"ARC	         : {objc_release}")
			print(f"PIE	         : {self.has_pie}")
			print(f"Stack Canary	 : {__stack_chk_guard and __stack_chk_fail}")
			print(f"Encrypted	 : {self.is_encrypted}")
			print(f"NX Heap		 : {self.has_nx_heap()}")
			print(f"NX Stack 	 : {self.has_nx_stack()}")
			print(f"Restricted 	 : {self.has_restricted()}")

		def has_nx_heap(self):
			#do we need to check this??? I'm gonna return TRUE cause of W^X
			return True if self.flags.bits & MH_NO_HEAP_EXECUTION else True
		
		def has_nx_stack(self):
			return False if self.flags.bits & MH_ALLOW_STACK_EXECUTION else True

		def has_arc_and_strong_stack(self):
			objc_release	  = False
			__stack_chk_guard = False
			__stack_chk_fail  = False

			selected_target = self.debugger.GetSelectedTarget()

			target = self.debugger.CreateTarget(self.path)
			for module in target.modules:
				if fnmatch.fnmatch(module.file.fullpath.lower(), self.path.lower()):

					for i in module.symbols:
						if i.name == "objc_release":
							objc_release =  True
						if i.name == "__stack_chk_guard":
							__stack_chk_guard =  True
						if i.name == "__stack_chk_fail":
							__stack_chk_fail =  True

			self.debugger.DeleteTarget(target)
			self.debugger.SetSelectedTarget(selected_target)	# reset back to previously selected target

			return objc_release, __stack_chk_guard, __stack_chk_fail

		def has_restricted(self):
			#3 cases restrictedBySetGUid, restrictedBySegment, restrictedByEntitlements
			codesign = run_shell_command(f"codesign -dvvvv '{self.path}'").stderr.decode() #stderr ( :| ) ???
			
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
			for seg in self.segments:
				if seg.segname.lower()=="__restrict":
					return "True (__restrict)"

			return False
			
		def description(self):
			return '%#8.8x: %s (%s)' % (self.file_off, self.path, self.arch)

		def unpack(self, data, magic=None):
			self.data = data
			self.file_off = data.tell()
			if magic is None:
				self.magic = Mach.Magic()
				self.magic.unpack(data)
			else:
				self.magic = magic
				self.file_off = self.file_off - 4
			data.set_byte_order(self.magic.get_byte_order())
			self.arch.cpu, self.arch.sub, self.filetype.value, self.ncmds, self.sizeofcmds, bits = data.get_n_uint32(
				6)
			self.flags.bits = bits

			if self.is_64_bit():
				data.get_uint32()  # Skip reserved word in mach_header_64

			for i in range(0, self.ncmds):
				lc = self.unpack_load_command(data)
				self.commands.append(lc)

		def get_data(self):
			if self.data:
				self.data.set_byte_order(self.magic.get_byte_order())
				return self.data
			return None

		def unpack_load_command(self, data):
			lc = Mach.LoadCommand()
			lc.unpack(self, data)
			lc_command = lc.command.get_enum_value()
			if (lc_command == LC_SEGMENT or
					lc_command == LC_SEGMENT_64):
				lc = Mach.SegmentLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_LOAD_DYLIB or
				  lc_command == LC_ID_DYLIB or
				  lc_command == LC_LOAD_WEAK_DYLIB or
				  lc_command == LC_REEXPORT_DYLIB):
				lc = Mach.DylibLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_LOAD_DYLINKER or
				  lc_command == LC_SUB_FRAMEWORK or
				  lc_command == LC_SUB_CLIENT or
				  lc_command == LC_SUB_UMBRELLA or
				  lc_command == LC_SUB_LIBRARY or
				  lc_command == LC_ID_DYLINKER or
				  lc_command == LC_RPATH):
				lc = Mach.LoadDYLDLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_DYLD_INFO_ONLY):
				lc = Mach.DYLDInfoOnlyLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_SYMTAB):
				lc = Mach.SymtabLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_DYSYMTAB):
				lc = Mach.DYLDSymtabLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_UUID):
				lc = Mach.UUIDLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_CODE_SIGNATURE or
				  lc_command == LC_SEGMENT_SPLIT_INFO or
				  lc_command == LC_FUNCTION_STARTS):
				lc = Mach.DataBlobLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_UNIXTHREAD):
				lc = Mach.UnixThreadLoadCommand(lc)
				lc.unpack(self, data)
			elif (lc_command == LC_ENCRYPTION_INFO):
				lc = Mach.EncryptionInfoLoadCommand(lc)
				lc.unpack(self, data)
				self.is_encrypted = bool(cryptid)
				
			lc.skip(data)
			return lc

		def compare(self, rhs):
			print("\nComparing:")
			print("a) %s %s" % (self.arch, self.path))
			print("b) %s %s" % (rhs.arch, rhs.path))
			result = True
			if self.type == rhs.type:
				for lhs_section in self.sections[1:]:
					rhs_section = rhs.get_section_by_section(lhs_section)
					if rhs_section:
						print('comparing %s.%s...' % (lhs_section.segname, lhs_section.sectname), end=' ')
						sys.stdout.flush()
						lhs_data = lhs_section.get_contents(self)
						rhs_data = rhs_section.get_contents(rhs)
						if lhs_data and rhs_data:
							if lhs_data == rhs_data:
								print('ok')
							else:
								lhs_data_len = len(lhs_data)
								rhs_data_len = len(rhs_data)
								# if lhs_data_len < rhs_data_len:
								#     if lhs_data == rhs_data[0:lhs_data_len]:
								#         print 'section data for %s matches the first %u bytes' % (lhs_section.sectname, lhs_data_len)
								#     else:
								#         # TODO: check padding
								#         result = False
								# elif lhs_data_len > rhs_data_len:
								#     if lhs_data[0:rhs_data_len] == rhs_data:
								#         print 'section data for %s matches the first %u bytes' % (lhs_section.sectname, lhs_data_len)
								#     else:
								#         # TODO: check padding
								#         result = False
								# else:
								result = False
								print('error: sections differ')
								# print 'a) %s' % (lhs_section)
								# dump_hex_byte_string_diff(0, lhs_data, rhs_data)
								# print 'b) %s' % (rhs_section)
								# dump_hex_byte_string_diff(0, rhs_data, lhs_data)
						elif lhs_data and not rhs_data:
							print('error: section data missing from b:')
							print('a) %s' % (lhs_section))
							print('b) %s' % (rhs_section))
							result = False
						elif not lhs_data and rhs_data:
							print('error: section data missing from a:')
							print('a) %s' % (lhs_section))
							print('b) %s' % (rhs_section))
							result = False
						elif lhs_section.offset or rhs_section.offset:
							print('error: section data missing for both a and b:')
							print('a) %s' % (lhs_section))
							print('b) %s' % (rhs_section))
							result = False
						else:
							print('ok')
					else:
						result = False
						print('error: section %s is missing in %s' % (lhs_section.sectname, rhs.path))
			else:
				print('error: comparing a %s mach-o file with a %s mach-o file is not supported' % (self.type, rhs.type))
				result = False
			if not result:
				print('error: mach files differ')
			return result

		def dump_header(self, dump_description=True, options=None):
			if options.verbose:
				print("MAGIC      CPU        SUBTYPE    FILETYPE   NUM CMDS SIZE CMDS  FLAGS")
				print("---------- ---------- ---------- ---------- -------- ---------- ----------")
			else:
				print("MAGIC        ARCH       FILETYPE       NUM CMDS SIZE CMDS  FLAGS")
				print("------------ ---------- -------------- -------- ---------- ----------")

		def dump_flat(self, options):
			if options.verbose:
				print("%#8.8x %#8.8x %#8.8x %#8.8x %#8u %#8.8x %#8.8x" % (self.magic, self.arch.cpu, self.arch.sub, self.filetype.value, self.ncmds, self.sizeofcmds, self.flags.bits))
			else:
				print("%-12s %-10s %-14s %#8u %#8.8x %s" % (self.magic, self.arch, self.filetype, self.ncmds, self.sizeofcmds, self.flags))

		def dump(self, options):
			if options.dump_header:
				self.dump_header(True, options)
			if options.dump_load_commands:
				self.dump_load_commands(False, options)
			if options.dump_sections:
				self.dump_sections(False, options)
			if options.section_names:
				self.dump_section_contents(options)
			if options.dump_symtab:
				self.get_symtab()
				if len(self.symbols):
					self.dump_sections(False, options)
				else:
					print("No symbols")
			if options.find_mangled:
				self.dump_symbol_names_matching_regex(re.compile('^_?_Z'))

		def dump_header(self, dump_description=True, options=None):
			if dump_description:
				print(self.description())
			print("Mach Header")
			print("       magic: %#8.8x %s" % (self.magic.value, self.magic))
			print("     cputype: %#8.8x" % (self.arch.cpu))
			print("  cpusubtype: %#8.8x" % self.arch.sub)
			print("    filetype: %#8.8x %s" % (self.filetype.get_enum_value(), self.filetype.get_enum_name()))
			print("       ncmds: %#8.8x %u" % (self.ncmds, self.ncmds))
			print("  sizeofcmds: %#8.8x" % self.sizeofcmds)
			print("       flags: %#8.8x %s" % (self.flags.bits, self.flags))

		def dump_load_commands(self, dump_description=True, options=None):
			if dump_description:
				print(self.description())
			for lc in self.commands:
				print(lc)

		def get_section_by_name(self, name):
			for section in self.sections:
				if section.sectname and section.sectname == name:
					return section
			return None

		def get_section_by_section(self, other_section):
			for section in self.sections:
				if section.sectname == other_section.sectname and section.segname == other_section.segname:
					return section
			return None

		def dump_sections(self, dump_description=True, options=None):
			if dump_description:
				print(self.description())
			num_sections = len(self.sections)
			if num_sections > 1:
				self.sections[1].dump_header()
				for sect_idx in range(1, num_sections):
					print("%s" % self.sections[sect_idx])

		def dump_section_contents(self, options):
			saved_section_to_disk = False
			for sectname in options.section_names:
				section = self.get_section_by_name(sectname)
				if section:
					sect_bytes = section.get_contents(self)
					if options.outfile:
						if not saved_section_to_disk:
							outfile = open(options.outfile, 'w')
							if options.extract_modules:
								# print "Extracting modules from mach file..."
								data = file_extract.FileExtract(
									io.BytesIO(sect_bytes), self.data.byte_order)
								version = data.get_uint32()
								num_modules = data.get_uint32()
								# print "version = %u, num_modules = %u" %
								# (version, num_modules)
								for i in range(num_modules):
									data_offset = data.get_uint64()
									data_size = data.get_uint64()
									name_offset = data.get_uint32()
									language = data.get_uint32()
									flags = data.get_uint32()
									data.seek(name_offset)
									module_name = data.get_c_string()
									# print "module[%u] data_offset = %#16.16x,
									# data_size = %#16.16x, name_offset =
									# %#16.16x (%s), language = %u, flags =
									# %#x" % (i, data_offset, data_size,
									# name_offset, module_name, language,
									# flags)
									data.seek(data_offset)
									outfile.write(data.read_size(data_size))
							else:
								print("Saving section %s to '%s'" % (sectname, options.outfile))
								outfile.write(sect_bytes)
							outfile.close()
							saved_section_to_disk = True
						else:
							print("error: you can only save a single section to disk at a time, skipping section '%s'" % (sectname))
					else:
						print('section %s:\n' % (sectname))
						section.dump_header()
						print('%s\n' % (section))
						dump_memory(0, sect_bytes, options.max_count, 16)
				else:
					print('error: no section named "%s" was found' % (sectname))

		def get_segment(self, segname):
			if len(self.segments) == 1 and self.segments[0].segname == '':
				return self.segments[0]
			for segment in self.segments:
				if segment.segname == segname:
					return segment
			return None

		def get_first_load_command(self, lc_enum_value):
			for lc in self.commands:
				if lc.command.value == lc_enum_value:
					return lc
			return None

		def get_symtab(self):
			if self.data and not self.symbols:
				lc_symtab = self.get_first_load_command(LC_SYMTAB)
				if lc_symtab:
					symtab_offset = self.file_off
					if self.data.is_in_memory():
						linkedit_segment = self.get_segment('__LINKEDIT')
						if linkedit_segment:
							linkedit_vmaddr = linkedit_segment.vmaddr
							linkedit_fileoff = linkedit_segment.fileoff
							symtab_offset = linkedit_vmaddr + lc_symtab.symoff - linkedit_fileoff
							symtab_offset = linkedit_vmaddr + lc_symtab.stroff - linkedit_fileoff
					else:
						symtab_offset += lc_symtab.symoff

					self.data.seek(symtab_offset)
					is_64 = self.is_64_bit()
					for i in range(lc_symtab.nsyms):
						nlist = Mach.NList()
						nlist.unpack(self, self.data, lc_symtab)
						self.symbols.append(nlist)
				else:
					print("no LC_SYMTAB")

		def dump_symtab(self, dump_description=True, options=None):
			self.get_symtab()
			if dump_description:
				print(self.description())
			for i, symbol in enumerate(self.symbols):
				print('[%5u] %s' % (i, symbol))

		def dump_symbol_names_matching_regex(self, regex, file=None):
			self.get_symtab()
			for symbol in self.symbols:
				if symbol.name and regex.search(symbol.name):
					print(symbol.name)
					if file:
						file.write('%s\n' % (symbol.name))

		def is_64_bit(self):
			return self.magic.is_64_bit()

	class LoadCommand:

		class Command(Enum):
			enum = {
				'LC_SEGMENT': LC_SEGMENT,
				'LC_SYMTAB': LC_SYMTAB,
				'LC_SYMSEG': LC_SYMSEG,
				'LC_THREAD': LC_THREAD,
				'LC_UNIXTHREAD': LC_UNIXTHREAD,
				'LC_LOADFVMLIB': LC_LOADFVMLIB,
				'LC_IDFVMLIB': LC_IDFVMLIB,
				'LC_IDENT': LC_IDENT,
				'LC_FVMFILE': LC_FVMFILE,
				'LC_PREPAGE': LC_PREPAGE,
				'LC_DYSYMTAB': LC_DYSYMTAB,
				'LC_LOAD_DYLIB': LC_LOAD_DYLIB,
				'LC_ID_DYLIB': LC_ID_DYLIB,
				'LC_LOAD_DYLINKER': LC_LOAD_DYLINKER,
				'LC_ID_DYLINKER': LC_ID_DYLINKER,
				'LC_PREBOUND_DYLIB': LC_PREBOUND_DYLIB,
				'LC_ROUTINES': LC_ROUTINES,
				'LC_SUB_FRAMEWORK': LC_SUB_FRAMEWORK,
				'LC_SUB_UMBRELLA': LC_SUB_UMBRELLA,
				'LC_SUB_CLIENT': LC_SUB_CLIENT,
				'LC_SUB_LIBRARY': LC_SUB_LIBRARY,
				'LC_TWOLEVEL_HINTS': LC_TWOLEVEL_HINTS,
				'LC_PREBIND_CKSUM': LC_PREBIND_CKSUM,
				'LC_LOAD_WEAK_DYLIB': LC_LOAD_WEAK_DYLIB,
				'LC_SEGMENT_64': LC_SEGMENT_64,
				'LC_ROUTINES_64': LC_ROUTINES_64,
				'LC_UUID': LC_UUID,
				'LC_RPATH': LC_RPATH,
				'LC_CODE_SIGNATURE': LC_CODE_SIGNATURE,
				'LC_SEGMENT_SPLIT_INFO': LC_SEGMENT_SPLIT_INFO,
				'LC_REEXPORT_DYLIB': LC_REEXPORT_DYLIB,
				'LC_LAZY_LOAD_DYLIB': LC_LAZY_LOAD_DYLIB,
				'LC_ENCRYPTION_INFO': LC_ENCRYPTION_INFO,
				'LC_DYLD_INFO': LC_DYLD_INFO,
				'LC_DYLD_INFO_ONLY': LC_DYLD_INFO_ONLY,
				'LC_LOAD_UPWARD_DYLIB': LC_LOAD_UPWARD_DYLIB,
				'LC_VERSION_MIN_MACOSX': LC_VERSION_MIN_MACOSX,
				'LC_VERSION_MIN_IPHONEOS': LC_VERSION_MIN_IPHONEOS,
				'LC_FUNCTION_STARTS': LC_FUNCTION_STARTS,
				'LC_DYLD_ENVIRONMENT': LC_DYLD_ENVIRONMENT
			}

			def __init__(self, initial_value=0):
				Enum.__init__(self, initial_value, self.enum)

		def __init__(self, c=None, l=0, o=0):
			if c is not None:
				self.command = c
			else:
				self.command = Mach.LoadCommand.Command(0)
			self.length = l
			self.file_off = o

		def unpack(self, mach_file, data):
			self.file_off = data.tell()
			self.command.value, self.length = data.get_n_uint32(2)

		def skip(self, data):
			data.seek(self.file_off + self.length, 0)

		def __str__(self):
			lc_name = self.command.get_enum_name()
			return '%#8.8x: <%#4.4x> %-24s' % (self.file_off,
											   self.length, lc_name)

	class Section:

		def __init__(self):
			self.index = 0
			self.is_64 = False
			self.sectname = None
			self.segname = None
			self.addr = 0
			self.size = 0
			self.offset = 0
			self.align = 0
			self.reloff = 0
			self.nreloc = 0
			self.flags = 0
			self.reserved1 = 0
			self.reserved2 = 0
			self.reserved3 = 0

		def unpack(self, is_64, data):
			self.is_64 = is_64
			self.sectname = data.get_fixed_length_c_string(16, '', True)
			self.segname = data.get_fixed_length_c_string(16, '', True)
			if self.is_64:
				self.addr, self.size = data.get_n_uint64(2)
				self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2, self.reserved3 = data.get_n_uint32(
					8)
			else:
				self.addr, self.size = data.get_n_uint32(2)
				self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2 = data.get_n_uint32(
					7)

		def dump_header(self):
			if self.is_64:
				print("INDEX ADDRESS            SIZE               OFFSET     ALIGN      RELOFF     NRELOC     FLAGS      RESERVED1  RESERVED2  RESERVED3  NAME")
				print("===== ------------------ ------------------ ---------- ---------- ---------- ---------- ---------- ---------- ---------- ---------- ----------------------")
			else:
				print("INDEX ADDRESS    SIZE       OFFSET     ALIGN      RELOFF     NRELOC     FLAGS      RESERVED1  RESERVED2  NAME")
				print("===== ---------- ---------- ---------- ---------- ---------- ---------- ---------- ---------- ---------- ----------------------")

		def __str__(self):
			if self.is_64:
				return "[%3u] %#16.16x %#16.16x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %s.%s" % (
					self.index, self.addr, self.size, self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2, self.reserved3, self.segname, self.sectname)
			else:
				return "[%3u] %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %s.%s" % (
					self.index, self.addr, self.size, self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2, self.segname, self.sectname)

		def get_contents(self, mach_file):
			'''Get the section contents as a python string'''
			if self.size > 0 and mach_file.get_segment(
					self.segname).filesize > 0:
				data = mach_file.get_data()
				if data:
					section_data_offset = mach_file.file_off + self.offset
					# print '%s.%s is at offset 0x%x with size 0x%x' %
					# (self.segname, self.sectname, section_data_offset,
					# self.size)
					data.push_offset_and_seek(section_data_offset)
					bytes = data.read_size(self.size)
					data.pop_offset_and_seek()
					return bytes
			return None

	class DylibLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.name = None
			self.timestamp = 0
			self.current_version = 0
			self.compatibility_version = 0

		def unpack(self, mach_file, data):
			byte_order_char = mach_file.magic.get_byte_order()
			name_offset, self.timestamp, self.current_version, self.compatibility_version = data.get_n_uint32(
				4)
			data.seek(self.file_off + name_offset, 0)
			self.name = data.get_fixed_length_c_string(self.length - 24)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			s += "%#8.8x %#8.8x %#8.8x " % (self.timestamp,
											self.current_version,
											self.compatibility_version)
			s += self.name
			return s

	class LoadDYLDLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.name = None

		def unpack(self, mach_file, data):
			data.get_uint32()
			self.name = data.get_fixed_length_c_string(self.length - 12)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			s += "%s" % self.name
			return s

	class UnixThreadLoadCommand(LoadCommand):

		class ThreadState:

			def __init__(self):
				self.flavor = 0
				self.count = 0
				self.register_values = list()

			def unpack(self, data):
				self.flavor, self.count = data.get_n_uint32(2)
				self.register_values = data.get_n_uint32(self.count)

			def __str__(self):
				s = "flavor = %u, count = %u, regs =" % (
					self.flavor, self.count)
				i = 0
				for register_value in self.register_values:
					if i % 8 == 0:
						s += "\n                                            "
					s += " %#8.8x" % register_value
					i += 1
				return s

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.reg_sets = list()

		def unpack(self, mach_file, data):
			reg_set = Mach.UnixThreadLoadCommand.ThreadState()
			reg_set.unpack(data)
			self.reg_sets.append(reg_set)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			for reg_set in self.reg_sets:
				s += "%s" % reg_set
			return s

	class DYLDInfoOnlyLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.rebase_off = 0
			self.rebase_size = 0
			self.bind_off = 0
			self.bind_size = 0
			self.weak_bind_off = 0
			self.weak_bind_size = 0
			self.lazy_bind_off = 0
			self.lazy_bind_size = 0
			self.export_off = 0
			self.export_size = 0

		def unpack(self, mach_file, data):
			byte_order_char = mach_file.magic.get_byte_order()
			self.rebase_off, self.rebase_size, self.bind_off, self.bind_size, self.weak_bind_off, self.weak_bind_size, self.lazy_bind_off, self.lazy_bind_size, self.export_off, self.export_size = data.get_n_uint32(
				10)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			s += "rebase_off = %#8.8x, rebase_size = %u, " % (
				self.rebase_off, self.rebase_size)
			s += "bind_off = %#8.8x, bind_size = %u, " % (
				self.bind_off, self.bind_size)
			s += "weak_bind_off = %#8.8x, weak_bind_size = %u, " % (
				self.weak_bind_off, self.weak_bind_size)
			s += "lazy_bind_off = %#8.8x, lazy_bind_size = %u, " % (
				self.lazy_bind_off, self.lazy_bind_size)
			s += "export_off = %#8.8x, export_size = %u, " % (
				self.export_off, self.export_size)
			return s

	class DYLDSymtabLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.ilocalsym = 0
			self.nlocalsym = 0
			self.iextdefsym = 0
			self.nextdefsym = 0
			self.iundefsym = 0
			self.nundefsym = 0
			self.tocoff = 0
			self.ntoc = 0
			self.modtaboff = 0
			self.nmodtab = 0
			self.extrefsymoff = 0
			self.nextrefsyms = 0
			self.indirectsymoff = 0
			self.nindirectsyms = 0
			self.extreloff = 0
			self.nextrel = 0
			self.locreloff = 0
			self.nlocrel = 0

		def unpack(self, mach_file, data):
			byte_order_char = mach_file.magic.get_byte_order()
			self.ilocalsym, self.nlocalsym, self.iextdefsym, self.nextdefsym, self.iundefsym, self.nundefsym, self.tocoff, self.ntoc, self.modtaboff, self.nmodtab, self.extrefsymoff, self.nextrefsyms, self.indirectsymoff, self.nindirectsyms, self.extreloff, self.nextrel, self.locreloff, self.nlocrel = data.get_n_uint32(
				18)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			# s += "ilocalsym = %u, nlocalsym = %u, " % (self.ilocalsym, self.nlocalsym)
			# s += "iextdefsym = %u, nextdefsym = %u, " % (self.iextdefsym, self.nextdefsym)
			# s += "iundefsym %u, nundefsym = %u, " % (self.iundefsym, self.nundefsym)
			# s += "tocoff = %#8.8x, ntoc = %u, " % (self.tocoff, self.ntoc)
			# s += "modtaboff = %#8.8x, nmodtab = %u, " % (self.modtaboff, self.nmodtab)
			# s += "extrefsymoff = %#8.8x, nextrefsyms = %u, " % (self.extrefsymoff, self.nextrefsyms)
			# s += "indirectsymoff = %#8.8x, nindirectsyms = %u, " % (self.indirectsymoff, self.nindirectsyms)
			# s += "extreloff = %#8.8x, nextrel = %u, " % (self.extreloff, self.nextrel)
			# s += "locreloff = %#8.8x, nlocrel = %u" % (self.locreloff,
			# self.nlocrel)
			s += "ilocalsym      = %-10u, nlocalsym     = %u\n" % (
				self.ilocalsym, self.nlocalsym)
			s += "                                             iextdefsym     = %-10u, nextdefsym    = %u\n" % (
				self.iextdefsym, self.nextdefsym)
			s += "                                             iundefsym      = %-10u, nundefsym     = %u\n" % (
				self.iundefsym, self.nundefsym)
			s += "                                             tocoff         = %#8.8x, ntoc          = %u\n" % (
				self.tocoff, self.ntoc)
			s += "                                             modtaboff      = %#8.8x, nmodtab       = %u\n" % (
				self.modtaboff, self.nmodtab)
			s += "                                             extrefsymoff   = %#8.8x, nextrefsyms   = %u\n" % (
				self.extrefsymoff, self.nextrefsyms)
			s += "                                             indirectsymoff = %#8.8x, nindirectsyms = %u\n" % (
				self.indirectsymoff, self.nindirectsyms)
			s += "                                             extreloff      = %#8.8x, nextrel       = %u\n" % (
				self.extreloff, self.nextrel)
			s += "                                             locreloff      = %#8.8x, nlocrel       = %u" % (
				self.locreloff, self.nlocrel)
			return s

	class SymtabLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.symoff = 0
			self.nsyms = 0
			self.stroff = 0
			self.strsize = 0

		def unpack(self, mach_file, data):
			byte_order_char = mach_file.magic.get_byte_order()
			self.symoff, self.nsyms, self.stroff, self.strsize = data.get_n_uint32(
				4)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			s += "symoff = %#8.8x, nsyms = %u, stroff = %#8.8x, strsize = %u" % (
				self.symoff, self.nsyms, self.stroff, self.strsize)
			return s

	class UUIDLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.uuid = None

		def unpack(self, mach_file, data):
			uuid_data = data.get_n_uint8(16)
			uuid_str = ''
			for byte in uuid_data:
				uuid_str += '%2.2x' % byte
			self.uuid = uuid.UUID(uuid_str)
			mach_file.uuid = self.uuid

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			s += self.uuid.__str__()
			return s

	class DataBlobLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.dataoff = 0
			self.datasize = 0

		def unpack(self, mach_file, data):
			byte_order_char = mach_file.magic.get_byte_order()
			self.dataoff, self.datasize = data.get_n_uint32(2)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			s += "dataoff = %#8.8x, datasize = %u" % (
				self.dataoff, self.datasize)
			return s

	class EncryptionInfoLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.cryptoff = 0
			self.cryptsize = 0
			self.cryptid = 0

		def unpack(self, mach_file, data):
			byte_order_char = mach_file.magic.get_byte_order()
			self.cryptoff, self.cryptsize, self.cryptid = data.get_n_uint32(3)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			s += "file-range = [%#8.8x - %#8.8x), cryptsize = %u, cryptid = %u" % (
				self.cryptoff, self.cryptoff + self.cryptsize, self.cryptsize, self.cryptid)
			return s

	class SegmentLoadCommand(LoadCommand):

		def __init__(self, lc):
			Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
			self.sectname = None
			self.segname = None
			self.vmaddr = 0
			self.vmsize = 0
			self.fileoff = 0
			self.filesize = 0
			self.maxprot = 0
			self.initprot = 0
			self.nsects = 0
			self.flags = 0

		def unpack(self, mach_file, data):
			is_64 = self.command.get_enum_value() == LC_SEGMENT_64
			self.segname = data.get_fixed_length_c_string(16, '', True)
			if is_64:
				self.vmaddr, self.vmsize, self.fileoff, self.filesize = data.get_n_uint64(4)
			else:
				self.vmaddr, self.vmsize, self.fileoff, self.filesize = data.get_n_uint32(4)
			self.maxprot, self.initprot, self.nsects, self.flags = data.get_n_uint32(4)
			mach_file.segments.append(self)

			for i in range(self.nsects):
				section = Mach.Section()
				section.unpack(is_64, data)
				section.index = len(mach_file.sections)
				mach_file.sections.append(section)

		def __str__(self):
			s = Mach.LoadCommand.__str__(self)
			if self.command.get_enum_value() == LC_SEGMENT:
				s += "%#8.8x %#8.8x %#8.8x %#8.8x " % (
					self.vmaddr, self.vmsize, self.fileoff, self.filesize)
			else:
				s += "%#16.16x %#16.16x %#16.16x %#16.16x " % (
					self.vmaddr, self.vmsize, self.fileoff, self.filesize)
			s += "%s %s %3u %#8.8x" % (vm_prot_names[self.maxprot], vm_prot_names[
									   self.initprot], self.nsects, self.flags)
			s += ' ' + self.segname
			return s

	class NList:

		class Type:

			class Stab(Enum):
				enum = {
					'N_GSYM': N_GSYM,
					'N_FNAME': N_FNAME,
					'N_FUN': N_FUN,
					'N_STSYM': N_STSYM,
					'N_LCSYM': N_LCSYM,
					'N_BNSYM': N_BNSYM,
					'N_OPT': N_OPT,
					'N_RSYM': N_RSYM,
					'N_SLINE': N_SLINE,
					'N_ENSYM': N_ENSYM,
					'N_SSYM': N_SSYM,
					'N_SO': N_SO,
					'N_OSO': N_OSO,
					'N_LSYM': N_LSYM,
					'N_BINCL': N_BINCL,
					'N_SOL': N_SOL,
					'N_PARAMS': N_PARAMS,
					'N_VERSION': N_VERSION,
					'N_OLEVEL': N_OLEVEL,
					'N_PSYM': N_PSYM,
					'N_EINCL': N_EINCL,
					'N_ENTRY': N_ENTRY,
					'N_LBRAC': N_LBRAC,
					'N_EXCL': N_EXCL,
					'N_RBRAC': N_RBRAC,
					'N_BCOMM': N_BCOMM,
					'N_ECOMM': N_ECOMM,
					'N_ECOML': N_ECOML,
					'N_LENG': N_LENG
				}

				def __init__(self, magic=0):
					Enum.__init__(self, magic, self.enum)

			def __init__(self, t=0):
				self.value = t

			def __str__(self):
				n_type = self.value
				if n_type & N_STAB:
					stab = Mach.NList.Type.Stab(self.value)
					return '%s' % stab
				else:
					type = self.value & N_TYPE
					type_str = ''
					if type == N_UNDF:
						type_str = 'N_UNDF'
					elif type == N_ABS:
						type_str = 'N_ABS '
					elif type == N_SECT:
						type_str = 'N_SECT'
					elif type == N_PBUD:
						type_str = 'N_PBUD'
					elif type == N_INDR:
						type_str = 'N_INDR'
					else:
						type_str = "??? (%#2.2x)" % type
					if n_type & N_PEXT:
						type_str += ' | PEXT'
					if n_type & N_EXT:
						type_str += ' | EXT '
					return type_str

		def __init__(self):
			self.index = 0
			self.name_offset = 0
			self.name = 0
			self.type = Mach.NList.Type()
			self.sect_idx = 0
			self.desc = 0
			self.value = 0

		def unpack(self, mach_file, data, symtab_lc):
			self.index = len(mach_file.symbols)
			self.name_offset = data.get_uint32()
			self.type.value, self.sect_idx = data.get_n_uint8(2)
			self.desc = data.get_uint16()
			if mach_file.is_64_bit():
				self.value = data.get_uint64()
			else:
				self.value = data.get_uint32()
			data.push_offset_and_seek(
				mach_file.file_off +
				symtab_lc.stroff +
				self.name_offset)
			# print "get string for symbol[%u]" % self.index
			self.name = data.get_c_string()
			data.pop_offset_and_seek()

		def __str__(self):
			name_display = ''
			if len(self.name):
				name_display = ' "%s"' % self.name
			return '%#8.8x %#2.2x (%-20s) %#2.2x %#4.4x %16.16x%s' % (self.name_offset,
																	  self.type.value, self.type, self.sect_idx, self.desc, self.value, name_display)

	class Interactive(cmd.Cmd):
		'''Interactive command interpreter to mach-o files.'''

		def __init__(self, mach, options):
			cmd.Cmd.__init__(self)
			self.intro = 'Interactive mach-o command interpreter'
			self.prompt = 'mach-o: %s %% ' % mach.path
			self.mach = mach
			self.options = options

		def default(self, line):
			'''Catch all for unknown command, which will exit the interpreter.'''
			print("uknown command: %s" % line)
			return True

		def do_q(self, line):
			'''Quit command'''
			return True

		def do_quit(self, line):
			'''Quit command'''
			return True

		def do_header(self, line):
			'''Dump mach-o file headers'''
			self.mach.dump_header(True, self.options)
			return False

		def do_load(self, line):
			'''Dump all mach-o load commands'''
			self.mach.dump_load_commands(True, self.options)
			return False

		def do_sections(self, line):
			'''Dump all mach-o sections'''
			self.mach.dump_sections(True, self.options)
			return False

		def do_symtab(self, line):
			'''Dump all mach-o symbols in the symbol table'''
			self.mach.dump_symtab(True, self.options)
			return False

#################################################################################
############################ ARCH definition ####################################
#################################################################################
def run_command(command):
	lldb.debugger.HandleCommand(command)

# execute command and return output
def run_command_return_output(debugger,lldb_command, result, dict):
	"""Execute given command and returns the outout"""
	res = lldb.SBCommandReturnObject()
	command_iterpreter.HandleCommand(lldb_command,res)
	output = res.GetOutput()
	error = res.GetError()
	return (output,error)

def get_pc_addresses(thread):
	"""
	Returns a sequence of pc addresses for this thread.
	"""
	def GetPCAddress(i):
		return thread.GetFrameAtIndex(i).GetPCAddress()

	return list(map(GetPCAddress, list(range(thread.GetNumFrames()))))

def get_register(reg, frame=None):
	if not frame:
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.process
		thread	= process.GetSelectedThread()
		frame	= thread.GetSelectedFrame()

	result = 0
	registers = frame.GetRegisters()
	for value in registers:
		for child in value:
			if child.GetName().lower() == reg.lower() and child.value:
				return child.GetValueAsUnsigned()

			if not child.value and child.GetName().lower() == reg.lower():
				errlog(f"Failed to get register : {child.GetName()}")
				return 0xffff_ffff_ffff_ffff

def dereference(pointer):
	"""
	Recursively dereference a pointer for display
	"""
	MAX_DEREF = 8
	t = lldb.debugger.GetSelectedTarget()
	error = lldb.SBError()

	addr = pointer
	chain = []

	# recursively dereference
	for i in range(0, MAX_DEREF):
		ptr = t.process.ReadPointerFromMemory(addr, error)
		if error.Success():
			if ptr in chain:
				chain.append(('circular', 'circular'))
				break
			chain.append(('pointer', addr))
			addr = ptr
		else:
			break

	if len(chain) == 0:
		# errlog(f"0x{pointer:x} is not a valid pointer")
		return

	# get some info for the last pointer
	# first try to resolve a symbol context for the address
	p, addr = chain[-1]
	sbaddr = lldb.SBAddress(addr, t)
	ctx = t.ResolveSymbolContextForAddress(sbaddr, lldb.eSymbolContextEverything)
	if ctx.IsValid() and ctx.GetSymbol().IsValid():
		# found a symbol, store some info and we're done for this pointer
		fstart = ctx.GetSymbol().GetStartAddress().GetLoadAddress(t)
		offset = addr - fstart
		chain.append(('symbol', '{} + 0x{:X}'.format(ctx.GetSymbol().name, offset)))
		# log.debug("symbol context: {}".format(str(chain[-1])))
	else:
		# no symbol context found, see if it looks like a string
		# errlog("no symbol context")
		try:
			s = t.process.ReadCStringFromMemory(addr, 256, error)
			for i in range(0, len(s)):
				if ord(s[i]) >= 128:
					s = s[:i]
					break
			if len(s):
				chain.append(('string', s))
		
		except:
			pass

	return chain

def format_address(address, size=8, pad=True, prefix='0x'):
	fmt = '{:' + ('0=' + str(size * 2) if pad else '') + 'X}'
	addr_str = fmt.format(address)
	if prefix:
		addr_str = prefix + addr_str
	return addr_str

def get_deref_chain_as_string(chain):
	for i, (t, item) in enumerate(chain):
		if t == "pointer":
			yield (MAG, format_address(item, size=16, pad=False))
		elif t == "string":
			for r in ['\n', '\r', '\v']:
				item = item.replace(r, '\\{:x}'.format(ord(r)))
			yield (RED, '"' + item + '"')
		elif t == "unicode":
			for r in ['\n', '\r', '\v']:
				item = item.replace(r, '\\{:x}'.format(ord(r)))
			yield (RED, 'u"' + item + '"')
		elif t == "symbol":
			yield (BLU, '`' + item + '`')
		elif t == "circular":
			yield (GRN, '(circular)')
		if i < len(chain) - 1:
			yield (CYN, ' => ')

def parse_stopDescription(description):
	'''
	Returns up to three values. Exception Type as a string
	'EXC_BAD_ACCESS', Exception Code as a string (can be like '1'
	or like 'EXC_I386_GPFLT') and Extra as a string (can be an address
	'0x00000000' or a subcode '0x0')
	'''

	# EXC_BAD_ACCESS (code=2, address=0x100804000)
	# EXC_BAD_ACCESS (code=EXC_I386_GPFLT)
	# EXC_BAD_INSTRUCTION (code=EXC_I386_INVOP, subcode=0x0)

	table = str.maketrans(dict.fromkeys('(),'))
	desc = description.translate(table)

	if not (desc.startswith("EXC_") or desc.startswith("code=")):
		print("WARNING: Malformed exception description output %s" % desc)
		return None, None, None

	fields = desc.split()
	exc = fields[0]
	code = fields[1].split("=", 2)[1]
	extra = None
	for f in fields:
		if f.startswith("address=") or f.startswith("subcode="):
			extra = f.split("=", 2)[1]
			break

	return [exc, code, extra]

def check_if_recursion(thread):
	idx = 0
	while idx < MINIMUM_RECURSION_LENGTH:
		if not thread.GetFrameAtIndex(idx).IsValid():
			return False
		idx += 1
	return True

#determine if a log is exploitable by processing the stack trace, (not by disassembly)
def is_stack_suspicious(thread, exception, code, extra):
	# returns NO_CHANGE, CHANGE_TO_EXPLOITABLE, or CHANGE_TO_NOT_EXPLOITABLE

	# //If any of these functions are in the stack trace, it's likely that the crash is exploitable.
	# //It uses a substring match, so we put spaces around the names to prevent false positives.
	# //the CSMem ones are used a lot by QuickTime.
	# //objc_msgSend has no space at the end because there are other similar named functions 
	# //like objc_msgSend_vtable14
	suspicious_functions = ["__stack_chk_fail","szone_error","CFRelease","CFRetain","_CFRelease","_CFRetain", 
		"malloc","calloc","realloc", "objc_msgSend",
		"szone_free","free_small","tiny_free_list_add_ptr","tiny_free_list_remove_ptr",
		"small_free_list_add_ptr","small_free_list_remove_ptr","large_entries_free_no_lock", 
		"large_free_no_lock","szone_batch_free","szone_destroy","free", 
		"CSMemDisposeHandle", "CSMemDisposePtr",
		"_CFStringAppendFormatAndArgumentsAux","WTF::fastFree","WTF::fastMalloc",
		"WTF::FastCalloc","WTF::FastRealloc"," WTF::tryFastCalloc","WTF::tryFastMalloc",  
		"WTF::tryFastRealloc","WTF::TCMalloc_Central_FreeList","GMfree","GMmalloc_zone_free",
		"GMrealloc","GMmalloc_zone_realloc","WTFCrashWithSecurityImplication","__chk_fail_overflow"]

	non_exploitable_functions = ["ABORTING_DUE_TO_OUT_OF_MEMORY"]

	funcs = [ ]
	for i in range(0, thread.GetNumFrames()):
		frame = thread.GetFrameAtIndex(i)
		funcname = frame.GetFunctionName()
		for susp in suspicious_functions:
			if exception == "EXC_BREAKPOINT" and funcname in ("CFRelease", "CFRetain"):
				return CHANGE_TO_NOT_EXPLOITABLE

			if susp == funcname:
				funcs.append(susp)

	if funcs:
		return " ".join(funcs)
	
	if exception == "EXC_BREAKPOINT":
		return NO_CHANGE

	return False
		
def is_near_null(address):
	if address < 16 * get_host_pagesize():
		return True
	
	return False

def flags_to_human(reg_value, value_table):
	"""Return a human readable string showing the flag states."""
	flags = []
	for i in value_table:
		# flag_str = Color.boldify(value_table[i].upper()) if reg_value & (1<<i) else value_table[i].lower()
		flag_str = f"{RED}{value_table[i].upper()}{RST}" if reg_value & (1<<i) else value_table[i].lower()
		flags.append(flag_str)
	return "[{}]".format(" ".join(flags))

class Architecture(object):
	"""Generic metaclass for the architecture supported by GEF."""
	__metaclass__ = abc.ABCMeta

	@abc.abstractproperty
	def all_registers(self):                       pass
	@abc.abstractproperty
	def instruction_length(self):                  pass
	@abc.abstractproperty
	def nop_insn(self):                            pass
	@abc.abstractproperty
	def return_register(self):                     pass
	@abc.abstractproperty
	def flag_register(self):                       pass
	@abc.abstractproperty
	def flags_table(self):                         pass
	@abc.abstractproperty
	def function_parameters(self):                 pass
	@abc.abstractmethod
	def flag_register_to_human(self, val=None):    pass
	@abc.abstractmethod
	def is_call(self, insn):                       pass
	@abc.abstractmethod
	def is_ret(self, insn):                        pass
	@abc.abstractmethod
	def is_conditional_branch(self, insn):         pass
	@abc.abstractmethod
	def is_branch_taken(self, insn):               pass
	@abc.abstractmethod
	def get_ra(self, insn, frame):                 pass

	special_registers = []

	@property
	def pc(self):
		return get_register("pc")

	@property
	def sp(self):
		return get_register("sp")

	@property
	def fp(self):
		return get_register("fp")

	@property
	def ptrsize(self):
		return get_memory_alignment()

	def get_ith_parameter(self, i, in_func=True):
		"""Retrieves the correct parameter used for the current function call."""
		reg = self.function_parameters[i]
		val = get_register(reg)
		key = reg
		return key, val

def capstone_analyze_pc(current_arch, insn, nb_insn):
	if current_arch.is_conditional_branch(insn):
		is_taken, reason = current_arch.is_branch_taken(insn)
		if is_taken:
			reason = "[Reason: {:s}]".format(reason) if reason else ""
			msg = f"{GRN}TAKEN {reason}{RST}"
		else:
			reason = "[Reason: !({:s})]".format(reason) if reason else ""
			msg = f"{RED}NOT taken {reason}{RST}"
		return (is_taken, msg)

	if current_arch.is_call(insn):
		target_address = int(insn.operands[-1].split()[0], 16)
		msg = []
		for i, new_insn in enumerate(capstone_disassemble(target_address, nb_insn)):
			msg.append("   {}  {}".format (DOWN_ARROW if i==0 else " ", str(new_insn)))
		return (True, "\n".join(msg))

	return (False, "")

class AARCH64(Architecture):
	arch = "ARM64"
	mode = "ARM"
	
	flag_register = "cpsr"

	flags_table = {
		31: "negative",
		30: "zero",
		29: "carry",
		28: "overflow",
		7: "interrupt",
		6: "fast"
	}
	
	all_registers = [
		"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
		"x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
		"pc", "cpsr"]

	branches = {
		"b."	: "Branch conditionally to a label at a PC-relative offset, with a hint that this is not a subroutine call or return.",
		"cbnz"	: "Compare and Branch on Nonzero compares the value in a register with zero, and conditionally branches to a label at a PC-relative offset if the comparison is not equal.",
		"cbz"	: "Compare and Branch on Zero compares the value in a register with zero, and conditionally branches to a label at a PC- relative offset if the comparison is equal.",
		"tbnz"	: "Test bit and Branch if Nonzero compares the value of a bit in a general-purpose register with zero, and conditionally branches to a label at a PC-relative offset if the comparison is not equal.",
		"tbz"	: "Test bit and Branch if Zero compares the value of a test bit with zero, and conditionally branches to a label at a PC- relative offset if the comparison is equal.",
		}
	
	return_register 	 = "x0"
	syscall_register 	 = "x8"
	syscall_instructions = "svc"
	function_parameters  = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
	exceptions	= {
					"EXC_BAD_ACCESS" :
					{
							0x101	:	{"title": "EXC_ARM_DA_ALIGN", "desc" : "Alignment Fault"},
							0x102	:	{"title":"EXC_ARM_DA_DEBUG", "desc"  : "Debug (watch/break) Fault"},
							0x103	:	{"title":"EXC_ARM_SP_ALIGN", "desc" : "SP Alignment Fault"},
							0x104	:	{"title":"EXC_ARM_SWP", "desc" : "SWP instruction"},
							0x105	:	{"title":"EXC_ARM_PAC_FAIL", "desc":"PAC authentication failure"},
							0x1 	:	{"title" : "KERN_INVALID_ADDRESS", "desc": "Specified address is not currently valid."},
							0x2		:	{"title":"KERN_PROTECTION_FAILURE", "desc":"Specified memory is valid, but does not permit the required forms of access"}
					},
					"EXC_ARITHMETIC" :
					{
						0x0: {'title': 'EXC_ARM_FP_UNDEFINED', 'desc': 'Undefined Floating Point Exception'}, 
						0x1: {'title': 'EXC_ARM_FP_IO', 'desc': 'Invalid Floating Point Operation'}, 
						0x2: {'title': 'EXC_ARM_FP_DZ', 'desc': 'Floating Point Divide by Zero'}, 
						0x3: {'title': 'EXC_ARM_FP_OF', 'desc': 'Floating Point Overflow'}, 
						0x4: {'title': 'EXC_ARM_FP_UF', 'desc': 'Floating Point Underflow'}, 
						0x5: {'title': 'EXC_ARM_FP_IX', 'desc': 'Inexact Floating Point Result'}, 
						0x6: {'title': 'EXC_ARM_FP_ID', 'desc': 'Floating Point Denormal Input'}
					},
					"EXC_BAD_INSTRUCTION" :
					{
						'EXC_ARM_UNDEFINED' : { 'code': 0x1, 'desc':"Undefined"}
					},
					"EXC_BREAKPOINT" :
					{
						0x1 : { 'title': 'EXC_ARM_BREAKPOINT', 'desc' : "breakpoint trap"}
					}
				}

	def get_code_desc(self, exc, code):
		crash_code, crash_desc = None, None

		if exc in ['EXC_BAD_INSTRUCTION']:
			exception	= self.exceptions[exc]
			crash_code 	= exc
			crash_desc	= exception[code]['desc']

		elif exc in self.exceptions:
			exception 	= self.exceptions[exc]
			crash_code 	= exception[code]['title']
			crash_desc	= exception[code]['desc']
		
		return crash_code, crash_desc

	def is_call(self, insn):
		mnemo = insn.mnemonic
		call_mnemos = {"bl", "blr"}
		return mnemo in call_mnemos

	def flag_register_to_human(self, val=None):
		# http://events.linuxfoundation.org/sites/events/files/slides/KoreaLinuxForum-2014.pdf
		reg = self.flag_register
		if not val:
			val = get_register(reg)
		return flags_to_human(val, self.flags_table)

	def is_conditional_branch(self, insn):
		# https://www.element14.com/community/servlet/JiveServlet/previewBody/41836-102-1-229511/ARM.Reference_Manual.pdf
		# sect. 5.1.1
		mnemo = insn.mnemonic
		branch_mnemos = {"cbnz", "cbz", "tbnz", "tbz"}
		return mnemo.startswith("b.") or mnemo in branch_mnemos
		
	def is_branch_taken(self, insn):
		mnemo, operands = insn.mnemonic, insn.operands
		flags = dict((self.flags_table[k], k) for k in self.flags_table)
		val = get_register(self.flag_register)
		taken, reason = False, ""

		if mnemo in {"cbnz", "cbz", "tbnz", "tbz"}:
			reg = operands[0]
			reg = insn.reg_name(reg.reg)
			op = get_register(reg)
			if mnemo=="cbnz":
				if op!=0: taken, reason = True, "{}!=0".format(reg)
				else: taken, reason = False, "{}==0".format(reg)
			elif mnemo=="cbz":
				if op==0: taken, reason = True, "{}==0".format(reg)
				else: taken, reason = False, "{}!=0".format(reg)
			elif mnemo=="tbnz":
				# operands[1] has one or more white spaces in front, then a #, then the number
				# so we need to eliminate them
				i = int(operands[1].imm)
				if (op & 1<<i) != 0: taken, reason = True, "{}&1<<{}!=0".format(reg,i)
				else: taken, reason = False, "{}&1<<{}==0".format(reg,i)
			elif mnemo=="tbz":
				# operands[1] has one or more white spaces in front, then a #, then the number
				# so we need to eliminate them
				i = int(operands[1].imm)
				if (op & 1<<i) == 0: taken, reason = True, "{}&1<<{}==0".format(reg,i)
				else: taken, reason = False, "{}&1<<{}!=0".format(reg,i)
		
		if not reason:
			taken, reason = self.is_branch_taken_arm(insn)
		return taken, reason

	def is_branch_taken_arm(self, insn):
		mnemo = insn.mnemonic
		# ref: http://www.davespace.co.uk/arm/introduction-to-arm/conditional.html
		flags = dict((self.flags_table[k], k) for k in self.flags_table)
		val = get_register(self.flag_register)
		taken, reason = False, ""
		
		if mnemo.endswith("eq"):
			taken, reason = bool(val&(1<<flags["zero"])), "Z"
		elif mnemo.endswith("hs"):
			taken, reason = val & (1<<flags["carry"]), "C==1"
		elif mnemo.endswith("lo"):
			taken, reason = not val & (1<<flags["carry"]), "C==0"
		elif mnemo.endswith("ne"):
			taken, reason = not val&(1<<flags["zero"]), "!Z"
		elif mnemo.endswith("lt"):
			taken, reason = bool(val&(1<<flags["negative"])) != bool(val&(1<<flags["overflow"])), "N!=V"
		elif mnemo.endswith("le"):
			taken, reason = val&(1<<flags["zero"]) or \
				bool(val&(1<<flags["negative"])) != bool(val&(1<<flags["overflow"])), "Z || N!=V"
		elif mnemo.endswith("gt"):
			taken, reason = val&(1<<flags["zero"]) == 0 and \
				bool(val&(1<<flags["negative"])) == bool(val&(1<<flags["overflow"])), "!Z && N==V"
		elif mnemo.endswith("ge"):
			taken, reason = bool(val&(1<<flags["negative"])) == bool(val&(1<<flags["overflow"])), "N==V"
		elif mnemo.endswith("vs"):
			taken, reason = bool(val&(1<<flags["overflow"])), "V"
		elif mnemo.endswith("vc"):
			taken, reason = not val&(1<<flags["overflow"]), "!V"
		elif mnemo.endswith("mi"):
			taken, reason = bool(val&(1<<flags["negative"])), "N"
		elif mnemo.endswith("pl"):
			taken, reason = not val&(1<<flags["negative"]), "N==0"
		elif mnemo.endswith("hi"):
			taken, reason = val&(1<<flags["carry"]) and not val&(1<<flags["zero"]), "C && !Z"
		elif mnemo.endswith("ls"):
			taken, reason = not val&(1<<flags["carry"]) or val&(1<<flags["zero"]), "!C || Z"
		return taken, reason

	def get_access_type(self, insn):
		if insn.mnemonic[:2].lower()=="st":
			return "write"

		if insn.mnemonic[:2].lower()=="ld":
			return "read"
		
		return "unknown"

	def get_previous_pc(self, pc, frame, process):
		return pc-4

	def get_register(self, reg, frame=None):
		if not frame:
			target 	= lldb.debugger.GetSelectedTarget()
			process = target.process
			thread	= process.GetSelectedThread()
			frame	= thread.GetSelectedFrame()

		if reg=="pc":
			return frame.pc
		
		if reg=="sp":
			return frame.sp
		
		if reg=="fp" or reg=="x29":
			return frame.fp
		
		if reg == "lr"  or reg=="x30":
			return get_register("lr")
			
		return get_register(reg)
			
	def get_registers(self, required=[]):
		gpr = {}
		
		for reg in self.all_registers:
			if required == [] or reg in required:
				gpr[reg.name] = get_register(reg)

		return gpr

	def get_disas(self, frame, process, pc=None):
		if not pc:
			pc 		= get_register("pc", frame)

		error 	= lldb.SBError()
		buffer 	= process.ReadMemory(pc, 20, error)

		cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
		cs.detail   = True
		
		return cs.disasm(buffer, pc)

	def get_disas_to_print(self, frame, process, pc=None):
		if not pc:
			pc 		= get_register("pc", frame)

		instructions = list(self.get_disas(frame, process, pc))

		if instructions == []:
			return "", False, None

		insn = instructions[0]
		av_access_type = self.get_access_type(insn)
		av_on_branch = False
		
		for g in insn.groups:
			if g == arm64_const.ARM64_GRP_BRANCH_RELATIVE or g == arm64_const.ARM64_GRP_CALL or g == arm64_const.ARM64_GRP_JUMP:
				av_on_branch = True

		disassembly_operands	=	""
		for i in insn.operands:
			if i.type== arm64_const.ARM64_OP_REG:
				reg 	= insn.reg_name(i.reg)
				val 	= self.get_register(reg)
				disassembly_operands += f"{reg}={val:x}; "
			elif i.type == arm64_const.ARM64_OP_MEM:
				if i.reg:
					reg 	= insn.reg_name(i.reg)
					val 	= self.get_register(reg)
					disassembly_operands += f"{reg}={val:x}; "

		if disassembly_operands:
			disassembly	=	f"{insn.mnemonic}\t{insn.op_str} => {disassembly_operands}"
		else:
			disassembly	=	f"{insn.mnemonic}\t{insn.op_str}"

		return disassembly, av_on_branch, av_access_type

	def disasm(self, address, buffer, pc):
		cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
		cs.detail   = True
		
		instuctions = cs.disasm(buffer, address)
		try:
			instuctions = list(instuctions)
		except:
			errlog(f"Failed to disassemble at {address:x}")
			return

		for i in instuctions:
			if i.address == pc:
				msg = ""
				if self.is_conditional_branch(i):
					is_taken, msg = capstone_analyze_pc(self, i, len(buffer))
					msg = f"{RED}->{RST} {i.address:x}{RED} :\t{GRN}{i.mnemonic}{RST}\t{i.op_str}\t [{RED}{msg}{RST}]"
				else:
					msg = f"{RED}->{RST} {i.address:x}{RED} :\t{GRN}{i.mnemonic}{RST}\t{i.op_str}\t"

				print(msg)
			else:
				print(f"   {i.address:x}{RED} :\t{GRN}{i.mnemonic}{RST}\t{i.op_str}")

	def print_registers(self, frame):
		print("$x0  : 0x%016x   $x1  : 0x%016x    $x2 : 0x%016x    $x3 : 0x%016x"%(get_register("X0", frame),  get_register("X1", frame),  get_register("X2", frame),  get_register("X3", frame)))
		print("$x4  : 0x%016x   $x5  : 0x%016x    $x6 : 0x%016x    $x7 : 0x%016x"%(get_register("X4", frame),  get_register("X5", frame),  get_register("X6", frame),  get_register("X7", frame)))
		print("$x8  : 0x%016x   $x9  : 0x%016x   $x10 : 0x%016x   $x11 : 0x%016x"%(get_register("X8", frame),  get_register("X9", frame),  get_register("X10", frame),  get_register("X11", frame)))
		print("$x12 : 0x%016x   $x13 : 0x%016x   $x14 : 0x%016x   $x15 : 0x%016x"%(get_register("X12", frame),  get_register("X13", frame),  get_register("X14", frame),  get_register("X15", frame)))
		print("$x18 : 0x%016x   $x19 : 0x%016x   $x20 : 0x%016x   $x21 : 0x%016x"%(get_register("X18", frame),  get_register("X23", frame),  get_register("X24", frame),  get_register("X25", frame)))
		print("$x26 : 0x%016x   $x27 : 0x%016x   $x28 : 0x%016x   "%(get_register("X26", frame),  get_register("X27", frame),  get_register("X28", frame)))
		print("$fp  : 0x%016x    $lr : 0x%016x    $pc : 0x%016x"%(get_register("FP", frame),  get_register("LR", frame),  get_register("PC", frame)))
		print("CPSR : 0x%016x    "%(get_register("CPSR", frame)))
		
class X8664(Architecture):
	arch = "X86"
	mode = "64"

	syscall_register = "rax"
	syscall_instructions = ["syscall"]
	
	flags_table = {
		6: "zero",
		0: "carry",
		2: "parity",
		4: "adjust",
		7: "sign",
		8: "trap",
		9: "interrupt",
		10: "direction",
		11: "overflow",
		16: "resume",
		17: "virtualx86",
		21: "identification",
	}
	
	flag_register = "rflags"

	special_registers = ["cs", "ss", "ds", "es", "fs", "gs"]

	gpr_registers = [
		"rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", ]
	all_registers = gpr_registers + [ flag_register] + special_registers

	function_parameters = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]

	exceptions = {
			"EXC_ARITHMETIC" :
			{
					"EXC_I386_DIVERR"  		: { "desc": "divide by 0 eprror", "code": 0x0},
					"EXC_I386_DIV"			: { "desc": "integer divide by zero", "code": 0x1 },
					"EXC_I386_INTO"			: { "desc": "integer overflow", "code": 0x2},
					"EXC_I386_EXTERR"		: { "desc": "FPU error", "code" : 0x5},
					"EXC_I386_SSEEXTERR"	: { "desc": "SSE arithmetic exception", "code" :0x8}
			},

			"EXC_BAD_ACCESS":
				{
					0x1 	:	{"title" : "KERN_INVALID_ADDRESS", "desc": "Specified address is not currently valid."},
					0x2   	:	{"title":"KERN_PROTECTION_FAILURE", "desc":"Specified memory is valid, but does not permit the required forms of access"},				
					0xd		: 	{ "desc": "general protection fault", "title": "EXC_I386_GPFLT" },
				},
			"EXC_BREAKPOINT":
				{
					0x3		: { "desc": "breakpoint fault", "title": "EXC_I386_BPTFLT" },
					0x4		: { "desc": "INTO overflow fault", "title": "EXC_I386_INTOFLT" },
					0x5		: { "desc": "BOUND instruction fault", "title": "EXC_I386_BOUNDFLT" },

					0x6		: { "desc": "invalid opcode fault", "title": "EXC_I386_INVOPFLT" },
					0x7		: { "desc": "extension not available fault", "title": "EXC_I386_NOEXTFLT" },
					0x8		: { "desc": "double fault", "title": "EXC_I386_DBLFLT" },
					0x9		: { "desc": "extension overrun fault", "title": "EXC_I386_EXTOVRFLT" },
					0xa		: { "desc": "invalid TSS fault", "title": "EXC_I386_INVTSSFLT" },
					0xb		: { "desc": "segment not present fault", "title": "EXC_I386_SEGNPFLT" },
					0xc		: { "desc": "stack fault", "title": "EXC_I386_STKFLT" },
					
					0xe		: { "desc": "page fault", "title": "EXC_I386_PGFLT" },
					0x10 	: { "desc": "extension error fault", "title": "EXC_I386_EXTERRFLT"},
					0x11 	: { "desc": "Alignment fault", "title": "EXC_I386_ALIGNFLT" },
					0x20	: { "desc": "emulated ext not present", "title": "EXC_I386_ENOEXTFLT"},
					0x21	: { "desc": "emulated extension error flt", "title": "EXC_I386_ENDPERR"},
				},
			"EXC_BAD_INSTRUCTION" :
			{
				"EXC_I386_INVOP" : {"desc": "Undefined", "code": 0x1}
			}
	}

	def get_code_desc(self, exc, code):
		crash_code, crash_desc = None, None

		if exc in ['EXC_BAD_INSTRUCTION', 'EXC_ARITHMETIC']:
			exception	= self.exceptions[exc]
			crash_code 	= exc
			crash_desc	= exception[code]['desc']

		elif exc in self.exceptions:
			exception 	= self.exceptions[exc]
			crash_code 	= exception[code]['title']
			crash_desc	= exception[code]['desc']
		
		return crash_code, crash_desc
		
	def flag_register_to_human(self, val=None):
		reg = self.flag_register
		if not val:
			val = get_register(reg)
		return flags_to_human(val, self.flags_table)

	def is_call(self, insn):
		mnemo = insn.mnemonic
		call_mnemos = {"call", "callq"}
		return mnemo in call_mnemos

	def is_ret(self, insn):
		return insn.mnemonic == "ret"

	def is_conditional_branch(self, insn):
		mnemo = insn.mnemonic
		branch_mnemos = {
			"ja", "jnbe", "jae", "jnb", "jnc", "jb", "jc", "jnae", "jbe", "jna",
			"jcxz", "jecxz", "jrcxz", "je", "jz", "jg", "jnle", "jge", "jnl",
			"jl", "jnge", "jle", "jng", "jne", "jnz", "jno", "jnp", "jpo", "jns",
			"jo", "jp", "jpe", "js"
		}
		return mnemo in branch_mnemos

	def is_branch_taken(self, insn):
		mnemo = insn.mnemonic
		# all kudos to fG! (https://github.com/gdbinit/Gdbinit/blob/master/gdbinit#L1654)
		flags = dict((self.flags_table[k], k) for k in self.flags_table)
		val = get_register(self.flag_register)

		taken, reason = False, ""

		if mnemo in ("ja", "jnbe"):
			taken, reason = not val&(1<<flags["carry"]) and not val&(1<<flags["zero"]), "!C && !Z"
		elif mnemo in ("jae", "jnb", "jnc"):
			taken, reason = not val&(1<<flags["carry"]), "!C"
		elif mnemo in ("jb", "jc", "jnae"):
			taken, reason = val&(1<<flags["carry"]), "C"
		elif mnemo in ("jbe", "jna"):
			taken, reason = val&(1<<flags["carry"]) or val&(1<<flags["zero"]), "C || Z"
		elif mnemo in ("jcxz", "jecxz", "jrcxz"):
			cx = get_register("$rcx") if self.mode == 64 else get_register("$ecx")
			taken, reason = cx == 0, "!$CX"
		elif mnemo in ("je", "jz"):
			taken, reason = val&(1<<flags["zero"]), "Z"
		elif mnemo in ("jne", "jnz"):
			taken, reason = not val&(1<<flags["zero"]), "!Z"
		elif mnemo in ("jg", "jnle"):
			taken, reason = not val&(1<<flags["zero"]) and bool(val&(1<<flags["overflow"])) == bool(val&(1<<flags["sign"])), "!Z && S==O"
		elif mnemo in ("jge", "jnl"):
			taken, reason = bool(val&(1<<flags["sign"])) == bool(val&(1<<flags["overflow"])), "S==O"
		elif mnemo in ("jl", "jnge"):
			taken, reason = val&(1<<flags["overflow"]) != val&(1<<flags["sign"]), "S!=O"
		elif mnemo in ("jle", "jng"):
			taken, reason = val&(1<<flags["zero"]) or bool(val&(1<<flags["overflow"])) != bool(val&(1<<flags["sign"])), "Z || S!=O"
		elif mnemo in ("jo",):
			taken, reason = val&(1<<flags["overflow"]), "O"
		elif mnemo in ("jno",):
			taken, reason = not val&(1<<flags["overflow"]), "!O"
		elif mnemo in ("jpe", "jp"):
			taken, reason = val&(1<<flags["parity"]), "P"
		elif mnemo in ("jnp", "jpo"):
			taken, reason = not val&(1<<flags["parity"]), "!P"
		elif mnemo in ("js",):
			taken, reason = val&(1<<flags["sign"]), "S"
		elif mnemo in ("jns",):
			taken, reason = not val&(1<<flags["sign"]), "!S"
		return taken, reason

	def get_register(self, reg):
		return get_register(reg)

	def get_registers(self, want=[]):
		'''
		Returns the general purpose registers and returns them as a
		map[string]uint64 or whatever you call that in python
		'''

		got = {}
		for reg in self.all_registers:
			if want == [] or reg in want:
				got[reg.name] = get_register(reg)

		return got

	def get_previous_pc(self, pc, frame, process):
		disassembly = frame.Disassemble().splitlines()
		
		for i in range(len(disassembly)):
			instruction = disassembly[i]
			if instruction.find(f"{pc:08x}")!=-1 and i!=0:
				instruction = disassembly[i-1]
				address = re.search("0x(.*)?<", instruction).group(1)
				address = int(address, 16)
				return address
			
		return 0

	def get_access_type(self, insn):
		operands = insn.operands
		mnemonic = insn.mnemonic

		operand_values = {}
		if operands.count:
			for i in insn.operands:
				if i.reg:
					reg 	= insn.reg_name(i.reg)
					val 	= self.get_register(reg)
					operand_values[reg] = val

		print(insn.groups)

	def get_disas(self, frame, process, pc=None):
		if not pc:
			pc 		= frame.pc

		error = lldb.SBError()
		buffer = process.ReadMemory(pc, 20, error)
		
		cs = Cs(CS_ARCH_X86, CS_MODE_64)
		cs.detail   = True
		
		return cs.disasm(buffer, pc)

	def get_disas_to_print(self, frame, process, pc=None):
		if pc==None:
			pc = frame.pc
		
		instructions = list(self.get_disas(frame, process, pc))

		if instructions == []:
			return "", False, None

		insn = instructions[0]

		av_access_type 	= self.get_access_type(insn)
		av_on_branch 	= False

		for g in insn.groups:
			if g == x86_const.X86_GRP_JUMP or g == x86_const.X86_GRP_BRANCH_RELATIVE:
				av_on_branch = True

		disassembly_operands	=	""
		for i in insn.operands:
			if i.reg:
				reg 	= insn.reg_name(i.reg)
				val 	= self.get_register(reg)
				disassembly_operands += f"{reg}={val:x}; "

		if disassembly_operands:
			disassembly	=	f"{insn.mnemonic}\t{insn.op_str} => {disassembly_operands}"		
		else:
			disassembly	=	f"{insn.mnemonic}\t{insn.op_str}"

		return disassembly, av_on_branch, av_access_type
		
	def disasm(self, address, buffer, pc):
		cs = Cs(CS_ARCH_X86, CS_MODE_64)
		cs.detail   = True

		instuctions = cs.disasm(buffer, address)
		try:
			instuctions = list(instuctions)
		except:
			errlog(f"Failed to disassemble at {address:x}")
			return

		for i in instuctions:
			if i.address == pc:
				msg = ""
				if self.is_conditional_branch(i):
					is_taken, msg = capstone_analyze_pc(self, i, len(buffer))
					msg = f"{RED}->{RST} {i.address:x}{RED} :\t{GRN}{i.mnemonic}{RST}\t{i.op_str}\t {RED} [{msg}]{RST}"
				else:
					msg = f"{RED}->{RST} {i.address:x}{RED} :\t{GRN}{i.mnemonic}{RST}\t{i.op_str}\t"

				print(msg)
			else:
				print(f"   {i.address:x}{RED} :\t{GRN}{i.mnemonic}{RST}\t{i.op_str}")

	def print_registers(self, frame):
		print("$rax : 0x%016x   $rbx : 0x%016x   $rcx : 0x%016x   $rdx : 0x%016x"%(get_register("rax", frame),  get_register("rbx", frame),  get_register("rcx", frame),  get_register("rdx", frame)))
		print("$r8  : 0x%016x   $r9  : 0x%016x   $r10 : 0x%016x   $r11 : 0x%016x"%(get_register("r8", frame),  get_register("r9", frame),  get_register("r10", frame),  get_register("r11", frame)))
		print("$r12 : 0x%016x   $r13 : 0x%016x   $r14 : 0x%016x   $r15 : 0x%016x"%(get_register("r12", frame),  get_register("r13", frame),  get_register("r14", frame),  get_register("r15", frame)))
		print("$rbp : 0x%016x   $rsp : 0x%016x   $rsi : 0x%016x   $rdi : 0x%016x"%(get_register("rbp", frame),  get_register("rsp", frame),  get_register("rsi", frame),  get_register("rdi", frame)))
		print("$rip : 0x%016x"%(get_register("rip", frame)))
		print("flags: 0x%016x"%(get_register("rflags", frame)))
		

#################################################################################
############################ COMMANDS ###########################################
#################################################################################

def process_is_alive(f):
	@functools.wraps(f)
	def wrapper(*args, **kwargs):
		target  = lldb.debugger.GetSelectedTarget()
		process = target.process
		if process.is_alive:
			return f(*args, **kwargs)
		else:
			warnlog("Target is not running :( ")
	return wrapper

class ASLRCommand(LLDBCommand):
	def name(self):
		return "aslr"
	
	def args(self):
		return [
			CommandArgument(
				arg="on/off",
				help="Enable/Disable ASLR. Usage: aslr on",
			),
		]

	def description(self):
		return "View/modify ASLR setting of target."
	
	def run(self, arguments, option):
		launchInfo = lldb.debugger.GetSelectedTarget().GetLaunchInfo()
		flags 	= launchInfo.GetLaunchFlags()
		
		if not arguments[0]:
			if flags & lldb.eLaunchFlagDisableASLR:
				print(f"{RED}ASLR{RST} : {GRN}off{RST}")
			else:
				print(f"{RED}ASLR{RST} : {GRN}on{RST}")
		
		else:
			if arguments[0]=="off":
				# set eLaunchFlagDisableASLR flag
				flags |= (lldb.eLaunchFlagDisableASLR)
				launchInfo.SetLaunchFlags(flags)
				lldb.debugger.GetSelectedTarget().SetLaunchInfo(launchInfo)

			elif arguments[0]=="on":
				# clear the eLaunchFlagDisableASLR flag
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
		if not arguments[0]:
			arguments[0] = lldb.debugger.GetSelectedTarget().GetExecutable().fullpath
		
		mach = Mach(lldb.debugger)
		mach.parse(arguments[0])
		if mach.content:
			mach.content.checksec()

class DisplayMachoHeaderCommand(LLDBCommand):
	def name(self):
		return "show_header"
	
	def description(self):
		return "Dump Mach-O headers"
	
	def args(self):
		return [
			CommandArgument(
				arg="macho",
				type="str",
				help="Path to mach-o binary. Usage: show_header /usr/bin/qlmanage or macho",
			)
		]
	
	def run(self, arguments, option):
		if not arguments[0]:
			arguments[0] = lldb.debugger.GetSelectedTarget().GetExecutable().fullpath
		
		mach = Mach(lldb.debugger)
		mach.parse(arguments[0])
		if mach.content:
			mach.content.dump_header()

class DisplayMachoLoadCmdCommand(LLDBCommand):
	def name(self):
		return "show_lc"
	
	def description(self):
		return "Dump Load Commands from Mach-O"

	def args(self):
		return [
			CommandArgument(
				arg="macho",
				type="str",
				help="Path to mach-o binary. Usage: show_lc /usr/bin/qlmanage or macho",
			)
		]
	
	def run(self, arguments, option):
		if not arguments[0]:
			arguments[0] = lldb.debugger.GetSelectedTarget().GetExecutable().fullpath
		
		mach = Mach(lldb.debugger)
		mach.parse(arguments[0])
		if mach.content:
			mach.content.dump_load_commands()

class CapstoneDisassembleCommand(LLDBCommand):
	def name(self):
		return "csdis"
	
	def description(self):
		return "Disassemble buffer at a given pointer using Capstone"

	def args(self):
		return [
			CommandArgument(
				arg="pointer",
				type="int",
				help="Pointer to buffer to disassemble",
			),
			CommandArgument(
				arg="length",
				type="int",
				help="length of buffer to disassemble",
			)
		]
	
	@process_is_alive
	def run(self, arguments, option):
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.process
		thread 	= process.selected_thread
		frame 	= thread.GetSelectedFrame()
		address	= frame.pc

		if arguments[0]:
			address = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()

		length = 32
		if arguments[1]:
			length = evaluateInputExpression(arguments[1]).GetValueAsUnsigned()

		error = lldb.SBError()
		buffer = process.ReadMemory(address, length, error)

		arch = get_target_arch()
		if arch:
			arch.disasm(address, buffer, frame.pc)

class ContextCommand(LLDBCommand):
	def name(self):
		return "context"
	
	def description(self):
		return "Display context of given thread or selected thread by default. Usage: 'context all' or 'context 1'"

	def args(self):
		return [
			CommandArgument(
				arg="thread",
				type="int",
				help="thread id or all.",
			)
		]
	
	@process_is_alive
	def run(self, arguments, option):
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.process

		if arguments[0] == "all":
			for thread in process.threads:
				self.print_thread_context(thread, process)

		elif arguments[0]:
			thread_id = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()
			thread	  = process.GetThreadByIndexID(thread_id)
			if thread:
				self.print_thread_context(thread, process)

		else:
			thread = process.GetSelectedThread()
			self.print_thread_context(thread, process)

	def print_thread_context(self, thread, process):
		print()
		context_title(f"thread #{thread.idx}")

		frame 	= thread.GetSelectedFrame()

		address	= frame.pc
		
		length = 32

		error = lldb.SBError()
		buffer = process.ReadMemory(address, length, error)

		arch = get_target_arch()

		if arch:
			context_title("stack")
			run_command("rstack")

			context_title("registers")
			arch.print_registers(frame)

			context_title("code")
			arch.disasm(address, buffer, frame.pc)

class RegisterReadCommand(LLDBCommand):
	def name(self):
		return "rr"
	
	def description(self):
		return "Display registers for a given thread and frame or selected thread and selected frame by default"

	def args(self):
		return [
			CommandArgument(
				arg="thread",
				type="int",
				help="thread id",
			),
			CommandArgument(
				arg="frame",
				type="int",
				help="frame id",
			)			
		]
	
	@process_is_alive
	def run(self, arguments, option):
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.process
		
		if arguments[0] and arguments[1]:
			thread_id = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()
			frame_id  = evaluateInputExpression(arguments[1]).GetValueAsUnsigned()

			thread	  = process.GetThreadByIndexID(thread_id)
			if thread:
				self.print_registers(thread, frame_id, process)

		else:
			thread = process.GetSelectedThread()
			self.print_registers(thread, 0, process)

	def print_registers(self, thread, frame_id, process):

		frame	  = thread.GetFrameAtIndex(frame_id)

		address	= frame.pc
		
		length = 32

		error = lldb.SBError()
		buffer = process.ReadMemory(address, length, error)

		arch = get_target_arch()
		arch.print_registers(frame)

class DisplayStackCommand(LLDBCommand):
	def name(self):
		return "pstack"

	def description(self):
		return "Visualize stack for a given frame or selected frame by default"

	def args(self):
		return [
			CommandArgument(
				arg="size",
				type="int",
				help="stack size to display"
			),
			CommandArgument(
				arg="frame",
				type="int",
				help="frame id",
			),
			CommandArgument(
				arg="thread",
				type="int",
				help="thread id",
			)
		]
	
	@process_is_alive
	def run(self, arguments, option):
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.process
		stack_size = 128

		if arguments[0]:
			stack_size = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()

		if arguments[1] and arguments[2]:
			stack_size = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()
			frame_id  = evaluateInputExpression(arguments[1]).GetValueAsUnsigned()
			thread_id = evaluateInputExpression(arguments[2]).GetValueAsUnsigned()

			thread	  = process.GetThreadByIndexID(thread_id)
			if thread:
				self.print_stack(stack_size, frame_id, thread, process)

		else:
			thread = process.GetSelectedThread()
			frame = thread.GetSelectedFrame()
			self.print_stack(stack_size, frame.idx, thread, process)

	def print_stack(self, stack_size, frame_id, thread, process):

		frame 	= thread.GetFrameAtIndex(frame_id)
		address	= frame.sp
		
		error = lldb.SBError()
		buffer = process.ReadMemory(address, stack_size, error)

		arch = get_target_arch()
		if buffer:
			visual_hexdump(buffer, start=address, end=address+stack_size, columns=16)

class DumpStackCommand(LLDBCommand):
	def name(self):
		return "rstack"

	def description(self):
		return "Hexdump stack for a given frame or selected frame by default"

	def args(self):
		return [
			CommandArgument(
				arg="size",
				type="int",
				help="stack size to display",
			),
			CommandArgument(
				arg="frame",
				type="int",
				help="frame id",
			),
			CommandArgument(
				arg="thread",
				type="int",
				help="thread id",
			)
		]
	
	@process_is_alive
	def run(self, arguments, option):
		self.target 	= lldb.debugger.GetSelectedTarget()
		process = self.target.process
		stack_size = 128

		if arguments[0]:
			stack_size = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()
		
		if arguments[0] and arguments[1]:
			stack_size = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()
			frame_id  = evaluateInputExpression(arguments[1]).GetValueAsUnsigned()
			thread_id = evaluateInputExpression(arguments[2]).GetValueAsUnsigned()
			thread	  = process.GetThreadByIndexID(thread_id)
			if thread:
				self.print_stack(stack_size, frame_id, thread, process)

		else:
			thread = process.GetSelectedThread()
			self.print_stack(stack_size, 0, thread, process)

	def print_stack(self, stack_size, frame_id, thread, process):
		
		frame 	= thread.GetFrameAtIndex(frame_id)
		address	= frame.sp
		
		error = lldb.SBError()
		buffer = process.ReadMemory(address, stack_size, error)
		
		arch = get_target_arch()
		if buffer:
			HEADER = '┌────────────────┬─────────────────────────┬──────────┐'
			FOOTER = RST+'└────────────────┴─────────────────────────┴──────────┘'
			LINE_FORMATTER = '│' + '' + '{:016x}' + '│ {}' + '{}'  + ' │' + RST+' => {}' + RST

			cache = {hexmod(b): colored(b) for b in range(256)} #0x00 - 0xff
			cache['  '] = ('  ', ' ')

			print(HEADER)
			cur = 0
			row = address
			line = buffer[cur:cur+8]
			

			while line:
				chain_display = ""
				addr = struct.unpack("<Q", line)[0]
				taddr = self.target.ResolveLoadAddress(addr)
				if taddr.IsValid:
					chain = dereference(addr)
					if chain:
						for i,j in get_deref_chain_as_string(chain):
							chain_display += f"{i}{j}"

				line_hex = line.hex().ljust(16)
				
				hexbytes = ''
				printable = ''
				for i in range(0, len(line_hex), 2):
					hbyte, abyte = cache[line_hex[i:i+2]]
					hexbytes += hbyte + ' ' if i != 14 else hbyte + ' ┊ '
					printable += abyte if i != 14 else abyte 

				print(LINE_FORMATTER.format(row, hexbytes, printable, chain_display))
				
				row += 0x10
				cur += 0x10
				line = buffer[cur:cur+8]
			
			print(FOOTER)

	
class DisplayMemoryCommand(LLDBCommand):
	def name(self):
		return "pmem"

	def description(self):
		return "Visualize memory at a given address and size"

	def args(self):
		return [
			CommandArgument(
				arg="address",
				type="int",
				help="start of memory to display",
				default=1
			),
			CommandArgument(
				arg="size",
				type="int",
				help="size of memory to display",
			)
		]
	
	@process_is_alive
	def run(self, arguments, option):
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.process
		address = 0
		length = 64

		if arguments[0]:
			address = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()
		
		if arguments[1]:
			length = evaluateInputExpression(arguments[1]).GetValueAsUnsigned()

		if address and length:
			self.print_memory(address, length, process)

	def print_memory(self, address, size, process):

		error = lldb.SBError()
		buffer = process.ReadMemory(address, size, error)

		arch = get_target_arch()
		if buffer:
			visual_hexdump(buffer, start=address, end=address+size, columns=16)

class ReadMemoryCommand(LLDBCommand):
	def name(self):
		return "rmem"

	def description(self):
		return "Hexdump memory at a given address and size"

	def args(self):
		return [
			CommandArgument(
				arg="address",
				type="int",
				help="start of memory to display",
				default=1
			),
			CommandArgument(
				arg="size",
				type="int",
				help="size of memory to display",
			)
		]
	
	@process_is_alive
	def run(self, arguments, option):
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.process
		address = 0
		length = 64

		if arguments[0]:
			address = evaluateInputExpression(arguments[0]).GetValueAsUnsigned()

		if arguments[1]:
			length 	 = evaluateInputExpression(arguments[1]).GetValueAsUnsigned()
		
		if address and length:
			self.print_memory(address, length, process)

	def print_memory(self, address, size, process):

		error = lldb.SBError()
		buffer = process.ReadMemory(address, size, error)

		arch = get_target_arch()
		if buffer:
			hexdump(buffer, address)

class PrettyBacktraceCommand(LLDBCommand):
	def name(self):
		return "pbt"

	def description(self):
		return "Pretty print backtrace"
	
	def args(self):
		return []

	def run(self, arguments, option):
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.GetProcess()
		thread	= process.GetSelectedThread()
		sframe	= thread.GetSelectedFrame()
		addrs   = get_pc_addresses(thread)

		frames	=	thread.GetNumFrames()
		thread_info = f"thread {RED}#{thread.idx}{RST}"
		
		if thread.queue:
			thread_info = f"{thread_info} queue = {GRN}'{thread.queue}'{RST}"
		
		if thread.GetStopReason() == lldb.eStopReasonException:
			print(f"{thread_info}, stop reason = {RED}{thread.GetStopDescription(1024)}{RST}")
		elif thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid:
			print(f"{thread_info}, stop reason = {CYN}{thread.GetStopDescription(1024)}{RST}")
		else:
			print(f"{thread_info}{YEL}{thread.GetStopDescription(1024)}{RST}")

		for i in range(0, frames):
			frame 	= thread.GetFrameAtIndex(i)

			file_addr = addrs[i].GetFileAddress()
			start_addr = frame.GetSymbol().GetStartAddress().GetFileAddress()
			symbol_offset = file_addr - start_addr

			module	= frame.module
			libname	= module.platform_file.basename

			if frame.idx == sframe.idx:
				print(f"{RED}=>{RST}  frame #{frame.idx:02} ->  {RED}0x{frame.pc:08x}{RST} {CYN}{libname}{RST}`{GRN}{frame.name}{RST} + {symbol_offset}")

				arch = get_target_arch()

				error = lldb.SBError()
				buffer = process.ReadMemory(frame.pc, 32, error)
				
				print(f"{YEL}<disassembly>{RST}")
				arch.disasm(frame.pc, buffer, frame.pc)
				print(f"{YEL}</disassembly>{RST}")
			else:
				print(f"    frame #{frame.idx:02} ->  {RED}0x{frame.pc:08x}{RST} {CYN}{libname}{RST}`{GRN}{frame.name}{RST} + {symbol_offset}")

class ExploitableCommand(LLDBCommand):
	def name(self):
		return "exploitable"

	def description(self):
		return "Check if the current exception context is exploitable"
	
	def args(self):
		return [
			CommandArgument(
				arg="thread_id",
				type="int",
				help="ID of the exception thread. Uses selected thread by default",
			)
		]

	@process_is_alive
	def run(self, arguments, option):
		# ========= Exploitability algorithm =========

		# The algorithm for determining exploitability looks like this:

		# Exploitable if
		# 	Crash on write instruction
		# 	Crash executing invalid address
		# 	Crash calling an invalid address
		# 	Illegal instruction exception
		# 	Abort due to -fstack-protector, _FORTIFY_SOURCE, heap corruption detected
		# 	Stack trace of crashing thread contains certain functions such as malloc, free, szone_error, objc_MsgSend, etc.

		# Not exploitable if
		# 	Divide by zero exception
		# 	Stack grows too large due to recursion
		# 	Null dereference(read or write)
		# 	Other abort
		# 	Crash on read instruction
		
		target 	= lldb.debugger.GetSelectedTarget()
		process = target.GetProcess()
		thread 	= process.GetSelectedThread()

		crash_code			= None
		crash_desc			= None
		av_is_exploitable 	= None
		av_access_type		= None
		access_address		= 0
		exploit_reason		= None
		stack_suspicious	= False
		av_on_branch		= False
		av_null_deref		= False
		av_badbeef			= False
		is_recursion		= check_if_recursion(thread)
		disassembly			= None
		av_exception		= None

		if arguments[0]:
			tid 	= evaluateInputExpression(arguments[0]).GetValueAsUnsigned()
			thread 	= process.GetThreadByIndexID(tid)

		frame 	= thread.GetFrameAtIndex(0)
		pc 		= frame.pc
		arch 	= get_target_arch()

		if thread.GetStopReason() == lldb.eStopReasonException:
			page_size = get_host_pagesize()
			av_exception = thread.GetStopDescription(1024)
			exc, code, extra = parse_stopDescription(av_exception)

			stack_suspicious = is_stack_suspicious(thread, exc, code, extra)

			if is_recursion:
				code = int(code)
				# exception 	= arch.exceptions[exc]
				# crash_code 	= exception[code]['title']
				# crash_desc	= exception[code]['desc']
				crash_code, crash_desc = arch.get_code_desc(exc, code)

				av_access_type	  	= "recursion"
				av_is_exploitable 	= False
				exploit_reason 		= f"The crash is suspected to be due to unbounded recursion since there were more than {MINIMUM_RECURSION_LENGTH} stack frames"
				disassembly, _, _ = arch.get_disas_to_print(frame, process)

			elif stack_suspicious:
				exploit_reason 		= "The crash is suspected to be an exploitable issue due to the suspicious function in the stack trace of the crashing thread."
				av_is_exploitable	= True
				code = int(code)
				# exception 	= arch.exceptions[exc]
				# crash_code 	= exception[code]['title']
				# crash_desc	= exception[code]['desc']
				crash_code, crash_desc = arch.get_code_desc(exc, code)
				disassembly, _, _	= arch.get_disas_to_print(frame, process)

			elif not is_recursion and exc == "EXC_BAD_ACCESS":
				if code and extra:
					code = int(code)
					# exception 	= arch.exceptions[exc]
					# crash_code 	= exception[code]['title']
					# crash_desc	= exception[code]['desc']
					crash_code, crash_desc = arch.get_code_desc(exc, code)

					access_address = int(extra, 16)

					if access_address == "0xbbadbeef":
						# WebCore functions call CRASH() in various assertions or if the amount to allocate was too big. CRASH writes a null byte to 0xbbadbeef.
						av_badbeef			= True
						av_is_exploitable	= False
						exploit_reason 		= "Not exploitable. Seems to be a safe crash. Calls to CRASH() function writes a null byte to 0xbbadbeef"

					elif is_near_null(access_address) and frame.pc == access_address:
						av_null_deref		= True
						av_is_exploitable	= False
						av_access_type 		= "exec"
						exploit_reason		= "Null Dereference. Probably not exploitable"

					elif frame.pc == access_address:
						av_is_exploitable	= True
						av_access_type 		= "exec"
						exploit_reason 		= "Trying to execute a bad address, this is a potentially exploitable issue"

					#it's either a read or a write
					else:
						max_offset	 = 1024
						disassembly, av_on_branch, av_access_type	= arch.get_disas_to_print(frame, process)

						if is_near_null(access_address):
							av_is_exploitable 	= False
							av_null_deref		= True
							exploit_reason		= "Null Dereference. Probably not exploitable"

						# cw: assumes reads are not exploitable
						elif av_access_type == "read" and access_address > 0x55555555 - max_offset and access_address < 0x55555555 + max_offset:
							# It's probably exploitable in the MallocScribble case, but not necessarily in the libgmalloc case.
							# Don't mark it exploitable, since libgmalloc is used much more than MallocScribble these days. 
							av_is_exploitable 	= False
							exploit_reason		= "The access address indicates the use of freed memory if MallocScribble was used, or uninitialized memory if libgmalloc and MALLOC_FILL_SPACE was used."
						
						elif av_access_type == "read" and access_address > 0xaaaaaaaa - max_offset and access_address < 0xaaaaaaaa + max_offset:
							# reading an uninitialized pointer isn't necessarily exploitable but it's interesting to note.
							av_is_exploitable	= False
							exploit_reason		= "The access address indicates that uninitialized memory was being used if MallocScribble was used."
						
						# cw: writes assumed as exploitable
						elif av_access_type == "write":
							# Crash on write instruction
							av_is_exploitable = True
							exploit_reason		= f"Crash writing to invalid address {RED}{access_address:x}{RST}"

					if av_access_type == "exec":
						# let's see who caused this?
						if thread.GetNumFrames() >= 2:
							frame1 = thread.GetFrameAtIndex(frame.idx+1)
							pc 	   = frame1.pc
							previous_pc = arch.get_previous_pc(pc, frame1, pc)
							disassembly, av_on_branch, _	= arch.get_disas_to_print(frame1, process, previous_pc)

				elif code == "EXC_I386_GPFLT":
					# //When the address would be invalid in the 64-bit ABI, we get a EXC_I386_GPFLT and 
					# //the access address shows up as 0.  That shouldn't count as a null deref.
					# //(0x0000800000000000 to 0xFFFF800000000000 is not addressable, 
					# //0xFFFF800000000000 and up is reserved for future kernel use)
					exploit_reason = "The exception code indicates that the access address was invalid in the 64-bit ABI (it was > 0x0000800000000000)."

				else:
					print(f"crash code  : {exception[code]['title']}")
					errlog("Not implemented")
					return

			elif exc == "EXC_BAD_INSTRUCTION":
				# (lisa:>) disassemble 
				# libsystem_c.dylib`__chk_fail_overflow:
				#     0x7fff2036a0fd <+0>:  pushq  %rbp
				#     0x7fff2036a0fe <+1>:  movq   %rsp, %rbp
				#     0x7fff2036a101 <+4>:  leaq   0x9c35(%rip), %rdi        ; "detected buffer overflow"
				#     0x7fff2036a108 <+11>: callq  0x7fff2036abc3            ; _os_crash
				# ->  0x7fff2036a10d <+16>: ud2
				crash_code, crash_desc = arch.get_code_desc(exc, code)
				disassembly, _, _	= arch.get_disas_to_print(frame, process, pc)


			elif exc == "EXC_ARITHMETIC":
				crash_code, crash_desc = arch.get_code_desc(exc, code)
				exploit_reason 	= f"Arithmetic exception at {pc:016x}, probably not exploitable."
				disassembly, _, av_access_type 	= arch.get_disas_to_print(frame, process)
			
		elif thread.GetStopReason() == lldb.eStopReasonSignal:
			av_exception = thread.GetStopDescription(1024)
			stack_suspicious = is_stack_suspicious(thread, None, None, None)
			crash_code		 = av_exception.split(' ')[1]

			if stack_suspicious:
				exploit_reason 		= "The crash is suspected to be an exploitable issue due to the suspicious function in the stack trace of the crashing thread."
				av_is_exploitable	= True
				disassembly, _, _	= arch.get_disas_to_print(frame, process)
			
		print(f"crash_code		: {GRN}{crash_code}{RST}")
		print(f"crash_desc		: {crash_desc}")
		print(f"av_on_branch		: {YEL}{av_on_branch}{RST}")
		print(f"av_null_deref		: {YEL}{av_null_deref}{RST}")
		print(f"av_badbeef		: {YEL}{av_badbeef}{RST}")
		print(f"is_recursion		: {YEL}{is_recursion}{RST}")
		print(f"av_type			: {MAG}{av_access_type}{RST}")
		print(f"av_address		: {access_address:x}")
		print(f"stack_suspicious	: {stack_suspicious}")
		av_is_exploitable	=	f"{RED}True{RST}" if av_is_exploitable else f"{YEL}False{RST}"
		print(f"av_is_exploitable 	: {av_is_exploitable}")
		print(f"exploit_reason		: {exploit_reason}")
		print(f"disassembly		: {disassembly}")

class InstructionManualCommand(LLDBCommand):
	def name(self):
		return "man"
	
	def description(self):
		return "Full Instruction Reference Plugin (idaref)"
	
	def args(self):
		return [
			CommandArgument(
				arg="instruction",
				type="str",
				help="instruction to search",
			),
			CommandArgument(
				arg="arch",
				type="str",
				help="Architecture of the instruction. By default, uses Arch of selected target.",
			)
		]

	def run(self, arguments, option):
		if not arguments[1]:
			arch = get_target_arch()
		
		if not arguments[0]:
			current_instruction = ""


def __lldb_init_module(debugger, dict):
	context_title(" lisa ")

	global command_iterpreter

	res = lldb.SBCommandReturnObject()
	command_iterpreter = debugger.GetCommandInterpreter()

	command_iterpreter.HandleCommand(f"settings set prompt {__prompt__}", res)
	command_iterpreter.HandleCommand("settings set stop-disassembly-count 0", res)

	current_module = sys.modules[__name__]
	current_module._loadedFunctions = {}

	load_command(current_module, ASLRCommand(), "lisa")
	load_command(current_module, ChecksecCommand(), "lisa")
	load_command(current_module, DisplayMachoHeaderCommand(), "lisa")
	load_command(current_module, DisplayMachoLoadCmdCommand(), "lisa")
	load_command(current_module, CapstoneDisassembleCommand(), "lisa")
	load_command(current_module, ContextCommand(), "lisa")
	load_command(current_module, RegisterReadCommand(), "lisa")
	load_command(current_module, DisplayStackCommand(), "lisa")
	load_command(current_module, DumpStackCommand(), "lisa")	
	load_command(current_module, DisplayMemoryCommand(), "lisa")
	load_command(current_module, ReadMemoryCommand(), "lisa")
	load_command(current_module, PrettyBacktraceCommand(), "lisa")
	load_command(current_module, ExploitableCommand(), "lisa")
	load_command(current_module, InstructionManualCommand(), "lisa")

	command_iterpreter.HandleCommand("target stop-hook add --one-liner 'context'", res)
	command_iterpreter.HandleCommand("command alias ct context", res)
