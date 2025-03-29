# NOTE: This file has been automatically generated, do not modify!
from typing import Annotated, Optional, TypedDict, List, Dict, Any, Union
from pydantic import Field

class BreakpointLocation(TypedDict):
    id: int
    address: int
    enabled: bool
    hit_count: int
    function_name: Optional[str]
    file: Optional[str]
    line: Optional[int]

class FrameInfo(TypedDict):
    id: int
    pc: int
    function_name: Optional[str]
    module: Optional[str]
    file: Optional[str]
    line: Optional[int]
    args: Dict[str, str]
    locals: Dict[str, str]

class DisassemblyLine(TypedDict):
    address: int
    instruction: str
    operands: str
    bytes: List[int]
    is_current: bool

class MemoryData(TypedDict):
    address: int
    data: List[int]
    error: Optional[str]

class ThreadInfo(TypedDict):
    id: int
    name: str
    stop_reason: str
    frames: List[Dict[str, Any]]

class RegisterInfo(TypedDict):
    name: str
    value: str

class DisassembledInstruction(TypedDict):
    address: str
    instruction: str
    operands: str

class BreakpointInfo(TypedDict):
    id: int
    enabled: bool
    locations: List[Dict[str, Any]]
    hit_count: int

class VariableInfo(TypedDict):
    name: str
    type: str
    value: str
    has_children: bool
    children: List['VariableInfo']

@mcp.tool()
def create_target(executable_path: Annotated[str, Field(description='Path to the executable file')]) -> Dict[str, Any]:
    """Create a debug target from an executable path."""
    return make_jsonrpc_request('create_target', executable_path)

@mcp.tool()
def launch_process(args: Annotated[List[str], Field(description='Command line arguments for the program')]=[], env: Annotated[Dict[str, str], Field(description='Environment variables to set for the program')]={}, working_dir: Annotated[str, Field(description='Working directory for the program')]=None, stop_at_entry: Annotated[bool, Field(description='Whether to stop at the program entry point')]=True) -> Dict[str, Any]:
    """Launch the process with optional arguments."""
    return make_jsonrpc_request('launch_process', args, env, working_dir, stop_at_entry)

@mcp.tool()
def attach_to_process(pid: Annotated[int, Field(description='Process ID to attach to')]) -> Dict[str, Any]:
    """Attach to a running process by PID."""
    return make_jsonrpc_request('attach_to_process', pid)

@mcp.tool()
def detach_from_process() -> bool:
    """Detach from the current process."""
    return make_jsonrpc_request('detach_from_process')

@mcp.tool()
def continue_process() -> Dict[str, Any]:
    """Continue process execution."""
    return make_jsonrpc_request('continue_process')

@mcp.tool()
def step_over() -> Dict[str, Any]:
    """Step over current line or instruction."""
    return make_jsonrpc_request('step_over')

@mcp.tool()
def step_into() -> Dict[str, Any]:
    """Step into function call."""
    return make_jsonrpc_request('step_into')

@mcp.tool()
def step_out() -> Dict[str, Any]:
    """Step out of current function."""
    return make_jsonrpc_request('step_out')

@mcp.tool()
def set_breakpoint(location: Annotated[str, Field(description='Breakpoint specification (e.g., function name, file:line, or address)')]) -> Dict[str, Any]:
    """Set a breakpoint at a specified location."""
    return make_jsonrpc_request('set_breakpoint', location)

@mcp.tool()
def delete_breakpoint(breakpoint_id: Annotated[int, Field(description='ID of the breakpoint to delete')]) -> bool:
    """Delete a breakpoint by ID."""
    return make_jsonrpc_request('delete_breakpoint', breakpoint_id)

@mcp.tool()
def list_breakpoints() -> List[BreakpointInfo]:
    """List all breakpoints."""
    return make_jsonrpc_request('list_breakpoints')

@mcp.tool()
def get_backtrace(thread_id: Annotated[Optional[int], Field(description='ID of the thread to get backtrace for')]=None) -> List[Dict[str, Any]]:
    """Get backtrace for current thread or specified thread."""
    return make_jsonrpc_request('get_backtrace', thread_id)

@mcp.tool()
def get_variables(frame_id: Annotated[Optional[int], Field(description='ID of the frame to get variables for')]=None, thread_id: Annotated[Optional[int], Field(description='ID of the thread to get variables for')]=None) -> Dict[str, List[VariableInfo]]:
    """Get variables in current frame."""
    return make_jsonrpc_request('get_variables', frame_id, thread_id)

@mcp.tool()
def get_disassembly(address: Annotated[Optional[Union[int, str]], Field(description='Address to disassemble from (hex string or integer)')]=None, count: Annotated[int, Field(description='Number of instructions to disassemble')]=10) -> List[DisassemblyLine]:
    """Get disassembly around specified address or current PC."""
    return make_jsonrpc_request('get_disassembly', address, count)

@mcp.tool()
def read_memory(address: Annotated[int, Field(description='Address to read memory from')], size: Annotated[int, Field(description='Number of bytes to read')]) -> MemoryData:
    """Read memory from the process."""
    return make_jsonrpc_request('read_memory', address, size)

@mcp.tool()
def get_metadata() -> Dict[str, Any]:
    """Get metadata about the current LLDB debugging session."""
    return make_jsonrpc_request('get_metadata')

@mcp.tool()
def run_lldb_command(command: Annotated[str, Field(description='LLDB command to execute')]) -> Dict[str, Any]:
    """Execute an LLDB command and return the output."""
    return make_jsonrpc_request('run_lldb_command', command)

@mcp.tool()
def evaluate_expression(expression: Annotated[str, Field(description='Expression to evaluate')]) -> Dict[str, Any]:
    """Evaluate expression in current context."""
    return make_jsonrpc_request('evaluate_expression', expression)

