# LLDB MCP Integration

This project provides a Model-Context Protocol (MCP) integration for LLDB, allowing AI assistants like Claude to interact with your debugging sessions through a standardized interface.

## Overview

The integration consists of two main components:

1. **server.py** - An MCP server that communicates with Claude (or other MCP clients)
2. **lldb_plugin.py** - A plugin that runs inside LLDB and exposes debugger functionality via JSON-RPC

This architecture allows Claude to help you debug code by directly interacting with LLDB through natural language. The MCP server acts as a bridge, translating Claude's requests into LLDB commands and returning results in a structured format.

## Installation

### Prerequisites

- Python 3.10 or higher
- LLDB with Python bindings
- `fastmcp` Python package (for Claude Desktop integration)

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/ant4g0nist/lldb-mcp.git
   cd lldb-mcp
   ```

2. Install required dependencies:
   ```
   pip install "fastmcp>=1.2.0" httpx
   ```

   or

   ```
   uv install "fastmcp>=1.2.0" httpx
   ```

## Usage

### Method 1: Using with Claude for Desktop

1. Make sure Claude for Desktop is installed and updated to the latest version.

2. Configure Claude for Desktop to use the LLDB MCP server by editing:
   - path: `~/Library/Application Support/Claude/claude_desktop_config.json`

3. Update the paths and add the LLDB MCP configuration:
   ```json
   {
     "mcpServers": {
       "lldb": {
         "command": "/path/to/your/.local/bin/uv",
         "args": [
           "--directory",
           "/path/to/your/lldb-mcp/llmcp",
           "run",
           "lldb_mcp.py"
         ]
       }
     }
   }
   ```

4. Restart Claude for Desktop.

5. Start a debugging session in LLDB and enable the MCP server with:
   ```
   (lldb) command script import lisa.py
   ```

6. You should now see the LLDB tools available in Claude for Desktop. Look for the hammer icon.

### Method 2: Direct LLDB Integration

If you prefer to use the plugin directly from LLDB without Claude for Desktop:

1. Add the following to your `~/.lldbinit` file to load the plugin automatically:
   ```
   command script import /path/to/lldb_plugin.py
   ```

2. In your LLDB session, start the MCP server:
   ```
   (lldb) mcp start
   ```

3. The server will be available at http://localhost:13338 for any MCP client to connect to.

## Available LLDB Tools

The MCP server exposes the following methods for AI assistants:

- **create_target** - Create a debug target from an executable path
- **launch_process** - Launch a process with optional arguments, environment variables, and working directory
- **attach_to_process** - Attach to a running process by PID
- **detach_from_process** - Detach from the current process
- **continue_process** - Continue process execution
- **step_over** - Step over current line or instruction
- **step_into** - Step into function call
- **step_out** - Step out of current function
- **set_breakpoint** - Set a breakpoint at a specified location
- **delete_breakpoint** - Delete a breakpoint by ID
- **list_breakpoints** - List all breakpoints
- **get_backtrace** - Get backtrace for current thread or specified thread
- **get_variables** - Get variables in current frame
- **get_disassembly** - Get disassembly around specified address or current PC
- **read_memory** - Read memory from a specific address
- **get_metadata** - Get metadata about the current debugging session
- **run_lldb_command** - Execute an arbitrary LLDB command
- **evaluate_expression** - Evaluate expression in current context

## Example Interactions with Claude

Once set up, you can interact with LLDB through Claude using natural language. Some examples:

- "Debug this program at `/path/to/executable`"
- "Set a breakpoint at main"
- "Run the program with arguments `-v input.txt`"
- "Show me the variables in the current frame"
- "Step into the next function call"
- "What's the backtrace right now?"
- "Evaluate the expression `ptr->data[i]`"
- "Show me the assembly code at the current instruction"

## Troubleshooting

- **Plugin not loading**: Ensure LLDB's Python environment can access the necessary modules
- **Server connection issues**: Check if port 13338 is already in use by another application
- **Claude not detecting tools**: Verify the correct configuration in `claude_desktop_config.json`
- **Command errors**: The plugin logs errors to the LLDB console, check there for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## License

Apache License

## TODO
- [ ] Update instruction manuals
- [ ] Add more testcases

### Credits

- [voltron](https://github.com/snare/voltron)
- [lldb](https://lldb.llvm.org/)
- [chisel](https://github.com/facebook/chisel)
- [gef](https://github.com/hugsy/gef)
- [pixd](https://github.com/moreati/python-pixd)
- [hexdump](https://github.com/sinofp/hexdoor)
- [idaref](https://github.com/nologic/idaref)
- [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
