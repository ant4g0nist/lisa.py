# LLDB MCP Integration

This project provides a Model-Context Protocol (MCP) integration for LLDB, allowing AI assistants like Claude to interact with your debugging sessions through a standardized interface.

## Overview

The integration consists of two main components:

1. **lldb_mcp.py** - An MCP server that communicates with Claude (or other MCP clients)
2. **lisa.py** - A plugin that runs inside LLDB and exposes debugger functionality via JSON-RPC

This architecture allows Claude to help you debug code by directly interacting with LLDB through natural language. The MCP server acts as a bridge, translating Claude's requests into LLDB commands and returning results in a structured format.

## Installation

### Prerequisites

- Python 3.10 or higher
- LLDB with Python bindings
- `fastmcp` Python package (for Claude Desktop integration)

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/ant4g0nist/lisa.py.git
   cd lisa.py
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
           "/path/to/your/lisa.py",
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

### Method 3: Using with Roo Code

This section details how to set up and use the LLDB MCP server with Roo Code.

**Initial One-Time Setup:**

1.  **Clone the Repository (if not already done):**
    ```bash
    git clone https://github.com/ant4g0nist/lldb-mcp.git # Or your fork/project path
    cd lldb-mcp
    ```

2.  **Install `capstone` for LLDB's Internal Python Environment:**
    The LLDB plugin (`lldb_plugin.py` after installation) also requires `capstone`. LLDB often uses its own Python interpreter (e.g., bundled with Xcode), which is separate from your project's environment.
    *   **Identify LLDB's Python:** Start `lldb` and run:
        ```lldb
        (lldb) script import sys; print(sys.path)
        ```
        Look for a path like `/Applications/Xcode.app/.../Python3.framework/.../bin/python3.x`.
        For example, it might be `/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9`.
    *   **Install `capstone` into LLDB's Python:** Use the Python executable identified above.
        ```bash
        # Replace with the actual path you found:
        /Applications/Xcode.app/Contents/Developer/usr/bin/python3.9 -m pip install capstone==4.0.2
        ```
        *(Note: This command might install to your user's site-packages for that Python version, e.g., `~/Library/Python/3.9/lib/python/site-packages/`, which should be in LLDB's `sys.path`.)*

3.  **Configure Roo Code MCP Settings:**
    Add or verify the `lldb` server configuration in your Roo Code MCP settings file. On macOS, this is typically at `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json`.
    ```json
    {
      "mcpServers": {
        "lldb": {
          "command": "/opt/homebrew/bin/uv", // Or your system's `uv` path, e.g., /Users/dante/.local/bin/uv
          "args": [
            "--directory",
            "/path/to/your/lldb-mcp", // IMPORTANT: Absolute path to this project
            "run",
            "lldb_mcp.py"
          ],
          "disabled": false,
          "alwaysAllow": [] // Keep empty or customize as needed
        }
        // ... other servers if any ...
      }
    }
    ```
    **Important:**
    *   Replace `/path/to/your/lldb-mcp` with the **actual absolute path** to this cloned `lldb-mcp` project directory.
    *   Ensure the `command` path for `uv` (or `python3` if not using `uv` for the MCP server) is correct for your system.

**Manual Steps for Each Debugging Session with Roo Code:**

The `lldb_mcp.py` server (run by Roo Code) needs to connect to a JSON-RPC server that you manually start within an LLDB session. **You must perform these steps each time you want to use LLDB with Roo Code:**

1.  **Open a new terminal window.**
2.  **Start LLDB:**
    ```bash
    lldb
    ```
3.  **Import the LLDB plugin and start the MCP server:**
    Inside the `(lldb)` prompt, run the following commands:
    ```lldb
    (lldb) command script import lldb_plugin.py
    ```
    You should see output like "Manual loaded for architecture..." and the prompt might change to `(lisa:>)`. Then, start the server:
    ```lldb
    (lisa:>) mcp start
    ```
    You should see: `LLDB JSON-RPC server started on port 13338` and `Started LLDB JSON-RPC server on http://localhost:13338/mcp`.

4.  **Keep this LLDB terminal session running in the background.** Do not close it while using the LLDB tools with Roo Code.


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
