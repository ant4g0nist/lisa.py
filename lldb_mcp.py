#!/usr/bin/env python3

# Adapted from ida-pro-mcp (https://github.com/mrexodia/ida-pro-mcp)
# Copyright (c) 2025 Duncan Ogilvie => MIT License

import os
import sys
import ast
import json
import shutil
import http.client

from fastmcp import FastMCP

# The log_level is necessary for Cline to work: https://github.com/jlowin/fastmcp/issues/81
mcp = FastMCP("LLDB", log_level="ERROR")

jsonrpc_request_id = 1

def make_jsonrpc_request(method: str, *params):
    """Make a JSON-RPC request to the LLDB plugin"""
    global jsonrpc_request_id
    conn = http.client.HTTPConnection("localhost", 13338)  # Using port 13338 for LLDB
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": list(params),
        "id": jsonrpc_request_id,
    }
    jsonrpc_request_id += 1

    try:
        conn.request("POST", "/mcp", json.dumps(request), {
            "Content-Type": "application/json"
        })
        response = conn.getresponse()
        data = json.loads(response.read().decode())

        if "error" in data:
            error = data["error"]
            code = error["code"]
            message = error["message"]
            pretty = f"JSON-RPC error {code}: {message}"
            if "data" in error:
                pretty += "\n" + error["data"]
            raise Exception(pretty)

        result = data["result"]
        # NOTE: LLMs do not respond well to empty responses
        if result is None:
            result = "success"
        return result
    except Exception:
        raise
    finally:
        conn.close()

class MCPVisitor(ast.NodeVisitor):
    def __init__(self):
        self.types: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.descriptions: dict[str, str] = {}

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == "jsonrpc":
                    for i, arg in enumerate(node.args.args):
                        arg_name = arg.arg
                        arg_type = arg.annotation
                        if arg_type is None:
                            raise Exception(f"Missing argument type for {node.name}.{arg_name}")
                        if isinstance(arg_type, ast.Subscript):
                            assert isinstance(arg_type.value, ast.Name)
                            assert arg_type.value.id == "Annotated"
                            assert isinstance(arg_type.slice, ast.Tuple)
                            assert len(arg_type.slice.elts) == 2
                            annot_type = arg_type.slice.elts[0]
                            annot_description = arg_type.slice.elts[1]
                            assert isinstance(annot_description, ast.Constant)
                            node.args.args[i].annotation = ast.Subscript(
                                value=ast.Name(id="Annotated", ctx=ast.Load()),
                                slice=ast.Tuple(
                                    elts=[
                                    annot_type,
                                    ast.Call(
                                        func=ast.Name(id="Field", ctx=ast.Load()),
                                        args=[],
                                        keywords=[
                                        ast.keyword(
                                            arg="description",
                                            value=annot_description)])],
                                    ctx=ast.Load()),
                                ctx=ast.Load())
                        elif isinstance(arg_type, ast.Name):
                            pass
                        else:
                            raise Exception(f"Unexpected type annotation for {node.name}.{arg_name} -> {arg_type.__class__.__name__}")

                    body_comment = node.body[0]
                    if isinstance(body_comment, ast.Expr) and isinstance(body_comment.value, ast.Constant):
                        new_body = [body_comment]
                        self.descriptions[node.name] = body_comment.value.value
                    else:
                        new_body = []

                    call_args = []
                    call_args.append(ast.Constant(value=node.name))
                    for arg in node.args.args:
                        call_args.append(ast.Name(id=arg.arg, ctx=ast.Load()))
                    new_body += [ast.Return(
                        value=ast.Call(
                            func=ast.Name(id="make_jsonrpc_request", ctx=ast.Load()),
                            args=call_args,
                            keywords=[]))]
                    decorator_list = [
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id="mcp", ctx=ast.Load()),
                                attr="tool",
                                ctx=ast.Load()),
                            args=[],
                            keywords=[]
                        )
                    ]
                    node_nobody = ast.FunctionDef(node.name, node.args, new_body, decorator_list, node.returns, node.type_comment, lineno=node.lineno, col_offset=node.col_offset)
                    self.functions[node.name] = node_nobody

    def visit_ClassDef(self, node):
        for base in node.bases:
            if isinstance(base, ast.Name):
                if base.id == "TypedDict":
                    self.types[node.name] = node


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
LLDB_PLUGIN_PY = os.path.join(SCRIPT_DIR, "lisa.py")
GENERATED_PY = os.path.join(SCRIPT_DIR, "server_generated.py")

# NOTE: This is in the global scope on purpose
with open(LLDB_PLUGIN_PY, "r") as f:
    code = f.read()
module = ast.parse(code, LLDB_PLUGIN_PY)
visitor = MCPVisitor()
visitor.visit(module)
code = """# NOTE: This file has been automatically generated, do not modify!
from typing import Annotated, Optional, TypedDict, List, Dict, Any, Union
from pydantic import Field

"""
for type in visitor.types.values():
    code += ast.unparse(type)
    code += "\n\n"
for function in visitor.functions.values():
    code += ast.unparse(function)
    code += "\n\n"
with open(GENERATED_PY, "w") as f:
    f.write(code)
exec(compile(code, GENERATED_PY, "exec"))

def main():
    if sys.argv[1:] == ["--generate-only"]:
        for function in visitor.functions.values():
            signature = function.name + "("
            for i, arg in enumerate(function.args.args):
                if i > 0:
                    signature += ", "
                signature += arg.arg
            signature += ")"
            description = visitor.descriptions.get(function.name, "<no description>")
            if description[-1] != ".":
                description += "."
            print(f"- `{signature}`: {description}")
        sys.exit(0)
    elif sys.argv[1:] == ["--install-plugin"]:
        if sys.platform == "win32":
            lldb_plugin_dir = os.path.join(os.getenv("APPDATA"), "LLDB", "plugins")
        else:
            lldb_plugin_dir = os.path.join(os.path.expanduser("~"), ".lldb", "plugins")
        plugin_destination = os.path.join(lldb_plugin_dir, "lldb_plugin.py")
        if input(f"Installing LLDB plugin to {plugin_destination}, proceed? [Y/n] ").lower() == "n":
            sys.exit(1)
        if not os.path.exists(lldb_plugin_dir):
            os.makedirs(lldb_plugin_dir)
        shutil.copy(LLDB_PLUGIN_PY, plugin_destination)
        print(f"Installed plugin: {plugin_destination}")
        sys.exit(0)
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
