# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, timeout: int = 5) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 1000, filter: str = None) -> list:
    """
    List functions in the database with pagination and an optional name filter.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of functions to return (default: 1000)
        filter: Optional case-insensitive substring to match function names
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_functions", params)

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

# ---------------------------------------------------------------------------
# Firmware-RE tools (Priorities 1-5 from GHIDRA_MCP_WISHLIST)
# ---------------------------------------------------------------------------

# ----- Priority 1: code definition & analysis control -----

@mcp.tool()
def set_register_context(register: str, value: str, start: str, end: str = None) -> str:
    """
    Set a processor context register over an address range. This is the key to
    decoding mode-switched ISAs before disassembly: PowerPC VLE (register "vle",
    value "1"), ARM/Thumb ("TMode"), MIPS16, SH, etc.

    Args:
        register: Context register name (e.g. "vle", "TMode")
        value: Value to set, decimal or 0x-prefixed hex (e.g. "1")
        start: Start address of the range (e.g. "0x80000000")
        end: End address of the range (inclusive); defaults to start if omitted
    """
    data = {"register": register, "value": value, "start": start}
    if end:
        data["end"] = end
    return safe_post("set_register_context", data)

@mcp.tool()
def disassemble(address: str, length: int = None, end: str = None) -> str:
    """
    Force disassembly starting at an address (not limited to existing functions).
    Provide either length (bytes) or end address to restrict the range; omit both
    to follow flow from the start address.

    Args:
        address: Start address (e.g. "0x80000000")
        length: Optional number of bytes to restrict disassembly to
        end: Optional end address (inclusive) to restrict disassembly to
    """
    data = {"address": address}
    if length is not None:
        data["length"] = length
    if end:
        data["end"] = end
    return safe_post("disassemble", data, timeout=60)

@mcp.tool()
def create_function(address: str, name: str = None) -> str:
    """
    Create a function at the given entry-point address, optionally naming it.

    Args:
        address: Function entry-point address
        name: Optional name for the new function
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data, timeout=30)

@mcp.tool()
def delete_function(address: str) -> str:
    """
    Delete the function at the given address.
    """
    return safe_post("delete_function", {"address": address})

@mcp.tool()
def clear_code(start: str, end: str = None) -> str:
    """
    Clear code units (instructions/data) over an address range, reverting to
    undefined bytes. Use before re-disassembling after fixing context registers.

    Args:
        start: Start address
        end: End address (inclusive); defaults to start if omitted
    """
    data = {"start": start}
    if end:
        data["end"] = end
    return safe_post("clear_code", data, timeout=30)

@mcp.tool()
def auto_analyze(aggressive: bool = False) -> str:
    """
    Run Ghidra auto-analysis on the current program and wait for completion.
    Useful for turning a freshly disassembled raw blob into functions.

    Note: on a headerless blob with no entry point, plain analysis finds nothing
    until code is seeded. Either force disassembly first (disassemble /
    create_function) or pass aggressive=True.

    Args:
        aggressive: Enable the Aggressive Instruction Finder analyzer, which
            digs code out of undefined bytes. Recommended for raw blobs; it can
            create false-positive code, so verify the results.
    """
    return safe_post("auto_analyze", {"aggressive": "true" if aggressive else "false"}, timeout=600)

@mcp.tool()
def run_analysis(aggressive: bool = False) -> str:
    """
    Alias for auto_analyze: run Ghidra auto-analysis and wait for completion.

    Args:
        aggressive: Enable the Aggressive Instruction Finder analyzer (see
            auto_analyze).
    """
    return safe_post("run_analysis", {"aggressive": "true" if aggressive else "false"}, timeout=600)

@mcp.tool()
def analysis_status() -> str:
    """
    Report whether auto-analysis is running, plus current function and
    instruction counts.
    """
    return "\n".join(safe_get("analysis_status"))

@mcp.tool()
def define_data(address: str, type: str) -> str:
    """
    Define a typed data item at an address (carve a data table out of code).

    Args:
        address: Address to define data at
        type: Data type name (e.g. "dword", "char", "pointer")
    """
    return safe_post("define_data", {"address": address, "type": type})

# ----- Priority 2: program setup / import & sanity -----

@mcp.tool()
def import_program(path: str, language_id: str, base_address: str = None) -> str:
    """
    Import a raw/headerless binary into the active project with an explicit
    language, then open it. Lets an agent create the program instead of only
    attaching to one opened in the GUI.

    Args:
        path: Absolute path to the binary file on the Ghidra host
        language_id: Ghidra LanguageID (e.g. "PowerPC:BE:32:MPC8270" or a VLE
            variant). Use list_languages to discover valid IDs.
        base_address: Optional image base address (e.g. "0x80000000")
    """
    data = {"path": path, "language_id": language_id}
    if base_address:
        data["base_address"] = base_address
    return safe_post("import_program", data, timeout=600)

@mcp.tool()
def list_project_files(filter: str = None, offset: int = 0, limit: int = 200) -> list:
    """
    List programs and other files in the current Ghidra project (project path
    and content type), optionally filtered. Use to discover what open_program
    can open.

    Note: requires a CodeBrowser tool to be open (the MCP server runs inside it).

    Args:
        filter: Optional case-insensitive substring to match
        offset: Pagination offset (default: 0)
        limit: Maximum number of entries to return (default: 200)
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_project_files", params)

@mcp.tool()
def open_program(path: str) -> str:
    """
    Open a program from the current Ghidra project by its project path and make
    it the current program. Lets an agent switch between programs without the GUI.

    Note: a CodeBrowser tool must already be open (the MCP server runs inside
    it); this cannot open the first CodeBrowser itself.

    Args:
        path: Project path of the program, e.g. "/mcu_image.bin.0"
            (use list_project_files to discover paths)
    """
    return safe_post("open_program", {"path": path}, timeout=120)

@mcp.tool()
def list_languages(filter: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List available Ghidra LanguageIDs (processor/endian/size/description),
    optionally filtered. Parity with IDA's processor/device listing.

    Args:
        filter: Optional case-insensitive substring to match
        offset: Pagination offset (default: 0)
        limit: Maximum number of entries to return (default: 100)
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_languages", params)

@mcp.tool()
def program_info(verify: bool = False) -> str:
    """
    Return a summary of the current program: language, endianness, image base,
    segment map, and function/instruction counts. With verify=True, also test-
    decode a few instructions at the image base to catch a wrong-arch database.

    Args:
        verify: If True, include a decode sanity check at the image base
    """
    return "\n".join(safe_get("program_info", {"verify": "true" if verify else "false"}))

# ----- Priority 3: search & raw bytes -----

@mcp.tool()
def read_bytes(address: str, length: int = 16) -> str:
    """
    Read raw bytes at an address and return them as a hex string.

    Args:
        address: Address to read from
        length: Number of bytes to read (1-4096, default: 16)
    """
    return "\n".join(safe_get("read_bytes", {"address": address, "length": length}))

@mcp.tool()
def search_bytes(pattern: str, mask: str = None, limit: int = 100) -> list:
    """
    Search program memory for a byte pattern, returning matching addresses.
    Useful for locating opcode/immediate/signature patterns such as command
    dispatch tables.

    Args:
        pattern: Hex byte pattern (spaces allowed, e.g. "48 8b 05")
        mask: Optional hex mask of equal length (0xFF = must match, 0x00 = wildcard)
        limit: Maximum number of matches to return (default: 100)
    """
    params = {"pattern": pattern, "limit": limit}
    if mask:
        params["mask"] = mask
    return safe_get("search_bytes", params)

@mcp.tool()
def get_string(address: str) -> str:
    """
    Read the string at a specific address (point lookup), falling back to a
    null-terminated read if no string is defined there.
    """
    return "\n".join(safe_get("get_string", {"address": address}))

# ----- Priority 4: annotation parity & scale -----

@mcp.tool()
def decompile_many(addresses: str) -> str:
    """
    Decompile several functions in one call. Faster than decompiling leads one
    at a time.

    Args:
        addresses: Addresses separated by commas or whitespace
    """
    return safe_post("decompile_many", {"addresses": addresses}, timeout=120)

@mcp.tool()
def set_bookmark(address: str, category: str = "MCP", comment: str = "") -> str:
    """
    Set a Note bookmark at an address, so agents can tag leads (e.g. a
    "[LEAD:<grade>]" convention) and filter them later.

    Args:
        address: Address to bookmark
        category: Bookmark category (default: "MCP")
        comment: Bookmark comment/note text
    """
    return safe_post("set_bookmark", {"address": address, "category": category, "comment": comment})

@mcp.tool()
def list_bookmarks(filter: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List bookmarks (address, type, category, comment), optionally filtered.

    Args:
        filter: Optional case-insensitive substring to match
        offset: Pagination offset (default: 0)
        limit: Maximum number of bookmarks to return (default: 100)
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_bookmarks", params)

@mcp.tool()
def define_struct(c_declaration: str) -> str:
    """
    Parse a C declaration (e.g. a struct) and add it to the program's data type
    manager. Parity with IDA's type-declaration support for recovered wire
    structs.

    Args:
        c_declaration: A C type declaration, e.g.
            "struct Msg { int id; char name[16]; void *handler; };"
    """
    return safe_post("define_struct", {"c_declaration": c_declaration})

# ----- Priority 5: persistence -----

@mcp.tool()
def save_program() -> str:
    """
    Save the current program to its Ghidra project, persisting renames,
    comments, types, and bookmarks without using the GUI.
    """
    return safe_post("save_program", {}, timeout=120)

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

