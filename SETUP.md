# GhidraMCP (rweijnen fork) - setup

Firmware-RE fork of GhidraMCP, targeting **Ghidra 12.1.3**.

Two pieces must both run:
- the **Ghidra plugin** (an HTTP server embedded in Ghidra), and
- the **Python bridge** (`bridge_mcp_ghidra.py`), which your MCP client launches
  and which talks to that HTTP server.

## Prerequisites
- **Ghidra 12.1.3** (this exact version - the extension is version-locked).
  Ghidra runs on its own bundled JDK 21; no separate JDK is needed to run.
  JDK 21 is only required to build the plugin from source.
- **Python 3.10+**, and ideally **uv** (https://docs.astral.sh/uv/). uv pulls the
  Python deps automatically. Without uv: `pip install -r requirements.txt`.

## 1. Install the Ghidra plugin
Use a release `GhidraMCP-*.zip`, or build one (see "Building from Source" in
`README.md`), then:
1. Start Ghidra.
2. File > Install Extensions > "+" > pick the `GhidraMCP-*.zip`.
3. Restart Ghidra.
4. File > Configure > Developer > ensure `GhidraMCPPlugin` is checked.
5. Open a program in the CodeBrowser. The HTTP server starts on port 8080
   (change under Edit > Tool Options > GhidraMCP HTTP Server if needed).

Note: the HTTP server only runs while a CodeBrowser tool is open. With just the
project window open, nothing listens on 8080.

## 2. Point your MCP client at the bridge
1. Copy `.mcp.json.example` to your project's `.mcp.json` (or into your Claude
   Desktop / Claude Code config) and edit it:
   - `--directory`: the folder that contains `bridge_mcp_ghidra.py`.
   - `command`: `uv` if it is on PATH, otherwise the full path to `uv.exe`.
   - `--ghidra-server`: leave as `http://127.0.0.1:8080/` unless you changed the
     port.

Plain-python alternative (after `pip install -r requirements.txt`):
```json
"command": "python",
"args": ["<path>/bridge_mcp_ghidra.py", "--ghidra-server", "http://127.0.0.1:8080/"]
```

## 3. Verify
With a program open in Ghidra and the MCP server connected, call `program_info`
(add `verify=true` for a decode sanity check). You should see the program's
language, image base, and segment map.

## Raw / headerless blob workflow (the point of this fork)
1. `import_program(path, language_id, base_address)` - e.g. language
   `PowerPC:BE:64:VLE-32addr`, base `0x80000000`. (`list_languages` to find IDs.)
2. `set_register_context("vle", "1", start, end)` over the code range - the key
   to decoding mode-switched ISAs (VLE, ARM/Thumb, MIPS16, ...).
3. `disassemble(address)` to seed, then `create_function(address)`.
4. `auto_analyze()` - follows flow from seeds to find more functions.
   `auto_analyze(aggressive=True)` additionally enables the Aggressive
   Instruction Finder, but that only helps once many functions already exist.
5. `program_info(verify=True)` to confirm real instructions decode.
6. `save_program()` to persist.

Other tools: read_bytes, search_bytes (with mask), get_string, clear_code,
delete_function, define_data, define_struct, set_bookmark / list_bookmarks,
decompile_many, list_functions (paginated/filterable), open_program,
list_project_files.
