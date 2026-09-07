# GhidraMCP fork — implementation plan

Adapts the fork to the latest Ghidra and implements the firmware-RE wishlist
(`D:\VW\GHIDRA_MCP_WISHLIST.md`). Grounded in a live session against a raw NXP
MPC57xx PowerPC e200 VLE image where the agent could not get from raw bytes to
functions without the GUI.

## Where things stand

- **Fork:** `rweijnen/GhidraMCP`, `origin` = fork, `upstream` = LaurieWired. Local
  clone at `C:\Users\me\source\rweijnen\GhidraMCP`, on `main` at upstream `27f316f`.
- **Upstream target version:** the repo builds against Ghidra `11.3.2` (see `pom.xml`,
  `extension.properties`, `.github/workflows/build.yml`).
- **Latest installed Ghidra:** `12.1.3` at `C:\tools\ghidra_12.1.3_PUBLIC`
  (build 20260817, `application.java.min=21`).
- **Prior "12.1.3 work":** the copies under `C:\tools\ghidra-mcp` and
  `C:\tools\ghidra_12.1.3_PUBLIC\mcp` are **byte-identical to upstream** (only CRLF
  differs). The `GhidraMCP-12.1.3.zip` there is just a **version bump** — no wishlist
  features were added. So this fork starts from the stock upstream feature set.
- **Current surface:** 27 HTTP endpoints in `GhidraMCPPlugin.java`, mirrored by 27
  `@mcp.tool`s in `bridge_mcp_ghidra.py`. All are **read / rename / annotate** over an
  already-analyzed program. None of the wishlist Priority 1–5 items exist.

## Build-environment blockers (fix first)

1. **JDK 21 required, only JDK 11 present.** Ghidra 12.x jars are compiled for Java 21
   (`application.java.compiler=21`). The system `java`/`javac` is Microsoft OpenJDK 11.
   Install Temurin 21 (`scoop bucket add java; scoop install temurin21-jdk`) and point
   `JAVA_HOME` at it for the Maven build. The CI workflow already uses JDK 21.
2. **`pom.xml` / `build.yml` pin 11.3.2.** Decide the fork's baseline (see Decision A).

## Decision A — which Ghidra version(s) to target

- **Option 1 (recommended): retarget to 12.1.3.** Bump `pom.xml` deps, `build.yml`
  (`GHIDRA_VERSION`/`GHIDRA_DATE`), `extension.properties` (`version`/`ghidraVersion`),
  and `lib/`. Matches the installed toolchain and the machine we test on.
- **Option 2: keep 11.3.2** for easier upstream PRs, and cross-build 12.1.3 separately.
- Feed-back note: LaurieWired's `main` is on 11.3.2. If we intend PRs upstream, keep the
  **feature commits version-agnostic** (no API calls that only exist in 12.x) so they
  cherry-pick cleanly, and isolate the version bump in its own commit.

All wishlist features below verified to exist as APIs in the installed 12.1.3 jars:
`SetRegisterCmd`, `DisassembleCommand`, `CreateFunctionCmd`, `ClearCmd`,
`AutoAnalysisManager`, `AutoImporter`, `FlatProgramAPI`, `ProgramContext`, `Register`.

## Architecture (unchanged pattern)

Each feature = one HTTP endpoint in `GhidraMCPPlugin.java` + one `@mcp.tool` wrapper in
`bridge_mcp_ghidra.py`. Ghidra mutations must run inside a program transaction
(`program.startTransaction` / `endTransaction`) and, for Swing-thread safety, via
`SwingUtilities.invokeAndWait` like the existing rename endpoints do. Return plain-text
lines to match the existing `safe_get`/`safe_post` contract.

Cross-cutting conventions to add up front:
- **Address parsing helper** already exists for several endpoints; reuse it and accept
  hex (`0x…`) consistently.
- **Transaction + Swing wrapper helper** to avoid repeating boilerplate across the ~20
  new mutating endpoints.
- **Consistent error text** (`"Error: …"`) so the bridge surfaces failures verbatim.

## Work items (by wishlist priority)

### Priority 1 — code definition & analysis control (the blocker)

1. **`set_register_context(register, value, start, end)`** → `SetRegisterCmd`.
   The single highest-value item; unblocks VLE (`vle`=1), ARM/Thumb (`TMode`), MIPS16, SH.
2. **`disassemble(start, end=None)`** → `DisassembleCommand` over an address/range,
   not just an existing function.
3. **`create_function(addr, name=None)`** → `CreateFunctionCmd`;
   **`delete_function(addr)`** → `FunctionManager.removeFunction`.
4. **`clear_code(start, end)` / `undefine(range)`** → `ClearCmd` (clear code, keep or
   drop symbols/comments as flagged). Needed to redo bad disassembly after a context fix.
5. **`run_analysis(analyzers=None)` / `auto_analyze()` + `analysis_status()`** →
   `AutoAnalysisManager.getAnalysisManager(program)`, `startAnalysis` / `reAnalyzeAll`,
   and poll `isAnalyzing()`. Expose enabling "Aggressive Instruction Finder" /
   "Function Start Search" for raw blobs via analyzer options.
6. **Nice: `define_data(addr, type)`** → `FlatProgramAPI.createData` / `DataUtilities`.

### Priority 2 — program setup / import

7. **`import_program(path, language_id, base_address, endian, processor_options=None)`**
   → `AutoImporter` with an explicit `LanguageID` + `LoadSpec`, then set image base.
   Lets an agent create the program instead of only attaching. (Careful: importing needs
   a project + folder context; scope to the plugin's active tool/project.)
8. **`list_languages(filter)`** → `DefaultLanguageService.getLanguageDescriptions`,
   filterable — parity with IDA's `list_processors`.
9. **Load-verify / arch-sanity** → after import (or on demand) return a summary: segment
   map + whether the entry/reset vector decodes to sane instructions. Directly targets the
   "confidently-wrong wrong-arch DB" footgun called out in the wishlist and `IDA_MCP_ISSUES.md`.

### Priority 3 — search & raw bytes

10. **`read_bytes(addr, size)`** → `Memory.getBytes` (hex/base64 out).
11. **`search_bytes(pattern, mask=None)` / `search_immediate(value)`** →
    `Memory.findBytes` with mask; used to locate dispatch tables by opcode.
12. **`get_string(addr)`** → point lookup via `DataUtilities` / `StringDataInstance`
    (complements existing `list_strings`).

### Priority 4 — annotation parity & scale

13. **`list_functions(offset, limit, filter)`** → add pagination + name filter to the
    existing endpoint (today it takes no args; unusable on an 11k-function image).
14. **`decompile_many(addresses[])`** → batch decompile.
15. **`set_bookmark(addr, category, note)` / `list_bookmarks(filter)`** →
    `BookmarkManager`; supports the `[LEAD:<grade>]` tagging convention.
16. **`define_struct(c_decl)` / apply type** → parse C via `CParser` into a
    `DataTypeManager`; parity with IDA `declare_type`/`set_type`.

### Priority 5 — persistence

17. **`save_program()`** → `program.save(...)` / `DomainFile.save`, so renames/comments
    persist without the GUI.

## Suggested branch & commit layout

- Branch `feature/firmware-re-tools` off `main`.
- Commit 1: helpers (transaction+Swing wrapper, address parsing) — version-agnostic.
- Commits 2–6: one per Priority-1 feature (endpoint + bridge tool + brief test note).
- Commits 7–9: Priority 2. Commits 10–17: Priorities 3–5.
- Separate final commit: version bump to 12.1.3 (`pom.xml`, `build.yml`,
  `extension.properties`, `lib/`) — kept isolated so feature commits stay PR-able upstream.
- Update `README.md` Features list and add a short tools reference.

## Testing

- Build: `JAVA_HOME=<jdk21> mvn clean package assembly:single` → `target/GhidraMCP-*.zip`.
- Install the zip into Ghidra 12.1.3, enable the plugin, start the HTTP server.
- Smoke-test end to end on the MPC57xx VLE scenario: `import_program` (or attach) →
  `set_register_context vle=1` over the code range → `disassemble` → `create_function` →
  `auto_analyze` → `analysis_status` → `list_functions` returns real functions. That path
  is the concrete acceptance test from the wishlist.

## Open questions for you

- **Decision A:** retarget the fork to 12.1.3, or keep 11.3.2 as the PR-able baseline?
- **Scope of first PR:** all five priorities, or ship Priority 1 (the blocker) first?
- **`import_program` scope:** full raw-import support is the largest item and touches
  project/loader plumbing; OK to land it after the P1 code-definition tools?
