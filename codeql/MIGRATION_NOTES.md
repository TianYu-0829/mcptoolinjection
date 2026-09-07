# MCPToolInjection -> CodeQL Migration Notes

The core detection model from `mcptoolinjection` has been integrated into the current `codeql` directory layout.

- **Source side**
  - Python: required parameters of FastMCP `@mcp.tool` / `@mcp.tool(...)` functions.
  - JavaScript: `request.params.arguments` (the common MCP `tools/call` entry point).

- **Sink side** (aligned with the original script categories)
  - RCE
  - Command Injection
  - ReDoS
  - Arbitrary File Read
  - SSRF
  - File Injection (path creation / content write)

## Added files

### Python

- `python/mcp-tool-sources-python.qll`
- `python/mcp-tool-input-rce-python.ql`
- `python/mcp-tool-input-command-injection-python.ql`
- `python/mcp-tool-input-redos-python.ql`
- `python/mcp-tool-input-arbitrary-file-read-python.ql`
- `python/mcp-tool-input-file-injection-python.ql`
- `python/mcp-tool-input-ssrf-python.ql` (refactored to reuse a shared source library)

### JavaScript

- `javascript/mcp-request-arguments-sources-javascript.qll`
- `javascript/mcp-request-arguments-to-dangerous-sinks-javascript.ql`

## Notes

- This migration follows the existing CodeQL architecture (`python/` and `javascript/` packs) and preserves equivalent vulnerability coverage.
- Runtime behaviors from the original Python script (CLI summary, cross-file heuristic deduplication, text allow/deny lists) are not query semantics. Equivalent detection capability is expressed through CodeQL source/sink/path-problem modeling.
