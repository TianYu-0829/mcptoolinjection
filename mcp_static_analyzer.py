import os
import re
import json
import sys
import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from datetime import date
from expert_knowledge_base import (
    SINK_RULES,
    SAFE_SINK_PATTERNS,
    SANITIZER_PATTERNS,
    _FILE_INJECTION_RULE_META,
    _get_vuln_category,
    SINK_METRIC_ORDER,
    classify_sink_metric_key,
)
from vulnerability_discovery import collect_findings_json
_SKIP_DIRS_ALWAYS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "coverage",
        ".tox",
        "test",
        "tests",
        "__tests__",
        "__test__",
        "e2e",
        "docs",
        "vscode-extension",
        "browser-extension",
        ".smithery",
    }
)
_SKIP_DIRS_STRICT_ONLY = frozenset({"examples", "scripts", "demo", "sample"})
_SKIP_DIRS_STRICT_MERGED = _SKIP_DIRS_ALWAYS | _SKIP_DIRS_STRICT_ONLY
_USE_STRICT_SKIP_DIRS = False
def effective_skip_dirs():
    if _USE_STRICT_SKIP_DIRS:
        return _SKIP_DIRS_STRICT_MERGED
    return _SKIP_DIRS_ALWAYS
def set_scan_skip_strict(strict: bool):
    global _USE_STRICT_SKIP_DIRS
    _USE_STRICT_SKIP_DIRS = bool(strict)
SKIP_FILE_PATTERNS = {
    "setup-",
    "uninstall-",
    "install-",
    "publish-",
    "webpack.config",
    "rollup.config",
    "jest.config",
    "spec.",
    ".test.",
    ".spec.",
}
SCAN_EXTENSIONS = {".ts", ".js", ".py", ".mjs", ".cjs", ".tsx", ".jsx"}
MAX_SCAN_SOURCE_BYTES = 4 * 1024 * 1024
def _source_file_under_size_limit(fpath: str) -> bool:
    try:
        return os.path.getsize(fpath) <= MAX_SCAN_SOURCE_BYTES
    except OSError:
        return False
@dataclass
class MCPTool:
    name: str
    file: str
    line: int
    params: list
    handler_body: str = ""
    handler_start: int = 0
    handler_end: int = 0
@dataclass
class CrossFileLink:
    source_file: str
    source_tool: str
    command_name: str
    forwarded_params: dict
    target_file: str
    target_method: str
    target_start: int = 0
    target_end: int = 0
    target_body: str = ""
@dataclass
class Finding:
    rule_id: str
    severity: str
    vuln_type: str
    tool_name: str
    param_name: str
    file: str
    line: int
    code_snippet: str
    description: str
    source_info: str = ""
    sink_info: str = ""
    data_flow: str = ""
    recommendation: str = ""
    finding_kind: str = "vuln_trigger"
_TS_JSON_SCHEMA_TYPE_NAMES = frozenset(
    {
        "string",
        "number",
        "boolean",
        "bigint",
        "symbol",
        "undefined",
        "object",
        "function",
    }
)
_SWITCH_CASE_NON_TOOL_NAMES = frozenset(
    {
        "default",
        "true",
        "false",
        "null",
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "utf8",
        "utf-8",
        "ascii",
        "production",
        "development",
        "test",
        "staging",
    }
)
def _python_file_mcp_context_hint(lines: list[str]) -> bool:
    head = "".join(lines[:120])
    return bool(
        re.search(
            r"FastMCP|from\s+mcp\b|import\s+mcp\b|mcp\.server|modelcontextprotocol",
            head,
            re.I,
        )
    )
def discover_python_mcp_tools(filepath: str, lines: list[str]) -> list[MCPTool]:
    tools = []
    mcp_hint = _python_file_mcp_context_hint(lines)
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.search(r"@\w+\.tool\s*\(", line) or (
            mcp_hint and re.search(r"@tool\s*\(", line)
        ):
            explicit_tool = None
            _dec_name_patterns = (
                r'@\w+\.tool\s*\(\s*["\']([^"\']{1,120})["\']',
                r'@\w+\.tool\s*\(\s*name\s*=\s*["\']([^"\']{1,120})["\']',
                r'@tool\s*\(\s*["\']([^"\']{1,120})["\']',
                r'@tool\s*\(\s*name\s*=\s*["\']([^"\']{1,120})["\']',
            )
            for dec_i in range(max(0, i - 4), i + 1):
                dl = lines[dec_i] if dec_i < len(lines) else ""
                for pat in _dec_name_patterns:
                    em = re.search(pat, dl)
                    if em:
                        explicit_tool = em.group(1)
                        break
                if explicit_tool:
                    break
            j = i + 1
            while j < len(lines) and not re.match(r"\s*(?:async\s+)?def\s+", lines[j]):
                j += 1
                if j - i > 8:
                    break
            if j < len(lines):
                defline = lines[j]
                m = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\((.*)", defline)
                if m:
                    func_name = explicit_tool if explicit_tool else m.group(1)
                    sig = m.group(2)
                    k = j
                    while ")" not in sig and k < len(lines) - 1:
                        k += 1
                        sig += lines[k]
                    params = _parse_python_params(sig)
                    body_start = j
                    body_end = _find_python_block_end(lines, j)
                    body = "".join(lines[body_start:body_end])
                    tools.append(
                        MCPTool(
                            name=func_name,
                            file=filepath,
                            line=j + 1,
                            params=params,
                            handler_body=body,
                            handler_start=body_start,
                            handler_end=body_end,
                        )
                    )
        i += 1
    return tools
def _parse_python_params(sig: str) -> list[tuple]:
    sig = re.sub(r"\).*", "", sig)
    params = []
    for part in sig.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"(\w+)", part)
        if m:
            name = m.group(1)
            if name in ("self", "cls", "ctx"):
                continue
            type_hint = ""
            tm = re.search(r":\s*(.+?)(?:\s*=|$)", part)
            if tm:
                type_hint = tm.group(1).strip()
            params.append((name, type_hint))
    return params
def _find_python_block_end(lines: list[str], def_line: int) -> int:
    if def_line >= len(lines):
        return def_line + 1
    m = re.match(r"^(\s*)", lines[def_line])
    base_indent = len(m.group(1)) if m else 0
    i = def_line
    found_colon = False
    while i < len(lines):
        if ":" in lines[i].rstrip().rstrip("#").rstrip():
            stripped = lines[i].rstrip()
            if stripped.endswith(":") or re.search(r":\s*(#.*)?$", stripped):
                found_colon = True
                i += 1
                break
        i += 1
    if not found_colon:
        i = def_line + 1
    body_started = False
    in_docstring = False
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if in_docstring:
            if '"""' in stripped or "'''" in stripped:
                in_docstring = False
            i += 1
            continue
        if stripped.lstrip().startswith(('"""', "'''")):
            if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                in_docstring = True
            i += 1
            if not body_started:
                body_started = True
            continue
        if stripped == "" or stripped.startswith("#"):
            i += 1
            continue
        m = re.match(r"^(\s*)", line)
        indent = len(m.group(1)) if m else 0
        if not body_started:
            if indent > base_indent:
                body_started = True
            i += 1
            continue
        if indent <= base_indent and stripped:
            break
        i += 1
    return i
def discover_ts_mcp_tools_switch(
    filepath: str, lines: list[str], full_text: str
) -> list[MCPTool]:
    tools = []
    has_schema = "CallToolRequestSchema" in full_text
    has_dispatch = bool(
        re.search(
            r"(?:handleToolCall|handleTool|handleRequest)\s*\(.*\bswitch\b",
            full_text,
            re.DOTALL,
        )
    )
    has_mcp_tool_switch = bool(
        re.search(
            r"switch\s*\(\s*(?:name|toolName|params\.name|request\.params\.name|"
            r"\w+\.params\.name)\s*\)",
            full_text,
        )
    )
    if not (has_schema or has_dispatch or has_mcp_tool_switch):
        return tools
    calltool_reg = re.search(
        r"setRequestHandler\s*\(\s*CallToolRequestSchema",
        full_text,
    )
    calltool_line = (
        full_text.count("\n", 0, calltool_reg.start()) if calltool_reg else -1
    )
    for i, line in enumerate(lines):
        if calltool_line >= 0 and has_schema and i < calltool_line:
            continue
        m = re.search(r"case\s+['\"]([\\w-]+)['\"]", line)
        if not m:
            m = re.search(r"case\s+['\"]([a-zA-Z0-9_-]+)['\"]", line)
        if m:
            tool_name = m.group(1)
            if tool_name in _SWITCH_CASE_NON_TOOL_NAMES:
                continue
            if tool_name.lower() in _TS_JSON_SCHEMA_TYPE_NAMES:
                continue
            handler_info = ""
            for k in range(i, min(i + 5, len(lines))):
                handler_info += lines[k]
            tools.append(
                MCPTool(
                    name=tool_name,
                    file=filepath,
                    line=i + 1,
                    params=[("args", "request.params.arguments")],
                    handler_body=handler_info,
                    handler_start=i,
                    handler_end=min(i + 5, len(lines)),
                )
            )
    return tools
def discover_ts_mcp_tools_dynamic_dispatch(
    filepath: str, lines: list[str], full_text: str
) -> list[MCPTool]:
    tools = []
    if "CallToolRequestSchema" not in full_text:
        return tools
    bad_names = frozenset(
        {
            "true",
            "false",
            "null",
            "undefined",
            "default",
            "utf8",
            "utf-8",
            "ascii",
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
            "production",
            "development",
            "test",
            "staging",
        }
    )
    seen = set()
    for m in re.finditer(
        r"if\s*\(\s*(?:name|toolName|params\.name|request\.params\.name|args\.params\.name)\s*[=!]==\s*"
        r'["\']([a-zA-Z][a-zA-Z0-9_.-]{1,63})["\']',
        full_text,
    ):
        nm = m.group(1)
        if (
            nm in bad_names
            or nm.lower() in _TS_JSON_SCHEMA_TYPE_NAMES
            or nm in seen
            or "." in nm
        ):
            continue
        seen.add(nm)
        pos = m.start()
        line_no = full_text.count("\n", 0, pos)
        ctx_end = min(len(lines), line_no + 45)
        handler_body = "".join(lines[line_no:ctx_end])
        tools.append(
            MCPTool(
                name=nm,
                file=filepath,
                line=line_no + 1,
                params=[("args", "request.params.arguments")],
                handler_body=handler_body,
                handler_start=line_no,
                handler_end=ctx_end,
            )
        )
    return tools
def discover_ts_mcp_tools_listtools(
    filepath: str, lines: list[str], full_text: str
) -> list[MCPTool]:
    if "ListToolsRequestSchema" not in full_text:
        return []
    tools = []
    seen = set()
    list_pat = (
        r'name\s*:\s*["\']([a-zA-Z][a-zA-Z0-9_-]{1,63})["\']\s*,\s*'
        r"(?:description|title|inputSchema|annotations|outputSchema|schema)"
    )
    for m in re.finditer(list_pat, full_text, re.I):
        nm = m.group(1)
        if nm.lower() in _TS_JSON_SCHEMA_TYPE_NAMES:
            continue
        if nm in seen:
            continue
        seen.add(nm)
        pos = m.start()
        line_no = full_text.count("\n", 0, pos)
        ctx_end = min(len(lines), line_no + 35)
        handler_body = "".join(lines[line_no:ctx_end])
        tools.append(
            MCPTool(
                name=nm,
                file=filepath,
                line=line_no + 1,
                params=[("args", "request.params.arguments")],
                handler_body=handler_body,
                handler_start=line_no,
                handler_end=ctx_end,
            )
        )
    rev_pat = (
        r"(?:description|title|inputSchema|annotations|schema|outputSchema)\s*:\s*[^,\n]{1,800},"
        r'[\s\n]*name\s*:\s*["\']([a-zA-Z][a-zA-Z0-9_-]{1,63})["\']'
    )
    for m in re.finditer(rev_pat, full_text, re.I):
        nm = m.group(1)
        if nm.lower() in _TS_JSON_SCHEMA_TYPE_NAMES:
            continue
        if nm in seen:
            continue
        seen.add(nm)
        pos = m.start()
        line_no = full_text.count("\n", 0, pos)
        ctx_end = min(len(lines), line_no + 35)
        handler_body = "".join(lines[line_no:ctx_end])
        tools.append(
            MCPTool(
                name=nm,
                file=filepath,
                line=line_no + 1,
                params=[("args", "request.params.arguments")],
                handler_body=handler_body,
                handler_start=line_no,
                handler_end=ctx_end,
            )
        )
    return tools
def discover_ts_tool_handlers(project_path: str) -> dict:
    handlers = {}
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            if not fname.endswith((".ts", ".js")):
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (PermissionError, OSError):
                continue
            for i, line in enumerate(lines):
                m = re.match(
                    r"\s*(?:(?:export|private|public|protected|static)\s+)*"
                    r"(?:async\s+)?(handle\w+|toolHandler|\w+Handler)\s*\(\s*(\w+)",
                    line,
                )
                if m:
                    fn_name = m.group(1)
                    param = m.group(2)
                    if fn_name in handlers or fn_name == "setRequestHandler":
                        continue
                    end = _find_ts_block_end(lines, i)
                    body = "".join(lines[i:end])
                    handlers[fn_name] = (fpath, i, end, param, body)
                    continue
                m = re.match(
                    r"\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(\s*(\w+)\s*:",
                    line,
                )
                if m:
                    fn_name = m.group(1)
                    param = m.group(2)
                    if fn_name in handlers:
                        continue
                    if fn_name.startswith(("handle", "process", "execute", "run")):
                        end = _find_ts_block_end(lines, i)
                        body = "".join(lines[i:end])
                        handlers[fn_name] = (fpath, i, end, param, body)
    return handlers
def _find_ts_block_end(lines: list[str], start: int) -> int:
    paren_depth = 0
    paren_closed = False
    angle_depth = 0
    body_start_found = False
    body_line = start
    body_col = 0
    for i in range(start, min(start + 30, len(lines))):
        for ci, ch in enumerate(lines[i]):
            if not paren_closed:
                if ch == "(":
                    paren_depth += 1
                elif ch == ")":
                    paren_depth -= 1
                    if paren_depth == 0:
                        paren_closed = True
            else:
                if ch == "<":
                    angle_depth += 1
                elif ch == ">" and angle_depth > 0:
                    angle_depth -= 1
                elif ch == "{" and angle_depth == 0:
                    body_line = i
                    body_col = ci
                    body_start_found = True
                    break
        if body_start_found:
            break
    if not body_start_found:
        return min(start + 100, len(lines))
    depth = 0
    for i in range(body_line, len(lines)):
        line = lines[i]
        start_col = body_col if i == body_line else 0
        for ci in range(start_col, len(line)):
            ch = line[ci]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
    return min(start + 100, len(lines))
def _params_from_ts_async_handler_sig(sig: str) -> list[tuple[str, str]]:
    sig = sig.strip()
    if not sig:
        return [("args", "implicit-empty-args")]
    if sig.startswith("{"):
        end = sig.rfind("}")
        inner = sig[1:end] if end > 0 else sig[1:]
        params = []
        for p in inner.split(","):
            p = p.strip().split(":")[0].strip().split("=")[0].strip()
            if p and re.match(r"^\w+$", p):
                params.append((p, "destructured"))
        return params or [("args", "destructured")]
    out = []
    for part in sig.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"(\w+)", part)
        if m and m.group(1) not in ("self",):
            out.append((m.group(1), "handler-param"))
    return out or [("args", "handler-args")]
def discover_ts_mcp_tools_inline(
    filepath: str, lines: list[str], full_text: str
) -> list[MCPTool]:
    tools = []
    for m in re.finditer(
        r'(?:\w+\.)?(?:tool|defineTool|defineTabTool|registerTool)\s*\(\s*["\']([^"\']+)["\']\s*,',
        full_text,
    ):
        tool_name = m.group(1)
        rest_start = m.end()
        window = full_text[rest_start : rest_start + 5000]
        async_in_window = re.search(r"\basync\s*\(", window)
        zod_window = window[: async_in_window.start()] if async_in_window else window
        params = []
        zod_m = re.search(r"\{([^}]{1,3000})\}", zod_window)
        if zod_m:
            schema_block = zod_m.group(1)
            for pm in re.finditer(r"(\w+)\s*:\s*(?:z\.\w+|[\w.]*z\.\w+)", schema_block):
                pname = pm.group(1)
                if pname not in (
                    "type",
                    "description",
                    "default",
                    "optional",
                    "enum",
                    "properties",
                    "required",
                ):
                    params.append((pname, "z.schema"))
        handler_m = re.search(r"async\s*\(\s*\)\s*=>\s*\{", window)
        empty_async_handler = handler_m is not None
        if not handler_m:
            handler_m = re.search(r"async\s*\(([^)]*)\)\s*=>\s*\{", window)
        if handler_m:
            handler_start_in_rest = handler_m.end() - 1 + rest_start
            prefix = full_text[:handler_start_in_rest]
            handler_line = prefix.count("\n")
            if not params:
                if empty_async_handler:
                    params.append(("args", "implicit-empty-args"))
                elif handler_m.lastindex and handler_m.group(1) is not None:
                    params.extend(_params_from_ts_async_handler_sig(handler_m.group(1)))
            body_end = _find_ts_block_end(lines, handler_line)
            body = "".join(lines[handler_line:body_end])
            tools.append(
                MCPTool(
                    name=tool_name,
                    file=filepath,
                    line=handler_line + 1,
                    params=params,
                    handler_body=body,
                    handler_start=handler_line,
                    handler_end=body_end,
                )
            )
        elif params:
            tools.append(
                MCPTool(
                    name=tool_name,
                    file=filepath,
                    line=1,
                    params=params,
                )
            )
    for m in re.finditer(
        r"(?:\w+\.)?(?:tool|defineTool|defineTabTool|registerTool)\s*\(\s*`([^`${}]{1,120})`\s*,",
        full_text,
    ):
        tool_name = m.group(1).strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,120}$", tool_name):
            continue
        rest_start = m.end()
        window = full_text[rest_start : rest_start + 5000]
        async_in_window = re.search(r"\basync\s*\(", window)
        zod_window = window[: async_in_window.start()] if async_in_window else window
        params = []
        zod_m = re.search(r"\{([^}]{1,3000})\}", zod_window)
        if zod_m:
            schema_block = zod_m.group(1)
            for pm in re.finditer(r"(\w+)\s*:\s*(?:z\.\w+|[\w.]*z\.\w+)", schema_block):
                pname = pm.group(1)
                if pname not in (
                    "type",
                    "description",
                    "default",
                    "optional",
                    "enum",
                    "properties",
                    "required",
                ):
                    params.append((pname, "z.schema"))
        handler_m = re.search(r"async\s*\(\s*\)\s*=>\s*\{", window)
        empty_async_handler = handler_m is not None
        if not handler_m:
            handler_m = re.search(r"async\s*\(([^)]*)\)\s*=>\s*\{", window)
        if handler_m:
            handler_start_in_rest = handler_m.end() - 1 + rest_start
            prefix = full_text[:handler_start_in_rest]
            handler_line = prefix.count("\n")
            if not params:
                if empty_async_handler:
                    params.append(("args", "implicit-empty-args"))
                elif handler_m.lastindex and handler_m.group(1) is not None:
                    params.extend(_params_from_ts_async_handler_sig(handler_m.group(1)))
            body_end = _find_ts_block_end(lines, handler_line)
            body = "".join(lines[handler_line:body_end])
            tools.append(
                MCPTool(
                    name=tool_name,
                    file=filepath,
                    line=handler_line + 1,
                    params=params,
                    handler_body=body,
                    handler_start=handler_line,
                    handler_end=body_end,
                )
            )
        elif params:
            tools.append(
                MCPTool(
                    name=tool_name,
                    file=filepath,
                    line=1,
                    params=params,
                )
            )
    if "definePageTool" in full_text:
        for m in re.finditer(r"definePageTool\s*\(\s*\{", full_text):
            window = full_text[m.end() : m.end() + 8000]
            nm = re.search(
                r"""name\s*:\s*['"]([a-zA-Z][a-zA-Z0-9_-]{1,120})['"]""",
                window,
            )
            if not nm:
                continue
            tool_name = nm.group(1)
            params = []
            sch = re.search(r"schema\s*:\s*\{", window)
            if sch:
                sub = window[sch.end() : sch.end() + 4000]
                for pm in re.finditer(r"(\w+)\s*:\s*(?:zod|z)\.", sub):
                    pname = pm.group(1)
                    if pname in (
                        "type",
                        "description",
                        "default",
                        "optional",
                        "enum",
                        "properties",
                        "required",
                        "name",
                    ):
                        continue
                    params.append((pname, "z.schema"))
            if not params:
                params = [("params", "definePageTool-params")]
            h_m = re.search(r"handler\s*:\s*async", window)
            if h_m:
                abs_pos = m.end() + h_m.start()
                handler_line = full_text.count("\n", 0, abs_pos)
                body_end = _find_ts_block_end(lines, handler_line)
                body = "".join(lines[handler_line:body_end])
            else:
                handler_line = full_text.count("\n", 0, m.start() + nm.start())
                body = window[:5000]
                body_end = min(len(lines), handler_line + 120)
            tools.append(
                MCPTool(
                    name=tool_name,
                    file=filepath,
                    line=handler_line + 1,
                    params=params,
                    handler_body=body,
                    handler_start=handler_line,
                    handler_end=body_end,
                )
            )
    return tools
def _build_project_ts_string_constants(project_path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    ts_ext = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in ts_ext:
                continue
            fname_lower = fname.lower()
            if any(
                fname_lower.startswith(p) or p in fname_lower
                for p in SKIP_FILE_PATTERNS
            ):
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except (PermissionError, OSError):
                continue
            for m in re.finditer(
                r'(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*["\']([^"\'\\]{1,200})["\']',
                text,
            ):
                out[m.group(1)] = m.group(2)
    return out
def _ts_file_mcp_context_hint(filepath: str, full_text: str) -> bool:
    if any(
        s in full_text
        for s in (
            "@modelcontextprotocol",
            "modelcontextprotocol",
            "CallToolResult",
            "ListToolsRequestSchema",
            "CallToolRequestSchema",
            "RegisteredTool",
            "ToolBase",
            "ToolWithHandler",
            "registerTool",
            "McpServer",
        )
    ):
        return True
    fp = filepath.replace("\\", "/").lower()
    return (
        "/mcp/tools/" in fp or "/mcp/tool/" in fp or fp.endswith("/mcp/tools/index.ts")
    )
def _ts_class_tool_file_evidence(full_text: str, filepath: str) -> bool:
    if re.search(r"extends\s+\w*ToolBase\b", full_text):
        return True
    fp = filepath.replace("\\", "/").lower()
    if "/tools/" in fp:
        if (
            re.search(r"\b(?:async\s+)?execute\s*\(", full_text)
            or "argsShape" in full_text
        ):
            return True
    if "CallToolResult" in full_text and re.search(
        r"\b(?:async\s+)?execute\s*\(", full_text
    ):
        return True
    return False
def discover_ts_mcp_tools_register_object_literal(
    filepath: str,
    lines: list[str],
    full_text: str,
    const_map: dict[str, str],
) -> list[MCPTool]:
    tools: list[MCPTool] = []
    if ".registerTool" not in full_text and "registerTool({" not in full_text:
        return tools
    if not _ts_file_mcp_context_hint(filepath, full_text):
        return tools
    for m in re.finditer(r"\.registerTool\s*\(\s*\{", full_text):
        start = m.end()
        window = full_text[start : start + 14000]
        lit_m = re.search(r'name\s*:\s*["\']([^"\']+)["\']', window)
        if lit_m:
            name = lit_m.group(1)
        else:
            id_m = re.search(r"name\s*:\s*([A-Za-z_]\w*)\s*[,}]", window)
            if not id_m:
                continue
            ident = id_m.group(1)
            if ident in ("true", "false", "null", "undefined", "async", "await"):
                continue
            name = const_map.get(ident)
            if not name:
                continue
        h_async = re.search(r"handler\s*:\s*async\s*\(", window)
        h_plain = re.search(r"handler\s*:\s*\(", window) if not h_async else None
        handler_m = h_async or h_plain
        if not handler_m:
            params = [("args", "registerTool-args")]
            line_no = full_text.count("\n", 0, start)
            tools.append(
                MCPTool(
                    name=name,
                    file=filepath,
                    line=line_no + 1,
                    params=params,
                    handler_body=window[:6000],
                    handler_start=line_no,
                    handler_end=min(len(lines), line_no + 400),
                )
            )
            continue
        rel = handler_m.start()
        prefix = full_text[: start + rel]
        handler_line = prefix.count("\n")
        body_end = _find_ts_block_end(lines, handler_line)
        body = "".join(lines[handler_line:body_end])
        params = []
        for pm in re.finditer(r"(\w+)\s*:\s*z\.", window[: handler_m.start()]):
            pname = pm.group(1)
            if pname not in (
                "type",
                "description",
                "default",
                "optional",
                "enum",
                "properties",
                "required",
                "name",
            ):
                params.append((pname, "z.schema"))
        if not params:
            params = [("args", "registerTool-args")]
        tools.append(
            MCPTool(
                name=name,
                file=filepath,
                line=handler_line + 1,
                params=params,
                handler_body=body,
                handler_start=handler_line,
                handler_end=body_end,
            )
        )
    return tools
def discover_ts_mcp_tools_class_instance_name(
    filepath: str, lines: list[str], full_text: str
) -> list[MCPTool]:
    tools: list[MCPTool] = []
    if "name" not in full_text or "=" not in full_text:
        return tools
    if not _ts_file_mcp_context_hint(filepath, full_text):
        return tools
    if not _ts_class_tool_file_evidence(full_text, filepath):
        return tools
    for m in re.finditer(
        r'(?:^|\n)\s*(?:public\s+)?(?:override\s+)?name\s*=\s*["\']([a-zA-Z][a-zA-Z0-9_.-]{0,120})["\']',
        full_text,
    ):
        name = m.group(1)
        if "." in name:
            continue
        pos = m.start()
        line_no = full_text.count("\n", 0, pos)
        exec_line = None
        for i in range(line_no, min(line_no + 220, len(lines))):
            if re.search(r"\b(?:async\s+)?execute\s*\(", lines[i]):
                exec_line = i
                break
        if exec_line is not None:
            body_end = _find_ts_block_end(lines, exec_line)
            body = "".join(lines[exec_line:body_end])
            h_start, h_end = exec_line, body_end
        else:
            body = "".join(lines[line_no:])
            h_start, h_end = line_no, len(lines)
        chunk_for_zod = full_text[pos : pos + 4500]
        params = []
        for pm in re.finditer(r"(\w+)\s*:\s*z\.", chunk_for_zod):
            pname = pm.group(1)
            if pname not in (
                "type",
                "description",
                "default",
                "optional",
                "enum",
                "properties",
                "required",
                "name",
            ):
                params.append((pname, "z.schema"))
        if not params:
            params = [("args", "execute-args")]
        tools.append(
            MCPTool(
                name=name,
                file=filepath,
                line=line_no + 1,
                params=params,
                handler_body=body,
                handler_start=h_start,
                handler_end=h_end,
            )
        )
    return tools
def discover_ts_mcp_tools_export_default_tool_module(
    filepath: str,
    lines: list[str],
    full_text: str,
) -> list[MCPTool]:
    tools: list[MCPTool] = []
    if "export default" not in full_text or "name" not in full_text:
        return tools
    if not re.search(r"export\s+default\s*\{", full_text):
        return tools
    if not re.search(r"\b(?:handler|logicFunction)\s*:", full_text):
        return tools
    if not _ts_file_mcp_context_hint(filepath, full_text):
        return tools
    for m in re.finditer(r"export\s+default\s*\{", full_text):
        window = full_text[m.end() : m.end() + 5000]
        nm = re.search(r"""name\s*:\s*['"]([a-zA-Z][a-zA-Z0-9_-]{1,120})['"]""", window)
        if not nm:
            continue
        name = nm.group(1)
        line_no = full_text.count("\n", 0, m.start() + nm.start())
        h_m = re.search(r"\bhandler\s*:", window)
        logic_m = re.search(r"\blogicFunction\s*:", window)
        anchor = h_m or logic_m
        if anchor:
            abs_pos = m.end() + anchor.start()
            handler_line = full_text.count("\n", 0, abs_pos)
            body_end = _find_ts_block_end(lines, handler_line)
            body = "".join(lines[handler_line:body_end])
            h_start, h_end = handler_line, body_end
        else:
            body = window
            h_start = line_no
            h_end = min(len(lines), line_no + 80)
        params = []
        for pm in re.finditer(r"(\w+)\s*:\s*z\.", window):
            pname = pm.group(1)
            if pname not in (
                "type",
                "description",
                "default",
                "optional",
                "enum",
                "properties",
                "required",
                "name",
            ):
                params.append((pname, "z.schema"))
        if not params:
            params = [("args", "tool-module-args")]
        tools.append(
            MCPTool(
                name=name,
                file=filepath,
                line=line_no + 1,
                params=params,
                handler_body=body,
                handler_start=h_start,
                handler_end=h_end,
            )
        )
        break
    return tools
def discover_ts_mcp_tools_named_export_const_object(
    filepath: str,
    lines: list[str],
    full_text: str,
) -> list[MCPTool]:
    tools: list[MCPTool] = []
    if "export const" not in full_text:
        return tools
    if not _ts_file_mcp_context_hint(filepath, full_text):
        return tools
    fp = filepath.replace("\\", "/").lower()
    if "/tools/" not in fp and "/tool/" not in fp:
        return tools
    for m in re.finditer(r"export\s+const\s+\w+\s*(?::\s*[^{]+)?\s*=\s*\{", full_text):
        start_body = m.end()
        window = full_text[start_body : start_body + 16000]
        if not re.search(r"\bhandler\s*:", window[:12000]):
            continue
        nm = re.search(
            r'^\s*name\s*:\s*["\']([a-zA-Z][a-zA-Z0-9_.-]{0,120})["\']',
            window,
            re.M,
        )
        if not nm:
            continue
        name = nm.group(1)
        if name.lower() in _TS_JSON_SCHEMA_TYPE_NAMES:
            continue
        line_no = full_text.count("\n", 0, m.start() + nm.start())
        h_m = re.search(r"\bhandler\s*:", window)
        if not h_m:
            continue
        abs_pos = start_body + h_m.start()
        handler_line = full_text.count("\n", 0, abs_pos)
        body_end = _find_ts_block_end(lines, handler_line)
        body = "".join(lines[handler_line:body_end])
        params = []
        for pm in re.finditer(r"(\w+)\s*:\s*z\.", window[: h_m.start()]):
            pname = pm.group(1)
            if pname not in (
                "type",
                "description",
                "default",
                "optional",
                "enum",
                "properties",
                "required",
                "name",
            ):
                params.append((pname, "z.schema"))
        if not params and re.search(r"\binputSchema\s*:", window[: h_m.start()]):
            params.append(("args", "inputSchema-args"))
        elif not params:
            params.append(("args", "named-export-tool-args"))
        tools.append(
            MCPTool(
                name=name,
                file=filepath,
                line=line_no + 1,
                params=params,
                handler_body=body,
                handler_start=handler_line,
                handler_end=body_end,
            )
        )
    return tools
def discover_ts_mcp_tools_calltool_exclusive_guard(
    filepath: str,
    lines: list[str],
    full_text: str,
) -> list[MCPTool]:
    if "CallToolRequestSchema" not in full_text:
        return []
    idx = full_text.find("setRequestHandler(CallToolRequestSchema")
    if idx < 0:
        idx = full_text.find("setRequestHandler(CallToolRequestSchema,")
    if idx < 0:
        idx = full_text.find("CallToolRequestSchema")
    window = full_text[idx : idx + 12000]
    if not re.search(r"params\.name|\.params\.name", window[:3500]):
        return []
    neg_m = re.search(
        r'if\s*\(\s*\w+\s*!==\s*["\']([a-zA-Z][a-zA-Z0-9_-]{1,64})["\']\s*\)',
        window,
    )
    if not neg_m:
        return []
    name = neg_m.group(1)
    if name.lower() in (
        "true",
        "false",
        "null",
        "default",
        "undefined",
        "utf8",
        "production",
        "development",
    ):
        return []
    line_no = full_text.count("\n", 0, idx + neg_m.start())
    ctx_end = min(len(lines), line_no + 120)
    body = "".join(lines[line_no:ctx_end])
    return [
        MCPTool(
            name=name,
            file=filepath,
            line=line_no + 1,
            params=[("args", "request.params.arguments")],
            handler_body=body,
            handler_start=line_no,
            handler_end=ctx_end,
        )
    ]
def discover_bundled_tools(project_path: str) -> list[MCPTool]:
    tools = []
    nm_dir = os.path.join(project_path, "node_modules")
    if not os.path.isdir(nm_dir):
        return tools
    for root, dirs, files in os.walk(nm_dir):
        rel = os.path.relpath(root, nm_dir)
        rel_l = rel.lower()
        if "mcp" not in rel_l and "playwright/lib/mcp" not in rel_l:
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
            continue
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        for fname in files:
            if not fname.endswith((".js", ".mjs", ".cjs")):
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    flines = content.splitlines(keepends=True)
            except (PermissionError, OSError):
                continue
            for m in re.finditer(
                r'name:\s*["\']([a-zA-Z][a-zA-Z0-9_-]*)["\']', content
            ):
                tool_name = m.group(1)
                params = []
                for pm in re.finditer(
                    r"(\w+)\s*:\s*\w*\.?z\.(?:string|number|boolean|object|array)",
                    content,
                ):
                    pname = pm.group(1)
                    if pname not in ("type", "description", "default"):
                        params.append((pname, "z.schema"))
                if not params:
                    # Fallback for bundled/minified files: infer tool params from handler usage.
                    for pm in re.finditer(r"\bparams\.(\w+)\b", content):
                        pname = pm.group(1)
                        if pname not in ("type", "description", "default", "name"):
                            params.append((pname, "handler-param"))
                if not params:
                    # Keep analyzing even when schema parsing fails.
                    params.append(("args", "request.params.arguments"))
                params = list(dict.fromkeys(params))
                tools.append(
                    MCPTool(
                        name=tool_name,
                        file=fpath,
                        line=1,
                        params=params,
                        handler_body=content,
                        handler_start=0,
                        handler_end=len(flines),
                    )
                )
    return tools
def discover_cross_file_links(
    tools: list[MCPTool], project_path: str
) -> list[CrossFileLink]:
    links = []
    for tool in tools:
        body = tool.handler_body
        for m in re.finditer(r'send_command\s*\(\s*["\'](\w+)["\']\s*,\s*\{', body):
            cmd_name = m.group(1)
            start = m.end()
            depth = 1
            end = start
            for ci in range(start, min(start + 1000, len(body))):
                if body[ci] == "{":
                    depth += 1
                elif body[ci] == "}":
                    depth -= 1
                    if depth == 0:
                        end = ci
                        break
            params_block = body[start:end]
            forwarded = {}
            for pm in re.finditer(r'["\']?(\w+)["\']?\s*:\s*(\w+)', params_block):
                forwarded[pm.group(1)] = pm.group(2)
            all_handlers = _find_all_remote_handlers(project_path, cmd_name)
            for target_file, target_method, t_start, t_end, t_body in all_handlers:
                links.append(
                    CrossFileLink(
                        source_file=tool.file,
                        source_tool=tool.name,
                        command_name=cmd_name,
                        forwarded_params=forwarded,
                        target_file=target_file,
                        target_method=target_method,
                        target_start=t_start,
                        target_end=t_end,
                        target_body=t_body,
                    )
                )
        for m in re.finditer(
            r'send_command\s*\(\s*["\'](\w+)["\']\s*,\s*(\w+)\s*\)', body
        ):
            cmd_name = m.group(1)
            kwargs_var = m.group(2)
            forwarded = {}
            for km in re.finditer(
                rf"{re.escape(kwargs_var)}\s*=\s*\{{([^}}]*)\}}", body
            ):
                for pm in re.finditer(r'["\']?(\w+)["\']?\s*:\s*(\w+)', km.group(1)):
                    forwarded[pm.group(1)] = pm.group(2)
            for km in re.finditer(
                rf'{re.escape(kwargs_var)}\s*\[\s*["\'](\w+)["\']\s*\]\s*=\s*(\w+)',
                body,
            ):
                forwarded[km.group(1)] = km.group(2)
            for p_name, _ in tool.params:
                if p_name in forwarded.values():
                    continue
                if re.search(
                    rf"\b{re.escape(p_name)}\b", body[body.find(kwargs_var) :]
                ):
                    forwarded.setdefault(p_name, p_name)
            all_handlers = _find_all_remote_handlers(project_path, cmd_name)
            for target_file, target_method, t_start, t_end, t_body in all_handlers:
                if forwarded:
                    links.append(
                        CrossFileLink(
                            source_file=tool.file,
                            source_tool=tool.name,
                            command_name=cmd_name,
                            forwarded_params=forwarded,
                            target_file=target_file,
                            target_method=target_method,
                            target_start=t_start,
                            target_end=t_end,
                            target_body=t_body,
                        )
                    )
    return links
def _find_remote_handler(project_path: str, command_name: str):
    return _find_remote_handlers_all(project_path, command_name)
def _find_remote_handlers_all(project_path: str, command_name: str):
    exact = None
    prefix_matches = []
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (PermissionError, OSError):
                continue
            for i, line in enumerate(lines):
                m_exact = re.search(rf"def\s+{re.escape(command_name)}\s*\(", line)
                if m_exact:
                    end = _find_python_block_end(lines, i)
                    body = "".join(lines[i:end])
                    return fpath, command_name, i, end, body
                m_prefix = re.search(
                    rf"def\s+({re.escape(command_name)}_\w+)\s*\(", line
                )
                if m_prefix:
                    func_name = m_prefix.group(1)
                    end = _find_python_block_end(lines, i)
                    body = "".join(lines[i:end])
                    prefix_matches.append((fpath, func_name, i, end, body))
                if re.search(rf'["\']{re.escape(command_name)}["\']', line):
                    m2 = re.search(r"self\.(\w+)", line)
                    if m2:
                        method = m2.group(1)
                        for j, l2 in enumerate(lines):
                            if re.search(rf"def\s+{re.escape(method)}\s*\(", l2):
                                end = _find_python_block_end(lines, j)
                                body = "".join(lines[j:end])
                                return fpath, method, j, end, body
    if prefix_matches:
        return prefix_matches[0]
    return None, None, 0, 0, ""
def _find_all_remote_handlers(project_path: str, command_name: str):
    results = []
    seen_funcs = set()
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (PermissionError, OSError):
                continue
            for i, line in enumerate(lines):
                m_exact = re.search(rf"def\s+{re.escape(command_name)}\s*\(", line)
                m_prefix = re.search(
                    rf"def\s+({re.escape(command_name)}_\w+)\s*\(", line
                )
                if m_exact:
                    if command_name not in seen_funcs:
                        end = _find_python_block_end(lines, i)
                        body = "".join(lines[i:end])
                        results.append((fpath, command_name, i, end, body))
                        seen_funcs.add(command_name)
                elif m_prefix:
                    func_name = m_prefix.group(1)
                    if func_name not in seen_funcs:
                        end = _find_python_block_end(lines, i)
                        body = "".join(lines[i:end])
                        results.append((fpath, func_name, i, end, body))
                        seen_funcs.add(func_name)
    return results
def check_taint_reaches_sink(
    param_name: str,
    body: str,
    body_lines: list[str],
    body_start: int,
    sink_pattern: str,
    rule_id: str,
) -> list[tuple]:
    hits = []
    lang = "py" if rule_id.endswith("PY") else "js"
    tainted_vars = {param_name}
    _propagate_taint(body_lines, tainted_vars, param_name)
    for i, line in enumerate(body_lines):
        if not re.search(sink_pattern, line):
            continue
        if any(re.search(sp, line) for sp in SAFE_SINK_PATTERNS):
            continue
        sink_is_tainted = False
        taint_var = None
        lhs_vars = set()
        lhs_m = re.match(r"^\s*(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=", line)
        if lhs_m:
            if lhs_m.group(1):
                for part in lhs_m.group(1).split(","):
                    for name in re.findall(r"(\w+)", part):
                        lhs_vars.add(name)
            elif lhs_m.group(2):
                lhs_vars.add(lhs_m.group(2))
        py_lhs = re.match(r"^\s*(\w+)\s*=\s*", line)
        if py_lhs:
            lhs_vars.add(py_lhs.group(1))
        for tv in tainted_vars:
            if tv in lhs_vars:
                continue
            if re.search(rf"\b{re.escape(tv)}\b", line):
                sink_is_tainted = True
                taint_var = tv
                break
        if not sink_is_tainted:
            for tv in tainted_vars:
                if tv in lhs_vars:
                    continue
                dollar_pat = rf"\$\{{\s*{re.escape(tv)}"
                brace_pat = r"\{" + re.escape(tv) + r"\}"
                if re.search(dollar_pat, line) or re.search(brace_pat, line):
                    sink_is_tainted = True
                    taint_var = tv
                    break
        if not sink_is_tainted:
            continue
        if "REDOS" in rule_id:
            redos_ok = False
            rm = re.search(r"new\s+RegExp\s*\(\s*([^,\)]+)", line)
            if rm:
                first_arg = rm.group(1)
                if re.search(rf"\b{re.escape(taint_var)}\b", first_arg):
                    redos_ok = True
            rm = re.search(r"re\.compile\s*\(\s*([^,\)]+)", line)
            if rm:
                first_arg = rm.group(1)
                if re.search(rf"\b{re.escape(taint_var)}\b", first_arg):
                    redos_ok = True
            if not redos_ok:
                continue
        context_block = "".join(body_lines[max(0, i - 30) : i + 1])
        sanitizer_found = None
        for vuln_key, patterns in SANITIZER_PATTERNS.items():
            if vuln_key in _get_vuln_category(rule_id):
                for pat in patterns:
                    if re.search(pat, context_block, re.IGNORECASE):
                        sanitizer_found = pat
                        break
        if sanitizer_found:
            continue
        abs_line = body_start + i + 1
        chain = f"{param_name}"
        if taint_var != param_name:
            chain = f"{param_name} → {taint_var}"
        hits.append((abs_line, line.strip(), chain))
    return hits
def _file_split_call_args(inner: str) -> list[str]:
    if not inner or not inner.strip():
        return []
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for c in inner:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]
def _file_find_paren_arg_region(line: str, open_paren_idx: int) -> Optional[str]:
    if open_paren_idx < 0 or open_paren_idx >= len(line) or line[open_paren_idx] != "(":
        return None
    depth = 0
    for i in range(open_paren_idx, len(line)):
        c = line[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return line[open_paren_idx + 1 : i]
    return None
def _file_expr_mentions_tainted(expr: str, tainted_vars: set, lhs_vars: set) -> bool:
    if not expr or not expr.strip():
        return False
    for tv in tainted_vars:
        if tv in lhs_vars:
            continue
        if re.search(rf"\b{re.escape(tv)}\b", expr):
            return True
        if re.search(rf"\$\{{\s*{re.escape(tv)}", expr):
            return True
        if re.search(r"\{" + re.escape(tv) + r"\}", expr):
            return True
    return False
def _file_js_sink_classifications(
    line: str,
    tainted_vars: set,
    lhs_vars: set,
) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    js_writes = [
        r"fs\.promises\.(?:writeFile|appendFile)\s*\(\s*",
        r"(?<![\w.])fs\.writeFile(?:Sync)?\s*\(\s*",
        r"fs\.appendFile(?:Sync)?\s*\(\s*",
        r"(?<![\w.])writeFile\s*\(\s*",
    ]
    for pat in js_writes:
        for m in re.finditer(pat, line):
            lp = m.end() - 1
            if lp < 0 or line[lp] != "(":
                continue
            region = _file_find_paren_arg_region(line, lp)
            if region is None:
                continue
            parts = _file_split_call_args(region)
            path_ex = parts[0] if len(parts) >= 1 else ""
            data_ex = parts[1] if len(parts) >= 2 else ""
            data_t = _file_expr_mentions_tainted(data_ex, tainted_vars, lhs_vars)
            if data_t and path_ex.strip():
                hits.append(("file_injection", "FILE-07-CONTENT-JS"))
    return hits
def _file_js_mkdir_classifications(
    line: str,
    tainted_vars: set,
    lhs_vars: set,
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    mkdir_pats = [
        r"fs\.promises\.mkdir\s*\(\s*",
        r"(?<![\w.])fs\.mkdir(?:Sync)?\s*\(\s*",
        r"(?<![\w.])mkdir(?:Sync)?\s*\(\s*",
    ]
    for pat in mkdir_pats:
        for m in re.finditer(pat, line):
            lp = m.end() - 1
            if lp < 0 or line[lp] != "(":
                continue
            region = _file_find_paren_arg_region(line, lp)
            if not region:
                continue
            parts = _file_split_call_args(region)
            path_ex = parts[0] if parts else ""
            if _file_expr_mentions_tainted(path_ex, tainted_vars, lhs_vars):
                out.append(("file_injection", "FILE-06-MKDIR-JS"))
    return out
def _file_py_sink_classifications(
    line: str, tainted_vars: set, lhs_vars: set
) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for m in re.finditer(
        r"Path\s*\(([^)]*)\)\s*\.\s*write_(?:text|bytes)\s*\(\s*",
        line,
    ):
        path_ex = m.group(1)
        tail = line[m.end() :]
        rp = tail.find("(")
        if rp < 0:
            continue
        region = _file_find_paren_arg_region(tail, rp)
        if not region:
            continue
        parts = _file_split_call_args(region)
        c0 = parts[0] if parts else ""
        pt_cont = _file_expr_mentions_tainted(c0, tainted_vars, lhs_vars)
        if pt_cont:
            hits.append(("file_injection", "FILE-07-CONTENT-PY"))
    return hits
def _file_py_mkdir_classifications(
    line: str, tainted_vars: set, lhs_vars: set
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for _, pat in (
        ("makedirs", r"\bos\.makedirs\s*\(\s*"),
        ("mkdir", r"\bos\.mkdir\s*\(\s*"),
    ):
        for m in re.finditer(pat, line):
            rp = line.find("(", m.start())
            region = _file_find_paren_arg_region(line, rp)
            if not region:
                continue
            parts = _file_split_call_args(region)
            p0 = parts[0] if parts else ""
            if _file_expr_mentions_tainted(p0, tainted_vars, lhs_vars):
                out.append(("file_injection", "FILE-06-MKDIR-PY"))
    for m in re.finditer(r"Path\s*\(([^)]*)\)\s*\.\s*mkdir\s*\(\s*", line):
        path_ex = m.group(1)
        if _file_expr_mentions_tainted(path_ex, tainted_vars, lhs_vars):
            out.append(("file_injection", "FILE-06-MKDIR-PY"))
    return out
def check_file_injection_hits(
    param_name: str,
    body_lines: list[str],
    body_start: int,
    lang: str,
) -> list[tuple]:
    out: list[tuple] = []
    tainted_vars = {param_name}
    _propagate_taint(body_lines, tainted_vars, param_name)
    for i, line in enumerate(body_lines):
        lhs_vars: set[str] = set()
        lhs_m = re.match(
            r"^\s*(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=",
            line,
        )
        if lhs_m:
            if lhs_m.group(1):
                for part in lhs_m.group(1).split(","):
                    for name in re.findall(r"(\w+)", part):
                        lhs_vars.add(name)
            elif lhs_m.group(2):
                lhs_vars.add(lhs_m.group(2))
        py_lhs = re.match(r"^\s*(\w+)\s*=\s*", line)
        if py_lhs:
            lhs_vars.add(py_lhs.group(1))
        if lang == "js":
            kinds = _file_js_sink_classifications(line, tainted_vars, lhs_vars)
            kinds.extend(_file_js_mkdir_classifications(line, tainted_vars, lhs_vars))
        else:
            kinds = _file_py_sink_classifications(line, tainted_vars, lhs_vars)
            kinds.extend(_file_py_mkdir_classifications(line, tainted_vars, lhs_vars))
        kinds = list(dict.fromkeys(kinds))
        if not kinds:
            continue
        context_block = "".join(body_lines[max(0, i - 30) : i + 1])
        sanitizer_found = False
        for pat in SANITIZER_PATTERNS.get("File Injection", []):
            if re.search(pat, context_block, re.IGNORECASE):
                sanitizer_found = True
                break
        if sanitizer_found:
            kinds = [(fk, rid) for fk, rid in kinds if rid.startswith("FILE-06-MKDIR")]
            if not kinds:
                continue
        abs_line = body_start + i + 1
        for finding_kind, rule_id in kinds:
            tv_used = param_name
            for tv in tainted_vars:
                if tv in lhs_vars:
                    continue
                if tv in line and re.search(rf"\b{re.escape(tv)}\b", line):
                    tv_used = tv
                    break
            chain = param_name if tv_used == param_name else f"{param_name} → {tv_used}"
            out.append((abs_line, line.strip(), chain, rule_id, finding_kind))
    return out
def _propagate_taint(lines: list[str], tainted: set, seed: str):
    full = "".join(lines)
    changed = True
    iterations = 0
    while changed and iterations < 8:
        changed = False
        iterations += 1
        for tv in list(tainted):
            tv_esc = re.escape(tv)
            for i, line in enumerate(lines):
                if "." in tv:
                    base_obj, field_name = tv.split(".", 1)
                    if base_obj in line:
                        base_esc = re.escape(base_obj)
                        for alias_pat in [
                            rf"^\s*(?:const|let|var)\s+(\w+)\s*=\s*{base_esc}\b",
                            rf"^\s*(\w+)\s*=\s*{base_esc}\b",
                        ]:
                            m_alias = re.match(alias_pat, line)
                            if m_alias:
                                alias = m_alias.group(1)
                                if alias != base_obj:
                                    new_tv = f"{alias}.{field_name}"
                                    if new_tv not in tainted:
                                        tainted.add(new_tv)
                                        changed = True
                                break
                if tv not in line:
                    continue
                if re.search(
                    rf"\b{tv_esc}\.(?:json|text|content|read|readlines|decode)\s*\(",
                    line,
                ):
                    lhs_m = re.match(r"^\s*(?:const|let|var\s+)?(\w+)\s*=", line)
                    if lhs_m and lhs_m.group(1) not in tainted:
                        continue
                if re.search(rf"\[\s*{tv_esc}\s*\]", line) or re.search(
                    rf"\.get\s*\(\s*{tv_esc}\s*[,\)]", line
                ):
                    lhs_m = re.match(r"^\s*(?:const|let|var\s+)?(\w+)\s*=", line)
                    if lhs_m:
                        lhs_name = lhs_m.group(1)
                        rhs = line[lhs_m.end() :]
                        rhs_no_bracket = re.sub(rf"\[.*?{tv_esc}.*?\]", "", rhs)
                        rhs_no_bracket = re.sub(
                            rf"\.get\s*\(.*?{tv_esc}.*?\)", "", rhs_no_bracket
                        )
                        if not re.search(rf"\b{tv_esc}\b", rhs_no_bracket):
                            if lhs_name not in tainted:
                                continue
                m = re.match(rf"^\s*(\w+)\s*=.*\b{tv_esc}\b", line)
                if m and m.group(1) not in tainted and m.group(1) != tv:
                    tainted.add(m.group(1))
                    changed = True
                m = re.match(rf"^\s*(?:const|let|var)\s+(\w+)\s*=.*\b{tv_esc}\b", line)
                if m and m.group(1) not in tainted:
                    tainted.add(m.group(1))
                    changed = True
                m = re.match(
                    rf"^\s*(?:const|let|var)\s+\{{\s*([^}}]+)\}}\s*=.*\b{tv_esc}\b",
                    line,
                )
                if m:
                    for p in m.group(1).split(","):
                        p = p.strip().split(":")[0].strip()
                        if p and p not in tainted:
                            tainted.add(p)
                            changed = True
            for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*", full):
                var_name = m.group(1)
                if var_name in tainted:
                    continue
                start = m.end()
                depth = 0
                end = start
                for ci in range(start, min(start + 2000, len(full))):
                    ch = full[ci]
                    if ch in "({[`":
                        depth += 1
                    elif ch in ")}]":
                        depth -= 1
                        if depth < 0:
                            end = ci
                            break
                    elif ch == ";" and depth == 0:
                        end = ci
                        break
                else:
                    end = min(start + 2000, len(full))
                stmt = full[start:end]
                if re.search(rf"\b{tv_esc}\b", stmt):
                    tainted.add(var_name)
                    changed = True
    for tv in list(tainted):
        for line in lines:
            for pm in re.finditer(rf"\b{re.escape(tv)}\.(\w+)\b", line):
                prop = pm.group(1)
                if prop not in (
                    "length",
                    "toString",
                    "trim",
                    "replace",
                    "split",
                    "join",
                    "map",
                    "filter",
                    "forEach",
                    "get",
                    "set",
                    "then",
                    "catch",
                    "finally",
                    "prototype",
                    "constructor",
                ):
                    tainted.add(prop)
def _append_file_injection_findings(
    findings: list[Finding],
    tool_name: str,
    param_name: str,
    file_path: str,
    file_lines: list[str],
    fi_hits: list[tuple],
    *,
    source_info: str,
) -> None:
    seen = set()
    for abs_line, sink_text, chain, rule_id, fk in fi_hits:
        key = (rule_id, file_path, abs_line, param_name)
        if key in seen:
            continue
        seen.add(key)
        meta = _FILE_INJECTION_RULE_META.get(rule_id)
        if not meta:
            continue
        sev, vt, desc, rec = meta
        ctx_start = max(0, abs_line - 4)
        ctx_end = min(len(file_lines), abs_line + 3)
        snippet = "".join(file_lines[ctx_start:ctx_end]).strip()
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=sev,
                vuln_type=vt,
                tool_name=tool_name,
                param_name=param_name,
                file=file_path,
                line=abs_line,
                code_snippet=snippet[:600],
                description=desc,
                source_info=source_info,
                sink_info=f"Line {abs_line}: {sink_text}",
                data_flow=f"User calls tool '{tool_name}' → parameter '{chain}' → {sink_text[:80]}",
                recommendation=rec,
                finding_kind=fk,
            )
        )
def discover_mcp_tools(project_path: str) -> list[MCPTool]:
    all_tools: list[MCPTool] = []
    const_map = _build_project_ts_string_constants(project_path)
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fname_lower = fname.lower()
            if any(
                fname_lower.startswith(p) or p in fname_lower
                for p in SKIP_FILE_PATTERNS
            ):
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    full_text = "".join(lines)
            except (PermissionError, OSError):
                continue
            if ext == ".py":
                all_tools.extend(discover_python_mcp_tools(fpath, lines))
            elif ext in (".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"):
                all_tools.extend(discover_ts_mcp_tools_switch(fpath, lines, full_text))
                all_tools.extend(
                    discover_ts_mcp_tools_dynamic_dispatch(fpath, lines, full_text)
                )
                all_tools.extend(
                    discover_ts_mcp_tools_listtools(fpath, lines, full_text)
                )
                all_tools.extend(discover_ts_mcp_tools_inline(fpath, lines, full_text))
                all_tools.extend(
                    discover_ts_mcp_tools_register_object_literal(
                        fpath, lines, full_text, const_map
                    )
                )
                all_tools.extend(
                    discover_ts_mcp_tools_class_instance_name(fpath, lines, full_text)
                )
                all_tools.extend(
                    discover_ts_mcp_tools_export_default_tool_module(
                        fpath, lines, full_text
                    )
                )
                all_tools.extend(
                    discover_ts_mcp_tools_named_export_const_object(
                        fpath, lines, full_text
                    )
                )
                all_tools.extend(
                    discover_ts_mcp_tools_calltool_exclusive_guard(
                        fpath, lines, full_text
                    )
                )
    if not all_tools:
        for bt in discover_bundled_tools(project_path):
            if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", bt.name):
                all_tools.append(bt)
    seen_tools = set()
    unique_tools: list[MCPTool] = []
    for t in all_tools:
        if t.name not in seen_tools:
            seen_tools.add(t.name)
            unique_tools.append(t)
    return unique_tools
def analyze_project(project_name: str, project_path: str) -> list[Finding]:
    findings = []
    all_tools = discover_mcp_tools(project_path)
    if not all_tools:
        return findings
    func_index = _build_function_index(project_path)
    cross_links = discover_cross_file_links(all_tools, project_path)
    for tool in all_tools:
        if not tool.params:
            continue
        try:
            with open(tool.file, "r", encoding="utf-8", errors="ignore") as f:
                file_lines = f.readlines()
        except (PermissionError, OSError):
            continue
        body_lines = file_lines[tool.handler_start : tool.handler_end]
        lang = "py" if tool.file.endswith(".py") else "js"
        for param_name, param_type in tool.params:
            for (
                rule_id,
                severity,
                vuln_type,
                rule_lang,
                sink_pat,
                desc,
                rec,
            ) in SINK_RULES:
                if rule_lang != lang:
                    continue
                hits = check_taint_reaches_sink(
                    param_name,
                    tool.handler_body,
                    body_lines,
                    tool.handler_start,
                    sink_pat,
                    rule_id,
                )
                for abs_line, sink_text, chain in hits:
                    ctx_start = max(0, abs_line - 4)
                    ctx_end = min(len(file_lines), abs_line + 3)
                    snippet = "".join(file_lines[ctx_start:ctx_end]).strip()
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            vuln_type=vuln_type,
                            tool_name=tool.name,
                            param_name=param_name,
                            file=tool.file,
                            line=abs_line,
                            code_snippet=snippet[:600],
                            description=desc,
                            source_info=f"MCP Tool: {tool.name}() -> parameter: {param_name}",
                            sink_info=f"Line {abs_line}: {sink_text}",
                            data_flow=f"User calls tool '{tool.name}' → parameter '{chain}' → {sink_text[:80]}",
                            recommendation=rec,
                        )
                    )
            fi_h = check_file_injection_hits(
                param_name,
                body_lines,
                tool.handler_start,
                lang,
            )
            _append_file_injection_findings(
                findings,
                tool.name,
                param_name,
                tool.file,
                file_lines,
                fi_h,
                source_info=f"MCP Tool: {tool.name}() -> parameter: {param_name}",
            )
            if param_type != "request.params.arguments" and tool.handler_body:
                tainted_ipa = {param_name}
                _propagate_taint(body_lines, tainted_ipa, param_name)
                callees = _follow_interprocedural_taint(
                    tainted_ipa,
                    tool.handler_body,
                    func_index,
                    depth=3,
                    visited=set(),
                )
                for (
                    callee_name,
                    callee_file,
                    callee_start,
                    callee_end,
                    mapped_param,
                    callee_body,
                    callee_body_lines,
                    chain_str,
                ) in callees:
                    callee_lang = "py" if callee_file.endswith(".py") else "js"
                    for (
                        rule_id,
                        severity,
                        vuln_type,
                        rule_lang,
                        sink_pat,
                        desc,
                        rec,
                    ) in SINK_RULES:
                        if rule_lang != callee_lang:
                            continue
                        hits = check_taint_reaches_sink(
                            mapped_param,
                            callee_body,
                            callee_body_lines,
                            callee_start,
                            sink_pat,
                            rule_id,
                        )
                        for abs_line, sink_text, taint_chain in hits:
                            try:
                                with open(
                                    callee_file, "r", encoding="utf-8", errors="ignore"
                                ) as f:
                                    fl = f.readlines()
                                ctx_s = max(0, abs_line - 4)
                                ctx_e = min(len(fl), abs_line + 3)
                                snippet = "".join(fl[ctx_s:ctx_e]).strip()
                            except:
                                snippet = sink_text
                            findings.append(
                                Finding(
                                    rule_id=rule_id,
                                    severity=severity,
                                    vuln_type=vuln_type,
                                    tool_name=tool.name,
                                    param_name=param_name,
                                    file=callee_file,
                                    line=abs_line,
                                    code_snippet=snippet[:600],
                                    description=desc,
                                    source_info=(
                                        f"MCP Tool: {tool.name}() -> parameter: {param_name} → "
                                        f"{chain_str} → sink in {callee_name}()"
                                    ),
                                    sink_info=f"Line {abs_line}: {sink_text}",
                                    data_flow=(
                                        f"User calls tool '{tool.name}' → parameter '{param_name}' → "
                                        f"{chain_str} → {sink_text[:60]}"
                                    ),
                                    recommendation=rec,
                                )
                            )
                    fi_ipa = check_file_injection_hits(
                        mapped_param,
                        callee_body_lines,
                        callee_start,
                        callee_lang,
                    )
                    if fi_ipa:
                        try:
                            with open(
                                callee_file, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                fl_ipa = f.readlines()
                        except (OSError, PermissionError):
                            fl_ipa = []
                        if fl_ipa:
                            _append_file_injection_findings(
                                findings,
                                tool.name,
                                param_name,
                                callee_file,
                                fl_ipa,
                                fi_ipa,
                                source_info=(
                                    f"MCP Tool: {tool.name}() -> parameter: {param_name} → "
                                    f"{chain_str} → sink in {callee_name}()"
                                ),
                            )
        for link in cross_links:
            if link.source_tool != tool.name:
                continue
            if not link.target_body:
                continue
            target_lines = link.target_body.splitlines(keepends=True)
            for param_name, _ in tool.params:
                remote_key = None
                for rk, lp in link.forwarded_params.items():
                    if lp == param_name:
                        remote_key = rk
                        break
                if not remote_key:
                    continue
                target_ext = Path(link.target_file).suffix.lower()
                target_lang = "py" if target_ext == ".py" else "js"
                for (
                    rule_id,
                    severity,
                    vuln_type,
                    rule_lang,
                    sink_pat,
                    desc,
                    rec,
                ) in SINK_RULES:
                    if rule_lang != target_lang:
                        continue
                    hits = check_taint_reaches_sink(
                        remote_key,
                        link.target_body,
                        target_lines,
                        link.target_start,
                        sink_pat,
                        rule_id,
                    )
                    for abs_line, sink_text, chain in hits:
                        try:
                            with open(
                                link.target_file, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                tgt_file_lines = f.readlines()
                            ctx_start = max(0, abs_line - 4)
                            ctx_end = min(len(tgt_file_lines), abs_line + 3)
                            snippet = "".join(tgt_file_lines[ctx_start:ctx_end]).strip()
                        except:
                            snippet = sink_text
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                severity=severity,
                                vuln_type=vuln_type,
                                tool_name=tool.name,
                                param_name=param_name,
                                file=link.target_file,
                                line=abs_line,
                                code_snippet=snippet[:600],
                                description=desc,
                                source_info=(
                                    f"MCP Tool: {tool.name}() -> parameter: {param_name} → "
                                    f"send_command('{link.command_name}', {{{remote_key}: {param_name}}}) → "
                                    f"{link.target_file}::{link.target_method}()"
                                ),
                                sink_info=f"Line {abs_line}: {sink_text}",
                                data_flow=(
                                    f"User calls tool '{tool.name}' → parameter '{param_name}' → "
                                    f"send_command('{link.command_name}') → "
                                    f"remote handler {link.target_method}() → "
                                    f"parameter '{chain}' → {sink_text[:60]}"
                                ),
                                recommendation=rec,
                            )
                        )
                fi_cf = check_file_injection_hits(
                    remote_key,
                    target_lines,
                    link.target_start,
                    target_lang,
                )
                if fi_cf:
                    try:
                        with open(
                            link.target_file, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            tgt_fl = f.readlines()
                    except (OSError, PermissionError):
                        tgt_fl = []
                    if tgt_fl:
                        _append_file_injection_findings(
                            findings,
                            tool.name,
                            param_name,
                            link.target_file,
                            tgt_fl,
                            fi_cf,
                            source_info=(
                                f"MCP Tool: {tool.name}() -> parameter: {param_name} → "
                                f"send_command('{link.command_name}', {{{remote_key}: {param_name}}}) → "
                                f"{link.target_file}::{link.target_method}()"
                            ),
                        )
    findings.extend(_analyze_ts_dispatch_handlers(project_path, all_tools, func_index))
    return deduplicate_findings(findings)
def _build_function_index(project_path: str) -> dict:
    index = {}
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fname_lower = fname.lower()
            if any(
                fname_lower.startswith(p) or p in fname_lower
                for p in SKIP_FILE_PATTERNS
            ):
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (PermissionError, OSError):
                continue
            lang = "py" if ext == ".py" else "js"
            blocks = _extract_function_blocks(lines, lang)
            for func_name, fstart, fend, fparams in blocks:
                body_lines = lines[fstart:fend]
                body_text = "".join(body_lines)
                index.setdefault(func_name, []).append(
                    (fpath, fstart, fend, fparams, body_text, body_lines)
                )
    return index
def _follow_interprocedural_taint(
    tainted_vars: set,
    body: str,
    func_index: dict,
    depth: int = 3,
    visited: set = None,
) -> list[tuple]:
    if depth <= 0:
        return []
    if visited is None:
        visited = set()
    results = []
    _SKIP_CALLEES = frozenset(
        {
            "if",
            "for",
            "while",
            "switch",
            "catch",
            "return",
            "require",
            "import",
            "console",
            "log",
            "setTimeout",
            "clearTimeout",
            "parseInt",
            "parseFloat",
            "String",
            "Number",
            "Boolean",
            "Error",
            "new",
            "typeof",
            "parse",
            "stringify",
            "resolve",
            "reject",
            "then",
            "catch",
            "finally",
            "map",
            "filter",
            "forEach",
            "push",
            "pop",
            "slice",
            "splice",
            "trim",
            "split",
            "join",
            "includes",
            "indexOf",
            "startsWith",
            "endsWith",
            "assign",
            "keys",
            "values",
            "entries",
            "print",
            "len",
            "str",
            "int",
            "float",
            "list",
            "dict",
            "set",
            "tuple",
            "isinstance",
            "hasattr",
            "getattr",
            "setattr",
            "super",
            "range",
            "enumerate",
            "zip",
            "sorted",
            "min",
            "max",
            "append",
            "extend",
            "update",
            "format",
            "encode",
        }
    )
    for cm in re.finditer(r"(?:await\s+)?(?:\w+\.)*(\w+)\s*\(", body):
        callee_name = cm.group(1)
        if callee_name in _SKIP_CALLEES or callee_name in visited:
            continue
        line_start = body.rfind("\n", 0, cm.start()) + 1
        line_prefix = body[line_start : cm.start()].lstrip()
        if re.search(r"(?:^|\s)(?:async\s+)?(?:def|function)\s*$", line_prefix):
            continue
        start_pos = cm.end()
        paren_depth = 1
        end_pos = start_pos
        for ci in range(start_pos, min(start_pos + 5000, len(body))):
            if body[ci] == "(":
                paren_depth += 1
            elif body[ci] == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    end_pos = ci
                    break
        args_str = body[start_pos:end_pos]
        tainted_arg_mappings = []
        stripped_args = args_str.strip()
        if stripped_args.startswith("{"):
            inner = stripped_args
            brace_depth = 0
            obj_end = len(inner)
            for ci_obj, ch in enumerate(inner):
                if ch == "{":
                    brace_depth += 1
                elif ch == "}":
                    brace_depth -= 1
                    if brace_depth == 0:
                        obj_end = ci_obj
                        break
            inner = inner[1:obj_end]
            kv_pairs = []
            d = 0
            last = 0
            for ci_kv, ch in enumerate(inner):
                if ch in "({[":
                    d += 1
                elif ch in ")}]":
                    d -= 1
                elif ch == "," and d == 0:
                    kv_pairs.append(inner[last:ci_kv].strip())
                    last = ci_kv + 1
            kv_pairs.append(inner[last:].strip())
            for pair in kv_pairs:
                if ":" not in pair:
                    continue
                key, val = pair.split(":", 1)
                key = key.strip()
                val = val.strip()
                if not re.match(r"^\w+$", key):
                    continue
                for tv in tainted_vars:
                    if re.search(rf"\b{re.escape(tv)}\b", val):
                        tainted_arg_mappings.append((0, tv, key, False))
                        break
        else:
            actual_args = [a.strip() for a in args_str.split(",") if a.strip()]
            for idx, arg in enumerate(actual_args):
                kw_name = None
                arg_value = arg
                if "=" in arg and not arg.startswith(("==", "!=", "<=", ">=")):
                    parts = arg.split("=", 1)
                    candidate_kw = parts[0].strip()
                    if re.match(r"^\w+$", candidate_kw):
                        kw_name = candidate_kw
                        arg_value = parts[1].strip()
                for tv in tainted_vars:
                    if re.search(rf"\b{re.escape(tv)}\b", arg_value):
                        tainted_arg_mappings.append((idx, tv, kw_name, False))
                        break
                    if "." in tv:
                        tv_base, tv_field = tv.split(".", 1)
                        arg_clean = re.sub(r"\s+as\s+\w+", "", arg_value).strip()
                        if re.match(rf"^{re.escape(tv_base)}$", arg_clean):
                            tainted_arg_mappings.append((idx, tv, kw_name, True))
                            break
        if not tainted_arg_mappings:
            continue
        defs = func_index.get(callee_name, [])
        if not defs:
            continue
        visited.add(callee_name)
        for def_fpath, def_start, def_end, def_params, def_body, def_body_lines in defs:
            param_list = list(def_params)
            for (
                arg_idx,
                taint_source,
                kw_name,
                is_base_obj_match,
            ) in tainted_arg_mappings:
                if kw_name:
                    mapped_param = kw_name
                elif arg_idx < len(param_list):
                    mapped_param = param_list[arg_idx]
                else:
                    mapped_param = taint_source
                if (
                    is_base_obj_match
                    and "." in taint_source
                    and "." not in mapped_param
                ):
                    _, field_part = taint_source.split(".", 1)
                    mapped_param = f"{mapped_param}.{field_part}"
                results.append(
                    (
                        callee_name,
                        def_fpath,
                        def_start,
                        def_end,
                        mapped_param,
                        def_body,
                        def_body_lines,
                        f"{taint_source} → {callee_name}({mapped_param})",
                    )
                )
                deeper = _follow_interprocedural_taint(
                    {mapped_param},
                    def_body,
                    func_index,
                    depth - 1,
                    visited,
                )
                for r in deeper:
                    results.append(
                        (
                            r[0],
                            r[1],
                            r[2],
                            r[3],
                            r[4],
                            r[5],
                            r[6],
                            f"{taint_source} → {callee_name}({mapped_param}) → {r[7]}",
                        )
                    )
    return results
def _analyze_ts_dispatch_handlers(
    project_path: str, tools: list[MCPTool], func_index: dict
) -> list[Finding]:
    findings = []
    handlers = discover_ts_tool_handlers(project_path)
    tool_handler_map = {}
    for tool in tools:
        body = tool.handler_body
        m = re.search(
            r"(?:this\.)?(\w+)\s*\(\s*(?:request\.params\.arguments|args)", body
        )
        if m:
            tool_handler_map[tool.name] = m.group(1)
    for tool_name, handler_name in tool_handler_map.items():
        if handler_name in handlers:
            fpath, start, end, args_param, body = handlers[handler_name]
        elif handler_name in func_index:
            defs = func_index[handler_name]
            fi_fpath, fi_start, fi_end, fi_params, fi_body, _ = defs[0]
            fpath = fi_fpath
            start = fi_start
            end = fi_end
            args_param = fi_params[0] if fi_params else "args"
            body = fi_body
        else:
            continue
        body_lines = body.splitlines(keepends=True)
        used_fields = set()
        for m in re.finditer(rf"{re.escape(args_param)}\.(\w+)", body):
            used_fields.add(m.group(1))
        parsed_vars = set()
        for m in re.finditer(
            rf"(?:const|let|var)\s+(\w+)\s*=\s*\w+\.parse\s*\(\s*{re.escape(args_param)}\s*\)",
            body,
        ):
            parsed_vars.add(m.group(1))
        for m in re.finditer(
            rf"(?:const|let|var)\s+\{{\s*([^}}]+)\}}\s*=\s*\w+\.parse\s*\(\s*{re.escape(args_param)}\s*\)",
            body,
        ):
            for part in m.group(1).split(","):
                fname = part.strip().split(":")[0].strip().split("=")[0].strip()
                if fname and re.match(r"^\w+$", fname):
                    used_fields.add(fname)
        for pvar in parsed_vars:
            for m in re.finditer(rf"{re.escape(pvar)}\.(\w+)", body):
                used_fields.add(m.group(1))
        for m in re.finditer(r"(?:parsed\.data|options|params)\.(\w+)", body):
            used_fields.add(m.group(1))
        used_fields -= {
            "parse",
            "then",
            "catch",
            "finally",
            "data",
            "length",
            "toString",
            "valueOf",
            "constructor",
            "prototype",
            "params",
            "arguments",
            "name",
            "type",
            "method",
            "request",
            "response",
            "options",
            "result",
            "error",
            "status",
            "message",
            "config",
            "headers",
        }
        for field_name in used_fields:
            for (
                rule_id,
                severity,
                vuln_type,
                rule_lang,
                sink_pat,
                desc,
                rec,
            ) in SINK_RULES:
                if rule_lang != "js":
                    continue
                hits = check_taint_reaches_sink(
                    field_name,
                    body,
                    body_lines,
                    start,
                    sink_pat,
                    rule_id,
                )
                for abs_line, sink_text, chain in hits:
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            fl = f.readlines()
                        ctx_s = max(0, abs_line - 4)
                        ctx_e = min(len(fl), abs_line + 3)
                        snippet = "".join(fl[ctx_s:ctx_e]).strip()
                    except:
                        snippet = sink_text
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            vuln_type=vuln_type,
                            tool_name=tool_name,
                            param_name=f"args.{field_name}",
                            file=fpath,
                            line=abs_line,
                            code_snippet=snippet[:600],
                            description=desc,
                            source_info=f"MCP Tool: {tool_name} → handler: {handler_name}() -> parameter: args.{field_name}",
                            sink_info=f"Line {abs_line}: {sink_text}",
                            data_flow=f"User calls tool '{tool_name}' → args.{chain} → {sink_text[:80]}",
                            recommendation=rec,
                        )
                    )
            fi_d = check_file_injection_hits(field_name, body_lines, start, "js")
            if fi_d:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        fl_d = f.readlines()
                except (OSError, PermissionError):
                    fl_d = []
                if fl_d:
                    _append_file_injection_findings(
                        findings,
                        tool_name,
                        f"args.{field_name}",
                        fpath,
                        fl_d,
                        fi_d,
                        source_info=(
                            f"MCP Tool: {tool_name} → handler: {handler_name}() -> parameter: args.{field_name}"
                        ),
                    )
            tainted = {field_name, f"{args_param}.{field_name}"}
            _propagate_taint(body_lines, tainted, field_name)
            callees = _follow_interprocedural_taint(
                tainted,
                body,
                func_index,
                depth=3,
                visited=set(),
            )
            for (
                callee_name,
                callee_file,
                callee_start,
                callee_end,
                mapped_param,
                callee_body,
                callee_body_lines,
                chain_str,
            ) in callees:
                callee_lang = "py" if callee_file.endswith(".py") else "js"
                for (
                    rule_id,
                    severity,
                    vuln_type,
                    rule_lang,
                    sink_pat,
                    desc,
                    rec,
                ) in SINK_RULES:
                    if rule_lang != callee_lang:
                        continue
                    hits = check_taint_reaches_sink(
                        mapped_param,
                        callee_body,
                        callee_body_lines,
                        callee_start,
                        sink_pat,
                        rule_id,
                    )
                    for abs_line, sink_text, taint_chain in hits:
                        try:
                            with open(
                                callee_file, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                fl = f.readlines()
                            ctx_s = max(0, abs_line - 4)
                            ctx_e = min(len(fl), abs_line + 3)
                            snippet = "".join(fl[ctx_s:ctx_e]).strip()
                        except:
                            snippet = sink_text
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                severity=severity,
                                vuln_type=vuln_type,
                                tool_name=tool_name,
                                param_name=f"args.{field_name}",
                                file=callee_file,
                                line=abs_line,
                                code_snippet=snippet[:600],
                                description=desc,
                                source_info=(
                                    f"MCP Tool: {tool_name} → handler: {handler_name}() → "
                                    f"args.{field_name} → {chain_str} → sink in {callee_name}()"
                                ),
                                sink_info=f"Line {abs_line}: {sink_text}",
                                data_flow=(
                                    f"User calls tool '{tool_name}' → args.{field_name} → "
                                    f"{chain_str} → {sink_text[:60]}"
                                ),
                                recommendation=rec,
                            )
                        )
                    fi_disp = check_file_injection_hits(
                        mapped_param,
                        callee_body_lines,
                        callee_start,
                        callee_lang,
                    )
                    if fi_disp:
                        try:
                            with open(
                                callee_file, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                fl_disp = f.readlines()
                        except (OSError, PermissionError):
                            fl_disp = []
                        if fl_disp:
                            _append_file_injection_findings(
                                findings,
                                tool_name,
                                f"args.{field_name}",
                                callee_file,
                                fl_disp,
                                fi_disp,
                                source_info=(
                                    f"MCP Tool: {tool_name} → handler: {handler_name}() → "
                                    f"args.{field_name} → {chain_str} → sink in {callee_name}()"
                                ),
                            )
    return findings
def extract_schema_params(project_path: str) -> list[tuple]:
    results = []
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in (".ts", ".js"):
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (PermissionError, OSError):
                continue
            for m in re.finditer(
                r"(?:export\s+)?(?:const|let|var)\s+(\w*(?:Args|Schema|Input)\w*)\s*=\s*z\.object\s*\(\s*\{",
                content,
            ):
                schema_name = m.group(1)
                start = m.end()
                depth = 1
                end = start
                for ci in range(start, min(start + 3000, len(content))):
                    if content[ci] == "{":
                        depth += 1
                    elif content[ci] == "}":
                        depth -= 1
                        if depth == 0:
                            end = ci
                            break
                block = content[start:end]
                params = []
                for pm in re.finditer(r"(\w+)\s*:\s*z\.", block):
                    pname = pm.group(1)
                    if pname not in (
                        "type",
                        "description",
                        "enum",
                        "default",
                        "optional",
                    ):
                        params.append(pname)
                tool_name = re.sub(r"ArgsSchema$|Schema$|Input$", "", schema_name)
                tool_name = re.sub(r"([A-Z])", r"_\1", tool_name).strip("_").lower()
                if params:
                    results.append((tool_name, params, fpath))
            for m in re.finditer(r"inputSchema\s*:\s*\{", content):
                start = m.end()
                depth = 1
                end = start
                for ci in range(start, min(start + 5000, len(content))):
                    if content[ci] == "{":
                        depth += 1
                    elif content[ci] == "}":
                        depth -= 1
                        if depth == 0:
                            end = ci
                            break
                block = content[start:end]
                prop_m = re.search(r"properties\s*:\s*\{", block)
                if prop_m:
                    pstart = prop_m.end()
                    pdepth = 1
                    pend = pstart
                    for ci in range(pstart, min(pstart + 3000, len(block))):
                        if block[ci] == "{":
                            pdepth += 1
                        elif block[ci] == "}":
                            pdepth -= 1
                            if pdepth == 0:
                                pend = ci
                                break
                    pblock = block[pstart:pend]
                    params = []
                    for pm in re.finditer(r"(\w+)\s*:\s*\{", pblock):
                        pname = pm.group(1)
                        if pname not in (
                            "type",
                            "description",
                            "enum",
                            "default",
                            "properties",
                            "items",
                            "required",
                        ):
                            params.append(pname)
                    pre_context = content[max(0, m.start() - 500) : m.start()]
                    nm = re.search(r"name\s*:\s*['\"](\w+)['\"]", pre_context)
                    tool_name = nm.group(1) if nm else "unknown_tool"
                    if params:
                        results.append((tool_name, params, fpath))
    return results
def analyze_param_name_across_project(
    project_path: str, tools: list[MCPTool]
) -> list[Finding]:
    findings = []
    param_tool_map = {}
    for tool in tools:
        for pname, _ in tool.params:
            if pname in ("args", "name", "ctx", "self"):
                continue
            param_tool_map.setdefault(pname, []).append((tool.name, tool.file))
    if not param_tool_map:
        return findings
    file_cache = {}
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in effective_skip_dirs()]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fname_lower = fname.lower()
            if any(
                fname_lower.startswith(p) or p in fname_lower
                for p in SKIP_FILE_PATTERNS
            ):
                continue
            fpath = os.path.join(root, fname)
            if not _source_file_under_size_limit(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                file_cache[fpath] = (
                    lines,
                    "".join(lines),
                    "py" if ext == ".py" else "js",
                )
            except (PermissionError, OSError):
                continue
    call_index = {}
    for fpath, (_, full_text, _) in file_cache.items():
        for word in set(re.findall(r"\b(\w{3,})\b", full_text)):
            call_index.setdefault(word, set()).add(fpath)
    for fpath, (file_lines, full_text, lang) in file_cache.items():
        func_blocks = _extract_function_blocks(file_lines, lang)
        for func_name, func_start, func_end, func_params in func_blocks:
            for pname, tool_list in param_tool_map.items():
                if pname not in func_params:
                    continue
                body_lines = file_lines[func_start:func_end]
                body = "".join(body_lines)
                for (
                    rule_id,
                    severity,
                    vuln_type,
                    rule_lang,
                    sink_pat,
                    desc,
                    rec,
                ) in SINK_RULES:
                    if rule_lang != lang:
                        continue
                    hits = check_taint_reaches_sink(
                        pname,
                        body,
                        body_lines,
                        func_start,
                        sink_pat,
                        rule_id,
                    )
                    for abs_line, sink_text, chain in hits:
                        callers = call_index.get(func_name, set())
                        is_called = bool(callers - {fpath}) or any(
                            fpath == tf for _, tf in tool_list
                        )
                        if not is_called:
                            continue
                        ctx_s = max(0, abs_line - 4)
                        ctx_e = min(len(file_lines), abs_line + 3)
                        snippet = "".join(file_lines[ctx_s:ctx_e]).strip()
                        for tool_name, tool_file in tool_list:
                            findings.append(
                                Finding(
                                    rule_id=rule_id,
                                    severity=severity,
                                    vuln_type=vuln_type,
                                    tool_name=tool_name,
                                    param_name=pname,
                                    file=fpath,
                                    line=abs_line,
                                    code_snippet=snippet[:600],
                                    description=desc,
                                    source_info=(
                                        f"MCP Tool: {tool_name}() -> parameter: {pname} → "
                                        f"cross-function propagation → {func_name}() in {os.path.basename(fpath)}"
                                    ),
                                    sink_info=f"Line {abs_line}: {sink_text}",
                                    data_flow=(
                                        f"User calls tool '{tool_name}' → parameter '{pname}' → "
                                        f"... → {func_name}({pname}) → {sink_text[:60]}"
                                    ),
                                    recommendation=rec,
                                )
                            )
    return findings
def _extract_function_blocks(lines: list[str], lang: str) -> list[tuple]:
    _TS_TYPE_KEYWORDS = {
        "string",
        "number",
        "boolean",
        "any",
        "void",
        "Promise",
        "Array",
        "object",
        "true",
        "false",
        "null",
        "undefined",
        "Record",
        "Partial",
        "Required",
        "Readonly",
        "Map",
        "Set",
        "Date",
        "Buffer",
        "Uint8Array",
        "RegExp",
        "Error",
        "Function",
        "never",
        "unknown",
        "bigint",
        "symbol",
    }
    blocks = []
    for i, line in enumerate(lines):
        if lang == "py":
            m = re.match(r"\s*def\s+(\w+)\s*\((.*)$", line)
            if m:
                func_name = m.group(1)
                sig = m.group(2)
                k = i
                while ")" not in sig and k < len(lines) - 1:
                    k += 1
                    sig += lines[k]
                sig = re.sub(r"#[^\n]*", "", sig)
                pdepth = 0
                for ci, ch in enumerate(sig):
                    if ch == "(":
                        pdepth += 1
                    elif ch == ")":
                        if pdepth == 0:
                            sig = sig[:ci]
                            break
                        pdepth -= 1
                params = []
                for p in sig.split(","):
                    pm = re.match(r"\s*(\w+)", p.strip())
                    if pm and pm.group(1) not in ("self", "cls", "ctx"):
                        pname = pm.group(1)
                        if pname not in params:
                            params.append(pname)
                end = _find_python_block_end(lines, i)
                blocks.append((func_name, i, end, params))
        else:
            m = re.match(r".*?(?:function|async)\s+(\w+)\s*\((.*)$", line)
            if not m:
                m = re.match(
                    r"\s*(?:private\s+|public\s+|protected\s+)?(?:async\s+)?(\w+)\s*\((.*)$",
                    line,
                )
            if m:
                func_name = m.group(1)
                if func_name in (
                    "if",
                    "for",
                    "while",
                    "switch",
                    "catch",
                    "return",
                    "import",
                    "from",
                    "export",
                    "const",
                    "let",
                    "var",
                    "new",
                ):
                    continue
                sig = m.group(2)
                k = i
                while ")" not in sig and k < min(i + 15, len(lines) - 1):
                    k += 1
                    sig += lines[k]
                pdepth = 0
                for ci, ch in enumerate(sig):
                    if ch == "(":
                        pdepth += 1
                    elif ch == ")":
                        if pdepth == 0:
                            sig = sig[:ci]
                            break
                        pdepth -= 1
                params = []
                for part in sig.split(","):
                    part = part.strip()
                    pm = re.match(r"(\w+)\s*[\?:]", part)
                    if pm:
                        pname = pm.group(1)
                        if pname not in _TS_TYPE_KEYWORDS and pname not in params:
                            params.append(pname)
                    elif part:
                        pm = re.match(r"(\w+)", part)
                        if (
                            pm
                            and pm.group(1) not in _TS_TYPE_KEYWORDS
                            and pm.group(1) not in params
                        ):
                            params.append(pm.group(1))
                end = _find_ts_block_end(lines, i)
                blocks.append((func_name, i, end, params))
    return blocks
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.tool_name, f.file, f.line, f.param_name, f.finding_kind)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    dedup2 = {}
    for f in unique:
        semantic_key = (f.tool_name, f.param_name, f.file, f.line)
        if getattr(f, "finding_kind", "vuln_trigger") == "file_injection":
            group_key = (semantic_key, f.rule_id, "file_injection")
        else:
            vuln_cat = f.rule_id.rsplit("-", 1)[0]
            group_key = (semantic_key, vuln_cat, "vuln_trigger")
        if group_key in dedup2:
            existing = dedup2[group_key]
            if getattr(f, "finding_kind", "vuln_trigger") == "file_injection":
                continue
            if "BARE" in f.rule_id:
                continue
            elif "BARE" in existing.rule_id:
                dedup2[group_key] = f
            else:
                continue
        else:
            dedup2[group_key] = f
    return list(dedup2.values())
def _classify_sink_metric(f: Finding) -> Optional[str]:
    return classify_sink_metric_key(
        f.rule_id,
        getattr(f, "finding_kind", "vuln_trigger"),
    )
def count_servers_per_sink_metric(findings_json: list[dict]) -> dict[str, int]:
    per_project: dict[str, set[str]] = {}
    for d in findings_json:
        proj = d.get("project")
        if not proj:
            continue
        k = classify_sink_metric_key(
            str(d.get("rule_id", "")),
            str(d.get("finding_kind", "vuln_trigger")),
        )
        if not k:
            continue
        per_project.setdefault(proj, set()).add(k)
    out = {key: 0 for key, _ in SINK_METRIC_ORDER}
    for keys in per_project.values():
        for k in keys:
            out[k] += 1
    return out
def count_servers_with_any_finding(findings_json: list[dict]) -> int:
    return len({d.get("project") for d in findings_json if d.get("project")})
def count_sink_metrics(findings: list[Finding]) -> dict[str, int]:
    out = {key: 0 for key, _ in SINK_METRIC_ORDER}
    for f in findings:
        k = _classify_sink_metric(f)
        if k in out:
            out[k] += 1
    return out
def _terminal_vuln_type_label(d: dict) -> str:
    k = classify_sink_metric_key(
        str(d.get("rule_id", "")),
        str(d.get("finding_kind", "vuln_trigger")),
    )
    if k:
        for mkey, label in SINK_METRIC_ORDER:
            if mkey == k:
                return label
    return (d.get("vuln_type") or "").strip() or str(d.get("rule_id", ""))
def build_cli_summary_payload(findings_json: list[dict]) -> dict:
    srv = count_servers_per_sink_metric(findings_json)
    n_affected = count_servers_with_any_finding(findings_json)
    by_cat = {label: srv[key] for key, label in SINK_METRIC_ORDER}
    summary = {
        "caption": "Servers affected by vuln type",
        "servers_with_findings": n_affected,
        "by_vuln_category": by_cat,
    }
    detail_items = []
    if findings_json:
        groups = {}
        for d in findings_json:
            proj = (d.get("project") or "").strip() or "(unknown)"
            vtype = _terminal_vuln_type_label(d)
            tool = (d.get("tool_name") or "").strip() or "(unknown)"
            groups.setdefault((proj, vtype), set()).add(tool)
        for proj, vtype in sorted(groups.keys(), key=lambda t: (t[0], t[1])):
            tools = sorted(
                groups[(proj, vtype)],
                key=lambda s: (len(s), s.lower()),
            )
            detail_items.append(
                {
                    "mcp_server": proj,
                    "vuln_type": vtype,
                    "tools": tools,
                }
            )
    detail = {
        "caption": "Triggered tools by server/type",
        "items": detail_items,
    }
    return {"summary": summary, "detail": detail}
def print_cli_summary_payload(payload: dict, quiet: bool) -> None:
    if quiet:
        return
    s = payload["summary"]
    print("\n[SUMMARY] " + s["caption"])
    print(f"  Servers with findings: {s['servers_with_findings']}")
    for key, label in SINK_METRIC_ORDER:
        print(f"  {label}: {s['by_vuln_category'][label]}")
    d = payload["detail"]
    if not d["items"]:
        return
    print("\n[DETAIL] " + d["caption"])
    for it in d["items"]:
        print(f"[Server] {it['mcp_server']}")
        print(f"[Type] {it['vuln_type']}")
        tools_line = ", ".join(it["tools"])
        print(f"[Tools] {tools_line}")
        print("")
def format_sink_metric_footer_lines(findings: list[Finding]) -> list[str]:
    c = count_sink_metrics(findings)
    return [f"{label}: {c[key]}" for key, label in SINK_METRIC_ORDER]
def generate_report(
    project_name: str, project_path: str, findings: list[Finding]
) -> str:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vuln_fs = [
        f
        for f in findings
        if getattr(f, "finding_kind", "vuln_trigger") == "vuln_trigger"
    ]
    file_fs = [
        f
        for f in findings
        if getattr(f, "finding_kind", "vuln_trigger") == "file_injection"
    ]
    vuln_fs.sort(key=lambda f: (sev_order.get(f.severity, 99), f.rule_id))
    file_fs.sort(key=lambda f: (sev_order.get(f.severity, 99), f.rule_id))
    r = []
    r.append(f"# Static Analysis Report: {project_name}")
    r.append(f"\n**Scan path**: `{project_path}`")
    r.append(f"**Scan date**: {date.today().isoformat()}")
    r.append(f"**Method**: MCP Tool parameter → Sink taint tracking")
    r.append(
        "**Finding classes**: Vulnerability Trigger (RCE / Command Injection / ReDoS / Arbitrary File Read / SSRF); "
        "File Injection (mkdir-like directory paths / unrestricted content write under fixed path)"
    )
    crit = sum(1 for f in vuln_fs if f.severity == "CRITICAL")
    high = sum(1 for f in vuln_fs if f.severity == "HIGH")
    med = sum(1 for f in vuln_fs if f.severity == "MEDIUM")
    r.append(f"\n## Summary\n")
    r.append("### Vulnerability Trigger (excluding file injection)\n")
    r.append(f"| Severity | Count |")
    r.append(f"|----------|-------|")
    r.append(f"| CRITICAL | {crit} |")
    r.append(f"| HIGH | {high} |")
    r.append(f"| MEDIUM | {med} |")
    r.append(f"| **Subtotal** | **{len(vuln_fs)}** |")
    r.append(f"\n### File Injection\n")
    r.append(f"| Item | Count |")
    r.append(f"|------|-------|")
    r.append(f"| File Injection Findings | {len(file_fs)} |")
    if not findings:
        r.append("\n> No MCP-parameter sink findings (vulnerability trigger or file injection) detected.")
        r.extend(["", *format_sink_metric_footer_lines(findings)])
        return "\n".join(r)
    if not vuln_fs:
        r.append(
            "\n> Vulnerability Trigger: no RCE / Command Injection / ReDoS / Arbitrary File Read / SSRF sinks detected."
        )
    if not file_fs:
        r.append("\n> File Injection: no file-write sinks detected.")
    vuln_types = {}
    for f in vuln_fs:
        vuln_types.setdefault(f.vuln_type, []).append(f)
    if vuln_types:
        r.append(f"\n## Vulnerability Trigger — Type Distribution\n")
        for vt, fs in vuln_types.items():
            r.append(f"- **{vt}**: {len(fs)} finding(s)")
    file_types = {}
    for f in file_fs:
        file_types.setdefault(f.vuln_type, []).append(f)
    if file_types:
        r.append(f"\n## File Injection — Type Distribution\n")
        for vt, fs in file_types.items():
            r.append(f"- **{vt}**: {len(fs)} finding(s)")
    tool_vulns = {}
    for f in vuln_fs:
        tool_vulns.setdefault(f.tool_name, []).append(f)
    if tool_vulns:
        r.append(f"\n## Vulnerability Trigger — Affected MCP Tools\n")
        r.append("| Tool | Findings | Highest Severity | Affected Parameters |")
        r.append("|------|----------|------------------|---------------------|")
        for tn, fs in tool_vulns.items():
            max_sev = min(fs, key=lambda x: sev_order.get(x.severity, 99)).severity
            params = ", ".join(sorted(set(f.param_name for f in fs)))
            r.append(f"| `{tn}` | {len(fs)} | {max_sev} | `{params}` |")
    tool_files = {}
    for f in file_fs:
        tool_files.setdefault(f.tool_name, []).append(f)
    if tool_files:
        r.append(f"\n## File Injection — Affected MCP Tools\n")
        r.append("| Tool | Findings | Highest Severity | Affected Parameters |")
        r.append("|------|----------|------------------|---------------------|")
        for tn, fs in tool_files.items():
            max_sev = min(fs, key=lambda x: sev_order.get(x.severity, 99)).severity
            params = ", ".join(sorted(set(f.param_name for f in fs)))
            r.append(f"| `{tn}` | {len(fs)} | {max_sev} | `{params}` |")
    def _emit_detail_block(title: str, block: list[Finding], start_idx: int) -> int:
        r.append(f"\n---\n")
        r.append(title + "\n")
        idx = start_idx
        for f in block:
            rel_path = os.path.relpath(f.file, project_path)
            kind_label = (
                "File Injection" if f.finding_kind == "file_injection" else "Vulnerability Trigger"
            )
            r.append(f"### [{f.severity}] [{kind_label}] #{idx}: {f.vuln_type}")
            idx += 1
            r.append(f"\n- **Rule ID**: `{f.rule_id}`")
            r.append(f"- **MCP Tool**: `{f.tool_name}`")
            r.append(f"- **User-controlled parameter**: `{f.param_name}`")
            r.append(f"- **File**: `{rel_path}` (Line {f.line})")
            r.append(f"- **Description**: {f.description}")
            r.append(f"\n**Data flow (Source → Sink)**:")
            r.append(f"```")
            r.append(f"{f.data_flow}")
            r.append(f"```")
            if f.source_info:
                r.append(f"\n**Source (MCP tool entry)**:")
                r.append(f"```")
                r.append(f"{f.source_info}")
                r.append(f"```")
            if f.code_snippet:
                r.append(f"\n**Code context**:")
                r.append(f"```")
                r.append(f"{f.code_snippet}")
                r.append(f"```")
            if f.recommendation:
                r.append(f"\n**Recommendation**: {f.recommendation}")
            r.append(f"\n---\n")
        return idx
    nxt = 1
    if vuln_fs:
        nxt = _emit_detail_block("## Detailed Findings — Vulnerability Trigger", vuln_fs, nxt)
    if file_fs:
        _emit_detail_block("## Detailed Findings — File Injection", file_fs, nxt)
    r.extend(["", *format_sink_metric_footer_lines(findings)])
    return "\n".join(r)
def main():
    parser = argparse.ArgumentParser(
        description="MCP static security analyzer for tool-parameter-driven risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./my-mcp-server
  %(prog)s ./proj1 ./proj2
  %(prog)s ./repo --strict-skip   # skip examples/scripts/demo/sample dirs
Detected vulnerability types:
  VUL-01  RCE           exec()/eval()/vm.runInContext() code execution
  VUL-02  Command Injection  Shell command injection via string concatenation
  VUL-03  ReDoS         Regular expression denial of service
  VUL-04  Path Traversal  Arbitrary file read via unvalidated paths
  VUL-05  SSRF          Server-side request forgery via user-controlled URLs
""",
    )
    parser.add_argument(
        "projects",
        nargs="+",
        metavar="PROJECT_DIR",
        help="Path(s) to MCP server project directory(ies) to scan",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="Ignored (file output is disabled).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["md", "json", "both"],
        default="both",
        help="Ignored (file output is disabled).",
    )
    parser.add_argument(
        "-n",
        "--name",
        default=None,
        help="Project name (only used when scanning a single project, auto-detected otherwise)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--strict-skip",
        action="store_true",
        help="Also skip examples/, scripts/, demo/, sample/ when walking sources "
        "(faster; may miss MCP code that only lives under those dirs)",
    )
    args = parser.parse_args()
    set_scan_skip_strict(args.strict_skip)
    all_findings_json = collect_findings_json(args.projects, args.name, analyze_project)
    cli_payload = build_cli_summary_payload(all_findings_json)
    print_cli_summary_payload(cli_payload, args.quiet)
    has_serious = any(
        d.get("severity") in ("CRITICAL", "HIGH")
        and d.get("finding_kind", "vuln_trigger") == "vuln_trigger"
        for d in all_findings_json
    )
    sys.exit(1 if has_serious else 0)
if __name__ == "__main__":
    main()
  
