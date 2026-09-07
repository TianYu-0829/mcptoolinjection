import json, os, re
from pathlib import Path
from urllib.parse import unquote

base = Path(r"D:\MCP\codeql\audit-latest")
repo_base = Path(r"C:\Users\skywings\Desktop\database")

rule_map = {
    "custom/python/mcp-tool-input-ssrf": "SSRF",
    "custom/js/mcp-tool-input-ssrf": "SSRF",
    "custom/python/mcp-tool-input-rce": "RCE",
    "custom/python/mcp-tool-input-command-injection": "Command Injection",
    "custom/python/mcp-tool-input-redos": "ReDoS",
    "custom/python/mcp-tool-input-arbitrary-file-read": "Arbitrary File Read",
    "custom/python/mcp-tool-input-file-injection": "File Injection",
}

def classify_from_message(msg: str) -> str:
    m = msg.lower()
    if "ssrf" in m:
        return "SSRF"
    if "rce" in m or "runincontext" in m or "vm.script" in m:
        return "RCE"
    if "command injection" in m or "exec-like" in m:
        return "Command Injection"
    if "redos" in m:
        return "ReDoS"
    if "arbitrary file read" in m or "filesystem read path" in m:
        return "Arbitrary File Read"
    if "mkdir path" in m:
        return "Arbitrary Path Write via mkdir"
    if "write content" in m or "path.write" in m:
        return "Arbitrary File Content Write"
    if "file injection" in m:
        return "File Injection"
    return "Unknown"


def snake_from_camel(s: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()


def tool_name_from_function_name(name: str):
    if not name:
        return None
    n = name.strip()
    # Common handler naming conventions, e.g. handleReadFile -> read_file
    m = re.match(r"^handle([A-Z].+)$", n)
    if m:
        return snake_from_camel(m.group(1))
    return None


def nearest_tool_from_source(project: str, rel_uri: str, line_no: int):
    rel = unquote(rel_uri).replace('/', os.sep)
    fpath = repo_base / project / rel
    if not fpath.exists():
        return "<unknown>"
    try:
        lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return "<unknown>"
    i = max(0, min(len(lines)-1, line_no-1))

    # special known mapping
    if project == "pptr-mcp" and rel.replace('\\','/').endswith("src/vm-executor.ts"):
        return "execute"

    best = None
    best_dist = 10**9

    # case label heuristic
    for j in range(max(0, i-2000), i+1):
        m = re.search(r"\bcase\s+['\"]([^'\"]+)['\"]\s*:", lines[j])
        if m:
            d = i - j
            if d < best_dist:
                best_dist = d
                best = m.group(1)

    # server.tool/registerTool/mcp.tool heuristic around candidate
    for j in range(max(0, i-1200), min(len(lines), i+1200)):
        if "server.tool(" in lines[j] or ".registerTool(" in lines[j] or "mcp.tool(" in lines[j]:
            for k in range(j, min(len(lines), j+8)):
                m = re.search(r"['\"]([^'\"]+)['\"]", lines[k])
                if m:
                    d = abs(i - j)
                    if d < best_dist:
                        best_dist = d
                        best = m.group(1)
                    break

    # Enclosing function heuristic (restricted):
    #   only handler-like names, e.g. handleReadFile -> read_file
    for j in range(i, max(-1, i-400), -1):
        m = re.search(
            r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            lines[j]
        )
        if m:
            candidate = tool_name_from_function_name(m.group(1))
            if candidate:
                d = i - j
                if d >= 0 and d < best_dist:
                    best_dist = d
                    best = candidate
            break

    return best or "<unknown>"


def candidate_locations_from_result(res):
    out = []
    loc = (res.get("locations") or [{}])[0]
    pl = loc.get("physicalLocation", {})
    uri = ((pl.get("artifactLocation") or {}).get("uri") or "")
    line_no = ((pl.get("region") or {}).get("startLine") or 1)
    if uri:
        out.append((uri, int(line_no)))

    for cf in res.get("codeFlows") or []:
        for tf in cf.get("threadFlows") or []:
            for tl in tf.get("locations") or []:
                pl = (tl.get("location") or {}).get("physicalLocation", {})
                uri = ((pl.get("artifactLocation") or {}).get("uri") or "")
                line_no = ((pl.get("region") or {}).get("startLine") or 1)
                if uri:
                    out.append((uri, int(line_no)))
    return out

report = {}
for sarif_file in sorted(base.glob("*.sarif")):
    stem = sarif_file.stem
    lang = "python" if stem.endswith("-python") else "javascript" if stem.endswith("-javascript") else "unknown"
    project = stem.rsplit("-", 1)[0]
    obj = json.loads(sarif_file.read_text(encoding="utf-8", errors="ignore"))

    for run in obj.get("runs", []):
        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "")
            msg = (res.get("message", {}) or {}).get("text", "") or ""
            vuln = rule_map.get(rid) or classify_from_message(msg)

            tools = re.findall(r"in tool '([^']+)'", msg)
            if not tools:
                candidates = []
                for uri, line_no in candidate_locations_from_result(res):
                    t = nearest_tool_from_source(project, uri, line_no)
                    if t != "<unknown>":
                        candidates.append(t)
                if candidates:
                    # One finding maps to one primary tool.
                    tools = [candidates[0]]
                else:
                    tools = ["<unknown>"]

            report.setdefault(project, {})
            for t in tools:
                report[project].setdefault(t, set()).add(vuln)

out = {p: {t: sorted(vs) for t, vs in sorted(tv.items())} for p, tv in sorted(report.items())}
(base / "server-tool-vulns.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

md = ["# CodeQL Audit Results: Server / Tool / Vulnerability", ""]
for project, tools in out.items():
    md.append(f"## {project}")
    for tool, vulns in tools.items():
        md.append(f"- `{tool}`: {', '.join(vulns)}")
    md.append("")
(base / "server-tool-vulns.md").write_text("\n".join(md), encoding="utf-8")
print("ok")
