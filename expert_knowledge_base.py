from typing import Optional

SINK_RULES = [
    (
        "VUL-01-RCE-EXEC-PY",
        "CRITICAL",
        "RCE — unsandboxed exec() execution",
        "py",
        r"\bexec\s*\(",
        "User input reaches exec() and runs as code.",
        "Avoid exec(); use an allowlisted parser or an isolated runtime.",
    ),
    (
        "VUL-01-RCE-EVAL-PY",
        "CRITICAL",
        "RCE — eval() code execution",
        "py",
        r"\beval\s*\(",
        "User input reaches eval().",
        "Use ast.literal_eval() for data parsing.",
    ),
    (
        "VUL-01-RCE-VM-JS",
        "CRITICAL",
        "RCE — Node.js vm sandbox escape",
        "js",
        r"(?:vm\.runInContext|runInContext)\s*\(",
        "User input reaches vm.runInContext(); host objects in context enable sandbox escape.",
        "Use isolated-vm/WebAssembly; do not inject host objects into vm context.",
    ),
    (
        "VUL-02-CMDI-EXEC-JS",
        "CRITICAL",
        "Command Injection — shell command string concatenation",
        "js",
        r"(?:execAsync|execSync|exec)\s*\(\s*(?:cmd|command)",
        "User input is concatenated into shell command strings.",
        "Prefer execFile()/spawn(args); if using exec(), shell-escape input.",
    ),
    (
        "VUL-02-CMDI-EXECASYNC-JS",
        "CRITICAL",
        "Command Injection — execAsync string concatenation",
        "js",
        r"execAsync\s*\(\s*(?:cmd|command|\`)",
        "execAsync() runs concatenated command strings in a shell.",
        "Use execFile() or spawn([...args]).",
    ),
    (
        "VUL-02-CMDI-OS-PY",
        "CRITICAL",
        "Command Injection — os.system()",
        "py",
        r"os\.system\s*\(",
        "os.system() executes user-controlled shell strings.",
        "Use subprocess.run([...], shell=False).",
    ),
    (
        "VUL-03-REDOS-REGEXP-JS",
        "MEDIUM",
        "ReDoS — new RegExp(user input)",
        "js",
        r"new\s+RegExp\s*\(",
        "User input reaches RegExp constructor; pattern may trigger catastrophic backtracking.",
        "Use re2/safe-regex checks and enforce regex timeout.",
    ),
    (
        "VUL-03-REDOS-RE-PY",
        "MEDIUM",
        "ReDoS — re.compile(user input)",
        "py",
        r"re\.compile\s*\(",
        "User input reaches re.compile(); backtracking may cause DoS.",
        "Prefer google-re2 and add pattern validation/timeout.",
    ),
    (
        "VUL-04-PATHTRA-READ-JS",
        "HIGH",
        "Arbitrary File Read — unvalidated path",
        "js",
        r"fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream)\s*\(",
        "User path reaches fs.readFile* without boundary checks.",
        "Resolve path and enforce base-dir prefix check.",
    ),
    (
        "VUL-04-PATHTRA-READ-BARE-JS",
        "HIGH",
        "Arbitrary File Read — direct readFile import usage",
        "js",
        r"(?<!fs\.)(?<!promises\.)(?<!\w)readFile(?:Sync)?\s*\(",
        "User path reaches imported readFile* without boundary checks.",
        "Use path.resolve()+startsWith() base-dir validation.",
    ),
    (
        "VUL-04-PATHTRA-OPEN-PY",
        "HIGH",
        "Arbitrary File Read — unrestricted open() path",
        "py",
        r"\bopen\s*\(",
        "User path reaches open() without boundary checks.",
        "Use realpath()+startswith() base-dir validation.",
    ),
    (
        "VUL-05-SSRF-REQUESTS-PY",
        "MEDIUM",
        "SSRF — requests.get/post(user URL)",
        "py",
        r"requests\.(?:get|post)\s*\(",
        "User URL reaches requests.get/post without host/IP allowlist.",
        "Enforce domain allowlist and private-IP denylist.",
    ),
    (
        "VUL-05-SSRF-FETCH-JS",
        "MEDIUM",
        "SSRF — fetch/axios(user URL)",
        "js",
        r"(?:fetch|axios\.(?:get|post)|http\.get)\s*\(",
        "User URL reaches outbound HTTP request.",
        "Allowlist hostnames and block private/internal IP ranges.",
    ),
]
SAFE_SINK_PATTERNS = [
    r'exec\s*\(\s*["\']',
    r'execSync\s*\(\s*["\']',
    r'eval\s*\(\s*["\']',
    r'open\s*\(\s*["\']',
    r'open\s*\(\s*os\.path\.join\s*\(\s*["\']',
    r'readFile\s*\(\s*["\']',
    r"readFile\s*\(\s*path\.join\s*\(\s*__dirname",
    r'requests\.get\s*\(\s*["\']',
    r'requests\.get\s*\(\s*f["\']https://api\.',
    r'requests\.post\s*\(\s*["\']',
    r'requests\.post\s*\(\s*f["\']',
    r'fetch\s*\(\s*["\']',
    r'new\s+RegExp\s*\(\s*["\']',
    r"new\s+RegExp\s*\(\s*escaped",
    r're\.compile\s*\(\s*["\']',
    r"re\.compile\s*\(\s*re\.escape",
    r're\.compile\s*\(\s*rf?["\']',
]
SANITIZER_PATTERNS = {
    "RCE": [
        r"RestrictedPython",
        r"isolated[\-_]vm",
        r"__builtins__.*None",
        r"ast\.parse",
        r"ast\.literal_eval",
        r"sandbox",
    ],
    "Command Injection": [
        r"execFile\s*\(",
        r"shlex\.quote",
        r"shell_escape",
        r"shellescape",
        r"escapeshellarg",
    ],
    "ReDoS": [
        r"re2",
        r"safe[\-_]regex",
        r"google_re2",
        r"timeout",
        r"worker.*thread",
        r"Worker\(",
    ],
    "Arbitrary File Read": [
        r"realpath.*startswith",
        r"startsWith\s*\(",
        r"resolve.*startsWith",
        r"\.\..*reject",
        r"normalize.*startsWith",
        r"safePath",
        r"validatePath",
        r"validate_path",
        r"validate_file_path",
        r"isPathAllowed",
        r"safeJoin",
        r"safe_join",
        r"validPath",
        r"allowedDir",
    ],
    "SSRF": [
        r"allowed_domains",
        r"whitelist",
        r"allowlist",
        r"urlparse.*netloc.*in\s",
        r"private.*ip.*check",
        r"block.*internal",
        r"validate.*url.*host",
    ],
    "File Injection": [
        r"realpath.*startswith",
        r"startsWith\s*\(",
        r"resolve.*startsWith",
        r"\.\..*reject",
        r"normalize.*startsWith",
        r"safePath",
        r"validatePath",
        r"validate_path",
        r"validate_file_path",
        r"isPathAllowed",
        r"safeJoin",
        r"safe_join",
        r"validPath",
        r"allowedDir",
        r"path\.isAbsolute",
        r"pathWithin",
        r"containsPath",
        r"sanitize.*path",
    ],
}

_FILE_INJECTION_RULE_META = {
    "FILE-06-MKDIR-JS": (
        "HIGH",
        "File Injection — unrestricted path creation (mkdir)",
        "Tool-parameter taint reaches path arguments of fs.mkdir / mkdirSync / fs.promises.mkdir;"
        "a typical case is creating user-directed paths when directories do not exist (including recursive directory creation), which relates to arbitrary write capability.",
        "Restrict mkdir to base dir and validate with realpath+prefix.",
    ),
    "FILE-07-CONTENT-JS": (
        "MEDIUM",
        "File Injection — unrestricted content write under fixed path",
        "Target path is fixed, but user input controls writeFile content.",
        "Validate content and block sensitive overwrites.",
    ),
    "FILE-06-MKDIR-PY": (
        "HIGH",
        "File Injection — unrestricted path creation (mkdir / makedirs)",
        "Tool-parameter taint reaches path arguments of os.makedirs / os.mkdir / Path(...).mkdir;"
        "a typical case is creating user-directed directory trees when directories do not exist.",
        "Restrict mkdir/makedirs to base dir and validate with realpath.",
    ),
    "FILE-07-CONTENT-PY": (
        "MEDIUM",
        "File Injection — unrestricted content write under fixed path",
        "Target path is fixed, but user input controls write_text/write_bytes content.",
        "Limit write size/encoding and block sensitive overwrites.",
    ),
}

def _get_vuln_category(rule_id: str) -> str:
    if rule_id.startswith("FILE-"):
        return "File Injection"
    if "RCE" in rule_id:
        return "RCE"
    if "CMDI" in rule_id:
        return "Command Injection"
    if "REDOS" in rule_id:
        return "ReDoS"
    if "PATHTRA" in rule_id:
        return "Arbitrary File Read"
    if "SSRF" in rule_id:
        return "SSRF"
    return ""

SINK_METRIC_ORDER: list[tuple[str, str]] = [
    ("content_write", "Arbitrary File Content Write"),
    ("path_write", "Arbitrary Path Write via mkdir"),
    ("ssrf", "SSRF"),
    ("dos", "ReDoS"),
    ("rce", "RCE"),
    ("arbitrary_read", "Arbitrary File Read"),
]
def classify_sink_metric_key(
    rule_id: str,
    finding_kind: str = "vuln_trigger",
) -> Optional[str]:
    fk = finding_kind or "vuln_trigger"
    rid = rule_id or ""
    if fk == "file_injection":
        if rid.startswith("FILE-06-MKDIR"):
            return "path_write"
        if rid.startswith("FILE-07"):
            return "content_write"
        return None
    if rid.startswith("VUL-05") or "SSRF" in rid:
        return "ssrf"
    if rid.startswith("VUL-03") or "REDOS" in rid:
        return "dos"
    if (
        rid.startswith("VUL-01")
        or rid.startswith("VUL-02")
        or "RCE-" in rid
        or "CMDI" in rid
    ):
        return "rce"
    if rid.startswith("VUL-04") or "PATHTRA" in rid:
        return "arbitrary_read"
    return None
