CodeQL queries for detecting **Invocation Forwarding Attacks** in MCP servers: untrusted `tools/call` arguments forwarded into privileged operations.

## Prerequisites

- [CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli) on `PATH`
- Python 3
- MCP sources, one project per folder

## Usage

```powershell
cd D:\MCP\codeql
.\run-batch-scan.ps1
python .\audit-latest\build_report.py
```

Rebuild databases after source changes:

```powershell
.\run-batch-scan.ps1 -ForceRecreateDb
```

Custom paths:

```powershell
.\run-batch-scan.ps1 -DatabaseRoot "C:\path\to\repos" -CodeqlRoot "D:\MCP\codeql"
```

## Output

- `audit-latest\<project>-python.sarif` / `-javascript.sarif`
- `audit-latest\server-tool-vulns.json`
- `audit-latest\server-tool-vulns.md`
