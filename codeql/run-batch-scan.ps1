param(
    [string]$DatabaseRoot = "C:\Users\skywings\Desktop\database",
    [string]$CodeqlRoot   = "D:\MCP\codeql",
    [switch]$ForceRecreateDb
)

$ErrorActionPreference = "Stop"

$dbOutRoot   = Join-Path $CodeqlRoot "scan-results\db"
$auditRoot   = Join-Path $CodeqlRoot "audit-latest"
$pythonQlDir = Join-Path $CodeqlRoot "python"
$jsQlDir     = Join-Path $CodeqlRoot "javascript"

$pythonQueries = @(
    (Join-Path $pythonQlDir "mcp-tool-input-ssrf-python.ql"),
    (Join-Path $pythonQlDir "mcp-tool-input-rce-python.ql"),
    (Join-Path $pythonQlDir "mcp-tool-input-command-injection-python.ql"),
    (Join-Path $pythonQlDir "mcp-tool-input-redos-python.ql"),
    (Join-Path $pythonQlDir "mcp-tool-input-arbitrary-file-read-python.ql"),
    (Join-Path $pythonQlDir "mcp-tool-input-file-injection-python.ql")
)

$jsQueries = @(
    (Join-Path $jsQlDir "mcp-request-arguments-to-dangerous-sinks-javascript.ql"),
    (Join-Path $jsQlDir "mcp-tool-input-ssrf-javascript.ql")
)

if (-not (Get-Command codeql -ErrorAction SilentlyContinue)) {
    throw "The 'codeql' command was not found. Please install CodeQL and add it to PATH."
}
if (-not (Test-Path $DatabaseRoot)) { throw "Database root does not exist: $DatabaseRoot" }
if (-not (Test-Path $CodeqlRoot))   { throw "CodeQL root does not exist: $CodeqlRoot" }

New-Item -ItemType Directory -Force -Path $dbOutRoot  | Out-Null
New-Item -ItemType Directory -Force -Path $auditRoot  | Out-Null

function Test-HasLanguageFiles {
    param(
        [string]$RepoPath,
        [string[]]$Extensions
    )
    $files = Get-ChildItem -Path $RepoPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch "\\node_modules\\|\\\.git\\|\\venv\\|\\\.venv\\|\\dist\\|\\build\\|\\coverage\\" -and
            $Extensions -contains $_.Extension.ToLowerInvariant()
        } |
        Select-Object -First 1
    return $null -ne $files
}

function Invoke-CodeqlCreateAndAnalyze {
    param(
        [string]$RepoName,
        [string]$RepoPath,
        [string]$Language,
        [string[]]$Queries,
        [string]$Suffix
    )

    $dbPath    = Join-Path $dbOutRoot "$RepoName-$Suffix-db"
    $sarifPath = Join-Path $auditRoot "$RepoName-$Suffix.sarif"

    Write-Host "`n[$RepoName][$Language] Creating database..." -ForegroundColor Cyan

    if ((Test-Path $dbPath) -and $ForceRecreateDb) {
        Remove-Item -Recurse -Force $dbPath
    }

    if (-not (Test-Path $dbPath)) {
        & codeql database create $dbPath --language=$Language --source-root $RepoPath
    } else {
        Write-Host "[$RepoName][$Language] Reusing existing DB: $dbPath" -ForegroundColor Yellow
    }

    Write-Host "[$RepoName][$Language] Running analysis..." -ForegroundColor Cyan
    & codeql database analyze $dbPath @Queries --format=sarif-latest --output $sarifPath --threads=0 --rerun
    Write-Host "[$RepoName][$Language] Done. SARIF: $sarifPath" -ForegroundColor Green
}

$repos = Get-ChildItem -Path $DatabaseRoot -Directory | Sort-Object Name
if ($repos.Count -eq 0) {
    throw "No project directories were found under: $DatabaseRoot"
}

$scanned = 0
$skipped = 0

foreach ($repo in $repos) {
    $repoName = $repo.Name
    $repoPath = $repo.FullName

    Write-Host "`n==================================================" -ForegroundColor DarkGray
    Write-Host "Processing project: $repoName" -ForegroundColor White
    Write-Host "Path: $repoPath" -ForegroundColor DarkGray

    $hasPy = Test-HasLanguageFiles -RepoPath $repoPath -Extensions @(".py")
    $hasJs = Test-HasLanguageFiles -RepoPath $repoPath -Extensions @(".js", ".mjs", ".cjs", ".ts", ".tsx")

    if (-not $hasPy -and -not $hasJs) {
        Write-Host "Skipped (no Python/JS/TS source files detected)" -ForegroundColor Yellow
        $skipped++
        continue
    }

    try {
        if ($hasPy) {
            Invoke-CodeqlCreateAndAnalyze -RepoName $repoName -RepoPath $repoPath -Language "python" -Queries $pythonQueries -Suffix "python"
            $scanned++
        }
        if ($hasJs) {
            Invoke-CodeqlCreateAndAnalyze -RepoName $repoName -RepoPath $repoPath -Language "javascript" -Queries $jsQueries -Suffix "javascript"
            $scanned++
        }
    } catch {
        Write-Host "[$repoName] Scan failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nAll done. Scan tasks: $scanned, skipped projects: $skipped" -ForegroundColor Green
Write-Host "SARIF output directory: $auditRoot" -ForegroundColor Green
