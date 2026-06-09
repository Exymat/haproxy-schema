# CI-friendly test runner for HAProxy schema + VS Code extension
$ErrorActionPreference = "Stop"
$ToolsRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ToolsRoot
try {
Write-Host "== haproxy_schema pytest (with coverage report) =="
uv run pytest -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
  Pop-Location
}

$VscodeDir = Join-Path (Split-Path -Parent $ToolsRoot) "haproxy-vscode"
if (-not (Test-Path (Join-Path $VscodeDir "package.json"))) {
  Write-Host "== haproxy-vscode skipped (sibling repo not found) =="
  exit 0
}

Write-Host "== grammar coverage checks =="
$SchemaDir = Join-Path $VscodeDir "schemas"
$Versions = @("2.6", "2.8", "3.0", "3.2", "3.4")
foreach ($version in $Versions) {
  $SchemaPath = Join-Path $SchemaDir "haproxy-$version.schema.json"
  if (-not (Test-Path $SchemaPath)) {
    Write-Host "skip grammar check for $version (missing schema artifact)"
    continue
  }
  uv run --directory $ToolsRoot haproxy-schema check-grammar --schema $SchemaPath
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "== haproxy-vscode npm test =="
Push-Location $VscodeDir
npm test
$code = $LASTEXITCODE
Pop-Location
exit $code
