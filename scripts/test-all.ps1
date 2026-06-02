# CI-friendly test runner for HAProxy schema + VS Code extension
$ErrorActionPreference = "Stop"
$ToolsRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = $ToolsRoot

Write-Host "== haproxy_schema pytest =="
python -m pytest (Join-Path $ToolsRoot "haproxy_schema\tests") -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$VscodeDir = Join-Path (Split-Path -Parent $ToolsRoot) "haproxy-vscode"
if (-not (Test-Path (Join-Path $VscodeDir "package.json"))) {
  Write-Host "== haproxy-vscode skipped (sibling repo not found) =="
  exit 0
}

Write-Host "== haproxy-vscode npm test =="
Push-Location $VscodeDir
npm test
$code = $LASTEXITCODE
Pop-Location
exit $code
