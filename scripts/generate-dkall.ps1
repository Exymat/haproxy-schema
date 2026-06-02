# Regenerate haproxy_schema/dkall-<version>.txt using haproxy from WSL (or HAPROXY env).
param(
  [string]$Version = "3.2",
  [string]$Output = "",
  [string]$Haproxy = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$bashScript = Join-Path $PSScriptRoot "generate-dkall.sh"
$wslScript = "/mnt/c/" + ($bashScript -replace '\\', '/' -replace ':', '')

$args = @("bash", $wslScript, $Version)
if ($Output) {
  $wslOut = "/mnt/c/" + ((Resolve-Path $Output).Path -replace '\\', '/' -replace ':', '')
  $args += $wslOut
}
$envPrefix = ""
if ($Haproxy) {
  $envPrefix = "HAPROXY=$(($Haproxy -replace '\\', '/')) "
}

wsl bash -c "${envPrefix}$($args -join ' ')"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
