#requires -Version 5.1
<#
  Start the autonomous DeepSeek orchestrator (ds_orchestrator.py) for the Aegis 4-stage relay.
  Layout-aware: works both from the USB bundle root (.\suite\operator\...) and from the standalone
  DS-Orchestrator project root (.\operator\...). No interactive Claude session required -- DS is the
  brain; deep escalation uses `claude -p` if the CLI is present, else DS-thinking.

  Examples:
    .\start-ds-orchestrator.ps1 -Base http://127.0.0.1:8000 -Role dispatcher -Budget 50
    .\start-ds-orchestrator.ps1 -Objective "authz grid + money-integrity" -NoFollowUp
    .\start-ds-orchestrator.ps1 -SecretEnv .\secret.env         # provide DS/CF keys explicitly
#>
[CmdletBinding()]
param(
  [string]$Base,
  [string]$Role = "dispatcher",
  [int]$Budget = 50,
  [string]$Objective,
  [string]$Auth,
  [switch]$NoFollowUp,
  [switch]$Auto,
  [switch]$Dry,
  [double]$GateTimeout = 0,
  [string]$SecretEnv
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# locate ds_orchestrator.py (USB bundle: suite\operator\...; project: operator\...)
$cands = @((Join-Path $root 'suite\operator\ds_orchestrator.py'), (Join-Path $root 'operator\ds_orchestrator.py'))
$orch  = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $orch) { throw "ds_orchestrator.py not found under $root (looked in suite\operator and operator)" }
$suiteRoot = Split-Path -Parent (Split-Path -Parent $orch)   # the dir that holds operator\

# pick python: a local venv if present (USB: suite\.venv; project: .venv), else system python
$pyCands = @((Join-Path $suiteRoot '.venv\Scripts\python.exe'), (Join-Path $root '.venv\Scripts\python.exe'))
$py = $pyCands | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $py) {
  if (Get-Command python -ErrorAction SilentlyContinue) { $py = 'python' }
  else { throw "No Python found. Run bring-up.ps1 (USB) or create a venv and 'pip install -r requirements.txt'." }
}

# default secret.env: look next to the script / suite / a sibling ask-board
if (-not $SecretEnv) {
  $seCands = @((Join-Path $root 'secret.env'), (Join-Path $suiteRoot 'secret.env'),
               (Join-Path $root 'ask-board\secret.env'), (Join-Path $suiteRoot '..\ask-board\secret.env'))
  $SecretEnv = $seCands | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $SecretEnv) {
  Write-Warning "No secret.env found -- ds_orchestrator needs DS keys (AEGIS_LLM_API_KEY / CF creds) in the environment or via -SecretEnv."
}

$argsList = @('--role', $Role, '--budget', $Budget)
if ($Base)        { $argsList += @('--base', $Base) }
if ($Objective)   { $argsList += @('--objective', $Objective) }
if ($Auth)        { $argsList += @('--auth', $Auth) }
if ($NoFollowUp)  { $argsList += '--no-follow-up' }
if ($Auto)        { $argsList += '--auto' }
if ($Dry)         { $argsList += '--dry' }
if ($GateTimeout -gt 0) { $argsList += @('--gate-timeout', $GateTimeout) }
if ($SecretEnv)   { $argsList += @('--secret-env', $SecretEnv) }

Write-Host "== DS Orchestrator ==" -ForegroundColor Cyan
Write-Host "  python : $py"
Write-Host "  script : $orch"
$secDisplay = if ([string]::IsNullOrEmpty($SecretEnv)) { '(from environment)' } else { $SecretEnv }
Write-Host "  secrets: $secDisplay"
Write-Host "  args   : $($argsList -join ' ')"
Write-Host ""
& $py $orch @argsList
exit $LASTEXITCODE
