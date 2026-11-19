#requires -Version 5.1
<#
  ds-standby.ps1 -- bring the DS Orchestrator up on STANDBY, with DS in the driver's seat.

  Starts operator\aegis_operator.py in --chat mode (DeepSeek as the agent): tools loaded, context kept
  across turns, NO target set. You then talk to DS at the prompt exactly like you task Claude -- name the
  target URL in the task text when you're ready. This is the co-pilot (DS the agent), not the 4-stage relay.

  Examples:
    .\ds-standby.ps1                               # standby, no target, ask before each action
    .\ds-standby.ps1 -Target http://127.0.0.1:3000 # pre-set a default target
    .\ds-standby.ps1 -TargetMode mirror            # build/test a local twin
    .\ds-standby.ps1 -Mode safe                    # auto read-only, prompt on the rest (standby default)
    .\ds-standby.ps1 -Mode ask                     # prompt on every action
    .\ds-standby.ps1 -AutoApprove                  # -Mode auto: approve everything (your authorized targets)
    # Switch modes live while chatting: type /mode (cycle), or /ask /safe /auto
    .\ds-standby.ps1 -Session .\ds.json            # save/continue the conversation (named file, auto-resumed)
    .\ds-standby.ps1 -Resume                        # pick up the last session (default file is saved every turn; /resume works live too)
    .\ds-standby.ps1 -Think                        # enable deeper-reasoning (thinking) mode; OFF by default

  Brain: DS[deepseek-flash] in FAST (non-thinking) chat mode by DEFAULT. Pass -Think for the slower,
  deeper-reasoning mode, or -Brain deepseek-v4-pro to force pro. You can also toggle live in chat with
  /think and /nothink (and the per-brain /ds vs /ds-think switches).
#>
[CmdletBinding()]
param(
  [string]$Target,
  [ValidateSet('live','mirror','split')] [string]$TargetMode = 'live',
  [ValidateSet('ask','safe','auto')] [string]$Mode = 'safe',
  [string]$Brain = 'deepseek-flash',      # benchmarked primary brain (fastest+strongest across tiers)
  [string]$CfHelper = 'gpt-oss-120b',     # cheap CF helper DS calls when stuck (cf_helper tool)
  [switch]$AutoApprove,
  [switch]$Think,                         # deeper-reasoning (thinking) mode; OFF by default (fast chat mode)
  [switch]$NoThink,                       # deprecated/no-op: non-thinking is the default now (kept so old invocations don't error)
  [string]$Session,
  [switch]$Resume,                        # load the saved session on start (default file is saved every turn but only picked up on request; or type /resume live)
  [string]$SecretEnv,
  [string]$Provider = 'deepseek'
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$op   = Join-Path $root 'operator\aegis_operator.py'
if (-not (Test-Path $op)) { throw "aegis_operator.py not found at $op" }

# --- locate secret.env (DS key + endpoint). -SecretEnv wins, else search known spots. ---
if (-not $SecretEnv) {
  $cands = @(
    (Join-Path $root 'secret.env'),
    (Join-Path (Split-Path $root -Parent) 'ask-board\secret.env'),  # ..\ask-board\secret.env
    (Join-Path $root '..\ask-board\secret.env')
  )
  $SecretEnv = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $SecretEnv -or -not (Test-Path $SecretEnv)) {
  throw "No secret.env found (holds AEGIS_LLM_API_KEY). Pass -SecretEnv <path>."
}

# --- load KEY=VALUE lines from secret.env into this session's environment ---
Get-Content $SecretEnv |
  Where-Object { $_ -match '=' -and $_ -notmatch '^\s*#' } |
  ForEach-Object {
    $k,$v = $_ -split '=',2
    $v = $v.Trim().Trim('"').Trim("'")
    Set-Item "Env:$($k.Trim())" $v
  }
if (-not $env:AEGIS_LLM_API_KEY -and -not $env:DEEPSEEK_API_KEY) {
  throw "secret.env loaded but no AEGIS_LLM_API_KEY / DEEPSEEK_API_KEY in it ($SecretEnv)."
}

$env:PYTHONUTF8 = '1'
# brain + helper policy (override whatever secret.env set): flash primary, gpt-oss-120b helper
$env:AEGIS_MODEL = $Brain
$env:AEGIS_CF_HELPER = $CfHelper
if ($Target) { $env:AEGIS_TARGET = $Target }

# --- pick python: $env:AEGIS_PYTHON wins, else python on PATH ---
$py = $env:AEGIS_PYTHON
if ([string]::IsNullOrEmpty($py)) {
  $cmd = Get-Command python -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source } else { throw "No python on PATH; set `$env:AEGIS_PYTHON." }
}

# --- build the co-pilot argument list ---
if ($AutoApprove) { $Mode = 'auto' }   # -AutoApprove is shorthand for the full-trust mode
$argsList = @('aegis_operator.py','--chat','--provider',$Provider,'--target-mode',$TargetMode,'--mode',$Mode)
# Thinking is OFF by default (fast chat mode). -Think turns it on; -NoThink (deprecated) forces it off even with -Think.
$useThink = $Think -and (-not $NoThink)
if ($useThink) { $argsList += '--think' }
if ($Session) { $argsList += @('--session',$Session) }
if ($Resume)  { $argsList += '--resume' }   # pick up the saved session on launch (default file persists every turn regardless)

$Host.UI.RawUI.WindowTitle = 'DS Orchestrator - STANDBY (DS in the seat)'
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ' DS ORCHESTRATOR - launching co-pilot...  (DS in the seat)' -ForegroundColor Cyan
Write-Host (" helper={0}  think={1}   -- full status in the coordinator banner below" -f $CfHelper,($(if($useThink){'on'}else{'off'}))) -ForegroundColor DarkCyan
if ($Mode -eq 'auto') { Write-Host ' GATE=auto (full trust) - use only against a contained mirror.' -ForegroundColor Yellow }
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''

Set-Location (Join-Path $root 'operator')
& $py @argsList
