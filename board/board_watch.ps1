$bf = (Join-Path $PSScriptRoot "board_files")
Write-Host "Watching board answers (Ctrl+C to stop)..." -ForegroundColor Cyan
while ($true) {
  Clear-Host
  Get-ChildItem "$bf\ANSWER__*.md" | Sort-Object LastWriteTime -Descending | Select-Object -First 6 | ForEach-Object {
    Write-Host ("=== {0}  ({1}) ===" -f $_.Name, $_.LastWriteTime) -ForegroundColor Yellow
    Get-Content $_.FullName -Raw
    Write-Host ""
  }
  Start-Sleep -Seconds 5
}
