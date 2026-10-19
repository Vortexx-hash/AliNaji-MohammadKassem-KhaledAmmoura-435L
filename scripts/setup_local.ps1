$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed' }
}
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
if (-not (Test-Path -LiteralPath '.env')) {
    $localKey = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
    "JWT_SECRET=$localKey" | Set-Content -LiteralPath '.env' -Encoding ASCII
}
foreach ($line in Get-Content -LiteralPath '.env') {
    if ($line -match '^([A-Z][A-Z0-9_]*)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
}
& .\.venv\Scripts\python.exe -m scripts.dev_tokens --postman
if ($LASTEXITCODE -ne 0) { throw 'Token generation failed' }
Write-Output 'Local configuration ready. Start a service with: .\scripts\run.ps1 threats'
