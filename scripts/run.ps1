param([ValidateSet('users','logs','notifications','threats','vulnerabilities','reports')][string]$Service = 'threats')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
if (Test-Path -LiteralPath '.env') {
    foreach ($line in Get-Content -LiteralPath '.env') {
        if ($line -match '^([A-Z][A-Z0-9_]*)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
}
$servicePorts = @{users=8001; logs=8005; notifications=8008; threats=8004; vulnerabilities=8007; reports=8006}
& .\.venv\Scripts\python.exe -m uvicorn "services.$Service.app:create_app" --factory --host 127.0.0.1 --port $servicePorts[$Service]
exit $LASTEXITCODE
