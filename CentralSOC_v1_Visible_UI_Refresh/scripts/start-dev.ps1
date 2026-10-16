# Run inside the existing CentralSOC project; never copies or recreates local data.
$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $ProjectRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) {
    Write-Error 'Virtual environment missing. Run: python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt'
    exit 1
}
if (-not (Test-Path (Join-Path $ProjectRoot '.env'))) {
    Write-Error 'Missing .env. Copy .env.example to .env and set REGEXSOC_ENV=development, REGEXSOC_SECRET_KEY, and your existing DATABASE_URL.'
    exit 1
}
& $Python -m regexsoc.doctor
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Review the configuration warnings above before launching.' -ForegroundColor Yellow
    exit 1
}
& $Python run.py
exit $LASTEXITCODE
