$ErrorActionPreference = "Stop"

$outputDirectory = "outputs"

if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
    New-Item -ItemType File -Path "$outputDirectory/.gitkeep" -Force | Out-Null
    Write-Host "Created outputs directory." -ForegroundColor Green
    exit 0
}

Write-Host "Cleaning generated outputs..." -ForegroundColor Cyan

Get-ChildItem $outputDirectory -Force |
    Where-Object { $_.Name -ne ".gitkeep" } |
    Remove-Item -Recurse -Force

if (-not (Test-Path "$outputDirectory/.gitkeep")) {
    New-Item -ItemType File -Path "$outputDirectory/.gitkeep" -Force | Out-Null
}

Write-Host "Outputs cleaned. .gitkeep preserved." -ForegroundColor Green
