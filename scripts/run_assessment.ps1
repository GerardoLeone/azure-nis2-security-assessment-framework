$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

function Load-DotEnv {
    param([string]$Path = (Join-Path $ProjectRoot ".env"))

    if (-not (Test-Path $Path)) {
        throw "File .env non trovato nella root del progetto: $ProjectRoot"
    }

    Get-Content $Path | ForEach-Object {
        if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim().Trim('"').Trim("'")
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

function Assert-CommandExists {
    param([Parameter(Mandatory = $true)][string]$Command)

    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Comando richiesto non trovato: $Command"
    }
}

function Invoke-Az {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & az @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "Comando Azure CLI fallito: az $($Arguments -join ' ')"
    }
}

function Get-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) {
        return $null
    }

    $content = Get-Content $Path -Raw

    if ([string]::IsNullOrWhiteSpace($content)) {
        return $null
    }

    return $content | ConvertFrom-Json
}

Assert-CommandExists "az"
Assert-CommandExists "python"
Load-DotEnv

$subscriptionId = $env:AZURE_SUBSCRIPTION_ID
$resourceGroup = $env:AZURE_TARGET_RESOURCE_GROUP

if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
    throw "AZURE_SUBSCRIPTION_ID mancante nel file .env"
}

if ([string]::IsNullOrWhiteSpace($resourceGroup)) {
    throw "AZURE_TARGET_RESOURCE_GROUP mancante nel file .env"
}

Write-Host "Running Azure NIS2 Security Assessment Framework..." -ForegroundColor Cyan
Write-Host "Project Root: $ProjectRoot"
Write-Host "Subscription: $subscriptionId"
Write-Host "Resource Group: $resourceGroup"
Write-Host ""

Invoke-Az @("account", "set", "--subscription", $subscriptionId)

$activeSubscription = az account show --query "id" -o tsv
if ($activeSubscription -ne $subscriptionId) {
    throw "La subscription attiva non coincide con AZURE_SUBSCRIPTION_ID."
}

$resourceGroupExists = az group exists --name $resourceGroup -o tsv
if ($resourceGroupExists -ne "true") {
    throw "Resource Group non trovato: $resourceGroup"
}

if (-not (Test-Path "outputs")) {
    New-Item -ItemType Directory -Path "outputs" | Out-Null
}

$env:PYTHONPATH = "src"
python -m az_nis2.main

if ($LASTEXITCODE -ne 0) {
    throw "Assessment fallito."
}

Write-Host ""
Write-Host "Assessment completed." -ForegroundColor Green

$risk = Get-JsonFile "outputs/risk.json"
$findings = Get-JsonFile "outputs/findings.json"
$compliance = Get-JsonFile "outputs/compliance.json"

Write-Host ""
Write-Host "Output summary:" -ForegroundColor Cyan

if ($risk -ne $null -and $risk.overall -ne $null) {
    Write-Host "Risk grade: $($risk.overall.risk_grade)"
    Write-Host "Risk score: $($risk.overall.score_percent)%"
    Write-Host "Discovered resources: $($risk.overall.discovered_resources)"
    Write-Host "Assessed resources: $($risk.overall.assessed_resources)"
    Write-Host "Unassessed resources: $($risk.overall.unassessed_resources)"
    Write-Host "Total findings: $($risk.overall.total_findings)"
}

if ($findings -ne $null) {
    $findingsCount = @($findings.findings).Count
    if ($findingsCount -eq 0 -and $findings -is [array]) {
        $findingsCount = @($findings).Count
    }
    Write-Host "Findings file entries: $findingsCount"
}

if ($compliance -ne $null -and $compliance.summary -ne $null) {
    Write-Host "NIS2 controls passed: $($compliance.summary.passed_controls)/$($compliance.summary.total_controls)"
}

Write-Host ""
Write-Host "Generated files:" -ForegroundColor Cyan
Get-ChildItem "outputs" -File | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
