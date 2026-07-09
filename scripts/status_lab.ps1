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

Assert-CommandExists "az"
Load-DotEnv

$subscriptionId = $env:AZURE_SUBSCRIPTION_ID
$resourceGroup = $env:AZURE_TARGET_RESOURCE_GROUP

if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
    throw "AZURE_SUBSCRIPTION_ID mancante nel file .env"
}

if ([string]::IsNullOrWhiteSpace($resourceGroup)) {
    throw "AZURE_TARGET_RESOURCE_GROUP mancante nel file .env"
}

Write-Host "Azure NIS2 lab status" -ForegroundColor Cyan
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
    Write-Host "Resource Group non trovato." -ForegroundColor Yellow
    exit 0
}

$resourcesJson = az resource list `
    --resource-group $resourceGroup `
    --query "[].{Name:name, Type:type, Location:location}" `
    -o json

$resources = $resourcesJson | ConvertFrom-Json

Write-Host "Resources:" -ForegroundColor Cyan
$resources | Sort-Object Type, Name | Format-Table Name, Type, Location -AutoSize

Write-Host ""
Write-Host "Resource counts by type:" -ForegroundColor Cyan
$resources |
    Group-Object Type |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Expected stable lab state:" -ForegroundColor Cyan
Write-Host "Expected resources: 8"
Write-Host "Expected assessed resources by framework: 5"
Write-Host "Expected unassessed resources by framework: 3"
Write-Host ""

if (@($resources).Count -eq 8) {
    Write-Host "Resource count matches the documented validation state." -ForegroundColor Green
}
else {
    Write-Host "Resource count differs from the documented validation state: $(@($resources).Count)" -ForegroundColor Yellow
}

$unexpectedVmArtifacts = @($resources | Where-Object {
    $_.Type -in @(
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Compute/disks",
        "Microsoft.Network/networkInterfaces",
        "Microsoft.Network/publicIPAddresses",
        "Microsoft.Network/virtualNetworks"
    )
})

if ($unexpectedVmArtifacts.Count -gt 0) {
    Write-Host ""
    Write-Host "Possible VM-attempt residual resources detected:" -ForegroundColor Yellow
    $unexpectedVmArtifacts | Format-Table Name, Type, Location -AutoSize
}
