$ErrorActionPreference = "Stop"

function Load-DotEnv {
    param([string]$Path = ".env")

    if (-not (Test-Path $Path)) {
        throw "File .env non trovato nella root del progetto."
    }

    Get-Content $Path | ForEach-Object {
        if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim().Trim('"').Trim("'")
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

function Invoke-Az {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & az @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "Comando Azure CLI fallito: az $($Arguments -join ' ')"
    }
}

Load-DotEnv

$subscriptionId = $env:AZURE_SUBSCRIPTION_ID
$resourceGroup = $env:AZURE_TARGET_RESOURCE_GROUP

if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
    throw "AZURE_SUBSCRIPTION_ID mancante nel file .env"
}

if ([string]::IsNullOrWhiteSpace($resourceGroup)) {
    throw "AZURE_TARGET_RESOURCE_GROUP mancante nel file .env"
}

Write-Host "Azure NIS2 lab destroy script" -ForegroundColor Yellow
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
    Write-Host "Resource Group non trovato. Nessuna risorsa da eliminare." -ForegroundColor Green
    exit 0
}

Write-Host "Risorse attualmente presenti nel Resource Group:" -ForegroundColor Cyan

az resource list `
    --resource-group $resourceGroup `
    --query "[].{Name:name, Type:type, Location:location}" `
    -o table

Write-Host ""
Write-Host "ATTENZIONE: questa operazione eliminerà l'intero Resource Group e tutte le risorse contenute." -ForegroundColor Red
Write-Host "Resource Group target: $resourceGroup" -ForegroundColor Red
Write-Host ""

$confirmation = Read-Host "Per confermare, digita esattamente DELETE"

if ($confirmation -ne "DELETE") {
    Write-Host "Operazione annullata. Nessuna risorsa eliminata." -ForegroundColor Yellow
    exit 0
}

$resourceGroupConfirmation = Read-Host "Digita il nome del Resource Group per confermare definitivamente"

if ($resourceGroupConfirmation -ne $resourceGroup) {
    Write-Host "Nome Resource Group non corrispondente. Operazione annullata." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Eliminazione Resource Group in corso: $resourceGroup" -ForegroundColor Yellow

Invoke-Az @(
    "group", "delete",
    "--name", $resourceGroup,
    "--yes"
)

Write-Host ""
Write-Host "Resource Group eliminato correttamente." -ForegroundColor Green
