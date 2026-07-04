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

function Invoke-AzIgnore {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & az @Arguments 2>$null | Out-Null
}

function Wait-ProviderRegistration {
    param([Parameter(Mandatory = $true)][string]$Namespace)

    Write-Host "Checking provider: $Namespace"

    Invoke-Az @("provider", "register", "--namespace", $Namespace)

    for ($i = 0; $i -lt 40; $i++) {
        $state = az provider show `
            --namespace $Namespace `
            --query "registrationState" `
            -o tsv

        if ($state -eq "Registered") {
            Write-Host "$Namespace registered." -ForegroundColor Green
            return
        }

        Write-Host "$Namespace state: $state. Waiting..."
        Start-Sleep -Seconds 5
    }

    throw "Provider $Namespace non registrato dopo l'attesa."
}

function Get-FirstResourceNameByPurpose {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceType,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    $query = "[?tags.purpose=='$Purpose'].name | [0]"

    $result = az resource list `
        --resource-group $resourceGroup `
        --resource-type $ResourceType `
        --query $query `
        -o tsv 2>$null

    if ($LASTEXITCODE -ne 0) {
        return ""
    }

    if ($null -eq $result) {
        return ""
    }

    $value = ($result | Select-Object -First 1)

    if ($null -eq $value) {
        return ""
    }

    $value = $value.ToString().Trim()

    if ([string]::IsNullOrWhiteSpace($value)) {
        return ""
    }

    return $value
}

Load-DotEnv

$subscriptionId = $env:AZURE_SUBSCRIPTION_ID
$resourceGroup = $env:AZURE_TARGET_RESOURCE_GROUP
$location = $env:AZURE_LOCATION

if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
    throw "AZURE_SUBSCRIPTION_ID mancante nel file .env"
}

if ([string]::IsNullOrWhiteSpace($resourceGroup)) {
    throw "AZURE_TARGET_RESOURCE_GROUP mancante nel file .env"
}

if ([string]::IsNullOrWhiteSpace($location)) {
    $location = "francecentral"
}

Write-Host "Using subscription: $subscriptionId"
Invoke-Az @("account", "set", "--subscription", $subscriptionId)

$activeSubscription = az account show --query "id" -o tsv
if ($activeSubscription -ne $subscriptionId) {
    throw "La subscription attiva non coincide con AZURE_SUBSCRIPTION_ID."
}

Wait-ProviderRegistration "Microsoft.Storage"
Wait-ProviderRegistration "Microsoft.KeyVault"
Wait-ProviderRegistration "Microsoft.Network"
Wait-ProviderRegistration "Microsoft.Web"
Wait-ProviderRegistration "Microsoft.Sql"

$suffix = Get-Random -Minimum 10000 -Maximum 99999

Write-Host "Creating / updating Azure NIS2 lab resources..." -ForegroundColor Cyan
Write-Host "Resource Group: $resourceGroup"
Write-Host "Location: $location"

Invoke-Az @(
    "group", "create",
    "--name", $resourceGroup,
    "--location", $location,
    "--tags",
    "project=azure-nis2-security-assessment-framework",
    "env=dev",
    "purpose=thesis-lab"
)

# -------------------------------------------------------------------
# Storage Account
# -------------------------------------------------------------------

$storageAccount = Get-FirstResourceNameByPurpose `
    -ResourceType "Microsoft.Storage/storageAccounts" `
    -Purpose "storage-misconfiguration-test"

if ([string]::IsNullOrWhiteSpace($storageAccount)) {
    $storageAccount = "stnis2lab$suffix"

    Write-Host "Creating Storage Account: $storageAccount"

    Invoke-Az @(
        "storage", "account", "create",
        "--name", $storageAccount,
        "--resource-group", $resourceGroup,
        "--location", $location,
        "--sku", "Standard_LRS",
        "--kind", "StorageV2",
        "--allow-blob-public-access", "true",
        "--https-only", "false",
        "--public-network-access", "Enabled",
        "--tags",
        "project=azure-nis2-security-assessment-framework",
        "env=dev",
        "purpose=storage-misconfiguration-test"
    )
}
else {
    Write-Host "Reusing Storage Account: $storageAccount"

    Invoke-Az @(
        "storage", "account", "update",
        "--name", $storageAccount,
        "--resource-group", $resourceGroup,
        "--allow-blob-public-access", "true",
        "--https-only", "false",
        "--public-network-access", "Enabled"
    )
}

$storageKey = az storage account keys list `
    --resource-group $resourceGroup `
    --account-name $storageAccount `
    --query "[0].value" `
    -o tsv

if ([string]::IsNullOrWhiteSpace($storageKey)) {
    throw "Impossibile recuperare la storage account key."
}

Invoke-Az @(
    "storage", "container", "create",
    "--name", "public-container",
    "--account-name", $storageAccount,
    "--account-key", $storageKey,
    "--public-access", "blob"
)

# -------------------------------------------------------------------
# Key Vault
# -------------------------------------------------------------------

$keyVault = Get-FirstResourceNameByPurpose `
    -ResourceType "Microsoft.KeyVault/vaults" `
    -Purpose "keyvault-misconfiguration-test"

if ([string]::IsNullOrWhiteSpace($keyVault)) {
    $keyVault = "kv-nis2-lab-$suffix"

    Write-Host "Creating Key Vault: $keyVault"

    Invoke-Az @(
        "keyvault", "create",
        "--name", $keyVault,
        "--resource-group", $resourceGroup,
        "--location", $location,
        "--public-network-access", "Enabled",
        "--default-action", "Allow",
        "--tags",
        "project=azure-nis2-security-assessment-framework",
        "env=dev",
        "purpose=keyvault-misconfiguration-test"
    )
}
else {
    Write-Host "Reusing Key Vault: $keyVault"

    Invoke-Az @(
        "keyvault", "update",
        "--name", $keyVault,
        "--resource-group", $resourceGroup,
        "--public-network-access", "Enabled",
        "--default-action", "Allow"
    )
}

# -------------------------------------------------------------------
# Network Security Group
# -------------------------------------------------------------------

$nsgName = "nsg-nis2-open-dev"

Write-Host "Creating / updating NSG: $nsgName"

Invoke-Az @(
    "network", "nsg", "create",
    "--resource-group", $resourceGroup,
    "--name", $nsgName,
    "--location", $location,
    "--tags",
    "project=azure-nis2-security-assessment-framework",
    "env=dev",
    "purpose=network-misconfiguration-test"
)

$rulesToReset = @(
    "Allow-SSH-Internet",
    "Allow-RDP-Internet",
    "Allow-HTTP-Internet",
    "Allow-SQL-Internet"
)

foreach ($ruleName in $rulesToReset) {
    Invoke-AzIgnore @(
        "network", "nsg", "rule", "delete",
        "--resource-group", $resourceGroup,
        "--nsg-name", $nsgName,
        "--name", $ruleName
    )
}

Invoke-Az @(
    "network", "nsg", "rule", "create",
    "--resource-group", $resourceGroup,
    "--nsg-name", $nsgName,
    "--name", "Allow-SSH-Internet",
    "--priority", "100",
    "--direction", "Inbound",
    "--access", "Allow",
    "--protocol", "Tcp",
    "--source-address-prefixes", "*",
    "--source-port-ranges", "*",
    "--destination-address-prefixes", "*",
    "--destination-port-ranges", "22"
)

Invoke-Az @(
    "network", "nsg", "rule", "create",
    "--resource-group", $resourceGroup,
    "--nsg-name", $nsgName,
    "--name", "Allow-RDP-Internet",
    "--priority", "110",
    "--direction", "Inbound",
    "--access", "Allow",
    "--protocol", "Tcp",
    "--source-address-prefixes", "*",
    "--source-port-ranges", "*",
    "--destination-address-prefixes", "*",
    "--destination-port-ranges", "3389"
)

Invoke-Az @(
    "network", "nsg", "rule", "create",
    "--resource-group", $resourceGroup,
    "--nsg-name", $nsgName,
    "--name", "Allow-HTTP-Internet",
    "--priority", "120",
    "--direction", "Inbound",
    "--access", "Allow",
    "--protocol", "Tcp",
    "--source-address-prefixes", "*",
    "--source-port-ranges", "*",
    "--destination-address-prefixes", "*",
    "--destination-port-ranges", "80"
)

Invoke-Az @(
    "network", "nsg", "rule", "create",
    "--resource-group", $resourceGroup,
    "--nsg-name", $nsgName,
    "--name", "Allow-SQL-Internet",
    "--priority", "130",
    "--direction", "Inbound",
    "--access", "Allow",
    "--protocol", "Tcp",
    "--source-address-prefixes", "*",
    "--source-port-ranges", "*",
    "--destination-address-prefixes", "*",
    "--destination-port-ranges", "1433"
)

# -------------------------------------------------------------------
# Azure Web App
# -------------------------------------------------------------------

$appServicePlan = "asp-nis2-lab-dev"

$planExists = az appservice plan list `
    --resource-group $resourceGroup `
    --query "[?name=='$appServicePlan'].name | [0]" `
    -o tsv

if ([string]::IsNullOrWhiteSpace($planExists)) {
    Write-Host "Creating App Service Plan: $appServicePlan"

    Invoke-Az @(
        "appservice", "plan", "create",
        "--name", $appServicePlan,
        "--resource-group", $resourceGroup,
        "--location", $location,
        "--sku", "F1",
        "--is-linux",
        "--tags",
        "project=azure-nis2-security-assessment-framework",
        "env=dev",
        "purpose=appservice-plan"
    )
}
else {
    Write-Host "Reusing App Service Plan: $appServicePlan"
}

$webApp = Get-FirstResourceNameByPurpose `
    -ResourceType "Microsoft.Web/sites" `
    -Purpose "webapp-misconfiguration-test"

if ([string]::IsNullOrWhiteSpace($webApp)) {
    $webApp = "app-nis2-lab-$suffix"

    Write-Host "Creating Web App: $webApp"

    Invoke-Az @(
        "webapp", "create",
        "--resource-group", $resourceGroup,
        "--plan", $appServicePlan,
        "--name", $webApp,
        "--runtime", "PYTHON:3.12"
    )

    $webAppId = az webapp show `
        --resource-group $resourceGroup `
        --name $webApp `
        --query "id" `
        -o tsv

    Invoke-Az @(
        "resource", "tag",
        "--ids", $webAppId,
        "--tags",
        "project=azure-nis2-security-assessment-framework",
        "env=dev",
        "purpose=webapp-misconfiguration-test"
    )
}
else {
    Write-Host "Reusing Web App: $webApp"
}

Invoke-Az @(
    "webapp", "update",
    "--resource-group", $resourceGroup,
    "--name", $webApp,
    "--https-only", "false"
)

Invoke-Az @(
    "webapp", "config", "set",
    "--resource-group", $resourceGroup,
    "--name", $webApp,
    "--ftps-state", "AllAllowed"
)

# -------------------------------------------------------------------
# Azure SQL Server + Database
# -------------------------------------------------------------------

$sqlServer = Get-FirstResourceNameByPurpose `
    -ResourceType "Microsoft.Sql/servers" `
    -Purpose "sql-misconfiguration-test"

$sqlAdminUser = "nis2admin"
$sqlAdminPassword = "AzNis2!$suffix" + "xY9"
$sqlDatabase = "sqldb-nis2-lab"

if ([string]::IsNullOrWhiteSpace($sqlServer)) {
    $sqlServer = "sql-nis2-lab-$suffix"

    Write-Host "Creating Azure SQL Server: $sqlServer"

    Invoke-Az @(
        "sql", "server", "create",
        "--name", $sqlServer,
        "--resource-group", $resourceGroup,
        "--location", $location,
        "--admin-user", $sqlAdminUser,
        "--admin-password", $sqlAdminPassword,
        "--enable-public-network", "true",
        "--tags",
        "project=azure-nis2-security-assessment-framework",
        "env=dev",
        "purpose=sql-misconfiguration-test"
    )
}
else {
    Write-Host "Reusing Azure SQL Server: $sqlServer"

    Invoke-Az @(
        "sql", "server", "update",
        "--name", $sqlServer,
        "--resource-group", $resourceGroup,
        "--enable-public-network", "true"
    )
}

$dbExists = az sql db list `
    --resource-group $resourceGroup `
    --server $sqlServer `
    --query "[?name=='$sqlDatabase'].name | [0]" `
    -o tsv

if ([string]::IsNullOrWhiteSpace($dbExists)) {
    Write-Host "Creating Azure SQL Database: $sqlDatabase"

    Invoke-Az @(
        "sql", "db", "create",
        "--resource-group", $resourceGroup,
        "--server", $sqlServer,
        "--name", $sqlDatabase,
        "--service-objective", "Basic"
    )
}
else {
    Write-Host "Reusing Azure SQL Database: $sqlDatabase"
}

$firewallRule = az sql server firewall-rule list `
    --resource-group $resourceGroup `
    --server $sqlServer `
    --query "[?name=='AllowAllInternet'].name | [0]" `
    -o tsv

if ([string]::IsNullOrWhiteSpace($firewallRule)) {
    Invoke-Az @(
        "sql", "server", "firewall-rule", "create",
        "--resource-group", $resourceGroup,
        "--server", $sqlServer,
        "--name", "AllowAllInternet",
        "--start-ip-address", "0.0.0.0",
        "--end-ip-address", "255.255.255.255"
    )
}
else {
    Invoke-Az @(
        "sql", "server", "firewall-rule", "update",
        "--resource-group", $resourceGroup,
        "--server", $sqlServer,
        "--name", "AllowAllInternet",
        "--start-ip-address", "0.0.0.0",
        "--end-ip-address", "255.255.255.255"
    )
}

Write-Host ""
Write-Host "Lab resources ready." -ForegroundColor Green
Write-Host "Storage Account: $storageAccount"
Write-Host "Key Vault: $keyVault"
Write-Host "NSG: $nsgName"
Write-Host "Web App: $webApp"
Write-Host "SQL Server: $sqlServer"
Write-Host "SQL Database: $sqlDatabase"