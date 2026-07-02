$ErrorActionPreference = "Stop"

$resourceGroup = "rg-nis2-lab-frc-dev"
$location = "francecentral"
$suffix = Get-Random -Minimum 10000 -Maximum 99999

$storageAccount = "stnis2lab$suffix"
$keyVault = "kv-nis2-lab-$suffix"
$nsgName = "nsg-nis2-open-dev"

Write-Host "Creating Azure NIS2 lab resources..." -ForegroundColor Cyan
Write-Host "Resource Group: $resourceGroup"
Write-Host "Location: $location"
Write-Host "Storage Account: $storageAccount"
Write-Host "Key Vault: $keyVault"
Write-Host "NSG: $nsgName"

az group create `
  --name $resourceGroup `
  --location $location `
  --tags project=azure-nis2-security-assessment-framework env=dev purpose=thesis-lab

az storage account create `
  --name $storageAccount `
  --resource-group $resourceGroup `
  --location $location `
  --sku Standard_LRS `
  --kind StorageV2 `
  --allow-blob-public-access true `
  --https-only false `
  --public-network-access Enabled `
  --tags project=azure-nis2-security-assessment-framework env=dev purpose=storage-misconfiguration-test

$storageKey = az storage account keys list `
  --resource-group $resourceGroup `
  --account-name $storageAccount `
  --query "[0].value" `
  -o tsv

az storage container create `
  --name public-container `
  --account-name $storageAccount `
  --account-key $storageKey `
  --public-access blob

az keyvault create `
  --name $keyVault `
  --resource-group $resourceGroup `
  --location $location `
  --public-network-access Enabled `
  --default-action Allow `
  --tags project=azure-nis2-security-assessment-framework env=dev purpose=keyvault-misconfiguration-test

az network nsg create `
  --resource-group $resourceGroup `
  --name $nsgName `
  --location $location `
  --tags project=azure-nis2-security-assessment-framework env=dev purpose=network-misconfiguration-test

az network nsg rule create `
  --resource-group $resourceGroup `
  --nsg-name $nsgName `
  --name Allow-SSH-Internet `
  --priority 100 `
  --direction Inbound `
  --access Allow `
  --protocol Tcp `
  --source-address-prefixes "*" `
  --source-port-ranges "*" `
  --destination-address-prefixes "*" `
  --destination-port-ranges 22

az network nsg rule create `
  --resource-group $resourceGroup `
  --nsg-name $nsgName `
  --name Allow-RDP-Internet `
  --priority 110 `
  --direction Inbound `
  --access Allow `
  --protocol Tcp `
  --source-address-prefixes "*" `
  --source-port-ranges "*" `
  --destination-address-prefixes "*" `
  --destination-port-ranges 3389

az network nsg rule create `
  --resource-group $resourceGroup `
  --nsg-name $nsgName `
  --name Allow-HTTP-Internet `
  --priority 120 `
  --direction Inbound `
  --access Allow `
  --protocol Tcp `
  --source-address-prefixes "*" `
  --source-port-ranges "*" `
  --destination-address-prefixes "*" `
  --destination-port-ranges 80

az network nsg rule create `
  --resource-group $resourceGroup `
  --nsg-name $nsgName `
  --name Allow-SQL-Internet `
  --priority 130 `
  --direction Inbound `
  --access Allow `
  --protocol Tcp `
  --source-address-prefixes "*" `
  --source-port-ranges "*" `
  --destination-address-prefixes "*" `
  --destination-port-ranges 1433

Write-Host "Lab resources created." -ForegroundColor Green