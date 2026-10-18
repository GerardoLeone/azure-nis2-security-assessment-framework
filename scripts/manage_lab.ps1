param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("status", "provision", "run", "clean-outputs", "destroy")]
    [string]$Action
)

$ErrorActionPreference = "Stop"

conda activate az_nis2

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

function Invoke-Script {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Script non trovato: $Path"
    }

    & $Path

    if ($LASTEXITCODE -ne 0) {
        throw "Script fallito: $Path"
    }
}

switch ($Action) {
    "status" {
        Invoke-Script ".\scripts\status_lab.ps1"
    }

    "provision" {
        Invoke-Script ".\scripts\provision_lab.ps1"
    }

    "run" {
        Invoke-Script ".\scripts\run_assessment.ps1"
    }

    "clean-outputs" {
        Invoke-Script ".\scripts\clean_outputs.ps1"
    }

    "destroy" {
        Invoke-Script ".\scripts\destroy_lab.ps1"
    }
}
