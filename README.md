# Azure NIS2 Security Assessment Framework

Azure NIS2 Security Assessment Framework is a Python-based framework for detecting security misconfigurations in Microsoft Azure environments and mapping them to NIS2 Article 21 cybersecurity risk-management controls.

The project follows a modular cloud security assessment architecture based on inventory collection, configuration analysis, compliance evaluation, risk scoring and report generation. The main distinction of this implementation is the technical and interpretative mapping of Azure misconfigurations to NIS2 controls.

## Objectives

The framework aims to:

- collect Azure resources from a target Resource Group;
- extract relevant security configuration properties;
- detect misconfigurations through YAML-based rules;
- map findings to NIS2 Article 21 controls;
- compute an environment risk score;
- generate JSON outputs and a PDF report;
- validate the detection logic against a controlled vulnerable Azure laboratory.

## Architecture

The framework is organized into five main modules:

| Module | Description |
|---|---|
| Cloud Inventory Collector | Discovers Azure resources and collects configuration metadata. |
| Configuration Analyzer | Applies YAML security rules to collected configurations. |
| NIS2 Compliance Evaluator | Maps findings to NIS2 Article 21 controls and computes PASS/FAIL status. |
| Risk Scorer | Computes resource-level and environment-level risk scores. |
| Reporting Engine | Generates a human-readable PDF report with findings, compliance status and risk summary. |

## Assessed Azure Services

The current version assesses the following Azure resource types:

| Azure resource type | Assessment status |
|---|---|
| Microsoft.Network/networkSecurityGroups | Assessed |
| Microsoft.Storage/storageAccounts | Assessed |
| Microsoft.KeyVault/vaults | Assessed |
| Microsoft.Web/sites | Assessed |
| Microsoft.Sql/servers | Assessed |
| Microsoft.Web/serverFarms | Discovered, not assessed |
| Microsoft.Sql/servers/databases | Discovered, not assessed |

The framework distinguishes between discovered resources and assessed resources. Discovered resources are all Azure resources found in the target Resource Group. Assessed resources are the subset for which configuration collection and security rules are implemented.

Unassessed resources are kept in the inventory but excluded from the risk denominator.

## Implemented Security Rules

| Rule ID | Description | Severity |
|---|---|---|
| AZ-NSG-001 | SSH exposed to the Internet | Critical |
| AZ-NSG-002 | RDP exposed to the Internet | Critical |
| AZ-NSG-003 | HTTP exposed to the Internet | Medium |
| AZ-NSG-004 | SQL Server port exposed to the Internet | Critical |
| AZ-STORAGE-001 | Storage account allows blob public access | High |
| AZ-STORAGE-002 | Storage account does not enforce HTTPS-only traffic | High |
| AZ-STORAGE-003 | Storage account is reachable from public networks | Medium |
| AZ-STORAGE-004 | Blob container allows anonymous access | High |
| AZ-KV-001 | Key Vault public network access is enabled | High |
| AZ-KV-002 | Key Vault firewall default action allows traffic | High |
| AZ-WEB-001 | Web App does not enforce HTTPS-only traffic | High |
| AZ-WEB-002 | Web App allows insecure FTP access | High |
| AZ-WEB-003 | Web App is reachable from public networks | Medium |
| AZ-SQL-001 | Azure SQL Server public network access is enabled | High |
| AZ-SQL-002 | Azure SQL firewall allows all Internet sources | Critical |

Rules are defined in:

```text
rules/azure_security_rules.yml
```

Each rule includes:

- rule ID;
- title;
- Azure resource type;
- check function;
- severity;
- message;
- description;
- rationale;
- remediation;
- references;
- mapped NIS2 controls.

## NIS2 Mapping

The NIS2 mapping is defined in:

```text
benchmarks/nis2_controls.yml
```

The mapping is technical and interpretative. NIS2 Article 21 defines cybersecurity risk-management measures at a high level, while Azure misconfigurations are concrete technical conditions.

For this reason, each Azure rule is mapped to NIS2 controls according to the security objective affected by the misconfiguration.

Current NIS2 controls used by the framework:

| Control ID | Topic |
|---|---|
| NIS2-ART21-2-A | Risk analysis and information system security policies |
| NIS2-ART21-2-E | Security in network and information systems acquisition, development and maintenance |
| NIS2-ART21-2-H | Policies and procedures regarding cryptography and encryption |
| NIS2-ART21-2-I | Human resources security, access control policies and asset management |
| NIS2-ART21-2-J | Multi-factor authentication, secure communications and secured emergency communication systems |

## Project Structure

```text
azure-nis2-security-assessment-framework/
├── benchmarks/
│   └── nis2_controls.yml
├── docs/
│   └── validation_matrix.md
├── outputs/
│   └── .gitkeep
├── rules/
│   └── azure_security_rules.yml
├── scripts/
│   ├── provision_lab.ps1
│   ├── run_assessment.ps1
│   ├── status_lab.ps1
│   ├── clean_outputs.ps1
│   ├── manage_lab.ps1
│   └── destroy_lab.ps1
├── src/
│   └── az_nis2/
│       ├── main.py
│       ├── collectors/
│       │   └── azure_inventory_collector.py
│       ├── analyzers/
│       │   └── configuration_analyzer.py
│       ├── compliance/
│       │   └── nis2_mapper.py
│       ├── scoring/
│       │   └── risk_scorer.py
│       └── reporting/
│           └── reporting_engine.py
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Requirements

Required tools:

- Python 3.12+
- Azure CLI
- Conda or virtualenv
- Active Azure subscription
- Azure account authenticated through Azure CLI

Python dependencies are listed in:

```text
requirements.txt
```

## Environment Setup

Create and activate the Conda environment:

```powershell
conda create -n az_nis2 python=3.12
conda activate az_nis2
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Login to Azure:

```powershell
az login
```

Set the target subscription if needed:

```powershell
az account set --subscription "<SUBSCRIPTION_ID>"
```

## Configuration

Create a `.env` file from `.env.example`:

```powershell
copy .env.example .env
```

Example `.env` file:

```env
AZURE_SUBSCRIPTION_ID=
AZURE_TENANT_ID=
AZURE_TARGET_RESOURCE_GROUP=rg-nis2-lab-frc-dev
AZURE_LOCATION=francecentral
```

Do not commit `.env`.

## Provision the Vulnerable Azure Lab

The laboratory environment is intentionally insecure and is used to validate the detection logic.

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\provision_lab.ps1
```

The script creates or updates:

- Resource Group;
- Storage Account with insecure settings;
- public blob container;
- Key Vault with public network access;
- Network Security Group with exposed inbound ports;
- App Service Plan;
- Web App with HTTPS-only disabled and FTPS set to AllAllowed;
- Azure SQL Server with public network access;
- Azure SQL Database;
- Azure SQL firewall rule allowing all Internet sources.

Verify resources:

```powershell
az resource list `
  --resource-group rg-nis2-lab-frc-dev `
  --query "[].{Name:name, Type:type, Location:location}" `
  -o table
```

## Run the Assessment

From the project root:

```powershell
$env:PYTHONPATH="src"
python -m az_nis2.main
```

The framework will:

1. collect Azure inventory;
2. enrich supported resources with security configuration;
3. apply YAML security rules;
4. map findings to NIS2 controls;
5. compute risk score;
6. generate JSON outputs;
7. generate a PDF report.

## Management Scripts

The `scripts/` directory includes helper scripts for provisioning, assessment execution, status inspection, output cleanup and lab destruction.

| Script | Purpose |
|---|---|
| `provision_lab.ps1` | Creates or updates the intentionally vulnerable Azure lab. |
| `run_assessment.ps1` | Runs the complete assessment workflow and prints an output summary. |
| `status_lab.ps1` | Lists current Azure resources in the target Resource Group and checks whether the lab matches the expected stable state. |
| `clean_outputs.ps1` | Removes generated files from `outputs/` while preserving `.gitkeep`. |
| `destroy_lab.ps1` | Deletes the entire lab Resource Group after explicit confirmation. |
| `manage_lab.ps1` | Wrapper script used to call the main management actions from a single entry point. |

### Check Lab Status

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\status_lab.ps1
```

This command verifies the configured subscription and Resource Group, lists all resources, groups them by resource type and highlights unexpected residual resources.

### Run the Full Assessment

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_assessment.ps1
```

This command sets `PYTHONPATH=src`, runs the framework through `python -m az_nis2.main`, and prints a summary of the generated outputs.

### Clean Generated Outputs

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\clean_outputs.ps1
```

This command removes generated JSON and PDF files from `outputs/`, while keeping the `.gitkeep` file required by Git.

### Use the Management Wrapper

The same operations can be executed through `manage_lab.ps1`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\manage_lab.ps1 -Action status
powershell -ExecutionPolicy Bypass -File .\scripts\manage_lab.ps1 -Action provision
powershell -ExecutionPolicy Bypass -File .\scripts\manage_lab.ps1 -Action run
powershell -ExecutionPolicy Bypass -File .\scripts\manage_lab.ps1 -Action clean-outputs
powershell -ExecutionPolicy Bypass -File .\scripts\manage_lab.ps1 -Action destroy
```

The `destroy` action calls `destroy_lab.ps1` and therefore still requires explicit confirmation before deleting the Resource Group.

## Outputs

Generated files are written to:

```text
outputs/
```

Main outputs:

| File | Description |
|---|---|
| inventory.json | Discovered Azure resources and collected configurations. |
| findings.json | Security findings generated by the rule engine. |
| compliance.json | NIS2 PASS/FAIL compliance evaluation. |
| risk.json | Risk scoring output. |
| security_assessment_report.pdf | Final PDF report. |

Generated outputs are excluded from version control.

## Risk Scoring Methodology

The framework computes risk on assessed resources only.

The risk score considers:

- severity of findings;
- number of findings per resource;
- resource sensitivity inferred from tags;
- NIS2 compliance failure ratio.

Severity weights:

| Severity | Weight |
|---|---:|
| Critical | 10 |
| High | 5 |
| Medium | 3 |
| Low | 1 |

The final environment score is computed from the assessed resource risk scores and adjusted according to the ratio of failed NIS2 controls.

Risk grades:

| Score range | Grade |
|---|---|
| 0-19 | Low |
| 20-39 | Medium |
| 40-69 | High |
| 70-100 | Critical |

## Validation

Validation is documented in:

```text
docs/validation_matrix.md
```

The current controlled lab contains 14 intentionally introduced misconfigurations. The framework detects all expected findings.

Validation metrics:

| Metric | Value |
|---|---:|
| Expected findings | 14 |
| Detected findings | 14 |
| Detection rate | 100% |
| Discovered resources | 8 |
| Assessed resources | 5 |
| Unassessed resources | 3 |

## Cleanup

The lab may create Azure costs, especially for Azure SQL resources.

To delete the entire lab Resource Group:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\destroy_lab.ps1
```

The script requires explicit confirmation by typing:

```text
DELETE
```

## Security Notes

Do not commit:

- `.env`;
- credentials;
- Azure secrets;
- generated output files;
- PDF reports containing real subscription/resource information.

The vulnerable laboratory is intentionally insecure and should only be used for testing in an isolated Resource Group.

## Limitations

Current limitations:

- Linux VM assessment was considered but not included in the validated lab because the academic Azure subscription did not allow provisioning suitable Compute SKUs;
- database-level SQL checks are not implemented;
- App Service Plan configuration is discovered but not assessed;
- IAM/RBAC analysis is not yet implemented;
- NIS2 mapping is interpretative and not an official legal checklist;
- the framework currently targets Azure only.

## Future Work

Possible extensions:

- add Azure VM assessment when the subscription allows Compute provisioning;
- add IAM/RBAC checks;
- add SQL database-level checks;
- add App Service Plan checks;
- add secure remediation suggestions;
- add HTML report generation;
- add SARIF export;
- support additional compliance frameworks;
- support multi-subscription or multi-resource-group assessment.
