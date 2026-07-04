# Validation Matrix

This document validates the Azure NIS2 Security Assessment Framework against a controlled Azure laboratory environment containing intentionally insecure configurations.

The goal of the validation is to verify that each expected misconfiguration is detected by the Configuration Analyzer and correctly mapped to a security finding.

## Validation Scope

The laboratory environment contains the following assessed Azure resource types:

| Resource type | Assessed | Notes |
|---|---:|---|
| Microsoft.Network/networkSecurityGroups | Yes | NSG inbound rules are analyzed. |
| Microsoft.Storage/storageAccounts | Yes | Storage account and blob container settings are analyzed. |
| Microsoft.KeyVault/vaults | Yes | Key Vault public exposure settings are analyzed. |
| Microsoft.Web/sites | Yes | Web App HTTPS, FTPS and public network settings are analyzed. |
| Microsoft.Sql/servers | Yes | SQL public network access and firewall rules are analyzed. |
| Microsoft.Web/serverFarms | No | Discovered but not assessed. |
| Microsoft.Sql/servers/databases | No | Discovered but not assessed. Database-level checks are out of scope for the current version. |

## Expected Misconfigurations

| ID | Expected misconfiguration | Azure resource | Expected rule | Expected severity | Detected |
|---|---|---|---|---|---|
| V-001 | SSH exposed to the Internet | Network Security Group | AZ-NSG-001 | Critical | Yes |
| V-002 | RDP exposed to the Internet | Network Security Group | AZ-NSG-002 | Critical | Yes |
| V-003 | HTTP exposed to the Internet | Network Security Group | AZ-NSG-003 | Medium | Yes |
| V-004 | SQL Server port exposed to the Internet | Network Security Group | AZ-NSG-004 | Critical | Yes |
| V-005 | Storage account allows blob public access | Storage Account | AZ-STORAGE-001 | High | Yes |
| V-006 | Storage account does not enforce HTTPS-only traffic | Storage Account | AZ-STORAGE-002 | High | Yes |
| V-007 | Storage account is reachable from public networks | Storage Account | AZ-STORAGE-003 | Medium | Yes |
| V-008 | Blob container allows anonymous access | Storage Account | AZ-STORAGE-004 | High | Yes |
| V-009 | Key Vault public network access is enabled | Key Vault | AZ-KV-001 | High | Yes |
| V-010 | Web App does not enforce HTTPS-only traffic | Web App | AZ-WEB-001 | High | Yes |
| V-011 | Web App allows insecure FTP access | Web App | AZ-WEB-002 | High | Yes |
| V-012 | Web App is reachable from public networks | Web App | AZ-WEB-003 | Medium | Yes |
| V-013 | Azure SQL Server public network access is enabled | Azure SQL Server | AZ-SQL-001 | High | Yes |
| V-014 | Azure SQL firewall allows all Internet sources | Azure SQL Server | AZ-SQL-002 | Critical | Yes |

## Validation Result

The framework detected all intentionally introduced misconfigurations.

| Metric | Value |
|---|---:|
| Expected findings | 14 |
| Detected findings | 14 |
| Detection rate | 100% |
| Discovered resources | 8 |
| Assessed resources | 5 |
| Unassessed resources | 3 |
| Failed NIS2 controls | 5 |

## Notes on Unassessed Resources

Some resources are discovered by the Cloud Inventory Collector but are not included in the risk denominator because no dedicated configuration collector is currently implemented for them.

| Resource type | Reason |
|---|---|
| Microsoft.Web/serverFarms | The current version assesses Web App configuration, not App Service Plan configuration. |
| Microsoft.Sql/servers/databases | The current version assesses SQL Server exposure, not database-level settings. |

This design choice is intentional: the framework distinguishes discovered resources from assessed resources to avoid diluting the risk score with resources for which no checks are currently implemented.

## NIS2 Mapping Note

The NIS2 mapping is technical and interpretative. NIS2 Article 21 defines cybersecurity risk-management measures at a high level, while Azure misconfigurations are concrete technical conditions. Therefore, each rule is mapped to NIS2 controls according to the security objective affected by the misconfiguration.