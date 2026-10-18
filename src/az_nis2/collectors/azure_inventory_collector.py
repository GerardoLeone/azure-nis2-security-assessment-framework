from typing import Any, cast

from azure.core.credentials import TokenCredential
from azure.identity import DefaultAzureCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.web import WebSiteManagementClient


class AzureInventoryCollector:
    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = cast(TokenCredential, DefaultAzureCredential())

        self.resource_client = ResourceManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

        self.storage_client = StorageManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

        self.keyvault_client = KeyVaultManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

        self.network_client = NetworkManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

        self.web_client = WebSiteManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

        self.sql_client = SqlManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

    def collect_resource_group_inventory(self, resource_group_name: str) -> list[dict]:
        inventory = []

        for resource in self.resource_client.resources.list_by_resource_group(resource_group_name):
            item = {
                "id": resource.id,
                "name": resource.name,
                "type": resource.type,
                "location": resource.location,
                "resource_group": resource_group_name,
                "tags": resource.tags or {},
                "configuration": {},
                "collection_errors": []
            }

            self._enrich_resource(item)
            inventory.append(item)

        return inventory

    # Richiama i metodi per recuperare le configurazioni necessarie ai controlli di sicurezza implementati
    def _enrich_resource(self, resource: dict) -> None:
        resource_type = resource["type"].lower()

        if resource_type == "microsoft.storage/storageaccounts":
            self._collect_storage_account_config(resource)

        elif resource_type == "microsoft.keyvault/vaults":
            self._collect_key_vault_config(resource)

        elif resource_type == "microsoft.network/networksecuritygroups":
            self._collect_nsg_config(resource)

        elif resource_type == "microsoft.web/sites":
            self._collect_web_app_config(resource)

        elif resource_type == "microsoft.sql/servers":
            self._collect_sql_server_config(resource)

    def _collect_storage_account_config(self, resource: dict) -> None:
        resource_group = resource["resource_group"]
        account_name = resource["name"]

        try:
            account = self.storage_client.storage_accounts.get_properties(
                resource_group,
                account_name
            )

            containers = []

            try:
                for container in self.storage_client.blob_containers.list(
                    resource_group,
                    account_name
                ):
                    containers.append({
                        "name": container.name,
                        "public_access": self._clean_value(
                            getattr(container, "public_access", None)
                        )
                    })
            except Exception as exc:
                resource["collection_errors"].append(
                    f"Unable to list blob containers: {exc}"
                )

            resource["configuration"] = {
                "allow_blob_public_access": getattr(account, "allow_blob_public_access", None),
                "https_only": getattr(account, "enable_https_traffic_only", None),
                "public_network_access": self._clean_value(
                    getattr(account, "public_network_access", None)
                ),
                "minimum_tls_version": self._clean_value(
                    getattr(account, "minimum_tls_version", None)
                ),
                "containers": containers
            }

        except Exception as exc:
            resource["collection_errors"].append(
                f"Unable to collect storage account configuration: {exc}"
            )

    def _collect_key_vault_config(self, resource: dict) -> None:
        resource_group = resource["resource_group"]
        vault_name = resource["name"]

        try:
            vault = self.keyvault_client.vaults.get(resource_group, vault_name)
            properties = vault.properties
            network_acls = getattr(properties, "network_acls", None)

            resource["configuration"] = {
                "public_network_access": self._clean_value(
                    getattr(properties, "public_network_access", None)
                ),
                "network_acls_default_action": self._clean_value(
                    getattr(network_acls, "default_action", None)
                    if network_acls else None
                ),
                "network_acls_bypass": self._clean_value(
                    getattr(network_acls, "bypass", None)
                    if network_acls else None
                ),
                "enable_rbac_authorization": getattr(
                    properties,
                    "enable_rbac_authorization",
                    None
                ),
                "soft_delete_retention_days": getattr(
                    properties,
                    "soft_delete_retention_in_days",
                    None
                )
            }

        except Exception as exc:
            resource["collection_errors"].append(
                f"Unable to collect key vault configuration: {exc}"
            )

    def _collect_nsg_config(self, resource: dict) -> None:
        resource_group = resource["resource_group"]
        nsg_name = resource["name"]

        try:
            nsg = self.network_client.network_security_groups.get(
                resource_group,
                nsg_name
            )

            security_rules = []

            for rule in nsg.security_rules or []:
                security_rules.append({
                    "name": rule.name,
                    "priority": rule.priority,
                    "direction": self._clean_value(rule.direction),
                    "access": self._clean_value(rule.access),
                    "protocol": self._clean_value(rule.protocol),
                    "source_address_prefix": rule.source_address_prefix,
                    "source_address_prefixes": rule.source_address_prefixes or [],
                    "destination_address_prefix": rule.destination_address_prefix,
                    "destination_address_prefixes": rule.destination_address_prefixes or [],
                    "source_port_range": rule.source_port_range,
                    "source_port_ranges": rule.source_port_ranges or [],
                    "destination_port_range": rule.destination_port_range,
                    "destination_port_ranges": rule.destination_port_ranges or []
                })

            resource["configuration"] = {
                "security_rules": security_rules
            }

        except Exception as exc:
            resource["collection_errors"].append(
                f"Unable to collect NSG configuration: {exc}"
            )

    def _collect_web_app_config(self, resource: dict) -> None:
        resource_group = resource["resource_group"]
        app_name = resource["name"]

        try:
            site = self.web_client.web_apps.get(
                resource_group_name=resource_group,
                name=app_name
            )

            config = self.web_client.web_apps.get_configuration(
                resource_group_name=resource_group,
                name=app_name
            )

            ip_restrictions = []
            for restriction in getattr(config, "ip_security_restrictions", None) or []:
                ip_restrictions.append({
                    "name": getattr(restriction, "name", None),
                    "action": getattr(restriction, "action", None),
                    "ip_address": getattr(restriction, "ip_address", None),
                    "priority": getattr(restriction, "priority", None),
                    "description": getattr(restriction, "description", None)
                })

            scm_ip_restrictions = []
            for restriction in getattr(config, "scm_ip_security_restrictions", None) or []:
                scm_ip_restrictions.append({
                    "name": getattr(restriction, "name", None),
                    "action": getattr(restriction, "action", None),
                    "ip_address": getattr(restriction, "ip_address", None),
                    "priority": getattr(restriction, "priority", None),
                    "description": getattr(restriction, "description", None)
                })

            resource["configuration"] = {
                "https_only": getattr(site, "https_only", None),
                "public_network_access": self._clean_value(
                    getattr(site, "public_network_access", None)
                ),
                "ftps_state": self._clean_value(
                    getattr(config, "ftps_state", None)
                ),
                "min_tls_version": self._clean_value(
                    getattr(config, "min_tls_version", None)
                ),
                "scm_min_tls_version": self._clean_value(
                    getattr(config, "scm_min_tls_version", None)
                ),
                "remote_debugging_enabled": getattr(
                    config,
                    "remote_debugging_enabled",
                    None
                ),
                "ip_security_restrictions": ip_restrictions,
                "scm_ip_security_restrictions": scm_ip_restrictions
            }

        except Exception as exc:
            resource["collection_errors"].append(
                f"Unable to collect web app configuration: {exc}"
            )

    def _collect_sql_server_config(self, resource: dict) -> None:
        resource_group = resource["resource_group"]
        server_name = resource["name"]

        try:
            server = self.sql_client.servers.get(
                resource_group_name=resource_group,
                server_name=server_name
            )

            firewall_rules = []

            try:
                for rule in self.sql_client.firewall_rules.list_by_server(
                        resource_group_name=resource_group,
                        server_name=server_name
                ):
                    firewall_rules.append({
                        "name": rule.name,
                        "start_ip_address": rule.start_ip_address,
                        "end_ip_address": rule.end_ip_address
                    })
            except Exception as exc:
                resource["collection_errors"].append(
                    f"Unable to list SQL firewall rules: {exc}"
                )

            resource["configuration"] = {
                "public_network_access": self._clean_value(
                    getattr(server, "public_network_access", None)
                ),
                "minimal_tls_version": self._clean_value(
                    getattr(server, "minimal_tls_version", None)
                ),
                "restrict_outbound_network_access": self._clean_value(
                    getattr(server, "restrict_outbound_network_access", None)
                ),
                "firewall_rules": firewall_rules
            }

        except Exception as exc:
            resource["collection_errors"].append(
                f"Unable to collect SQL server configuration: {exc}"
            )

    @staticmethod
    def _clean_value(value: Any) -> Any:
        if value is None:
            return None

        if hasattr(value, "value"):
            return value.value

        return value