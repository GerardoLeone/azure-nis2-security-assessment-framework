from pathlib import Path
from typing import Any

import yaml


class ConfigurationAnalyzer:
    def __init__(self, rules_path: str | Path):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict]:
        if not self.rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")

        data = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}
        return data.get("rules", [])

    def analyze(self, inventory: list[dict]) -> list[dict]:
        findings = []

        for resource in inventory:
            for rule in self.rules:
                if not self._rule_applies_to_resource(rule, resource): #verifica che la regola è applicabile
                    continue

                result = self._evaluate_rule(rule, resource)

                if result["passed"]:
                    continue

                findings.append({
                    "finding_id": f"{rule['id']}:{resource['name']}",
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "message": rule.get("message", rule["title"]),
                    "description": rule["description"],
                    "rationale": rule.get("rationale", ""),
                    "remediation": rule["remediation"],
                    "references": rule.get("references", []),
                    "resource": {
                        "id": resource["id"],
                        "name": resource["name"],
                        "type": resource["type"],
                        "location": resource["location"],
                        "resource_group": resource["resource_group"]
                    },
                    "nis2_controls": rule.get("nis2_controls", []),
                    "evidence": result["evidence"]
                })

        return findings

    @staticmethod
    def _rule_applies_to_resource(rule: dict, resource: dict) -> bool:
        return rule["resource_type"].lower() == resource["type"].lower()

    def _evaluate_rule(self, rule: dict, resource: dict) -> dict:
        check_name = rule["check"]

        # dizionario chiave-valore, contiene riferimenti alle funzioni
        checks = {
            "storage_allow_blob_public_access_enabled": self._storage_allow_blob_public_access_enabled,
            "storage_https_only_disabled": self._storage_https_only_disabled,
            "storage_public_network_access_enabled": self._storage_public_network_access_enabled,
            "storage_container_public_access_enabled": self._storage_container_public_access_enabled,
            "keyvault_public_network_access_enabled": self._keyvault_public_network_access_enabled,
            "keyvault_default_action_allow": self._keyvault_default_action_allow,
            "nsg_inbound_port_open_to_internet": self._nsg_inbound_port_open_to_internet,
            "webapp_https_only_disabled": self._webapp_https_only_disabled,
            "webapp_ftps_all_allowed": self._webapp_ftps_all_allowed,
            "webapp_public_network_access_enabled": self._webapp_public_network_access_enabled,
            "sql_public_network_access_enabled": self._sql_public_network_access_enabled,
            "sql_firewall_allows_all_internet": self._sql_firewall_allows_all_internet,
        }

        if check_name not in checks:
            raise ValueError(f"Unknown check: {check_name}")

        return checks[check_name](resource, rule.get("params", {}))

    @staticmethod
    def _webapp_https_only_disabled(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("https_only")

        return {
            "passed": value is not False,
            "evidence": {
                "https_only": value
            }
        }

    @staticmethod
    def _webapp_ftps_all_allowed(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("ftps_state")

        return {
            "passed": value != "AllAllowed",
            "evidence": {
                "ftps_state": value
            }
        }

    @staticmethod
    def _webapp_public_network_access_enabled(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("public_network_access")

        return {
            "passed": value != "Enabled",
            "evidence": {
                "public_network_access": value
            }
        }

    @staticmethod
    def _sql_public_network_access_enabled(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("public_network_access")

        return {
            "passed": value != "Enabled",
            "evidence": {
                "public_network_access": value
            }
        }

    @staticmethod
    def _sql_firewall_allows_all_internet(resource: dict, params: dict) -> dict:
        firewall_rules = resource.get("configuration", {}).get("firewall_rules", [])

        matched_rules = []

        for rule in firewall_rules:
            if (
                    rule.get("start_ip_address") == "0.0.0.0"
                    and rule.get("end_ip_address") == "255.255.255.255"
            ):
                matched_rules.append(rule)

        return {
            "passed": len(matched_rules) == 0,
            "evidence": {
                "matched_firewall_rules": matched_rules
            }
        }

    @staticmethod
    def _storage_allow_blob_public_access_enabled(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("allow_blob_public_access")

        return {
            "passed": value is not True,
            "evidence": {
                "allow_blob_public_access": value
            }
        }

    @staticmethod
    def _storage_https_only_disabled(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("https_only")

        return {
            "passed": value is not False,
            "evidence": {
                "https_only": value
            }
        }

    @staticmethod
    def _storage_public_network_access_enabled(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("public_network_access")

        return {
            "passed": value != "Enabled",
            "evidence": {
                "public_network_access": value
            }
        }

    @staticmethod
    def _storage_container_public_access_enabled(resource: dict, params: dict) -> dict:
        containers = resource.get("configuration", {}).get("containers", [])

        public_containers = [
            {
                "name": container.get("name"),
                "public_access": container.get("public_access")
            }
            for container in containers
            if container.get("public_access") not in (None, "", "None")
        ]

        return {
            "passed": len(public_containers) == 0,
            "evidence": {
                "public_containers": public_containers
            }
        }

    @staticmethod
    def _keyvault_public_network_access_enabled(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("public_network_access")

        return {
            "passed": value != "Enabled",
            "evidence": {
                "public_network_access": value
            }
        }

    @staticmethod
    def _keyvault_default_action_allow(resource: dict, params: dict) -> dict:
        value = resource.get("configuration", {}).get("network_acls_default_action")

        return {
            "passed": value != "Allow",
            "evidence": {
                "network_acls_default_action": value
            }
        }

    def _nsg_inbound_port_open_to_internet(self, resource: dict, params: dict) -> dict:
        target_ports = [str(port) for port in params.get("ports", [])]
        rules = resource.get("configuration", {}).get("security_rules", [])

        matched_rules = []

        for rule in rules:
            if not self._is_inbound_allow_rule(rule):
                continue

            if not self._is_source_internet(rule):
                continue

            matched_ports = [
                port for port in target_ports
                if self._rule_allows_port(rule, port)
            ]

            if matched_ports:
                matched_rules.append({
                    "name": rule.get("name"),
                    "priority": rule.get("priority"),
                    "source": self._get_rule_sources(rule),
                    "destination_ports": self._get_rule_destination_ports(rule), # le porte possono essere rappresentate in modi diversi (singola: 22, range: 20-25, tutte: *)
                    "matched_ports": matched_ports
                })

        return {
            "passed": len(matched_rules) == 0,
            "evidence": {
                "target_ports": target_ports,
                "matched_rules": matched_rules
            }
        }

    @staticmethod
    def _is_inbound_allow_rule(rule: dict) -> bool:
        return (
            rule.get("direction") == "Inbound"
            and rule.get("access") == "Allow"
        )

    @staticmethod
    def _is_source_internet(rule: dict) -> bool:
        sources = ConfigurationAnalyzer._get_rule_sources(rule)

        internet_sources = {
            "*",
            "Internet",
            "0.0.0.0/0",
            "::/0"
        }

        return any(source in internet_sources for source in sources)

    @staticmethod
    def _get_rule_sources(rule: dict) -> list[str]:
        sources = []

        if rule.get("source_address_prefix"):
            sources.append(rule["source_address_prefix"])

        sources.extend(rule.get("source_address_prefixes", []))

        return sources

    @staticmethod
    def _get_rule_destination_ports(rule: dict) -> list[str]:
        ports = []

        if rule.get("destination_port_range"):
            ports.append(str(rule["destination_port_range"]))

        ports.extend(str(port) for port in rule.get("destination_port_ranges", []))

        return ports

    def _rule_allows_port(self, rule: dict, target_port: str) -> bool:
        ports = self._get_rule_destination_ports(rule)

        for port_expression in ports:
            if self._port_expression_matches(port_expression, target_port):
                return True

        return False

    @staticmethod
    def _port_expression_matches(port_expression: str, target_port: str) -> bool:
        if port_expression == "*":
            return True

        if port_expression == target_port:
            return True

        if "-" in port_expression:
            start, end = port_expression.split("-", maxsplit=1)

            if start.isdigit() and end.isdigit() and target_port.isdigit():
                return int(start) <= int(target_port) <= int(end)

        return False