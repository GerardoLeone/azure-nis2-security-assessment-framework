import json
import os
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from az_nis2.analyzers.configuration_analyzer import ConfigurationAnalyzer
from az_nis2.collectors.azure_inventory_collector import AzureInventoryCollector


def main() -> None:
    load_dotenv()

    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    resource_group = os.getenv("AZURE_TARGET_RESOURCE_GROUP")

    if not subscription_id:
        raise RuntimeError("AZURE_SUBSCRIPTION_ID mancante nel file .env")

    if not resource_group:
        raise RuntimeError("AZURE_TARGET_RESOURCE_GROUP mancante nel file .env")

    collector = AzureInventoryCollector(subscription_id)
    inventory = collector.collect_resource_group_inventory(resource_group)

    analyzer = ConfigurationAnalyzer("rules/azure_security_rules.yml")
    findings = analyzer.analyze(inventory)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    inventory_file = output_dir / "inventory.json"
    findings_file = output_dir / "findings.json"

    inventory_file.write_text(
        json.dumps(inventory, indent=2),
        encoding="utf-8"
    )

    findings_file.write_text(
        json.dumps(findings, indent=2),
        encoding="utf-8"
    )

    console = Console()

    inventory_table = Table(title=f"Azure Inventory - {resource_group}")
    inventory_table.add_column("Name")
    inventory_table.add_column("Type")
    inventory_table.add_column("Location")
    inventory_table.add_column("Config")
    inventory_table.add_column("Errors")

    for resource in inventory:
        inventory_table.add_row(
            resource["name"],
            resource["type"],
            resource["location"] or "-",
            "yes" if resource.get("configuration") else "no",
            str(len(resource.get("collection_errors", [])))
        )

    findings_table = Table(title="Security Findings")
    findings_table.add_column("Severity")
    findings_table.add_column("Rule")
    findings_table.add_column("Resource")
    findings_table.add_column("Title")

    for finding in findings:
        findings_table.add_row(
            finding["severity"],
            finding["rule_id"],
            finding["resource"]["name"],
            finding["title"]
        )

    console.print(inventory_table)
    console.print(findings_table)

    console.print(f"\nInventory salvato in: {inventory_file}")
    console.print(f"Findings salvati in: {findings_file}")


if __name__ == "__main__":
    main()