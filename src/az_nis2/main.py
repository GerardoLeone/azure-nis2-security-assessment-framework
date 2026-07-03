import json
import os
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from az_nis2.analyzers.configuration_analyzer import ConfigurationAnalyzer
from az_nis2.collectors.azure_inventory_collector import AzureInventoryCollector
from az_nis2.compliance.nis2_mapper import NIS2ComplianceEvaluator


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

    compliance_evaluator = NIS2ComplianceEvaluator("benchmarks/nis2_controls.yml")
    compliance = compliance_evaluator.evaluate(findings)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    inventory_file = output_dir / "inventory.json"
    findings_file = output_dir / "findings.json"
    compliance_file = output_dir / "compliance.json"

    inventory_file.write_text(
        json.dumps(inventory, indent=2),
        encoding="utf-8"
    )

    findings_file.write_text(
        json.dumps(findings, indent=2),
        encoding="utf-8"
    )

    compliance_file.write_text(
        json.dumps(compliance, indent=2),
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

    compliance_table = Table(title="NIS2 Compliance Summary")
    compliance_table.add_column("Control")
    compliance_table.add_column("Status")
    compliance_table.add_column("Findings")
    compliance_table.add_column("Title")

    for control in compliance["controls"]:
        compliance_table.add_row(
            control["control_id"],
            control["status"],
            str(control["findings_count"]),
            control["title"]
        )

    summary = compliance["summary"]

    console.print(inventory_table)
    console.print(findings_table)
    console.print(compliance_table)

    console.print(
        "\nCompliance NIS2: "
        f"{summary['passed_controls']}/{summary['total_controls']} controlli PASS "
        f"({summary['compliance_percentage']}%)"
    )

    console.print(f"\nInventory salvato in: {inventory_file}")
    console.print(f"Findings salvati in: {findings_file}")
    console.print(f"Compliance salvata in: {compliance_file}")


if __name__ == "__main__":
    main()