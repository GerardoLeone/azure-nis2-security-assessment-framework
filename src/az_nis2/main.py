import json
import os
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

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

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "inventory.json"
    output_file.write_text(
        json.dumps(inventory, indent=2),
        encoding="utf-8"
    )

    console = Console()

    table = Table(title=f"Azure Inventory - {resource_group}")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Location")

    for resource in inventory:
        table.add_row(
            resource["name"],
            resource["type"],
            resource["location"] or "-"
        )

    console.print(table)
    console.print(f"\nInventory salvato in: {output_file}")


if __name__ == "__main__":
    main()