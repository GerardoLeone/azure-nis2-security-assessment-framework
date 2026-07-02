from typing import cast

from azure.core.credentials import TokenCredential
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource.resources import ResourceManagementClient


class AzureInventoryCollector:
    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = cast(TokenCredential, DefaultAzureCredential())
        self.resource_client = ResourceManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

    def collect_resource_group_inventory(self, resource_group_name: str) -> list[dict]:
        resources = []

        for resource in self.resource_client.resources.list_by_resource_group(
            resource_group_name
        ):
            resources.append({
                "id": resource.id,
                "name": resource.name,
                "type": resource.type,
                "location": resource.location,
                "resource_group": resource_group_name,
                "tags": resource.tags or {}
            })

        return resources