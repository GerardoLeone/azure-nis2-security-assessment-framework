from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml


class NIS2ComplianceEvaluator:
    def __init__(self, mapping_path: str | Path):
        self.mapping_path = Path(mapping_path)
        self.mapping = self._load_mapping()

    def _load_mapping(self) -> dict:
        if not self.mapping_path.exists():
            raise FileNotFoundError(f"NIS2 mapping file not found: {self.mapping_path}")

        return yaml.safe_load(self.mapping_path.read_text(encoding="utf-8")) or {}

    def evaluate(self, findings: list[dict]) -> dict:
        framework = self.mapping.get("framework", "NIS2")
        version = self.mapping.get("version", "")
        controls_cfg = self.mapping.get("controls", [])

        # Group by rule id (ex. "AZ-NSG-001" : [ finding1, finding2, ... ], ...)
        findings_by_rule = self._group_findings_by_rule(findings)

        controls = []

        for control in controls_cfg:
            # for each control get rules
            rule_ids = control.get("rules", [])
            matched_findings = []

            for rule_id in rule_ids:
                matched_findings.extend(findings_by_rule.get(rule_id, []))

            # extract affected resources infos
            affected_resources = self._extract_affected_resources(matched_findings)

            controls.append({
                "control_id": control["id"],
                "framework": control.get("framework", framework),
                "title": control.get("title", ""),
                "description": control.get("description", ""),
                "status": "FAIL" if affected_resources else "PASS",
                "mapped_rules": rule_ids,
                "violated_rules": sorted({
                    finding["rule_id"]
                    for finding in matched_findings
                }),
                "affected_resources": affected_resources,
                "findings_count": len(matched_findings),
                "remediation": control.get("remediation", "")
            })

        summary = self._build_summary(controls)

        return {
            "framework": framework,
            "version": version,
            "description": self.mapping.get("description", ""),
            "summary": summary,
            "controls": controls
        }

    @staticmethod
    def _group_findings_by_rule(findings: list[dict]) -> dict[str, list[dict]]:
        grouped = defaultdict(list)

        for finding in findings:
            rule_id = finding.get("rule_id")

            if rule_id:
                grouped[rule_id].append(finding)

        return grouped

    @staticmethod
    def _extract_affected_resources(findings: list[dict]) -> list[dict[str, Any]]:
        resources = {}

        for finding in findings:
            resource = finding.get("resource", {})
            resource_id = resource.get("id")

            if not resource_id:
                continue

            resources[resource_id] = {
                "id": resource_id,
                "name": resource.get("name"),
                "type": resource.get("type"),
                "resource_group": resource.get("resource_group"),
                "location": resource.get("location")
            }

        return sorted(resources.values(), key=lambda item: item["name"] or "")

    @staticmethod
    def _build_summary(controls: list[dict]) -> dict:
        total = len(controls)
        passed = sum(1 for control in controls if control["status"] == "PASS")
        failed = sum(1 for control in controls if control["status"] == "FAIL")

        compliance_percentage = round((passed / total) * 100, 2) if total else 0.0

        return {
            "total_controls": total,
            "passed_controls": passed,
            "failed_controls": failed,
            "compliance_percentage": compliance_percentage
        }