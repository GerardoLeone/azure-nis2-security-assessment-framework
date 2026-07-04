from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any


class RiskScorer:
    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 5,
        "medium": 3,
        "low": 1,
    }

    MAX_SEVERITY_WEIGHT = 10
    MAX_SENSITIVITY = 2

    def score(
        self,
        inventory: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        compliance: dict[str, Any],
    ) -> dict[str, Any]:
        resources_by_id = {
            resource.get("id"): resource
            for resource in inventory
            if resource.get("id")
        }

        findings_by_resource: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            resource_id = finding.get("resource", {}).get("id")

            if resource_id:
                findings_by_resource[resource_id].append(finding)

        assessed_resource_ids = set()

        for resource in inventory:
            resource_id = resource.get("id")
            configuration = resource.get("configuration")

            if resource_id and configuration:
                assessed_resource_ids.add(resource_id)

        assessed_resource_ids.update(findings_by_resource.keys())

        assessed_resources = [
            resources_by_id[resource_id]
            for resource_id in assessed_resource_ids
            if resource_id in resources_by_id
        ]

        severity_counter = Counter()

        for finding in findings:
            severity = str(finding.get("severity", "low")).lower()
            severity_counter[severity] += 1

        resource_scores = []

        for resource in assessed_resources:
            resource_id = resource["id"]
            resource_findings = findings_by_resource.get(resource_id, [])

            sensitivity = self._infer_resource_sensitivity(resource)
            raw_score = self._calculate_raw_score(resource_findings, sensitivity)
            normalized_score = self._normalize_score(raw_score)

            max_severity_weight = 0

            if resource_findings:
                max_severity_weight = max(
                    self.SEVERITY_WEIGHTS.get(
                        str(finding.get("severity", "low")).lower(),
                        1,
                    )
                    for finding in resource_findings
                )

            resource_scores.append({
                "resource_id": resource_id,
                "resource_name": resource.get("name"),
                "resource_type": resource.get("type"),
                "location": resource.get("location"),
                "tags": resource.get("tags", {}),
                "sensitivity": sensitivity,
                "findings_count": len(resource_findings),
                "max_severity_weight": max_severity_weight,
                "raw_score": round(raw_score, 2),
                "normalized_score_percent": round(normalized_score, 2),
                "findings": [
                    {
                        "rule_id": finding.get("rule_id"),
                        "title": finding.get("title"),
                        "severity": finding.get("severity"),
                    }
                    for finding in resource_findings
                ],
            })

        resource_scores.sort(
            key=lambda item: item["normalized_score_percent"],
            reverse=True,
        )

        base_score = self._calculate_environment_base_score(resource_scores)

        compliance_summary = compliance.get("summary", {})
        total_controls = compliance_summary.get("total_controls", 0)
        failed_controls = compliance_summary.get("failed_controls", 0)

        compliance_failure_ratio = 0

        if total_controls:
            compliance_failure_ratio = failed_controls / total_controls

        final_score = min(
            100,
            base_score * (1 + 0.5 * compliance_failure_ratio),
        )

        unassessed_resources = self._get_unassessed_resources(
            inventory=inventory,
            assessed_resource_ids=assessed_resource_ids,
        )

        return {
            "schema_version": "1.1-risk",
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "overall": {
                "score_percent": round(final_score, 2),
                "base_score_percent": round(base_score, 2),
                "risk_grade": self._risk_grade(final_score),
                "discovered_resources": len(inventory),
                "assessed_resources": len(assessed_resources),
                "unassessed_resources": len(unassessed_resources),
                "total_resources": len(inventory),
                "total_findings": len(findings),
                "failed_controls": failed_controls,
                "total_controls": total_controls,
                "compliance_failure_ratio": round(compliance_failure_ratio, 2),
            },
            "by_severity": {
                "critical": severity_counter.get("critical", 0),
                "high": severity_counter.get("high", 0),
                "medium": severity_counter.get("medium", 0),
                "low": severity_counter.get("low", 0),
            },
            "resources": resource_scores,
            "unassessed_resources": unassessed_resources,
            "methodology": {
                "note": (
                    "Risk score is calculated on assessed resources only. "
                    "Discovered resources without collected configuration are kept in the inventory "
                    "but excluded from the risk denominator."
                ),
                "severity_weights": self.SEVERITY_WEIGHTS,
                "max_severity_weight": self.MAX_SEVERITY_WEIGHT,
                "max_sensitivity": self.MAX_SENSITIVITY,
            },
        }

    def _calculate_raw_score(
        self,
        findings: list[dict[str, Any]],
        sensitivity: float,
    ) -> float:
        total = 0

        for finding in findings:
            severity = str(finding.get("severity", "low")).lower()
            total += self.SEVERITY_WEIGHTS.get(severity, 1)

        return total * sensitivity

    def _normalize_score(self, raw_score: float) -> float:
        max_single_resource_score = (
            self.MAX_SEVERITY_WEIGHT * self.MAX_SENSITIVITY
        )

        if max_single_resource_score == 0:
            return 0

        return min(100, (raw_score / max_single_resource_score) * 100)

    def _calculate_environment_base_score(
        self,
        resource_scores: list[dict[str, Any]],
    ) -> float:
        if not resource_scores:
            return 0

        total_raw_score = sum(
            resource.get("raw_score", 0)
            for resource in resource_scores
        )

        max_environment_score = (
            len(resource_scores)
            * self.MAX_SEVERITY_WEIGHT
            * self.MAX_SENSITIVITY
        )

        if max_environment_score == 0:
            return 0

        return min(100, (total_raw_score / max_environment_score) * 100)

    def _infer_resource_sensitivity(self, resource: dict[str, Any]) -> float:
        tags = {
            str(key).lower(): str(value).lower()
            for key, value in (resource.get("tags") or {}).items()
        }

        sensitivity = 1.0

        sensitivity_tag = tags.get("sensitivity") or tags.get("data_classification")

        if sensitivity_tag in {"critical", "high", "confidential"}:
            sensitivity = max(sensitivity, 2.0)
        elif sensitivity_tag in {"medium", "internal"}:
            sensitivity = max(sensitivity, 1.5)
        elif sensitivity_tag in {"low", "public"}:
            sensitivity = max(sensitivity, 0.75)

        environment_tag = tags.get("env") or tags.get("environment")

        if environment_tag in {"prod", "production", "live"}:
            sensitivity = max(sensitivity, 2.0)
        elif environment_tag in {"staging", "preprod"}:
            sensitivity = max(sensitivity, 1.5)
        elif environment_tag in {"dev", "test", "lab"}:
            sensitivity = min(sensitivity, 0.75)

        return sensitivity

    def _get_unassessed_resources(
        self,
        inventory: list[dict[str, Any]],
        assessed_resource_ids: set[str],
    ) -> list[dict[str, Any]]:
        unassessed = []

        for resource in inventory:
            resource_id = resource.get("id")

            if not resource_id or resource_id in assessed_resource_ids:
                continue

            unassessed.append({
                "resource_id": resource_id,
                "resource_name": resource.get("name"),
                "resource_type": resource.get("type"),
                "location": resource.get("location"),
                "reason": "No configuration collector implemented for this resource type.",
            })

        return unassessed

    @staticmethod
    def _risk_grade(score: float) -> str:
        if score < 20:
            return "Low"

        if score < 40:
            return "Medium"

        if score < 70:
            return "High"

        return "Critical"