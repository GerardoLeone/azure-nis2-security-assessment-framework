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

    MAX_SEVERITY_WEIGHT = 10.0
    MAX_SENSITIVITY = 2.0

    def score(
        self,
        inventory: list[dict],
        findings: list[dict],
        compliance: dict | None = None
    ) -> dict:
        item_by_id = {
            resource.get("id"): resource
            for resource in inventory
            if resource.get("id")
        }

        findings_by_resource = self._group_findings_by_resource(findings)
        resource_scores = []
        total_raw_score = 0.0

        for resource_id, resource in item_by_id.items():
            resource_findings = findings_by_resource.get(resource_id, [])
            tags = resource.get("tags") or {}
            sensitivity = self._infer_sensitivity(tags)

            raw_score = 0.0
            max_severity_weight = 0.0
            findings_summary = []

            for finding in resource_findings:
                severity = (finding.get("severity") or "").lower()
                weight = self.SEVERITY_WEIGHTS.get(severity, 0)

                raw_score += weight
                max_severity_weight = max(max_severity_weight, weight)

                findings_summary.append({
                    "rule_id": finding.get("rule_id"),
                    "severity": severity,
                    "title": finding.get("title")
                })

            weighted_score = raw_score * sensitivity
            total_raw_score += weighted_score

            normalized_resource_score = self._normalize_resource_score(weighted_score)

            resource_scores.append({
                "resource_id": resource_id,
                "name": resource.get("name"),
                "type": resource.get("type"),
                "location": resource.get("location"),
                "tags": tags,
                "sensitivity": sensitivity,
                "findings_count": len(resource_findings),
                "max_severity_weight": max_severity_weight,
                "raw_score": round(weighted_score, 2),
                "normalized_score_percent": normalized_resource_score,
                "findings": findings_summary
            })

        total_resources = len(inventory)
        total_findings = len(findings)

        base_score_percent = self._calculate_base_environment_score(
            total_raw_score,
            total_resources
        )

        compliance_info = self._extract_compliance_info(compliance)
        final_score_percent = self._apply_compliance_adjustment(
            base_score_percent,
            compliance_info
        )

        risk_grade = self._risk_grade(final_score_percent)

        by_severity = self._count_findings_by_severity(findings)

        return {
            "schema_version": "1.0-risk",
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "overall": {
                "score_percent": final_score_percent,
                "base_score_percent": base_score_percent,
                "risk_grade": risk_grade,
                "total_resources": total_resources,
                "total_findings": total_findings,
                "failed_controls": compliance_info["failed_controls"],
                "total_controls": compliance_info["total_controls"],
                "compliance_failure_ratio": compliance_info["failure_ratio"]
            },
            "by_severity": by_severity,
            "resources": sorted(
                resource_scores,
                key=lambda item: item["raw_score"],
                reverse=True
            )
        }

    @staticmethod
    def _group_findings_by_resource(findings: list[dict]) -> dict[str, list[dict]]:
        grouped = defaultdict(list)

        for finding in findings:
            resource = finding.get("resource", {})
            resource_id = resource.get("id")

            if resource_id:
                grouped[resource_id].append(finding)

        return grouped

    @staticmethod
    def _infer_sensitivity(tags: dict[str, Any]) -> float:
        if not isinstance(tags, dict):
            return 1.0

        sensitivity_value = None
        for key in ["sensitivity", "Sensitivity", "data_classification"]:
            if key in tags and tags[key]:
                sensitivity_value = str(tags[key]).lower()
                break

        if sensitivity_value:
            if sensitivity_value in ["critical", "high"]:
                return 2.0
            if sensitivity_value == "medium":
                return 1.5
            if sensitivity_value == "low":
                return 0.75

        env_value = None
        for key in ["env", "environment", "Environment", "ENV", "Env"]:
            if key in tags and tags[key]:
                env_value = str(tags[key]).lower()
                break

        if env_value:
            if env_value in ["prod", "production", "live"]:
                return 2.0
            if env_value in ["stage", "staging", "preprod", "pre-production"]:
                return 1.5
            if env_value in ["dev", "development", "test", "testing", "lab"]:
                return 0.75

        return 1.0

    def _normalize_resource_score(self, raw_score: float) -> float:
        theoretical_max = self.MAX_SEVERITY_WEIGHT * self.MAX_SENSITIVITY
        score = (raw_score / theoretical_max) * 100.0 if theoretical_max else 0.0
        return round(min(max(score, 0.0), 100.0), 2)

    def _calculate_base_environment_score(
        self,
        total_raw_score: float,
        total_resources: int
    ) -> float:
        if total_resources == 0:
            return 0.0

        average_score_per_resource = total_raw_score / float(total_resources)
        theoretical_max = self.MAX_SEVERITY_WEIGHT * self.MAX_SENSITIVITY

        score = (average_score_per_resource / theoretical_max) * 100.0
        return round(min(max(score, 0.0), 100.0), 2)

    @staticmethod
    def _extract_compliance_info(compliance: dict | None) -> dict:
        if not compliance:
            return {
                "total_controls": 0,
                "failed_controls": 0,
                "failure_ratio": 0.0
            }

        summary = compliance.get("summary", {})

        total_controls = int(summary.get("total_controls", 0) or 0)
        failed_controls = int(summary.get("failed_controls", 0) or 0)

        failure_ratio = (
            failed_controls / float(total_controls)
            if total_controls
            else 0.0
        )

        return {
            "total_controls": total_controls,
            "failed_controls": failed_controls,
            "failure_ratio": round(failure_ratio, 4)
        }

    @staticmethod
    def _apply_compliance_adjustment(
        base_score_percent: float,
        compliance_info: dict
    ) -> float:
        failure_ratio = compliance_info["failure_ratio"]

        adjusted_score = base_score_percent * (1.0 + 0.5 * failure_ratio)
        return round(min(max(adjusted_score, 0.0), 100.0), 2)

    @staticmethod
    def _risk_grade(score_percent: float) -> str:
        if score_percent < 20:
            return "Low"
        if score_percent < 40:
            return "Medium"
        if score_percent < 70:
            return "High"
        return "Critical"

    @staticmethod
    def _count_findings_by_severity(findings: list[dict]) -> dict:
        counter = Counter()

        for finding in findings:
            severity = (finding.get("severity") or "unknown").lower()
            counter[severity] += 1

        return dict(counter)