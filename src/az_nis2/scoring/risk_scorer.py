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

        """
        Esempio:
        inventory:
        [
            {"id": "nsg-01", "name": "nsg-01", ...},
            {"id": "storage-01", "name": "storage-01", ...},
        ]

        findings:
        - AZ-NSG-001 su nsg-01, Critical
        - AZ-NSG-002 su nsg-01, Critical
        - AZ-STORAGE-002 su storage-01, High


        Serve per recuperare rapidamente la risorsa associata all'ID contenuto in un finding
        Trasforma inventory in un dizionario: resource_id → oggetto completo della risorsa
        Esempio:
        resources_by_id = {
            "nsg-01": {"id": "nsg-01", "name": "nsg-01", ...},
            "storage-01": {"id": "storage-01", "name": "storage-01", ...},
        }
        """
        resources_by_id = {
            resource.get("id"): resource
            for resource in inventory
            if resource.get("id")
        }

        # prepara un dizionario in cui ogni chiave avrà una lista di finding
        # resource_id → lista dei finding di quella risorsa
        findings_by_resource: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            resource_id = finding.get("resource", {}).get("id")

            # se esiste resid, inserisce il finding nella lista dei finding per risorsa con resid
            if resource_id:
                findings_by_resource[resource_id].append(finding)
            # in questo modo ogni finding conterrà il riferimento alla risorsa interessata.
            """
            Esempio:
                findings_by_resource = {
                    "nsg-01": [
                        finding_ssh,
                        finding_rdp,
                    ],
                    "storage-01": [
                        finding_https,
                    ],
                }
            """

        assessed_resource_ids = set()

        for resource in inventory:
            resource_id = resource.get("id")
            configuration = resource.get("configuration")

            # il codice considera una risorsa assessed se ha una configurazione raccolta
            if resource_id and configuration:
                assessed_resource_ids.add(resource_id)

        """
        assessed_resource_ids = {
            "nsg-01",
            "storage-01",
        }
        """

        # aggiunge le risorse che compaiono nei finding
        assessed_resource_ids.update(findings_by_resource.keys())

        # alla fine costruisce lista di risorse assessed (5) a partire dalle informazioni raccolte fino ad ora
        assessed_resources = [
            resources_by_id[resource_id]
            for resource_id in assessed_resource_ids
            if resource_id in resources_by_id
        ]
        """
        assessed_resources = [
            {"id": "nsg-01", ...},
            {"id": "storage-01", ...},
        ]
        da questo momento, il rischi viene calcolato solo su queste risorse
        """

        # Conteggio dei findings per severity
        severity_counter = Counter()

        for finding in findings:
            severity = str(finding.get("severity", "low")).lower()
            severity_counter[severity] += 1
        # "critical": 4, "high": 7, ...

        resource_scores = []

        # Calcolo il rischio per ogni risorsa
        for resource in assessed_resources:
            resource_id = resource["id"]
            resource_findings = findings_by_resource.get(resource_id, [])

            sensitivity = self._infer_resource_sensitivity(resource)
            raw_score = self._calculate_raw_score(resource_findings, sensitivity)
            normalized_score = self._normalize_score(raw_score)

            #Il codice cerca il peso più alto tra i finding
            max_severity_weight = 0

            if resource_findings:
                max_severity_weight = max(
                    self.SEVERITY_WEIGHTS.get(
                        str(finding.get("severity", "low")).lower(),
                        1,
                    )
                    for finding in resource_findings
                )

            # inserisce in resource_scores le informazioni ottenute
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

        # Calcolo del Risk Score finale!

        # Calcola prima il Base Score
        base_score = self._calculate_environment_base_score(resource_scores) # 63%

        # Il Risk Scorer legge il riepilogo prodotto al Mapper
        compliance_summary = compliance.get("summary", {})
        total_controls = compliance_summary.get("total_controls", 0)
        failed_controls = compliance_summary.get("failed_controls", 0)

        compliance_failure_ratio = 0

        # Calcola il rapporto di fallimento
        if total_controls:
            compliance_failure_ratio = failed_controls / total_controls


        # 1: nessun controllo NIS2 fallito F = 0/5=0 ratio = 1+0.5*0 = 1 * base_score = punteggio finale non cambia
        # 2: metà dei controlli falliti F = 2.5/5=0.5 ratio = 1+0.5*0.5=1+0.25 = 1.25 * base_score = rischio aumenta del 25%
        # 3: tutti i controlli falliti F = 5/5=1 ratio = 1+0.5*1=1.5 * base_score = 1.5 * 63% = 94.5% (caso di studio)
        # base_score = quanto sono gravi le misconfigurazioni Azure trovate
        # compliance = quanto l'ambiente fallisce i controlli NIS2
        # il fallimento NIS2 non pesa più del rischio tecnico, ma aumenta il rischio tecnico fino a un massimo del 50% (scelta progettuale personale)
        final_score = min(
            100,
            base_score * (1 + 0.5 * compliance_failure_ratio),
        )

        unassessed_resources = self._get_unassessed_resources(
            inventory=inventory,
            assessed_resource_ids=assessed_resource_ids,
        )

        # restituisce un dizionario con tutte le informazioni ottenute
        return {
            "schema_version": "1.1-risk",
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "overall": {
                "score_percent": round(final_score, 2),
                "base_score_percent": round(base_score, 2),
                "risk_grade": self._risk_grade(final_score), # Grado di Rischio
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
            total += self.SEVERITY_WEIGHTS.get(severity, 1) # somma dei pesi delle severity

        # somma delle severity * sensitivity
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

        # somma tutti i raw scores
        total_raw_score = sum(
            resource.get("raw_score", 0)
            for resource in resource_scores
        )

        # calcola il max score
        max_environment_score = (
            len(resource_scores)
            * self.MAX_SEVERITY_WEIGHT
            * self.MAX_SENSITIVITY
        )

        if max_environment_score == 0:
            return 0

        # normalize
        return min(100, (total_raw_score / max_environment_score) * 100)

    def _infer_resource_sensitivity(self, resource: dict[str, Any]) -> float:
        # La sensitivity viene stimata a partire dai tag Azure
        tags = {
            str(key).lower(): str(value).lower()
            for key, value in (resource.get("tags") or {}).items()
        }

        sensitivity = 1.0

        # questi tag possono essere inseriti esplicitamente da chi crea le risorse.
        sensitivity_tag = tags.get("sensitivity") or tags.get("data_classification")

        if sensitivity_tag in {"critical", "high", "confidential"}:
            sensitivity = max(sensitivity, 2.0)
        elif sensitivity_tag in {"medium", "internal"}:
            sensitivity = max(sensitivity, 1.5)
        elif sensitivity_tag in {"low", "public"}:
            sensitivity = max(sensitivity, 0.75)

        # questi tag si riferiscono all'environment
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