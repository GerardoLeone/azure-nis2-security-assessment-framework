from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from az_nis2.analyzers.configuration_analyzer import ConfigurationAnalyzer
from az_nis2.compliance.nis2_mapper import NIS2ComplianceEvaluator
from az_nis2.scoring.risk_scorer import RiskScorer
from az_nis2.reporting.reporting_engine import ReportingEngine


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


outputs = PROJECT_ROOT / "outputs"

inventory_path = outputs / "inventory.json"

if not inventory_path.exists():
    raise FileNotFoundError(
        "outputs/inventory.json non trovato. "
        "Senza l'inventario salvato non è possibile rigenerare offline."
    )

print("Caricamento inventory.json esistente...")
inventory = load_json(inventory_path)

print("Esecuzione Configuration Analyzer offline...")
analyzer = ConfigurationAnalyzer(
    PROJECT_ROOT / "rules" / "azure_security_rules.yml"
)
findings = analyzer.analyze(inventory)

print("Esecuzione NIS2 Compliance Mapper...")
mapper = NIS2ComplianceEvaluator(
    PROJECT_ROOT / "benchmarks" / "nis2_controls.yml"
)
compliance = mapper.evaluate(findings)

print("Esecuzione Risk Scorer...")
risk = RiskScorer().score(
    inventory,
    findings,
    compliance,
)

# Controlli di sicurezza sui risultati attesi
assert len(findings) == 14, (
    f"ATTENZIONE: trovati {len(findings)} finding invece di 14."
)

summary = compliance["summary"]

assert summary["total_controls"] == 5
assert summary["passed_controls"] == 0
assert summary["failed_controls"] == 5
assert summary["compliance_percentage"] == 0.0

overall = risk["overall"]

assert overall["score_percent"] == 94.5, (
    f"ATTENZIONE: risk score inatteso: {overall['score_percent']}"
)

assert overall["base_score_percent"] == 63.0
assert overall["risk_grade"] == "Critical"

# Verifica specifica dei tre mapping corretti
expected_controls = {
    "AZ-STORAGE-002": [
        "NIS2-ART21-2-A",
        "NIS2-ART21-2-H",
    ],
    "AZ-STORAGE-003": [
        "NIS2-ART21-2-A",
        "NIS2-ART21-2-E",
    ],
    "AZ-NSG-003": [
        "NIS2-ART21-2-A",
        "NIS2-ART21-2-E",
    ],
}

for finding in findings:
    rule_id = finding.get("rule_id")

    if rule_id in expected_controls:
        assert finding.get("nis2_controls") == expected_controls[rule_id], (
            f"Mapping inatteso per {rule_id}: "
            f"{finding.get('nis2_controls')}"
        )

# NON sovrascriviamo subito i vecchi output.
# Generiamo file separati per sicurezza.
findings_path = outputs / "findings_offline.json"
compliance_path = outputs / "compliance_offline.json"
risk_path = outputs / "risk_offline.json"
report_path = outputs / "security_assessment_report.pdf"

findings_path.write_text(
    json.dumps(findings, indent=2),
    encoding="utf-8",
)

compliance_path.write_text(
    json.dumps(compliance, indent=2),
    encoding="utf-8",
)

risk_path.write_text(
    json.dumps(risk, indent=2),
    encoding="utf-8",
)

print("Generazione PDF offline...")

ReportingEngine().generate_pdf(
    inventory=inventory,
    findings=findings,
    compliance=compliance,
    risk=risk,
    output_path=report_path,
)

print()
print("=== RIGENERAZIONE OFFLINE COMPLETATA ===")
print(f"Findings: {len(findings)}")
print(
    f"NIS2: {summary['passed_controls']}/"
    f"{summary['total_controls']} PASS "
    f"({summary['compliance_percentage']}%)"
)
print(
    f"Risk: {overall['score_percent']}% "
    f"({overall['risk_grade']})"
)
print(f"Report: {report_path}")