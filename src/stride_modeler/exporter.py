"""
Shared JSON Exporter for STRIDE Assessment Engine (Phase 4).

Generates schema v1.0 compliant JSON exports of assessments,
including the three version fields (library_version, rules_version, matrix_version),
scoping outcomes, components, facts, vulnerabilities with full trace, decisions, and recommendations.
"""

import json
from typing import Dict, Any, Optional
from stride_modeler.storage import AssessmentStorage
from stride_modeler.evaluator import STRIDEEvaluatorEngine


class AssessmentExporter:
    """Exports an assessment into the shared JSON format v1.0."""

    @staticmethod
    def export_assessment(assessment_id: str, storage: Optional[AssessmentStorage] = None, evaluator: Optional[STRIDEEvaluatorEngine] = None) -> Dict[str, Any]:
        storage = storage or AssessmentStorage()
        evaluator = evaluator or STRIDEEvaluatorEngine()

        a = storage.get_assessment(assessment_id)
        if not a:
            raise ValueError(f"Assessment {assessment_id} niet gevonden")

        components = storage.get_components(assessment_id)
        answers = storage.get_answers(assessment_id)
        vulns = storage.get_vulnerabilities(assessment_id)

        # Fetch facts
        all_facts = []
        with storage._get_connection() as conn:
            for r in conn.execute("SELECT * FROM facts WHERE assessment_id = ?", (assessment_id,)).fetchall():
                all_facts.append({
                    "component_id": r["component_id"],
                    "sleutel": r["sleutel"],
                    "waarde": r["waarde"],
                    "confidence": r["confidence"]
                })

        # Fetch ratings
        ratings = {}
        with storage._get_connection() as conn:
            for r in conn.execute("SELECT * FROM ratings WHERE assessment_id = ?", (assessment_id,)).fetchall():
                ratings[r["vulnerability_id"]] = dict(r)

        # Fetch recommendations
        recommendations = []
        with storage._get_connection() as conn:
            for r in conn.execute("SELECT * FROM recommendations WHERE assessment_id = ?", (assessment_id,)).fetchall():
                rec = dict(r)
                rec["vulnerability_ids"] = json.loads(rec["vulnerability_ids"])
                recommendations.append(rec)

        # Fetch abuse scenarios
        abuse_scenarios = []
        with storage._get_connection() as conn:
            for r in conn.execute("SELECT * FROM abuse_scenarios WHERE assessment_id = ?", (assessment_id,)).fetchall():
                scen = dict(r)
                scen["betrokken_componenten"] = json.loads(scen["betrokken_componenten"])
                scen["geraakte_unacceptable_outcomes"] = json.loads(scen["geraakte_unacceptable_outcomes"])
                abuse_scenarios.append(scen)

        # Assemble vulnerabilities list with rating & decision
        kwetsbaarheden_export = []
        for v in vulns:
            r = ratings.get(v["id"], {})
            kwetsbaarheden_export.append({
                "id": v["id"],
                "component_id": v["component_id"],
                "titel": v["titel"],
                "toelichting": v.get("toelichting", ""),
                "categorie": v["stride_categorie"],
                "herkomst": v.get("herkomst", "rule"),
                "status": v.get("status", "actief"),
                "bron_regel": v.get("bron_regel", ""),
                "bron_referentie": v.get("bron_referentie", ""),
                "triggering_facts": v.get("triggering_facts", {}),
                "exposure_voorstel": v.get("exposure_voorstel", 3),
                "impact_voorstel": v.get("impact_voorstel", 3),
                "risk_level_voorstel": v.get("risk_level_voorstel", "Midden"),
                "scoring_rationale": v.get("scoring_rationale", ""),
                "exposure": r.get("exposure", v.get("exposure_voorstel", 3)),
                "impact": r.get("impact", v.get("impact_voorstel", 3)),
                "risk_level": r.get("risk_level", v.get("risk_level_voorstel", "Midden")),
                "motivatie": r.get("motivatie"),
                "treatment": r.get("treatment", "Mitigate"),
                "eigenaar": r.get("eigenaar"),
                "besluit": r.get("besluit")
            })

        export_data = {
            "schema_version": "1.0",
            "assessment_id": a["id"],
            "naam": a["naam"],
            "methodology": a["methodology"],
            "depth": a["depth"],
            "status": a["status"],
            "rev": a["rev"],
            "aangemaakt": a["aangemaakt"],
            "gewijzigd": a["gewijzigd"],
            "unacceptable_outcomes": a.get("unacceptable_outcomes", []),
            "library_version": evaluator.library_version,
            "rules_version": evaluator.rules_version,
            "matrix_version": evaluator.matrix_version,
            "componenten": components,
            "feiten": all_facts,
            "kwetsbaarheden": kwetsbaarheden_export,
            "misbruikscenarios": abuse_scenarios,
            "aanbevelingen": recommendations
        }

        return export_data
