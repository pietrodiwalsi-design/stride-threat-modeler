"""
Unit Test Suite for STRIDE Assessment Engine (Phase 4 Reporting & Shared Export).

Acceptance Criteria:
1. Report displays scoring proposal next to human rating with motivation.
2. LLM sections (abuse scenarios, recommendations) are visibly marked with model and date provenance.
3. Export validates against shared JSON schema v1.0 and contains 3 version fields (library_version, rules_version, matrix_version).
4. Deterministic repeatability: identical inputs yield identical threat IDs across export runs.
5. HTML report contains all 9 structured sections including the mandatory decisions table for High & Critical findings.
"""

import os
import json
import pytest
import tempfile
from stride_modeler.storage import AssessmentStorage
from stride_modeler.state_machine import AssessmentStateMachine
from stride_modeler.evaluator import STRIDEEvaluatorEngine
from stride_modeler.exporter import AssessmentExporter
from stride_modeler.dashboard_generator import STRIDEDashboardGenerator


@pytest.fixture
def populated_assessment():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    storage = AssessmentStorage(db_path=path)
    evaluator = STRIDEEvaluatorEngine()
    sm = AssessmentStateMachine(storage=storage, evaluator=evaluator)

    # Start assessment with scoping outcomes
    a = sm.start_assessment(
        naam="Core Banking Transfer Service",
        depth="standard",
        methodology="stride",
        unacceptable_outcomes=[
            "Geldoverboeking naar ongeautoriseerde rekening",
            "Lekken van bankrekeningnummers en saldi"
        ]
    )
    aid = a["id"]

    # Add components
    storage.add_component(aid, "ds-core", "AccountLedgerDB", "data_store", trust_zone="Internal", is_crown_jewel=True)
    storage.add_component(aid, "proc-api", "TransferProcessor", "process", trust_zone="DMZ", is_crown_jewel=True)

    # Save answers & facts
    sm.submit_answer(aid, "ds-core", "ds-class-01", choice_nr=4, rev=a["rev"])
    curr_a = storage.get_assessment(aid)
    sm.submit_answer(aid, "ds-core", "ds-reach-01", choice_nr=3, rev=curr_a["rev"])
    curr_a = storage.get_assessment(aid)
    sm.submit_answer(aid, "ds-core", "ds-access-01", choice_nr=3, rev=curr_a["rev"])

    # Derive vulnerabilities
    vulns = sm.derive_and_save_vulnerabilities(aid)

    # Set rating for first vulnerability with deviation and motivation
    if vulns:
        v0 = vulns[0]
        storage.set_rating(
            assessment_id=aid,
            vuln_id=v0["id"],
            exposure=2,  # proposal was higher
            impact=4,
            risk_level="Hoog",
            motivatie="Strikte hardware firewall mitigeert externe netwerktoegang",
            treatment="Mitigate",
            eigenaar="Peter Van Walsem",
            besluit="Ontwerpwijziging: mTLS authenticatie afgedwongen"
        )

    # Add an AI abuse scenario
    with storage._get_connection() as conn:
        conn.execute(
            """
            INSERT INTO abuse_scenarios (id, assessment_id, titel, beschrijving, betrokken_componenten, geraakte_unacceptable_outcomes, model, gegenereerd_op)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "SCEN-001",
                aid,
                "Overboeking via asynchronous race condition",
                "Aanvaller triggert gelijktijdige debet- en credit calls tijdens database failover.",
                json.dumps(["TransferProcessor", "AccountLedgerDB"]),
                json.dumps(["Geldoverboeking naar ongeautoriseerde rekening"]),
                "claude-sonnet-5",
                "2026-09-21T14:00:00Z"
            )
        )
        conn.execute(
            """
            INSERT INTO recommendations (id, assessment_id, vulnerability_ids, tekst, model, gegenereerd_op)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "REC-001",
                aid,
                json.dumps([v0["id"] if vulns else "THR-001"]),
                "Implementeer distributed database locks met tweetraps-commit om race conditions te voorkomen.",
                "claude-sonnet-5",
                "2026-09-21T14:05:00Z"
            )
        )
        conn.commit()

    yield aid, storage, evaluator
    if os.path.exists(path):
        os.remove(path)


def test_shared_json_export_schema_compliance(populated_assessment):
    """Verifies that AssessmentExporter produces a compliant Schema v1.0 JSON payload."""
    aid, storage, evaluator = populated_assessment

    export_data = AssessmentExporter.export_assessment(aid, storage=storage, evaluator=evaluator)

    assert export_data["schema_version"] == "1.0"
    assert export_data["assessment_id"] == aid
    assert export_data["naam"] == "Core Banking Transfer Service"
    assert export_data["methodology"] == "stride"
    assert export_data["depth"] == "standard"

    # Verify 3 version fields
    assert "library_version" in export_data and export_data["library_version"] == "1.0.0"
    assert "rules_version" in export_data and export_data["rules_version"] == "1.0.0"
    assert "matrix_version" in export_data and export_data["matrix_version"] == "1.0.0"

    # Verify scoping anchors
    assert len(export_data["unacceptable_outcomes"]) == 2

    # Verify components and facts
    assert len(export_data["componenten"]) == 2
    assert len(export_data["feiten"]) >= 3

    # Verify vulnerabilities with lineage and rating
    vulns = export_data["kwetsbaarheden"]
    assert len(vulns) >= 1
    v = vulns[0]
    assert "id" in v and v["id"].startswith("THR-")
    assert "bron_regel" in v
    assert "bron_referentie" in v
    assert "exposure_voorstel" in v
    assert "impact_voorstel" in v
    assert "exposure" in v
    assert "impact" in v
    assert "risk_level" in v
    assert "treatment" in v

    # Verify abuse scenarios and recommendations with provenance
    assert len(export_data["misbruikscenarios"]) == 1
    assert export_data["misbruikscenarios"][0]["model"] == "claude-sonnet-5"
    assert len(export_data["aanbevelingen"]) == 1
    assert export_data["aanbevelingen"][0]["model"] == "claude-sonnet-5"


def test_html_report_rendering_and_sections(populated_assessment):
    """Verifies that HTML report renders all 9 required sections with proposal, rating, motivation, and provenance."""
    aid, storage, evaluator = populated_assessment

    html_out = STRIDEDashboardGenerator.generate_assessment_html(aid, storage=storage, evaluator=evaluator)

    # 1. Header with assessment ID and versions
    assert aid in html_out
    assert "Core Banking Transfer Service" in html_out
    assert "Bibliotheek v1.0.0" in html_out
    assert "Peter Van Walsem" in html_out

    # 2. Unacceptable outcomes
    assert "Geldoverboeking naar ongeautoriseerde rekening" in html_out

    # 3. Components
    assert "AccountLedgerDB" in html_out
    assert "TransferProcessor" in html_out

    # 4. 5x5 Risk Matrix
    assert "KRITIEK" in html_out or "HOOG" in html_out

    # 5. Register with Proposal vs Rating & Motivation
    assert "Voorstel:" in html_out
    assert "Motivatie oordeel:" in html_out
    assert "Strikte hardware firewall mitigeert externe netwerktoegang" in html_out

    # 6. Abuse scenarios with model provenance
    assert "claude-sonnet-5" in html_out
    assert "Overboeking via asynchronous race condition" in html_out

    # 7. Decisions section
    assert "Ontwerpwijziging: mTLS authenticatie afgedwongen" in html_out

    # 8. Recommendations with model provenance
    assert "REC-001" in html_out
    assert "distributed database locks" in html_out

    # 9. ASVS / Regulatory citations
    assert "ASVS" in html_out or "DORA" in html_out


def test_deterministic_threat_id_reproducibility(populated_assessment):
    """Verifies that re-exporting or re-evaluating the same assessment generates identical threat IDs."""
    aid, storage, evaluator = populated_assessment

    export1 = AssessmentExporter.export_assessment(aid, storage=storage, evaluator=evaluator)
    export2 = AssessmentExporter.export_assessment(aid, storage=storage, evaluator=evaluator)

    ids1 = [v["id"] for v in export1["kwetsbaarheden"]]
    ids2 = [v["id"] for v in export2["kwetsbaarheden"]]

    assert ids1 == ids2
    assert len(ids1) >= 1
