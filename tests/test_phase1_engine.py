"""
Unit Test Suite for STRIDE Assessment Engine (Phase 1).

Acceptance Criteria:
1. derive_vulnerabilities on facts returns vulnerabilities with source rule and ASVS/DORA references.
2. Every vulnerability names the rule and triggering facts that elicited it.
3. An unknown fact yields status: onbekend, never a favorable assumption.
4. Scoring proposal gives distribution: 5 different fact sets yield >= 3 different risk levels.
5. Strict expectation table for DORA and ISO 27001:2022 mappings (no superficial key existence check).
6. Deterministic threat IDs: identical inputs produce identical 8-character hex IDs.
"""

import pytest
from stride_modeler.evaluator import STRIDEEvaluatorEngine
from stride_modeler.dora_mitigations import DORA_MITIGATION_CATALOG
from stride_modeler.models import STRIDECategory


@pytest.fixture
def engine():
    return STRIDEEvaluatorEngine()


def test_rule_derivation_with_lineage(engine):
    """Verifies that derived vulnerabilities carry source rules, triggering facts, and ASVS citations."""
    facts = {
        "direct_access": "privileged_humans",
        "change_audit": "none",
        "data_class": "pii",
        "network_exposure": "internal_dmz"
    }

    vulns = engine.derive_vulnerabilities(
        component_id="ds-01",
        component_name="CustomerDB",
        component_type="data_store",
        facts=facts
    )

    assert len(vulns) >= 1
    repud_vuln = next((v for v in vulns if v["bron_regel"] == "R-DS-REPUD-01"), None)
    assert repud_vuln is not None
    assert "CustomerDB" in repud_vuln["titel"]
    assert repud_vuln["stride_categorie"] == "Repudiation"
    assert repud_vuln["bron_referentie"] == "ASVS V7.1.3"
    assert repud_vuln["herkomst"] == "rule"
    assert repud_vuln["triggering_facts"]["direct_access"] == "privileged_humans"
    assert repud_vuln["triggering_facts"]["change_audit"] == "none"
    assert repud_vuln["id"].startswith("THR-")


def test_unknown_fact_yields_onbekend_status(engine):
    """Verifies Evidence Integrity Standard: unknown facts result in status 'onbekend', never silent pass."""
    facts = {
        "direct_access": "unknown",
        "change_audit": "none",
        "data_class": "internal"
    }

    vulns = engine.derive_vulnerabilities(
        component_id="ds-unknown-test",
        component_name="LegacyStore",
        component_type="data_store",
        facts=facts
    )

    unknown_vuln = next((v for v in vulns if v["bron_regel"] == "R-DS-UNKNOWN-01"), None)
    assert unknown_vuln is not None
    assert unknown_vuln["status"] == "onbekend"
    assert unknown_vuln["triggering_facts"]["direct_access"] == "unknown"


def test_scoring_distribution_across_five_fact_sets(engine):
    """Verifies that 5 distinct fact sets produce at least 3 distinct qualitative risk levels (Laag, Midden, Hoog, Kritiek)."""
    fact_sets = [
        # Set 1: Hardened process with debug logs on public data -> Laag
        {
            "component_type": "process",
            "facts": {
                "process_logging": "unfiltered_debug",
                "entity_auth": "phishing_resistant_mfa_mtls",
                "data_class": "public"
            },
            "is_crown_jewel": False,
            "unacceptable_outcomes_hit": False
        },
        # Set 2: Internal basic framework process -> Midden
        {
            "component_type": "process",
            "facts": {
                "input_validation": "basic_framework",
                "data_class": "internal"
            },
            "is_crown_jewel": False,
            "unacceptable_outcomes_hit": False
        },
        # Set 3: Public internet PII store without audit -> Hoog
        {
            "component_type": "data_store",
            "facts": {
                "network_exposure": "internet_auth",
                "data_class": "pii",
                "direct_access": "privileged_humans",
                "change_audit": "none",
                "db_auth": "shared_secret"
            },
            "is_crown_jewel": False,
            "unacceptable_outcomes_hit": False
        },
        # Set 4: Crown Jewel Special Category with Unacceptable Outcome -> Kritiek
        {
            "component_type": "data_store",
            "facts": {
                "network_exposure": "internet_public",
                "data_class": "special_category",
                "direct_access": "multiple_systems",
                "change_audit": "none",
                "db_auth": "none"
            },
            "is_crown_jewel": True,
            "unacceptable_outcomes_hit": True
        },
        # Set 5: Plaintext Dataflow across trust boundary -> Hoog / Midden
        {
            "component_type": "data_flow",
            "facts": {
                "crosses_trust_boundary": True,
                "transit_encryption": "plaintext_none",
                "message_integrity": "none",
                "data_class": "pii"
            },
            "is_crown_jewel": False,
            "unacceptable_outcomes_hit": False
        }
    ]

    derived_risk_levels = set()
    for item in fact_sets:
        vulns = engine.derive_vulnerabilities(
            component_id="comp-test",
            component_name="TestComponent",
            component_type=item["component_type"],
            facts=item["facts"],
            is_crown_jewel=item["is_crown_jewel"],
            unacceptable_outcomes_hit=item["unacceptable_outcomes_hit"]
        )
        for v in vulns:
            derived_risk_levels.add(v["risk_level_voorstel"])

    # Must produce at least 3 distinct risk levels across the sets (e.g. Laag, Midden, Hoog, Kritiek)
    assert len(derived_risk_levels) >= 3, f"Expected >= 3 distinct risk levels, got {derived_risk_levels}"
    assert "Laag" in derived_risk_levels or "Midden" in derived_risk_levels
    assert "Hoog" in derived_risk_levels
    assert "Kritiek" in derived_risk_levels


def test_deterministic_threat_ids(engine):
    """Verifies that identical component, category, and rule generate identical threat IDs."""
    id1 = engine.generate_threat_id("CustomerDB", "Repudiation", "R-DS-REPUD-01")
    id2 = engine.generate_threat_id("CustomerDB", "Repudiation", "R-DS-REPUD-01")
    id3 = engine.generate_threat_id("CustomerDB", "Tampering", "R-DS-REPUD-01")

    assert id1 == id2
    assert id1 != id3
    assert len(id1) == 12  # "THR-" + 8 chars


def test_strict_dora_and_iso_2022_expectation_table():
    """
    Assurance Test: Verifies exact DORA articles and ISO/IEC 27001:2022 Annex A controls
    against a hardcoded expectation table to prevent fail-open regressions.
    """
    EXPECTED_MAPPINGS = {
        "MIT-DORA-AUTH-01": {"DORA": "Art. 9(2)", "ISO27001": "A.8.5"},
        "MIT-DORA-AUTH-02": {"DORA": "Art. 9(2)", "ISO27001": "A.8.5"},
        "MIT-DORA-INT-01": {"DORA": "Art. 9(4)(b)", "ISO27001": "A.8.24"},
        "MIT-DORA-INT-02": {"DORA": "Art. 10(2)-(3), plus art. 9(4)(b)", "ISO27001": "A.8.15"},
        "MIT-DORA-NONREP-01": {"DORA": "Art. 10(3), plus art. 17(1)", "ISO27001": "A.8.17"},
        "MIT-DORA-CONF-01": {"DORA": "Art. 9(4)(c)", "ISO27001": "A.8.24"},
        "MIT-DORA-CONF-02": {"DORA": "Art. 9(4)(a)", "ISO27001": "A.5.14"},
        "MIT-DORA-RES-01": {"DORA": "Art. 11(1)", "ISO27001": "A.5.29 / A.5.30"},
        "MIT-DORA-RES-02": {"DORA": "Art. 11(2)", "ISO27001": "A.8.6"},
        "MIT-DORA-RBAC-01": {"DORA": "Art. 9(1)", "ISO27001": "A.5.15 / A.8.3"},
        "MIT-DORA-RBAC-02": {"DORA": "Art. 9(3)", "ISO27001": "A.8.27"}
    }

    for cat, mitigations in DORA_MITIGATION_CATALOG.items():
        for m in mitigations:
            expected = EXPECTED_MAPPINGS.get(m.id)
            assert expected is not None, f"Untracked mitigation ID: {m.id}"

            # DORA check
            dora_val = m.framework_mapping.get("DORA", "")
            assert expected["DORA"] in dora_val, f"Mismatch in DORA for {m.id}: expected '{expected['DORA']}', got '{dora_val}'"

            # ISO 27001:2022 check
            iso_val = m.framework_mapping.get("ISO27001", "")
            assert expected["ISO27001"] in iso_val, f"Mismatch in ISO27001:2022 for {m.id}: expected '{expected['ISO27001']}', got '{iso_val}'"
