"""
Phase 1 Unit Tests for STRIDE Threat Engine.
"""

import pytest
from stride_modeler.models import Component, ComponentType, DataFlow, STRIDECategory, RiskLevel
from stride_modeler.stride_engine import STRIDEThreatEngine
from stride_modeler.dora_mitigations import get_mitigations_for_category


def test_stride_applicability_process():
    engine = STRIDEThreatEngine()
    comp = Component(id="proc-1", name="Payment Worker", type=ComponentType.PROCESS, is_crown_jewel=True)
    threats = engine.evaluate_component_threats(comp)

    # Process must have all 6 STRIDE categories
    categories = {t.category for t in threats}
    assert len(threats) == 6
    assert categories == {
        STRIDECategory.SPOOFING,
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
        STRIDECategory.ELEVATION_OF_PRIVILEGE
    }
    # Crown jewel impact boost
    for t in threats:
        assert t.impact == 5
        assert t.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]


def test_stride_applicability_data_store():
    engine = STRIDEThreatEngine()
    db = Component(id="db-1", name="SQL Database", type=ComponentType.DATA_STORE, trust_zone="Internal")
    threats = engine.evaluate_component_threats(db)

    # Data store has T, R, I, D (no Spoofing, no Elevation of Privilege)
    categories = {t.category for t in threats}
    assert len(threats) == 4
    assert categories == {
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE
    }


def test_stride_applicability_external_entity():
    engine = STRIDEThreatEngine()
    ext = Component(id="ext-1", name="External Client", type=ComponentType.EXTERNAL_ENTITY, trust_zone="Internet")
    threats = engine.evaluate_component_threats(ext)

    # External entity has S, R
    categories = {t.category for t in threats}
    assert len(threats) == 2
    assert categories == {
        STRIDECategory.SPOOFING,
        STRIDECategory.REPUDIATION
    }
    for t in threats:
        assert t.likelihood == 4  # Internet boost


def test_dora_mitigations_coverage():
    for cat in STRIDECategory:
        mits = get_mitigations_for_category(cat)
        assert len(mits) >= 1
        for m in mits:
            assert "DORA" in m.framework_mapping
            assert "NIST_CSF" in m.framework_mapping
