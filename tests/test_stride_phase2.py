"""
Phase 2 Tests for STRIDE Threat Modeler — Complex Data Flows and Risk Aggregation.
"""

import pytest
from stride_modeler.models import Component, ComponentType, DataFlow, STRIDECategory, RiskLevel
from stride_modeler.stride_engine import STRIDEThreatEngine
from stride_modeler.dashboard_generator import STRIDEDashboardGenerator


def test_data_flow_threats_trust_boundary_crossing():
    engine = STRIDEThreatEngine()
    c1 = Component(id="c1", name="Public Client", type=ComponentType.EXTERNAL_ENTITY, trust_zone="Internet")
    c2 = Component(id="c2", name="API Gateway", type=ComponentType.PROCESS, trust_zone="DMZ")
    engine.add_component(c1)
    engine.add_component(c2)

    # Data flow crossing trust boundary with confidential classification
    flow = DataFlow(
        id="flow-cross",
        source_id="c1",
        target_id="c2",
        protocol="HTTPS",
        crosses_trust_boundary=True,
        data_classification="Confidential"
    )
    engine.add_data_flow(flow)

    flow_threats = engine.evaluate_data_flow_threats(flow)
    assert len(flow_threats) == 3  # T, I, D
    
    for t in flow_threats:
        # Cross boundary should elevate likelihood and impact
        assert t.likelihood == 4
        assert t.impact == 4
        assert t.risk_score >= 16
        assert t.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]


def test_full_model_aggregation_and_dora_coverage():
    engine = STRIDEThreatEngine()
    c1 = Component(id="web", name="Web Frontend", type=ComponentType.PROCESS, trust_zone="DMZ")
    c2 = Component(id="backend", name="Microservice", type=ComponentType.PROCESS, trust_zone="Internal", is_crown_jewel=True)
    c3 = Component(id="vault", name="Secrets Vault", type=ComponentType.DATA_STORE, trust_zone="Internal", is_crown_jewel=True)
    
    engine.add_component(c1)
    engine.add_component(c2)
    engine.add_component(c3)

    f1 = DataFlow(id="f1", source_id="web", target_id="backend", crosses_trust_boundary=True)
    f2 = DataFlow(id="f2", source_id="backend", target_id="vault", crosses_trust_boundary=False)
    engine.add_data_flow(f1)
    engine.add_data_flow(f2)

    report = engine.generate_full_model("Pensions Cloud Core")

    # 6 threats for c1, 6 threats for c2, 4 threats for c3, 3 threats for f1, 3 threats for f2 = 22 threats
    assert report.threats_count == 22
    assert report.components_count == 3
    assert report.data_flows_count == 2
    assert "Microservice" in report.crown_jewels
    assert "Secrets Vault" in report.crown_jewels
    assert report.dora_resilience_coverage >= 90.0

    # Test HTML dashboard generation
    html = STRIDEDashboardGenerator.generate_html(report)
    assert "<!DOCTYPE html>" in html
    assert "Pensions Cloud Core" in html
    assert "DORA Resiliency Dekking" in html
    assert "STRIDE Verdeling" in html
