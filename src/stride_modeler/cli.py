"""
CLI interface for STRIDE Threat Modeler.
"""

import sys
import argparse
import json
from stride_modeler.models import Component, ComponentType, DataFlow
from stride_modeler.stride_engine import STRIDEThreatEngine
from stride_modeler.dashboard_generator import STRIDEDashboardGenerator


def main():
    parser = argparse.ArgumentParser(description="STRIDE Threat Modeler CLI")
    parser.add_argument("--system", type=str, default="Enterprise Cloud Architecture", help="Name of the system")
    parser.add_argument("--demo", action="store_true", help="Run with demo enterprise banking architecture")
    parser.add_argument("--output-html", type=str, default="threat_model_report.html", help="Path to output HTML report")
    parser.add_argument("--json", action="store_true", help="Output JSON threat report to stdout")

    args = parser.parse_args()
    engine = STRIDEThreatEngine()

    if args.demo:
        # Add Demo components
        c1 = Component(id="comp-web", name="Public Web Portal", type=ComponentType.PROCESS, trust_zone="DMZ", is_crown_jewel=False)
        c2 = Component(id="comp-api", name="Core Banking API Gateway", type=ComponentType.PROCESS, trust_zone="Internal", is_crown_jewel=True)
        c3 = Component(id="comp-db", name="Customer Ledger Database", type=ComponentType.DATA_STORE, trust_zone="Internal", is_crown_jewel=True)
        c4 = Component(id="comp-idp", name="External Identity Provider (OIDC)", type=ComponentType.EXTERNAL_ENTITY, trust_zone="External")
        
        engine.add_component(c1)
        engine.add_component(c2)
        engine.add_component(c3)
        engine.add_component(c4)

        # Add Data flows
        f1 = DataFlow(id="flow-1", source_id="comp-web", target_id="comp-api", protocol="HTTPS", crosses_trust_boundary=True, data_classification="Confidential")
        f2 = DataFlow(id="flow-2", source_id="comp-api", target_id="comp-db", protocol="TLS-mTLS", crosses_trust_boundary=False, data_classification="Restricted")
        f3 = DataFlow(id="flow-3", source_id="comp-idp", target_id="comp-web", protocol="HTTPS", crosses_trust_boundary=True, data_classification="Confidential")

        engine.add_data_flow(f1)
        engine.add_data_flow(f2)
        engine.add_data_flow(f3)

    report = engine.generate_full_model(args.system)

    if args.json:
        print(json.dumps(report.model_dump(), indent=2))
    else:
        STRIDEDashboardGenerator.generate_html(report, args.output_html)
        print(f"✅ STRIDE Threat Model generated successfully!")
        print(f"   System: {report.system_name}")
        print(f"   Threats Identified: {report.threats_count}")
        print(f"   DORA Coverage: {report.dora_resilience_coverage}%")
        print(f"   HTML Report: {args.output_html}")


if __name__ == "__main__":
    main()
