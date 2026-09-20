"""
Phase 3 Hardening & MCP Protocol Tests for STRIDE Threat Modeler.
"""

import pytest
import json
from stride_modeler.mcp_server import handle_request, PROTOCOL_VERSION, SERVER_INFO, TOOLS


def test_mcp_initialize():
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {}
        }
    }
    res = handle_request(req)
    assert res["jsonrpc"] == "2.0"
    assert res["id"] == 1
    assert res["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert res["result"]["serverInfo"]["name"] == "stride-threat-modeler-mcp"


def test_mcp_tools_list():
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }
    res = handle_request(req)
    assert res["jsonrpc"] == "2.0"
    assert res["id"] == 2
    tools = res["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "generate_stride_threat_model" in tool_names
    assert "suggest_dora_mitigations" in tool_names
    assert "generate_threat_model_html_report" in tool_names


def test_mcp_generate_stride_model_call():
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "generate_stride_threat_model",
            "arguments": {
                "system_name": "Life & Pensions Insurance API",
                "components": [
                    {"id": "c1", "name": "Policy Gateway", "type": "process", "trust_zone": "DMZ", "is_crown_jewel": False},
                    {"id": "c2", "name": "Underwriting DB", "type": "data_store", "trust_zone": "Internal", "is_crown_jewel": True}
                ],
                "data_flows": [
                    {"id": "f1", "source_id": "c1", "target_id": "c2", "protocol": "TLS-1.3", "crosses_trust_boundary": True}
                ]
            }
        }
    }
    res = handle_request(req)
    assert res["jsonrpc"] == "2.0"
    assert res["id"] == 3
    assert not res["result"]["isError"]
    content = json.loads(res["result"]["content"][0]["text"])
    assert content["system_name"] == "Life & Pensions Insurance API"
    assert content["threats_count"] == 13  # 6 (proc) + 4 (db) + 3 (flow)
    assert content["dora_resilience_coverage"] >= 90.0


def test_mcp_suggest_dora_mitigations():
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "suggest_dora_mitigations",
            "arguments": {
                "category": "Tampering"
            }
        }
    }
    res = handle_request(req)
    assert res["jsonrpc"] == "2.0"
    assert res["id"] == 4
    content = json.loads(res["result"]["content"][0]["text"])
    assert content["category"] == "Tampering"
    assert len(content["mitigations"]) >= 2
    assert any("Art. 9" in str(m) for m in content["mitigations"])


def test_mcp_error_handling_invalid_tool():
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "non_existent_tool",
            "arguments": {}
        }
    }
    res = handle_request(req)
    assert "error" in res
    assert res["error"]["code"] == -32601


def test_mcp_error_handling_missing_required_args():
    req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "generate_stride_threat_model",
            "arguments": {
                "system_name": ""  # empty
            }
        }
    }
    res = handle_request(req)
    assert "error" in res
    assert res["error"]["code"] == -32602


def test_mcp_non_dict_payload_guard():
    # Tests that non-dict payloads return -32600 instead of crashing the process
    res1 = handle_request("plain_string")
    assert res1["error"]["code"] == -32600
    res2 = handle_request([1, 2, 3])
    assert res2["error"]["code"] == -32600


def test_xss_escaping_in_dashboard():
    from stride_modeler.models import Component, ComponentType, ThreatModelReport, STRIDECategory, RiskLevel, Threat
    from stride_modeler.dashboard_generator import STRIDEDashboardGenerator

    malicious_name = "<script>alert('xss')</script>"
    t = Threat(
        id="THR-XSS",
        category=STRIDECategory.SPOOFING,
        target_id="c1",
        target_name=malicious_name,
        title="<img src=x onerror=alert(1)>",
        description="test",
        likelihood=3,
        impact=3
    )
    report = ThreatModelReport(
        system_name=malicious_name,
        components_count=1,
        data_flows_count=0,
        threats_count=1,
        risk_summary={"Medium": 1},
        stride_distribution={"Spoofing": 1},
        crown_jewels=[],
        threats=[t],
        dora_resilience_coverage=100.0
    )
    html_out = STRIDEDashboardGenerator.generate_html(report)
    assert "<script>alert('xss')</script>" not in html_out
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_out or "&lt;script&gt;alert('xss')&lt;/script&gt;" in html_out
    assert "<img src=x onerror=alert(1)>" not in html_out


def test_immutable_mitigation_copies():
    from stride_modeler.models import STRIDECategory
    from stride_modeler.dora_mitigations import get_mitigations_for_category

    m1 = get_mitigations_for_category(STRIDECategory.SPOOFING)
    m2 = get_mitigations_for_category(STRIDECategory.SPOOFING)
    assert m1[0] is not m2[0]  # Deep copies ensure mutation isolation
    m1[0].status = "MutatedStatus"
    assert m2[0].status == "Open"
