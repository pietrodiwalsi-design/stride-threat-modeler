"""
Unit Test Suite for STRIDE Assessment Engine (Phase 3 Surfaces & Integration).

Acceptance Criteria:
1. Complete MCP tool suite works via JSON-RPC 2.0 (start, next, answer, component, derive, propose, rate, check, matrix, catalog).
2. Output budget adherence: responses are compact JSON without massive unpaginated payload dumps.
3. CLI commands execute properly and return structured text/JSON.
4. Cross-surface interoperability: assessment started via MCP can be inspected/answered via CLI and vice versa.
"""

import os
import json
import pytest
import tempfile
from stride_modeler.mcp_server import handle_request, PROTOCOL_VERSION, SERVER_INFO, TOOLS
from stride_modeler.storage import AssessmentStorage
from stride_modeler.state_machine import AssessmentStateMachine
from stride_modeler.evaluator import STRIDEEvaluatorEngine


def test_mcp_tools_list_contains_stateful_suite():
    """Verifies that tools/list exposes all 13 new stateful tools and 3 legacy tools."""
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    res = handle_request(req)
    assert res["jsonrpc"] == "2.0"
    tools = {t["name"] for t in res["result"]["tools"]}

    expected_tools = {
        "start_assessment", "get_next_step", "submit_answer", "add_component",
        "derive_vulnerabilities", "get_rating_proposal", "set_rating",
        "add_llm_finding", "confirm_finding", "check_completeness",
        "get_assessment", "get_risk_matrix", "get_mitigation_catalog",
        "generate_stride_threat_model", "suggest_dora_mitigations", "generate_threat_model_html_report"
    }
    assert expected_tools.issubset(tools)


def test_mcp_full_lifecycle_assessment_flow():
    """Verifies full end-to-end interactive assessment via MCP JSON-RPC 2.0 protocol."""
    # 1. start_assessment
    start_req = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "start_assessment",
            "arguments": {
                "naam": "Mobile Banking Gateway",
                "depth": "quick",
                "unacceptable_outcomes": ["Ongeautoriseerde geldopnames", "Klantdatabase dump online"]
            }
        }
    }
    start_res = handle_request(start_req)
    assert not start_res["result"]["isError"]
    start_data = json.loads(start_res["result"]["content"][0]["text"])
    aid = start_data["assessment"]["id"]
    rev = start_data["assessment"]["rev"]
    assert aid.startswith("TM-")
    assert rev == 1

    # 2. get_next_step
    next_req = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "get_next_step",
            "arguments": {"assessment_id": aid}
        }
    }
    next_res = handle_request(next_req)
    step = json.loads(next_res["result"]["content"][0]["text"])
    assert step["fase"] == "elicitatie"
    assert step["question_id"] == "ds-class-01"
    assert step["rev"] == rev

    # 3. submit_answer
    ans_req = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "submit_answer",
            "arguments": {
                "assessment_id": aid,
                "component_id": step["component_id"],
                "question_id": "ds-class-01",
                "keuze": 3,  # PII
                "rev": step["rev"]
            }
        }
    }
    ans_res = handle_request(ans_req)
    next_step = json.loads(ans_res["result"]["content"][0]["text"])
    assert next_step["question_id"] == "ds-reach-01"
    assert next_step["rev"] == rev + 1

    # 4. derive_vulnerabilities
    derive_req = {
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {
            "name": "derive_vulnerabilities",
            "arguments": {"assessment_id": aid}
        }
    }
    derive_res = handle_request(derive_req)
    assert not derive_res["result"]["isError"]

    # 5. check_completeness
    chk_req = {
        "jsonrpc": "2.0",
        "id": 14,
        "method": "tools/call",
        "params": {
            "name": "check_completeness",
            "arguments": {"assessment_id": aid}
        }
    }
    chk_res = handle_request(chk_req)
    audit = json.loads(chk_res["result"]["content"][0]["text"])
    assert audit["assessment_id"] == aid
    assert audit["totaal_beantwoord"] >= 1


def test_mcp_output_budget_cap():
    """Verifies that mitigation catalog and assessments return compact JSON under budget."""
    cat_req = {
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {"name": "get_mitigation_catalog", "arguments": {}}
    }
    cat_res = handle_request(cat_req)
    raw_text = cat_res["result"]["content"][0]["text"]
    assert len(raw_text) < 50000
    catalog = json.loads(raw_text)
    assert "Spoofing" in catalog
    assert "Tampering" in catalog


def test_mcp_llm_suggested_finding_and_confirmation():
    """Verifies adding an AI-suggested abuse finding (status: voorgesteld) and confirming it."""
    # 1. start assessment
    start_res = handle_request({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "tools/call",
        "params": {"name": "start_assessment", "arguments": {"naam": "AI Finding App"}}
    })
    aid = json.loads(start_res["result"]["content"][0]["text"])["assessment"]["id"]

    # 2. add_llm_finding
    add_req = {
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {
            "name": "add_llm_finding",
            "arguments": {
                "assessment_id": aid,
                "component_id": "comp-sys-01",
                "stride_categorie": "Elevation of Privilege",
                "titel": "Race condition in payment callback bypasses KYC check",
                "toelichting": "Attacker triggers asynchronous webhook during registration race.",
                "model": "claude-sonnet-5"
            }
        }
    }
    add_res = handle_request(add_req)
    data = json.loads(add_res["result"]["content"][0]["text"])
    vid = data["vulnerability_id"]
    assert data["status"] == "voorgesteld"

    # 3. confirm_finding
    conf_req = {
        "jsonrpc": "2.0",
        "id": 32,
        "method": "tools/call",
        "params": {
            "name": "confirm_finding",
            "arguments": {"assessment_id": aid, "vulnerability_id": vid}
        }
    }
    conf_res = handle_request(conf_req)
    conf_data = json.loads(conf_res["result"]["content"][0]["text"])
    assert conf_data["status"] == "actief"


def test_mcp_rating_with_validation():
    """Verifies set_rating enforces mandatory motivation when deviating."""
    start_res = handle_request({
        "jsonrpc": "2.0",
        "id": 40,
        "method": "tools/call",
        "params": {"name": "start_assessment", "arguments": {"naam": "Rating System"}}
    })
    aid = json.loads(start_res["result"]["content"][0]["text"])["assessment"]["id"]

    # Add a component and derive
    handle_request({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {
            "name": "add_llm_finding",
            "arguments": {
                "assessment_id": aid,
                "component_id": "comp-sys-01",
                "stride_categorie": "Tampering",
                "titel": "Unvalidated state change"
            }
        }
    })

    get_vulns_res = handle_request({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {"name": "get_assessment", "arguments": {"assessment_id": aid}}
    })
    vulns = json.loads(get_vulns_res["result"]["content"][0]["text"])["vulnerabilities"]
    vid = vulns[0]["id"]

    # 1. Deviate without motivation -> error code -32602
    bad_rate_res = handle_request({
        "jsonrpc": "2.0",
        "id": 43,
        "method": "tools/call",
        "params": {
            "name": "set_rating",
            "arguments": {
                "assessment_id": aid,
                "vulnerability_id": vid,
                "exposure": 1,  # proposal was 3
                "impact": 1,    # proposal was 4
                "risk_level": "Laag",
                "motivatie": None,
                "treatment": "Mitigate"
            }
        }
    })
    assert "error" in bad_rate_res
    assert "Motivatie is verplicht" in bad_rate_res["error"]["message"]

    # 2. Deviate WITH motivation -> success
    good_rate_res = handle_request({
        "jsonrpc": "2.0",
        "id": 44,
        "method": "tools/call",
        "params": {
            "name": "set_rating",
            "arguments": {
                "assessment_id": aid,
                "vulnerability_id": vid,
                "exposure": 1,
                "impact": 1,
                "risk_level": "Laag",
                "motivatie": "Mitigerende WAF en egress filter maken exploitatie nagenoeg onmogelijk",
                "treatment": "Mitigate"
            }
        }
    })
    assert not good_rate_res["result"]["isError"]
