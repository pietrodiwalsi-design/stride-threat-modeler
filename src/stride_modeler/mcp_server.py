#!/usr/bin/env python3
"""
STRIDE Threat Modeler — Model Context Protocol (MCP) Server.
Stateful Assessment Engine & Continuous STRIDE Threat Modeling under DORA ICT Resilience.
Supports single-step elicitation, persistent SQLite state, and compact JSON output budget.
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

from stride_modeler.models import (
    Component, ComponentType, DataFlow, ThreatModelReport
)
from stride_modeler.stride_engine import STRIDEThreatEngine
from stride_modeler.dora_mitigations import DORA_MITIGATION_CATALOG, get_mitigations_for_category
from stride_modeler.dashboard_generator import STRIDEDashboardGenerator
from stride_modeler.storage import AssessmentStorage, ConcurrencyConflictError
from stride_modeler.state_machine import AssessmentStateMachine
from stride_modeler.evaluator import STRIDEEvaluatorEngine

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {
    "name": "stride-threat-modeler-mcp",
    "version": "2.0.0"
}

MAX_OUTPUT_BYTES = 50000

# Shared state engine instance (uses assessments.db in working dir or default)
_storage = AssessmentStorage()
_evaluator = STRIDEEvaluatorEngine()
_state_machine = AssessmentStateMachine(storage=_storage, evaluator=_evaluator)

TOOLS = [
    # -------------------------------------------------------------------------
    # STATEFUL ASSESSMENT ENGINE TOOLS (Phase 2 & 3)
    # -------------------------------------------------------------------------
    {
        "name": "start_assessment",
        "description": "Starts a new threat assessment with persistent state, human-readable ID (e.g. TM-001), and initial rev=1. Depth can be 'quick' (10-15 questions), 'standard' (30-50 questions), or 'deep'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "naam": {"type": "string", "description": "Name of the target system (e.g. 'Customer Payment API')"},
                "depth": {"type": "string", "enum": ["quick", "standard", "deep"], "default": "quick"},
                "methodology": {"type": "string", "enum": ["stride", "linddun", "agentic"], "default": "stride"},
                "unacceptable_outcomes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Three catastrophic outcomes anchored during scoping that must never happen"
                }
            },
            "required": ["naam"]
        }
    },
    {
        "name": "get_next_step",
        "description": "Retrieves the single next question or step in the assessment. Fails closed: an unanswered question never defaults to a favorable assumption. Returns step payload with 'steptype' (relay/interpret/rate), 'resterend', and 'rev'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string", "description": "Assessment ID (e.g. 'TM-001')"}
            },
            "required": ["assessment_id"]
        }
    },
    {
        "name": "submit_answer",
        "description": "Submits the choice for the current question, extracts and stores normalized facts in SQLite, and advances the assessment state. Enforces optimistic concurrency via rev.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string", "description": "Assessment ID (e.g. 'TM-001')"},
                "component_id": {"type": "string", "description": "Component ID being assessed"},
                "question_id": {"type": "string", "description": "Question ID answered"},
                "keuze": {"type": "integer", "description": "Option number selected by the user (1-5)"},
                "vrije_tekst": {"type": "string", "description": "Optional free text input for interpret steptype"},
                "rev": {"type": "integer", "description": "Revision number matching get_next_step"}
            },
            "required": ["assessment_id", "component_id", "question_id"]
        }
    },
    {
        "name": "add_component",
        "description": "Adds an architectural component (data_store, process, external_entity, data_flow) to the assessment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"},
                "id": {"type": "string", "description": "Unique component ID within assessment (e.g. 'ds-01', 'proc-api')"},
                "naam": {"type": "string", "description": "Human-friendly component name"},
                "type": {"type": "string", "enum": ["data_store", "process", "external_entity", "data_flow"]},
                "trust_zone": {"type": "string", "default": "Internal"},
                "is_crown_jewel": {"type": "boolean", "default": False},
                "rev": {"type": "integer"}
            },
            "required": ["assessment_id", "id", "naam", "type"]
        }
    },
    {
        "name": "derive_vulnerabilities",
        "description": "Executes the deterministic YAML rule library against stored facts. Derives vulnerabilities with full lineage (source rule, triggering facts, ASVS citations) and calculates scoring proposals.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"}
            },
            "required": ["assessment_id"]
        }
    },
    {
        "name": "get_rating_proposal",
        "description": "Retrieves the objective scoring proposal (Exposure 1-5, Impact 1-5, Risk Level, and rationale) derived from facts for a specific vulnerability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"},
                "vulnerability_id": {"type": "string"}
            },
            "required": ["assessment_id", "vulnerability_id"]
        }
    },
    {
        "name": "set_rating",
        "description": "Records the final risk rating. Enforces mandatory motivation when deviating from the proposal or when selecting treatment 'Accept'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"},
                "vulnerability_id": {"type": "string"},
                "exposure": {"type": "integer", "minimum": 1, "maximum": 5},
                "impact": {"type": "integer", "minimum": 1, "maximum": 5},
                "risk_level": {"type": "string", "enum": ["Laag", "Midden", "Hoog", "Kritiek"]},
                "motivatie": {"type": "string", "description": "Mandatory when deviating from proposal or when accepting risk"},
                "treatment": {"type": "string", "enum": ["Mitigate", "Transfer", "Accept", "Eliminate"], "default": "Mitigate"},
                "eigenaar": {"type": "string", "description": "Risk owner"},
                "besluit": {"type": "string", "description": "Formal decision (Design change / Accepted risk / Postponed)"},
                "rev": {"type": "integer"}
            },
            "required": ["assessment_id", "vulnerability_id", "exposure", "impact", "risk_level"]
        }
    },
    {
        "name": "add_llm_finding",
        "description": "Proposes an AI-suggested composite abuse finding (llm_suggested). Remains in status 'voorgesteld' until explicitly confirmed into the register.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"},
                "component_id": {"type": "string"},
                "stride_categorie": {"type": "string"},
                "titel": {"type": "string"},
                "toelichting": {"type": "string"},
                "model": {"type": "string", "default": "claude-sonnet-5"}
            },
            "required": ["assessment_id", "component_id", "stride_categorie", "titel"]
        }
    },
    {
        "name": "confirm_finding",
        "description": "Confirms an AI-suggested candidate vulnerability into the official risk register.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"},
                "vulnerability_id": {"type": "string"},
                "rev": {"type": "integer"}
            },
            "required": ["assessment_id", "vulnerability_id"]
        }
    },
    {
        "name": "check_completeness",
        "description": "Returns a completeness audit of the assessment across scoping, elicitatie, and rating phases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"}
            },
            "required": ["assessment_id"]
        }
    },
    {
        "name": "get_assessment",
        "description": "Retrieves the complete state of an assessment in compact, capped JSON format.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"}
            },
            "required": ["assessment_id"]
        }
    },
    {
        "name": "get_risk_matrix",
        "description": "Returns the 5x5 matrix distribution of evaluated threats across Exposure and Impact.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_id": {"type": "string"}
            },
            "required": ["assessment_id"]
        }
    },
    {
        "name": "get_mitigation_catalog",
        "description": "Returns the complete DORA & NIST CSF 2.0 / ISO 27001:2022 mitigation catalog by reference to avoid inline repetition.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    # -------------------------------------------------------------------------
    # LEGACY / BATCH COMPATIBILITY TOOLS
    # -------------------------------------------------------------------------
    {
        "name": "generate_stride_threat_model",
        "description": "Generates a batch STRIDE threat model from a static list of components and data flows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "system_name": {"type": "string"},
                "components": {"type": "array"},
                "data_flows": {"type": "array", "default": []}
            },
            "required": ["system_name", "components"]
        }
    },
    {
        "name": "suggest_dora_mitigations",
        "description": "Retrieves specialized DORA ICT resilience and NIST CSF 2.0 mitigations for specific STRIDE threat categories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": [
                        "Spoofing", "Tampering", "Repudiation",
                        "Information Disclosure", "Denial of Service", "Elevation of Privilege"
                    ]
                }
            },
            "required": ["category"]
        }
    },
    {
        "name": "generate_threat_model_html_report",
        "description": "Generates a full interactive HTML threat modeling dashboard report with STRIDE risk metrics and DORA mappings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "system_name": {"type": "string"},
                "components": {"type": "array"},
                "data_flows": {"type": "array", "default": []},
                "output_path": {"type": "string"}
            },
            "required": ["system_name", "components"]
        }
    }
]


def _compact_json(obj: Any) -> str:
    """Formats JSON compactly with separators=(',', ':') to honor output budget."""
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    if len(raw) > MAX_OUTPUT_BYTES:
        return raw[:MAX_OUTPUT_BYTES] + '..."[TRUNCATED: Output budget reached]"}'
    return raw


def handle_request(req):
    if not isinstance(req, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: root payload must be a JSON object"}
        }

    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if not isinstance(method, str):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid Request: 'method' must be a string"}
        }

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO
            }
        }
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS}
        }
    elif method == "tools/call":
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: expected object"}}
        tool_name = params.get("name")
        args = params.get("arguments", {}) or {}

        try:
            # 1. start_assessment
            if tool_name == "start_assessment":
                naam = args.get("naam")
                depth = args.get("depth", "quick")
                methodology = args.get("methodology", "stride")
                unacceptable_outcomes = args.get("unacceptable_outcomes")
                res = _state_machine.start_assessment(
                    naam=naam,
                    depth=depth,
                    methodology=methodology,
                    unacceptable_outcomes=unacceptable_outcomes
                )
                step = _state_machine.get_next_step(res["id"])
                out = {"assessment": res, "next_step": step}
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(out)}], "isError": False}}

            # 2. get_next_step
            elif tool_name == "get_next_step":
                aid = args.get("assessment_id")
                step = _state_machine.get_next_step(aid)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(step)}], "isError": False}}

            # 3. submit_answer
            elif tool_name == "submit_answer":
                aid = args.get("assessment_id")
                cid = args.get("component_id")
                qid = args.get("question_id")
                keuze = args.get("keuze")
                vrije_tekst = args.get("vrije_tekst")
                rev = args.get("rev")
                step = _state_machine.submit_answer(
                    assessment_id=aid,
                    component_id=cid,
                    question_id=qid,
                    choice_nr=keuze,
                    free_text=vrije_tekst,
                    rev=rev
                )
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(step)}], "isError": False}}

            # 4. add_component
            elif tool_name == "add_component":
                aid = args.get("assessment_id")
                cid = args.get("id")
                naam = args.get("naam")
                ctype = args.get("type")
                tzone = args.get("trust_zone", "Internal")
                crown = bool(args.get("is_crown_jewel", False))
                rev = args.get("rev")
                res = _storage.add_component(aid, cid, naam, ctype, tzone, crown, rev=rev)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(res)}], "isError": False}}

            # 5. derive_vulnerabilities
            elif tool_name == "derive_vulnerabilities":
                aid = args.get("assessment_id")
                vulns = _state_machine.derive_and_save_vulnerabilities(aid)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json({"derived_count": len(vulns), "vulnerabilities": vulns})}], "isError": False}}

            # 6. get_rating_proposal
            elif tool_name == "get_rating_proposal":
                aid = args.get("assessment_id")
                vid = args.get("vulnerability_id")
                vulns = _storage.get_vulnerabilities(aid)
                v = next((item for item in vulns if item["id"] == vid), None)
                if not v:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Vulnerability {vid} niet gevonden"}}
                proposal = {
                    "vulnerability_id": vid,
                    "titel": v["titel"],
                    "stride_categorie": v["stride_categorie"],
                    "exposure_voorstel": v["exposure_voorstel"],
                    "impact_voorstel": v["impact_voorstel"],
                    "risk_level_voorstel": v["risk_level_voorstel"],
                    "scoring_rationale": v.get("scoring_rationale", "")
                }
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(proposal)}], "isError": False}}

            # 7. set_rating
            elif tool_name == "set_rating":
                aid = args.get("assessment_id")
                vid = args.get("vulnerability_id")
                exp = args.get("exposure")
                imp = args.get("impact")
                rlvl = args.get("risk_level")
                mot = args.get("motivatie")
                treat = args.get("treatment", "Mitigate")
                own = args.get("eigenaar")
                bes = args.get("besluit")
                rev = args.get("rev")
                res = _storage.set_rating(
                    assessment_id=aid,
                    vuln_id=vid,
                    exposure=exp,
                    impact=imp,
                    risk_level=rlvl,
                    motivatie=mot,
                    treatment=treat,
                    eigenaar=own,
                    besluit=bes,
                    rev=rev
                )
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(res)}], "isError": False}}

            # 8. add_llm_finding
            elif tool_name == "add_llm_finding":
                aid = args.get("assessment_id")
                cid = args.get("component_id")
                cat = args.get("stride_categorie")
                titel = args.get("titel")
                toel = args.get("toelichting", "")
                model = args.get("model", "claude-sonnet-5")
                vuln_id = _evaluator.generate_threat_id(cid, cat, "LLM-SUGGESTED")
                v_entry = [{
                    "id": vuln_id,
                    "component_id": cid,
                    "titel": titel,
                    "toelichting": toel,
                    "stride_categorie": cat,
                    "bron_regel": "LLM-MISBRUIKSCENARIO",
                    "bron_referentie": f"Model {model}",
                    "herkomst": "llm_suggested",
                    "status": "voorgesteld",
                    "exposure_voorstel": 3,
                    "impact_voorstel": 4,
                    "risk_level_voorstel": "Hoog",
                    "scoring_rationale": "Voorgesteld door LLM redenering over misbruikketen"
                }]
                _storage.save_vulnerabilities(aid, v_entry)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json({"vulnerability_id": vuln_id, "status": "voorgesteld"})}], "isError": False}}

            # 9. confirm_finding
            elif tool_name == "confirm_finding":
                aid = args.get("assessment_id")
                vid = args.get("vulnerability_id")
                with _storage._get_connection() as conn:
                    conn.execute("UPDATE vulnerabilities SET status = 'actief' WHERE id = ? AND assessment_id = ?", (vid, aid))
                    conn.commit()
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json({"vulnerability_id": vid, "status": "actief"})}], "isError": False}}

            # 10. check_completeness
            elif tool_name == "check_completeness":
                aid = args.get("assessment_id")
                audit = _state_machine.check_completeness(aid)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(audit)}], "isError": False}}

            # 11. get_assessment
            elif tool_name == "get_assessment":
                aid = args.get("assessment_id")
                a = _storage.get_assessment(aid)
                if not a:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Assessment {aid} niet gevonden"}}
                comps = _storage.get_components(aid)
                vulns = _storage.get_vulnerabilities(aid)
                ratings = {}
                with _storage._get_connection() as conn:
                    for r in conn.execute("SELECT * FROM ratings WHERE assessment_id = ?", (aid,)).fetchall():
                        ratings[r["vulnerability_id"]] = dict(r)
                out = {"assessment": a, "components": comps, "vulnerabilities": vulns, "ratings": ratings}
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(out)}], "isError": False}}

            # 12. get_risk_matrix
            elif tool_name == "get_risk_matrix":
                aid = args.get("assessment_id")
                with _storage._get_connection() as conn:
                    cursor = conn.execute("SELECT risk_level FROM ratings WHERE assessment_id = ?", (aid,))
                    levels = [r["risk_level"] for r in cursor.fetchall()]
                matrix_summary = {"Kritiek": 0, "Hoog": 0, "Midden": 0, "Laag": 0}
                for lvl in levels:
                    if lvl in matrix_summary:
                        matrix_summary[lvl] += 1
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(matrix_summary)}], "isError": False}}

            # 13. get_mitigation_catalog
            elif tool_name == "get_mitigation_catalog":
                catalog = {}
                for cat_enum, mits in DORA_MITIGATION_CATALOG.items():
                    catalog[cat_enum.value] = [m.model_dump() for m in mits]
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(catalog)}], "isError": False}}

            # -----------------------------------------------------------------
            # LEGACY TOOLS
            # -----------------------------------------------------------------
            elif tool_name == "generate_stride_threat_model":
                system_name = args.get("system_name")
                if not system_name or not isinstance(system_name, str) or not system_name.strip():
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'system_name' is required and must be a non-empty string"}}
                raw_components = args.get("components", [])
                raw_flows = args.get("data_flows", [])
                engine = STRIDEThreatEngine()
                for c in raw_components:
                    comp_type = ComponentType(c.get("type", "process"))
                    engine.add_component(Component(
                        id=str(c.get("id")),
                        name=str(c.get("name")),
                        type=comp_type,
                        trust_zone=c.get("trust_zone", "Internal"),
                        is_crown_jewel=bool(c.get("is_crown_jewel", False))
                    ))
                for f in raw_flows:
                    engine.add_data_flow(DataFlow(
                        id=str(f.get("id")),
                        source_id=str(f.get("source_id")),
                        target_id=str(f.get("target_id")),
                        protocol=f.get("protocol", "HTTPS"),
                        crosses_trust_boundary=bool(f.get("crosses_trust_boundary", False)),
                        data_classification=f.get("data_classification", "Confidential")
                    ))
                report = engine.generate_full_model(system_name)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json(report.model_dump())}], "isError": False}}

            elif tool_name == "suggest_dora_mitigations":
                category = args.get("category")
                cat_enum = None
                for c in DORA_MITIGATION_CATALOG.keys():
                    if c.value.lower() == str(category).lower() or c.name.lower() == str(category).lower():
                        cat_enum = c
                        break
                if not cat_enum:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown category: {category}"}}
                mits = get_mitigations_for_category(cat_enum)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": _compact_json({"category": cat_enum.value, "mitigations": [m.model_dump() for m in mits]})}], "isError": False}}

            elif tool_name == "generate_threat_model_html_report":
                system_name = args.get("system_name", "System")
                raw_components = args.get("components", [])
                raw_flows = args.get("data_flows", [])
                output_path = args.get("output_path")
                engine = STRIDEThreatEngine()
                for c in raw_components:
                    comp_type = ComponentType(c.get("type", "process"))
                    engine.add_component(Component(id=str(c.get("id")), name=str(c.get("name")), type=comp_type))
                for f in raw_flows:
                    engine.add_data_flow(DataFlow(id=str(f.get("id")), source_id=str(f.get("source_id")), target_id=str(f.get("target_id"))))
                report = engine.generate_full_model(system_name)
                html_out = STRIDEDashboardGenerator.generate_html(report, output_path)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"HTML report generated for {system_name}"}], "html": html_out[:500] + "...", "isError": False}}

            else:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}

        except ConcurrencyConflictError as cce:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": f"Concurrency Conflict: {str(cce)}"}}
        except ValueError as ve:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": str(ve)}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"Internal error: {str(e)}"}}

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = handle_request(req)
            if res is not None:
                sys.stdout.write(json.dumps(res, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error: Invalid JSON"}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
        except Exception as ex:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "Internal process error"}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
