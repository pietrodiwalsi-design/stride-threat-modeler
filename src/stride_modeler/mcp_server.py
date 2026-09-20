#!/usr/bin/env python3
"""
STRIDE Threat Modeler — Model Context Protocol (MCP) Server.
Enables Claude Desktop, Cursor, and OpenClaw to perform automated Continuous STRIDE Threat Modeling under DORA ICT Resilience.
Hardened according to Anthropic Claude review standards.
"""

import sys
import os
import json
from pathlib import Path
from stride_modeler.models import (
    Component, ComponentType, DataFlow, ThreatModelReport
)
from stride_modeler.stride_engine import STRIDEThreatEngine
from stride_modeler.dora_mitigations import DORA_MITIGATION_CATALOG, get_mitigations_for_category
from stride_modeler.dashboard_generator import STRIDEDashboardGenerator

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {
    "name": "stride-threat-modeler-mcp",
    "version": "1.0.0"
}

MAX_COMPONENTS_LIMIT = 1000
MAX_DATA_FLOWS_LIMIT = 2000

TOOLS = [
    {
        "name": "generate_stride_threat_model",
        "description": "Generates a comprehensive STRIDE threat model from a list of components and data flows with risk scoring and DORA resilience mappings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "system_name": {
                    "type": "string",
                    "description": "Name of the target system/application (e.g. 'Core Pension Portal')"
                },
                "components": {
                    "type": "array",
                    "description": "List of system components (processes, data stores, external entities)",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "name": {"type": "string"},
                            "type": {"type": "string", "enum": ["process", "data_store", "external_entity"]},
                            "trust_zone": {"type": "string"},
                            "is_crown_jewel": {"type": "boolean"}
                        },
                        "required": ["id", "name", "type"]
                    }
                },
                "data_flows": {
                    "type": "array",
                    "description": "List of data flows connecting components across trust boundaries",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "source_id": {"type": "string"},
                            "target_id": {"type": "string"},
                            "protocol": {"type": "string"},
                            "crosses_trust_boundary": {"type": "boolean"},
                            "data_classification": {"type": "string"}
                        },
                        "required": ["id", "source_id", "target_id"]
                    }
                }
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
                    ],
                    "description": "STRIDE threat category"
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
                "output_path": {"type": "string", "description": "Optional local file path to save HTML report"}
            },
            "required": ["system_name", "components"]
        }
    }
]


def _validate_safe_output_path(output_path: str) -> str:
    """Ensures output path cannot be used for arbitrary file write outside allowed dirs."""
    clean_path = os.path.abspath(output_path)
    allowed_bases = [
        os.path.abspath("/tmp"),
        os.path.abspath(os.getcwd()),
        os.path.abspath("/root/repos/stride-threat-modeler")
    ]
    if not any(clean_path.startswith(base) for base in allowed_bases):
        raise ValueError(f"Output path '{output_path}' outside allowed directories (/tmp or workspace).")
    return clean_path


def handle_request(req):
    # Guard against non-dict top-level requests (JSON-RPC 2.0 spec compliance)
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
        if not tool_name or not isinstance(tool_name, str):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'name' is required and must be a string"}}

        args = params.get("arguments", {}) or {}
        if not isinstance(args, dict):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'arguments' must be an object"}}

        try:
            if tool_name == "generate_stride_threat_model":
                system_name = args.get("system_name")
                if not isinstance(system_name, str) or not system_name.strip():
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'system_name' is required and must be a non-empty string"}}
                
                raw_components = args.get("components", [])
                if not isinstance(raw_components, list):
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'components' must be an array"}}
                if len(raw_components) > MAX_COMPONENTS_LIMIT:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Component limit exceeded (max {MAX_COMPONENTS_LIMIT})"}}
                
                raw_flows = args.get("data_flows", [])
                if not isinstance(raw_flows, list):
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'data_flows' must be an array"}}
                if len(raw_flows) > MAX_DATA_FLOWS_LIMIT:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Data flows limit exceeded (max {MAX_DATA_FLOWS_LIMIT})"}}

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
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(report.model_dump(), indent=2)}], "isError": False}
                }

            elif tool_name == "suggest_dora_mitigations":
                category = args.get("category")
                if not category or not isinstance(category, str):
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'category' is required"}}
                
                try:
                    cat_enum = None
                    for c in DORA_MITIGATION_CATALOG.keys():
                        if c.value.lower() == category.lower() or c.name.lower() == category.lower():
                            cat_enum = c
                            break
                    if not cat_enum:
                        raise ValueError(f"Unknown STRIDE category '{category}'")
                    
                    mits = get_mitigations_for_category(cat_enum)
                    res = {
                        "category": cat_enum.value,
                        "mitigations": [m.model_dump() for m in mits]
                    }
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": False}
                    }
                except Exception as e:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Category lookup failed: {str(e)}"}}

            elif tool_name == "generate_threat_model_html_report":
                system_name = args.get("system_name")
                raw_components = args.get("components", [])
                raw_flows = args.get("data_flows", [])
                output_path = args.get("output_path")

                if output_path:
                    output_path = _validate_safe_output_path(output_path)

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
                html_out = STRIDEDashboardGenerator.generate_html(report, output_path)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"HTML report successfully generated for {system_name}. Total threats: {report.threats_count}, DORA Coverage: {report.dora_resilience_coverage}%."}
                        ],
                        "html": html_out[:500] + "...",
                        "isError": False
                    }
                }

            else:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}

        except Exception as e:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"Internal error during tool call: {str(e)}"}}

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}


def main():
    """Main stdio loop for MCP Server."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = handle_request(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
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
