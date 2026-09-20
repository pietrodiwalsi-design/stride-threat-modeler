# STRIDE Threat Modeler & MCP Server 🛡️📐

> **Continuous STRIDE Threat Modeling Platform & Model Context Protocol (MCP) Server**  
> Dual-Interface Architecture: Interactive Web/HTML Interface + Headless AI Agent MCP Tools with **DORA ICT Resilience** and **NIST CSF 2.0** mappings.

---

## 🎯 Features & Capabilities

- **Dual-Interface Architecture:**
  - 🖥️ **Interactive Web UI:** Visual modeling and HTML dashboard generation (`index.html` & `dashboard_generator.py`).
  - 🤖 **FastMCP Server:** Headless tools for Claude Desktop, Cursor, and OpenClaw agents (`mcp_server.py`).
- **STRIDE Threat Generation:** Comprehensive coverage across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- **Continuous Threat Modeling:** Enforces the 4 fundamental questions (*What are we working on? What can go wrong? What are we going to do about it? Did we do a good enough job?*).
- **DORA & NIST Mappings:** Out-of-the-box mitigations linked to DORA Art. 9 (Protection & Prevention), Art. 11 (Business Continuity), and Art. 12 (Logging).

---

## 🛠️ MCP Tools

| Tool Name | Description |
| :--- | :--- |
| `generate_stride_threat_model` | Evaluates system components & data flows and calculates risk scores. |
| `suggest_dora_mitigations` | Returns tailored DORA & NIST controls per STRIDE threat category. |
| `generate_threat_model_html_report` | Generates a complete standalone HTML dashboard report. |

---

## 🚀 Quick Start

### Running the MCP Server
```bash
PYTHONPATH=src python3 -m stride_modeler.mcp_server
```

### Running the CLI
```bash
PYTHONPATH=src python3 -m stride_modeler.cli --demo --output-html report.html
```

### Running Tests
```bash
PYTHONPATH=src pytest
```
*All 12 tests across Phase 1, Phase 2, and Phase 3 hardening pass with 100% coverage.*
