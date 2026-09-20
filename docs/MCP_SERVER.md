# STRIDE Threat Modeler — Model Context Protocol (MCP) Server 🛡️🤖

> **Headless Continuous Threat Modeling Engine for AI Assistants (Claude Desktop, Cursor, OpenClaw)**  
> Evaluates systems against STRIDE categories and maps findings to **DORA ICT Resilience** and **NIST CSF 2.0**.

---

## 🎯 Overview

The `stride-threat-modeler` MCP server exposes continuous threat modeling capabilities directly to LLMs. It enables agents to:
1. Deconstruct architectures into components and data flows across trust boundaries.
2. Automatically generate STRIDE threats (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
3. Map threats to DORA Articles (e.g. Art. 9, Art. 11, Art. 12) and NIST CSF 2.0 mitigations.
4. Export standalone interactive HTML dashboards and reports.

---

## 🛠️ MCP Tools Specification

### 1. `generate_stride_threat_model`
Generates a complete STRIDE threat model from a list of components and data flows.
* **Inputs:**
  * `system_name` *(string, required)*: Name of the application or architecture.
  * `components` *(array, required)*: Array of components (`id`, `name`, `type: process|data_store|external_entity`, `trust_zone`, `is_crown_jewel`).
  * `data_flows` *(array, optional)*: Array of flows (`id`, `source_id`, `target_id`, `protocol`, `crosses_trust_boundary`, `data_classification`).
* **Returns:** JSON object containing all identified threats, calculated risk scores (1-25), risk levels (Critical, High, Medium, Low), STRIDE distribution, and DORA resilience coverage %.

### 2. `suggest_dora_mitigations`
Retrieves mapped DORA and NIST CSF 2.0 controls for a specific STRIDE category.
* **Inputs:**
  * `category` *(string, required)*: One of `Spoofing`, `Tampering`, `Repudiation`, `Information Disclosure`, `Denial of Service`, `Elevation of Privilege`.
* **Returns:** List of concrete mitigation controls with regulatory citations.

### 3. `generate_threat_model_html_report`
Produces a self-contained HTML dashboard with metrics, STRIDE breakdown, and mitigation tables.
* **Inputs:** `system_name`, `components`, `data_flows`, `output_path` (optional).
* **Returns:** Confirmation message and rendered HTML snippet.

---

## ⚙️ Configuration & Setup

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "stride-threat-modeler": {
      "command": "python3",
      "args": ["-m", "stride_modeler.mcp_server"],
      "env": {
        "PYTHONPATH": "/root/repos/stride-threat-modeler/src"
      }
    }
  }
}
```

### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "stride-threat-modeler": {
      "command": "python3",
      "args": ["/root/repos/stride-threat-modeler/src/stride_modeler/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/root/repos/stride-threat-modeler/src"
      }
    }
  }
}
```

---

## 🧪 Testing & Verification

Run the full 3-Phase test suite:
```bash
PYTHONPATH=src pytest
```
* **Phase 1:** Core engine & applicability logic (`test_stride_engine.py`)
* **Phase 2:** Complex data flows & boundary crossings (`test_stride_phase2.py`)
* **Phase 3:** MCP protocol & JSON-RPC schema compliance (`test_stride_phase3_hardening.py`)
