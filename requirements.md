# STRIDE Threat Modelling Assessment Tool - Requirements

**Version**: 1.0  
**Focus**: Execution of threat modelling assessments (recording, analyzing, documenting)

---

## Functional Requirements

### Visual Diagramming Capabilities
- Create architectural diagrams (Data Flow Diagrams)
- Support: data flows, data stores, processes, interactors, trust boundaries

### Model-as-Code Generation
- Create threat models programmatically via text or declarative markup
- Support automation and version control

### Multi-Methodology Support
- STRIDE (primary for MVP)
- Support for LINDDUN, PASTA, DREAD (future)

### Automated Threat Elicitation Engine
- Rule-based engine to identify and categorize threats
- Suggest mitigations based on architecture

### Predefined Risk Templates
- Built-in templates for common technologies and compliance needs

### Questionnaire-Based Risk Assessment
- Dynamic questionnaires for technical and compliance details
- Auto-generate vulnerabilities and mitigation tasks

### Risk Scoring and Prioritization
- Likelihood × Impact scoring
- Support CVSSv3 or custom ratings
- Priority levels (Trivial, Minor, Major, Critical)

### Mitigation Strategy Management
- Capture mitigation decisions
- Risk treatment classification: Transfer, Accept, Mitigate, Eliminate

### IT Issue Tracker Integration
- Export findings to Jira, Azure Boards, etc.
- Track remediation status

### Automated Security Tool Correlation
- Correlate threat models with DAST/SAST findings (OWASP ZAP, DefectDojo, etc.)

### Comprehensive Reporting and Exporting
- PDF, HTML, CSV export
- Full model, threats, risk scores, mitigation status

### Data Interoperability
- Support TM-BOM (Threat Model Bill of Materials) for import/export

---

## Non-Functional Requirements

- **Cross-Team Collaboration**: Real-time or async collaboration
- **CI/CD Pipeline Automation**: CLI/API support for automated validation
- **Developer-Centric Usability**: Support for Rapid Developer-Driven Threat Modeling (RaD-TM)
- **Traceability and Auditability**: Full audit trail of security decisions
- **Strict Access Control and Security**: Role-based access control
- **Living Document Lifecycle Management**: Auto-prompt for reviews on architectural changes
- **Compliance and Standards Alignment**: Map to OWASP ASVS, NIST 800-53
- **Highly Customizable Risk Frameworks**: Custom threat categories, asset classification, risk formulas

---

**Status**: Based on uploaded requirements document (May 2026)