# Threat Model Assessment Tool - Requirements

**Tool Name**: Threat Modeler (working title)  
**Version**: 1.0 MVP  
**Purpose**: Multi-methodology threat modeling tool supporting STRIDE, LINDDUN, PASTA, DREAD, RaD-TM and hybrid approaches for comprehensive security & privacy assessments.

## 1. Core Objective
Support the structured execution of STRIDE threat modeling assessments. Focus on guided recording, analysis and documentation of threats during the assessment process.

## 2. Supported Threat Modeling Methodologies

The tool shall support multiple established methodologies, allowing users to choose or combine frameworks based on assessment focus:

### 2.1 STRIDE (Core Security)
- **S**poofing – Identity impersonation
- **T**ampering – Unauthorized modification of data/code
- **R**epudiation – Denying performed actions
- **I**nformation Disclosure – Unauthorized data exposure
- **D**enial of Service – Availability attacks
- **E**levation of Privilege – Unauthorized access escalation

### 2.2 LINDDUN (Privacy-Focused)
- **L**inkability – Linking data to individuals
- **I**dentifiability – Identifying users from data
- **N**on-repudiation – Undeniable actions
- **D**etectability – Observing data existence
- **D**isclosure of information – Privacy leaks
- **U**nawareness – User unaware of data processing
- **N**on-compliance – Violations of privacy regulations (GDPR, HIPAA, etc.)

### 2.3 PASTA (Risk-Centric, 7-Step)
Process for Attack Simulation and Threat Analysis – integrates business objectives with technical requirements, attacker-centric view.

### 2.4 DREAD (Quantitative Risk Rating)
- **D**amage potential
- **R**eproducibility
- **E**xploitability
- **A**ffected users
- **D**iscoverability

### 2.5 RaD-TM (Rapid Developer-Driven)
Lightweight, feature-focused modeling using predefined risk templates. Ideal for agile/DevSecOps workflows.

### 2.6 Additional Frameworks (Future/Optional)
- CIA Triad
- Cyber Kill Chains
- OCTAVE
- Trike
- VAST

### 2.7 Hybrid & Combined Approaches
- Parallel STRIDE + LINDDUN runs (same data flow model)
- Attacker-centric + Asset-centric + Software-centric perspectives
- Support for hybrid methods (SQUARE, Security Cards, Personae Non Gratae)

### 2.8 Tool Philosophy
- Allow selection of primary methodology per assessment
- Enable side-by-side or sequential use of multiple models
- Standardized organizational language while supporting flexibility
- Reference: OWASP Threat Dragon & ThreatCanvas multi-model support as benchmark

## 3. Functional Requirements (MVP)

### 3.1 System Modeling
- Create and visualize system architecture (data flow diagrams)
- Define components: processes, data stores, external entities, trust boundaries
- Support simple drag-and-drop or form-based component definition
- Reuse the same model abstraction for multiple methodologies (STRIDE + LINDDUN in parallel)

### 3.2 Multi-Model Threat Assessment Execution
- Select primary methodology (or hybrid) per assessment
- Guided assessment per chosen framework:
  - STRIDE: 6 categories
  - LINDDUN: 7 privacy categories
  - DREAD: quantitative scoring per threat
  - PASTA: 7-step risk-centric flow
  - RaD-TM: feature-based rapid templates
- Record findings, evidence and observations directly in the tool
- Pre-filled threat examples per methodology + custom threats
- Status tracking per threat (Identified / Analyzed / Mitigated)

### 3.3 Risk Scoring & Heat Map
- Support both qualitative (Likelihood × Impact) and quantitative (DREAD) rating
- Automatic risk score calculation
- Visual threat heat map: plot threats on Likelihood vs Impact matrix
- Color-coded risk levels with improved contrast and readability

### 3.4 Mitigation Tracking
- Link mitigations/controls to threats
- Track mitigation status (Open / In Progress / Done)
- Suggest common mitigations per methodology/category

### 3.5 Reporting & Export
- Generate threat model report (PDF / Markdown) supporting selected methodologies
- Export threat register (CSV / JSON)
- Summary dashboards: threats per category, risk distribution, heat map view
- Multi-model comparison views (e.g. security vs privacy gaps)

## 4. Non-Functional Requirements
- Simple and fast UI (web-based)
- Works offline after initial load
- Easy to use for non-security experts
- Clear structure following STRIDE methodology strictly

## 5. Scope (MVP)
- Single system / application per model
- Basic data flow diagram support
- STRIDE threat suggestions (not AI-generated yet)
- Local storage of models

## 6. Out of Scope (v1.0)
- Multi-user collaboration
- AI-assisted threat generation
- Integration with code repos or architecture tools
- Advanced attack trees

## 7. Target Users
- Security engineers
- Risk managers
- DevSecOps teams
- External assessors / auditors

---

**Next step?**  
Start building the tool or first refine these requirements?