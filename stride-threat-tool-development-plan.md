# STRIDE Threat Model Assessment Tool - Development Plan

## 1. MVP Scope (v1.0)

### Core Features
- Create new threat model (name, description, scope)
- Define system components (name, type, description, trust level)
- Define data flows between components
- Per component: structured STRIDE assessment
- Record threats with: description, STRIDE category, likelihood, impact, notes/evidence
- Basic risk scoring (Likelihood × Impact)
- Mitigation field per threat + status
- Export: Full threat register (CSV + JSON)
- Export: Summary report (Markdown / PDF)

### Nice to Have in MVP (if time allows)
- Simple visual overview of components
- Risk matrix visualization
- Pre-filled example threats per STRIDE category

## 2. Data Model (Simplified)

- **ThreatModel**
  - id, name, description, createdAt, updatedAt
- **Component**
  - id, modelId, name, type, description, trustBoundary
- **DataFlow**
  - id, modelId, fromComponent, toComponent, dataType
- **Threat**
  - id, componentId, strideCategory, description, likelihood, impact, evidence, mitigation, status, createdAt

## 3. User Flow (MVP)

1. Create / open threat model
2. Add components
3. (Optional) Add data flows
4. Start assessment mode
5. Go through each component → STRIDE categories
6. Record findings
7. Review & prioritize
8. Export results

## 4. Technical Stack (Proposed)

- Frontend: React + Tailwind (or simpler: vanilla + Tailwind if faster)
- State: LocalStorage + exportable JSON
- PDF export: jsPDF or markdown export
- No backend in v1.0 (pure client-side)

## 5. Development Order

1. Project setup + basic UI structure
2. Threat model + component management
3. STRIDE assessment interface (most important)
4. Threat recording + status tracking
5. Risk scoring + overview
6. Export functionality
7. Polish + testing

---

**Next**: Execution Plan with tasks and priorities.