# Threat Model Assessment Tool - Development Plan

## 1. MVP Scope (v1.0)

### Core Features
- Create new threat model (name, description, scope)
- Define system components (name, type, description, trust level)
- Define data flows between components
- Methodology selector: STRIDE, LINDDUN, DREAD, PASTA, RaD-TM, Hybrid
- Per component: guided assessment using selected methodology
- Record threats with: description, category (per chosen model), likelihood, impact, notes/evidence
- Dual scoring: Qualitative (Likelihood × Impact) + DREAD quantitative
- Visual threat heat map (Likelihood vs Impact matrix)
- Mitigation field per threat + status
- Export: Full threat register (CSV + JSON)
- Export: Summary report (Markdown / PDF) with multi-model support

### Nice to Have in MVP (if time allows)
- Side-by-side STRIDE vs LINDDUN comparison view
- Pre-filled example threats per methodology
- Simple data flow diagram visualization

## 2. Data Model (Simplified)

- **ThreatModel**
  - id, name, description, selectedMethodologies, createdAt, updatedAt
- **Component**
  - id, modelId, name, type, description, trustBoundary
- **DataFlow**
  - id, modelId, fromComponent, toComponent, dataType
- **Threat**
  - id, componentId, methodology, category, description, likelihood, impact, dreadDamage, dreadReproducibility, dreadExploitability, dreadAffectedUsers, dreadDiscoverability, evidence, mitigation, status, createdAt

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
3. Multi-methodology selector + assessment interface
4. Threat recording + status tracking
5. Risk scoring + visual heat map
6. Export functionality (CSV/JSON + professional PDF)
7. Presentation polish + demo data

## 6. Presentation Polish (Senior Management Ready)

These items are prioritized to make the tool look credible and impressive in a 10-15 minute demo:

- Pre-loaded realistic demo model (e.g. Insurance Core System or Digital Banking Platform)
- Executive summary page in PDF report (1-pager for senior audience)
- High-contrast, readable threat heat map with clear risk quadrants
- Side-by-side methodology comparison view (STRIDE vs LINDDUN)
- Clean, professional PDF report template with logo placeholder, risk summary, and prioritized threats
- Strong onboarding / first-run experience with guided tour
- Consistent visual hierarchy, spacing and contrast (Apple-level polish)
- One-click "Export for presentation" that generates a polished PDF + summary slide content

---

**Next**: Execution Plan with tasks and priorities.