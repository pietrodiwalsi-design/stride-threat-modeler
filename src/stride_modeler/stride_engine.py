"""
Core STRIDE Threat Modeling Engine with Continuous Threat Modeling workflow.
"""

from typing import List, Dict, Any, Optional
import uuid
from stride_modeler.models import (
    Component, ComponentType, DataFlow, Threat, Mitigation,
    STRIDECategory, RiskLevel, ThreatModelReport
)
from stride_modeler.dora_mitigations import get_mitigations_for_category


# Standard STRIDE mapping matrix per component type
# Process: S, T, R, I, D, E
# Data Store: T, R, I, D
# Data Flow: T, I, D
# External Entity: S, R
STRIDE_APPLICABILITY: Dict[ComponentType, List[STRIDECategory]] = {
    ComponentType.PROCESS: [
        STRIDECategory.SPOOFING,
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
        STRIDECategory.ELEVATION_OF_PRIVILEGE,
    ],
    ComponentType.DATA_STORE: [
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
    ],
    ComponentType.DATA_FLOW: [
        STRIDECategory.TAMPERING,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
    ],
    ComponentType.EXTERNAL_ENTITY: [
        STRIDECategory.SPOOFING,
        STRIDECategory.REPUDIATION,
    ],
}


class STRIDEThreatEngine:
    """
    Continuous STRIDE Threat Modeling Engine.
    Implements 4 fundamental questions:
    1. What are we working on? (Components & Data Flows)
    2. What can go wrong? (STRIDE Threat Generation)
    3. What are we going to do about it? (DORA & NIST Mitigations)
    4. Did we do a good enough job? (Coverage & Risk Scoring)
    """

    def __init__(self):
        self.components: Dict[str, Component] = {}
        self.data_flows: Dict[str, DataFlow] = {}

    def add_component(self, component: Component) -> None:
        self.components[component.id] = component

    def add_data_flow(self, flow: DataFlow) -> None:
        self.data_flows[flow.id] = flow

    def evaluate_component_threats(self, component: Component) -> List[Threat]:
        threats: List[Threat] = []
        applicable_categories = STRIDE_APPLICABILITY.get(component.type, [])

        for cat in applicable_categories:
            threat_id = f"THR-{component.id[:8]}-{cat.name[:3]}-{uuid.uuid4().hex[:4].upper()}"
            title = f"{cat.value} Threat on {component.name}"
            
            # Base likelihood & impact
            likelihood = 3
            impact = 3
            if component.is_crown_jewel:
                impact = 5
            if component.trust_zone.lower() in ["dmz", "public", "internet", "external"]:
                likelihood = 4
            
            # Specific category descriptions
            desc = self._get_threat_description(cat, component)
            risk_score = likelihood * impact
            risk_lvl = self._calculate_risk_level(risk_score)
            mitigations = get_mitigations_for_category(cat)
            
            dora_articles = [
                m.framework_mapping.get("DORA", "").split(" - ")[0]
                for m in mitigations if "DORA" in m.framework_mapping
            ]

            threats.append(Threat(
                id=threat_id,
                category=cat,
                target_id=component.id,
                target_name=component.name,
                title=title,
                description=desc,
                likelihood=likelihood,
                impact=impact,
                risk_score=risk_score,
                risk_level=risk_lvl,
                mitigations=mitigations,
                dora_articles=dora_articles
            ))

        return threats

    def evaluate_data_flow_threats(self, flow: DataFlow) -> List[Threat]:
        threats: List[Threat] = []
        applicable_categories = STRIDE_APPLICABILITY.get(ComponentType.DATA_FLOW, [])

        source = self.components.get(flow.source_id)
        target = self.components.get(flow.target_id)
        source_name = source.name if source else flow.source_id
        target_name = target.name if target else flow.target_id
        flow_label = f"Flow {source_name} -> {target_name}"

        for cat in applicable_categories:
            threat_id = f"THR-FLOW-{flow.id[:8]}-{cat.name[:3]}-{uuid.uuid4().hex[:4].upper()}"
            title = f"{cat.value} on {flow_label}"
            
            likelihood = 3
            impact = 3
            if flow.crosses_trust_boundary:
                likelihood = 4
                impact = 4
            if flow.data_classification.lower() in ["secret", "restricted", "confidential"]:
                impact = max(impact, 4)

            desc = f"{cat.value} risk affecting transit stream ({flow.protocol}) between {source_name} and {target_name}."
            risk_score = likelihood * impact
            risk_lvl = self._calculate_risk_level(risk_score)
            mitigations = get_mitigations_for_category(cat)
            
            dora_articles = [
                m.framework_mapping.get("DORA", "").split(" - ")[0]
                for m in mitigations if "DORA" in m.framework_mapping
            ]

            threats.append(Threat(
                id=threat_id,
                category=cat,
                target_id=flow.id,
                target_name=flow_label,
                title=title,
                description=desc,
                likelihood=likelihood,
                impact=impact,
                risk_score=risk_score,
                risk_level=risk_lvl,
                mitigations=mitigations,
                dora_articles=dora_articles
            ))

        return threats

    def generate_full_model(self, system_name: str) -> ThreatModelReport:
        all_threats: List[Threat] = []

        for comp in self.components.values():
            all_threats.extend(self.evaluate_component_threats(comp))

        for flow in self.data_flows.values():
            all_threats.extend(self.evaluate_data_flow_threats(flow))

        # Risk distribution summary
        risk_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        stride_dist = {cat.value: 0 for cat in STRIDECategory}

        for t in all_threats:
            risk_summary[t.risk_level.value] += 1
            stride_dist[t.category.value] += 1

        crown_jewels = [c.name for c in self.components.values() if c.is_crown_jewel]

        # Calculate DORA resilience coverage (percentage of threats with >=1 mapped DORA control)
        covered_count = sum(1 for t in all_threats if t.dora_articles)
        dora_coverage = (covered_count / len(all_threats) * 100.0) if all_threats else 100.0

        return ThreatModelReport(
            system_name=system_name,
            version="1.0.0",
            assessor="OpenClaw STRIDE Engine",
            components_count=len(self.components),
            data_flows_count=len(self.data_flows),
            threats_count=len(all_threats),
            risk_summary=risk_summary,
            stride_distribution=stride_dist,
            crown_jewels=crown_jewels,
            threats=all_threats,
            dora_resilience_coverage=round(dora_coverage, 1)
        )

    def _calculate_risk_level(self, score: int) -> RiskLevel:
        if score >= 20:
            return RiskLevel.CRITICAL
        elif score >= 15:
            return RiskLevel.HIGH
        elif score >= 8:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _get_threat_description(self, cat: STRIDECategory, comp: Component) -> str:
        templates = {
            STRIDECategory.SPOOFING: f"An unauthorized actor or malicious entity impersonates {comp.name} ({comp.type.value}) to bypass authentication boundaries.",
            STRIDECategory.TAMPERING: f"Malicious modification of data, parameters, or internal state of {comp.name} leading to integrity loss.",
            STRIDECategory.REPUDIATION: f"Lack of non-repudiable audit trails for operations performed by or on {comp.name}.",
            STRIDECategory.INFORMATION_DISCLOSURE: f"Unauthorized data leakage or eavesdropping on confidential state stored/processed in {comp.name}.",
            STRIDECategory.DENIAL_OF_SERVICE: f"Resource exhaustion or algorithmic attack causing {comp.name} to degrade or become unavailable.",
            STRIDECategory.ELEVATION_OF_PRIVILEGE: f"Exploitation of vulnerabilities or misconfigurations in {comp.name} to execute actions with higher privileges."
        }
        return templates.get(cat, f"Generic {cat.value} threat against {comp.name}.")
