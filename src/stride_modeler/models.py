"""
Data models for STRIDE Threat Modeler.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, model_validator


class ComponentType(str, Enum):
    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_ENTITY = "external_entity"
    DATA_FLOW = "data_flow"


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Component(BaseModel):
    id: str
    name: str
    type: ComponentType
    trust_zone: str = "Internal"
    description: Optional[str] = None
    is_crown_jewel: bool = False
    attributes: Dict[str, Any] = Field(default_factory=dict)


class DataFlow(BaseModel):
    id: str
    source_id: str
    target_id: str
    protocol: str = "HTTPS"
    crosses_trust_boundary: bool = False
    data_classification: str = "Confidential"
    description: Optional[str] = None


class Mitigation(BaseModel):
    id: str
    title: str
    description: str
    framework_mapping: Dict[str, str] = Field(default_factory=dict) # e.g. {"DORA": "Art. 9(2)", "NIST_CSF": "PR.AC-1"}
    status: str = "Open" # Open, In Progress, Implemented


class Threat(BaseModel):
    id: str
    category: STRIDECategory
    target_id: str
    target_name: str
    title: str
    description: str
    likelihood: int = Field(ge=1, le=5, default=3)
    impact: int = Field(ge=1, le=5, default=3)
    risk_score: int = 9 # likelihood * impact
    risk_level: RiskLevel = RiskLevel.MEDIUM
    mitigations: List[Mitigation] = Field(default_factory=list)
    dora_articles: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_risk(self) -> "Threat":
        self.risk_score = self.likelihood * self.impact
        if self.risk_score >= 20:
            self.risk_level = RiskLevel.CRITICAL
        elif self.risk_score >= 15:
            self.risk_level = RiskLevel.HIGH
        elif self.risk_score >= 8:
            self.risk_level = RiskLevel.MEDIUM
        else:
            self.risk_level = RiskLevel.LOW
        return self


class ThreatModelReport(BaseModel):
    system_name: str
    version: str = "1.0.0"
    assessor: str = "OpenClaw STRIDE Modeler"
    components_count: int
    data_flows_count: int
    threats_count: int
    risk_summary: Dict[str, int]
    stride_distribution: Dict[str, int]
    crown_jewels: List[str]
    threats: List[Threat]
    dora_resilience_coverage: float
