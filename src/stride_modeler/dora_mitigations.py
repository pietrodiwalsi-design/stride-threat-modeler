"""
DORA & NIST CSF 2.0 / ISO 27001:2022 Mitigations mapping for STRIDE categories.
"""

from typing import Dict, List
from stride_modeler.models import STRIDECategory, Mitigation


DORA_MITIGATION_CATALOG: Dict[STRIDECategory, List[Mitigation]] = {
    STRIDECategory.SPOOFING: [
        Mitigation(
            id="MIT-DORA-AUTH-01",
            title="Enforce Multi-Factor & Cryptographic Authentication",
            description="Require phishing-resistant MFA, TLS client certificates, or OAuth2/OIDC mutual authentication for all entities.",
            framework_mapping={
                "DORA": "Art. 9(2) - Identification & Authentication Controls",
                "NIST_CSF": "PR.AA-01 / PR.AA-05",
                "ISO27001": "A.8.5"
            },
            status="Open"
        ),
        Mitigation(
            id="MIT-DORA-AUTH-02",
            title="Strict Identity Federation & Token Validation",
            description="Validate JWT signatures, claims, expiry, and issuer across trust boundaries.",
            framework_mapping={
                "DORA": "Art. 9(2) - Access Rights & Identity Management",
                "NIST_CSF": "PR.AA-02",
                "ISO27001": "A.8.5"
            },
            status="Open"
        )
    ],
    STRIDECategory.TAMPERING: [
        Mitigation(
            id="MIT-DORA-INT-01",
            title="Cryptographic Integrity Controls & HMAC Signatures",
            description="Use SHA-256/SHA-512 HMAC signatures or digital signatures on transit data and storage payloads.",
            framework_mapping={
                "DORA": "Art. 9(4)(b) - Data Integrity & Cryptographic Protection",
                "NIST_CSF": "PR.DS-01 / PR.DS-02",
                "ISO27001": "A.8.24"
            },
            status="Open"
        ),
        Mitigation(
            id="MIT-DORA-INT-02",
            title="Immutable Audit Logging & File Integrity Monitoring (FIM)",
            description="Employ write-once-read-many (WORM) storage and runtime FIM for sensitive code and configurations.",
            framework_mapping={
                "DORA": "Art. 10(2)-(3), plus art. 9(4)(b)",
                "NIST_CSF": "PR.PS-04 / DE.CM-01",
                "ISO27001": "A.8.15"
            },
            status="Open"
        )
    ],
    STRIDECategory.REPUDIATION: [
        Mitigation(
            id="MIT-DORA-NONREP-01",
            title="Centralized Non-Repudiation Audit Logs with NTP Sync",
            description="Sign and timestamp transactions with synchronized Stratum-1 time servers to ensure non-repudiation.",
            framework_mapping={
                "DORA": "Art. 10(3), plus art. 17(1)",
                "NIST_CSF": "PR.PS-04 / DE.AE-03",
                "ISO27001": "A.8.17"
            },
            status="Open"
        )
    ],
    STRIDECategory.INFORMATION_DISCLOSURE: [
        Mitigation(
            id="MIT-DORA-CONF-01",
            title="End-to-End TLS 1.3 & AES-256-GCM Encryption",
            description="Mandate TLS 1.3 in transit and AES-256-GCM at rest with hardware security module (HSM) managed keys.",
            framework_mapping={
                "DORA": "Art. 9(4)(c) - Encryption of Data in Transit and at Rest",
                "NIST_CSF": "PR.DS-01 / PR.DS-02",
                "ISO27001": "A.8.24"
            },
            status="Open"
        ),
        Mitigation(
            id="MIT-DORA-CONF-02",
            title="Zero Trust Data Loss Prevention & API Masking",
            description="Implement payload redaction, PII tokenization, and strict API output filtering.",
            framework_mapping={
                "DORA": "Art. 9(4)(a) - Data Protection & Access Segregation",
                "NIST_CSF": "PR.DS-05",
                "ISO27001": "A.5.14"
            },
            status="Open"
        )
    ],
    STRIDECategory.DENIAL_OF_SERVICE: [
        Mitigation(
            id="MIT-DORA-RES-01",
            title="High Availability, Auto-Scaling & Rate Limiting",
            description="Deploy multi-AZ active-active failover, token-bucket rate limiters, and DDoS scrubbing centers.",
            framework_mapping={
                "DORA": "Art. 11(1) - ICT Business Continuity Policy & Resiliency",
                "NIST_CSF": "PR.IR-01 / PR.PS-02",
                "ISO27001": "A.5.29 / A.5.30"
            },
            status="Open"
        ),
        Mitigation(
            id="MIT-DORA-RES-02",
            title="Circuit Breakers & Graceful Degradation",
            description="Implement timeout thresholds, backoff-retry logic, and queue dead-letter isolation.",
            framework_mapping={
                "DORA": "Art. 11(2) - Redundancy & Capacity Planning",
                "NIST_CSF": "PR.IR-02",
                "ISO27001": "A.8.6"
            },
            status="Open"
        )
    ],
    STRIDECategory.ELEVATION_OF_PRIVILEGE: [
        Mitigation(
            id="MIT-DORA-RBAC-01",
            title="Principle of Least Privilege (PoLP) & RBAC/ABAC",
            description="Enforce granular role-based access control, JIT privilege elevation, and periodic access reviews.",
            framework_mapping={
                "DORA": "Art. 9(1) - Access Control & Privilege Management",
                "NIST_CSF": "PR.AA-05",
                "ISO27001": "A.5.15 / A.8.3"
            },
            status="Open"
        ),
        Mitigation(
            id="MIT-DORA-RBAC-02",
            title="Container Sandboxing & System Call Filtering",
            description="Run processes as unprivileged non-root users with seccomp, AppArmor, or SELinux policies.",
            framework_mapping={
                "DORA": "Art. 9(3) - Secure System Architecture & Isolation",
                "NIST_CSF": "PR.PS-01",
                "ISO27001": "A.8.27"
            },
            status="Open"
        )
    ]
}


def get_mitigations_for_category(category: STRIDECategory) -> List[Mitigation]:
    """Returns deep copies of mitigations to avoid mutating shared global state."""
    raw_list = DORA_MITIGATION_CATALOG.get(category, [])
    return [m.model_copy(deep=True) for m in raw_list]
