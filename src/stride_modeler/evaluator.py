"""
Evaluator and Rule Engine for STRIDE Assessment Engine (Phase 1).

Parses YAML question libraries, rules, and 5x5 risk matrix.
Derives vulnerabilities from normalized facts with full traceability,
and calculates scoring proposals (exposure 1-5, impact 1-5, matrix lookup).
"""

import os
import re
import yaml
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set


class RuleEvaluator:
    """Evaluates rule conditions against normalized facts."""

    @staticmethod
    def evaluate_condition(condition_str: str, facts: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluates a condition string such as:
        'direct_access in [privileged_humans, multiple_systems] and change_audit in [none, partial_app_only]'
        or 'execution_privilege == root_admin'.
        Returns (result: bool, triggering_facts: Dict[str, Any]).
        """
        if not condition_str or condition_str.strip() == "":
            return True, {}

        # Split on ' and ' (case-insensitive)
        clauses = re.split(r'\s+and\s+', condition_str, flags=re.IGNORECASE)
        triggering_facts: Dict[str, Any] = {}

        for clause in clauses:
            clause = clause.strip()
            clause_met, fact_key, fact_val = RuleEvaluator._evaluate_single_clause(clause, facts)
            if not clause_met:
                return False, {}
            if fact_key:
                triggering_facts[fact_key] = fact_val

        return True, triggering_facts

    @staticmethod
    def _evaluate_single_clause(clause: str, facts: Dict[str, Any]) -> Tuple[bool, Optional[str], Any]:
        clause = clause.strip()
        
        # Check ' in [...]'
        in_match = re.match(r'^([a-zA-Z0-9_]+)\s+in\s+\[(.*?)\]$', clause)
        if in_match:
            key = in_match.group(1).strip()
            raw_options = in_match.group(2).split(',')
            allowed = [opt.strip().strip("'\"") for opt in raw_options]
            
            fact_val = facts.get(key)
            # Boolean string handling
            if isinstance(fact_val, bool):
                fact_str = "true" if fact_val else "false"
            else:
                fact_str = str(fact_val) if fact_val is not None else "unknown"

            if fact_str in allowed or (fact_val in allowed):
                return True, key, fact_val
            return False, None, None

        # Check ' == '
        eq_match = re.match(r'^([a-zA-Z0-9_]+)\s*==\s*(.+)$', clause)
        if eq_match:
            key = eq_match.group(1).strip()
            target = eq_match.group(2).strip().strip("'\"")
            
            fact_val = facts.get(key)
            if isinstance(fact_val, bool):
                fact_str = "true" if fact_val else "false"
            else:
                fact_str = str(fact_val) if fact_val is not None else "unknown"
                
            if fact_str.lower() == target.lower():
                return True, key, fact_val
            return False, None, None

        # Check ' != '
        neq_match = re.match(r'^([a-zA-Z0-9_]+)\s*!=\s*(.+)$', clause)
        if neq_match:
            key = neq_match.group(1).strip()
            target = neq_match.group(2).strip().strip("'\"")
            
            fact_val = facts.get(key)
            if isinstance(fact_val, bool):
                fact_str = "true" if fact_val else "false"
            else:
                fact_str = str(fact_val) if fact_val is not None else "unknown"

            if fact_str.lower() != target.lower():
                return True, key, fact_val
            return False, None, None

        return False, None, None


class STRIDEEvaluatorEngine:
    """
    Engine that loads YAML questions, rules, and matrix definitions
    to perform deterministic threat derivation and scoring proposals.
    """

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        self.base_dir = base_dir
        self.questions_dir = os.path.join(base_dir, "questions")
        self.rules_path = os.path.join(base_dir, "rules", "stride_rules.yaml")
        self.matrix_path = os.path.join(base_dir, "matrices", "risk_matrix_5x5.yaml")

        self.questions: Dict[str, List[Dict[str, Any]]] = {}
        self.rules: List[Dict[str, Any]] = []
        self.matrix: Dict[int, List[str]] = {}
        self.library_version = "1.0.0"
        self.rules_version = "1.0.0"
        self.matrix_version = "1.0.0"

        self._load_all()

    def _load_all(self):
        # Load Questions
        if os.path.exists(self.questions_dir):
            for fname in os.listdir(self.questions_dir):
                if fname.endswith(".yaml") or fname.endswith(".yml"):
                    ctype = fname.rsplit(".", 1)[0]
                    fpath = os.path.join(self.questions_dir, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if data and "questions" in data:
                            self.questions[ctype] = data["questions"]
                            if "library_version" in data:
                                self.library_version = data["library_version"]

        # Load Rules
        if os.path.exists(self.rules_path):
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    self.rules = data["rules"]
                    if "rules_version" in data:
                        self.rules_version = data["rules_version"]

        # Load Matrix
        if os.path.exists(self.matrix_path):
            with open(self.matrix_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "matrix" in data:
                    self.matrix = {int(k): v for k, v in data["matrix"].items()}
                    if "matrix_version" in data:
                        self.matrix_version = data["matrix_version"]

    def generate_threat_id(self, component_id: str, stride_category: str, rule_id: str) -> str:
        """Deterministische Threat-ID: sha256(component_id + stride + rule_id + lib_ver)[:8]."""
        raw = f"{component_id}:{stride_category}:{rule_id}:{self.library_version}".encode("utf-8")
        return f"THR-{hashlib.sha256(raw).hexdigest()[:8].upper()}"

    def derive_vulnerabilities(
        self,
        component_id: str,
        component_name: str,
        component_type: str,
        facts: Dict[str, Any],
        is_crown_jewel: bool = False,
        unacceptable_outcomes_hit: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Derives vulnerabilities from normalized facts by matching rule conditions.
        """
        vulnerabilities = []

        for rule in self.rules:
            # Check component type if specified
            r_ctype = rule.get("component_type")
            if r_ctype and r_ctype != component_type:
                continue

            cond = rule.get("when", "")
            matches, triggering_facts = RuleEvaluator.evaluate_condition(cond, facts)
            if not matches:
                continue

            stride_cat = rule.get("stride", "Tampering")
            rule_id = rule.get("id", "R-GENERIC")
            threat_id = self.generate_threat_id(component_id, stride_cat, rule_id)
            title_template = rule.get("titel", "Vulnerability in {component}")
            title = title_template.replace("{component}", component_name)

            # Determine status: if rule explicitly has status 'onbekend' or any triggering fact is 'unknown'
            status = rule.get("status", "actief")
            if "unknown" in str(triggering_facts).lower():
                status = "onbekend"

            # Calculate scoring proposal
            scoring = self.calculate_scoring_proposal(
                rule=rule,
                facts=facts,
                is_crown_jewel=is_crown_jewel,
                unacceptable_outcomes_hit=unacceptable_outcomes_hit
            )

            vulnerabilities.append({
                "id": threat_id,
                "component_id": component_id,
                "component_name": component_name,
                "component_type": component_type,
                "titel": title,
                "toelichting": rule.get("toelichting", "").strip(),
                "stride_categorie": stride_cat,
                "bron_regel": rule_id,
                "bron_referentie": rule.get("bron", "NIST / ASVS"),
                "mitigaties": rule.get("mitigaties", []),
                "herkomst": "rule",
                "status": status,
                "triggering_facts": triggering_facts,
                "exposure_voorstel": scoring["exposure"],
                "impact_voorstel": scoring["impact"],
                "risk_level_voorstel": scoring["risk_level"],
                "scoring_rationale": scoring["rationale"]
            })

        return vulnerabilities

    def calculate_scoring_proposal(
        self,
        rule: Dict[str, Any],
        facts: Dict[str, Any],
        is_crown_jewel: bool = False,
        unacceptable_outcomes_hit: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates Exposure (1-5) and Impact (1-5), and performs 5x5 matrix lookup.
        """
        rationale_items = []

        # 1. Base Exposure
        base_exp = rule.get("likelihood_base", 3)
        exposure = base_exp
        rationale_items.append(f"Basis exposure uit regel: {base_exp}")

        # Exposure Modifiers
        net_exp = facts.get("network_exposure")
        if net_exp == "internet_public":
            exposure += 2
            rationale_items.append("Publieke internet-expositie (+2 exposure)")
        elif net_exp == "internet_auth":
            exposure += 1
            rationale_items.append("Geauthenticeerde internet-expositie (+1 exposure)")

        if facts.get("db_auth") in ["shared_secret", "none"]:
            exposure += 1
            rationale_items.append("Gedeeld of afwezig authenticatiegeheim (+1 exposure)")

        if facts.get("direct_access") == "multiple_systems":
            exposure += 1
            rationale_items.append("Directe toegang door meerdere systemen (+1 exposure)")

        if facts.get("entity_auth") == "phishing_resistant_mfa_mtls":
            exposure -= 1
            rationale_items.append("Phishing-resistente MFA/mTLS actief (-1 exposure)")

        if facts.get("execution_privilege") == "root_admin":
            exposure += 1
            rationale_items.append("Proces draait onder root/admin privileges (+1 exposure)")

        # Clamp exposure [1, 5]
        exposure = max(1, min(5, exposure))

        # 2. Impact Calculation
        impact = 2  # Baseline impact
        data_cls = facts.get("data_class")
        if data_cls == "special_category":
            impact += 2
            rationale_items.append("Bijzondere categorie persoonsgegevens (+2 impact)")
        elif data_cls == "pii":
            impact += 1
            rationale_items.append("Reguliere persoonsgegevens PII (+1 impact)")

        if is_crown_jewel or facts.get("is_crown_jewel") is True:
            impact += 1
            rationale_items.append("Component gemarkeerd als Crown Jewel (+1 impact)")

        if unacceptable_outcomes_hit:
            impact += 2
            rationale_items.append("Raakt onaanvaardbare uitkomst uit scoping (+2 impact)")

        if facts.get("availability_need") == "critical_minutes" and rule.get("stride") == "Denial of Service":
            impact += 1
            rationale_items.append("Kritieke procesafhankelijkheid RTO minuten (+1 impact DoS)")

        # Clamp impact [1, 5]
        impact = max(1, min(5, impact))

        # 3. 5x5 Matrix Lookup (Row = Exposure, Col = Impact)
        risk_level = "Midden"
        if exposure in self.matrix:
            col_idx = impact - 1  # 0-indexed list for columns 1-5
            row = self.matrix[exposure]
            if 0 <= col_idx < len(row):
                risk_level = row[col_idx]

        return {
            "exposure": exposure,
            "impact": impact,
            "risk_level": risk_level,
            "rationale": "; ".join(rationale_items)
        }
