"""
State Machine and Step Engine for STRIDE Assessment Engine (Phase 2).

Implements single-step interactive progression (get_next_step / submit_answer),
depth profiles (quick, standard, deep), scoping with unacceptable_outcomes,
and completeness checks.
"""

from typing import Dict, Any, List, Optional
from stride_modeler.storage import AssessmentStorage, ConcurrencyConflictError
from stride_modeler.evaluator import STRIDEEvaluatorEngine, RuleEvaluator


DEPTH_LEVELS = {
    "quick": 1,
    "standard": 2,
    "deep": 3
}


class AssessmentStateMachine:
    """Orchestrates interactive assessment flow, question ordering, and phase transitions."""

    def __init__(self, storage: Optional[AssessmentStorage] = None, evaluator: Optional[STRIDEEvaluatorEngine] = None):
        self.storage = storage or AssessmentStorage()
        self.evaluator = evaluator or STRIDEEvaluatorEngine()

    def start_assessment(
        self,
        naam: str,
        depth: str = "quick",
        methodology: str = "stride",
        unacceptable_outcomes: Optional[List[str]] = None,
        system_component_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Starts a new assessment with initial rev=1.
        For depth=quick, automatically creates a single default component representing the system.
        """
        initial_status = "elicitatie" if (unacceptable_outcomes and len(unacceptable_outcomes) >= 1) else "scoping"

        assessment = self.storage.create_assessment(
            naam=naam,
            methodology=methodology,
            depth=depth,
            unacceptable_outcomes=unacceptable_outcomes,
            status=initial_status
        )
        aid = assessment["id"]

        # If depth is quick or a system component is provided, add default component
        if depth == "quick" or system_component_name:
            cname = system_component_name or naam
            self.storage.add_component(
                assessment_id=aid,
                comp_id="comp-sys-01",
                naam=cname,
                comp_type="data_store",  # Default baseline for system store
                trust_zone="Internal",
                is_crown_jewel=False
            )

        return self.storage.get_assessment(aid)

    def set_scoping_outcomes(self, assessment_id: str, outcomes: List[str], rev: int) -> Dict[str, Any]:
        """Sets the unacceptable outcomes from scoping and transitions status to elicitatie."""
        if not outcomes or len(outcomes) == 0:
            raise ValueError("Minstens één onaanvaardbare uitkomst is vereist voor scoping")

        return self.storage.update_assessment(
            assessment_id=assessment_id,
            rev=rev,
            unacceptable_outcomes=outcomes,
            status="elicitatie"
        )

    def get_applicable_questions_for_component(
        self,
        assessment: Dict[str, Any],
        component: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Returns all questions from the library applicable to this component type,
        filtered by depth profile and conditional 'geldt_voor' expressions.
        """
        ctype = component["type"]
        lib_questions = self.evaluator.questions.get(ctype, [])
        depth_val = DEPTH_LEVELS.get(assessment["depth"], 1)

        facts = self.storage.get_facts(assessment["id"], component["id"])
        applicable = []

        for q in lib_questions:
            # Check depth
            q_depth_str = q.get("depth_min", "quick")
            q_depth_val = DEPTH_LEVELS.get(q_depth_str, 1)
            if q_depth_val > depth_val:
                continue

            # Check condition 'geldt_voor'
            cond = q.get("geldt_voor")
            if cond:
                met, _ = RuleEvaluator.evaluate_condition(cond, facts)
                if not met:
                    continue

            applicable.append(q)

        return applicable

    def get_next_step(self, assessment_id: str) -> Dict[str, Any]:
        """
        Evaluates the current state and returns EXACTLY ONE step to present to the user/client.
        """
        assessment = self.storage.get_assessment(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} niet gevonden")

        status = assessment["status"]
        rev = assessment["rev"]

        # ---------------------------------------------------------
        # FASE 1: SCOPING
        # ---------------------------------------------------------
        if status == "scoping":
            outcomes = assessment.get("unacceptable_outcomes", [])
            if not outcomes or len(outcomes) == 0:
                return {
                    "fase": "scoping",
                    "steptype": "interpret",
                    "assessment_id": assessment_id,
                    "vraag": "Noem drie dingen die met dit systeem NOOIT mogen gebeuren (onaanvaardbare uitkomsten voor impact-verankering):",
                    "instructie": "Geef 1 tot 3 concrete catastrofale incidenten op (bijv. 'Klantgegevens lekken naar derden' of 'Polis uitgegeven zonder betaling').",
                    "resterend": 1,
                    "rev": rev
                }
            else:
                # Auto-transition to elicitatie
                assessment = self.storage.update_assessment(assessment_id, rev, status="elicitatie")
                status = "elicitatie"
                rev = assessment["rev"]

        # ---------------------------------------------------------
        # FASE 2: ELICITATIE (Vragen per component)
        # ---------------------------------------------------------
        if status == "elicitatie":
            components = self.storage.get_components(assessment_id)
            if not components:
                return {
                    "fase": "elicitatie",
                    "steptype": "relay",
                    "assessment_id": assessment_id,
                    "vraag": "Er zijn nog geen componenten toegevoegd aan dit assessment. Voeg een component toe om te starten.",
                    "resterend": 0,
                    "rev": rev
                }

            answers = self.storage.get_answers(assessment_id)
            answered_set = {(a["component_id"], a["question_id"]) for a in answers}

            # Collect total applicable and find first unanswered
            total_applicable = 0
            total_answered = 0
            next_q_tuple = None

            for comp in components:
                app_questions = self.get_applicable_questions_for_component(assessment, comp)
                total_applicable += len(app_questions)
                for q in app_questions:
                    if (comp["id"], q["id"]) in answered_set:
                        total_answered += 1
                    elif next_q_tuple is None:
                        next_q_tuple = (comp, q)

            remaining = total_applicable - total_answered

            if next_q_tuple is not None:
                comp, q = next_q_tuple
                opties_payload = [
                    {"nr": opt["nr"], "label": opt["label"]}
                    for opt in q.get("opties", [])
                ]
                return {
                    "fase": "elicitatie",
                    "steptype": q.get("steptype", "relay"),
                    "assessment_id": assessment_id,
                    "component_id": comp["id"],
                    "component": comp["naam"],
                    "component_type": comp["type"],
                    "question_id": q["id"],
                    "vraag": q["tekst"],
                    "bron": q.get("bron", ""),
                    "opties": opties_payload,
                    "resterend": remaining,
                    "rev": rev
                }

            # All elicitatie questions answered -> auto-advance to afleiding
            assessment = self.storage.update_assessment(assessment_id, rev, status="afleiding")
            status = "afleiding"
            rev = assessment["rev"]

        # ---------------------------------------------------------
        # FASE 3: AFLEIDING (Regels draaien & kwetsbaarheden genereren)
        # ---------------------------------------------------------
        if status == "afleiding":
            self.derive_and_save_vulnerabilities(assessment_id)
            assessment = self.storage.update_assessment(assessment_id, rev, status="beoordeling")
            status = "beoordeling"
            rev = assessment["rev"]

        # ---------------------------------------------------------
        # FASE 4: BEOORDELING (Peter scoort kwetsbaarheden)
        # ---------------------------------------------------------
        if status == "beoordeling":
            vulns = self.storage.get_vulnerabilities(assessment_id)
            with self.storage._get_connection() as conn:
                cursor = conn.execute("SELECT vulnerability_id FROM ratings WHERE assessment_id = ?", (assessment_id,))
                rated_ids = {r["vulnerability_id"] for r in cursor.fetchall()}

            unrated_vulns = [v for v in vulns if v["id"] not in rated_ids]
            if unrated_vulns:
                v = unrated_vulns[0]
                return {
                    "fase": "beoordeling",
                    "steptype": "rate",
                    "assessment_id": assessment_id,
                    "vulnerability_id": v["id"],
                    "component": v.get("component_name", v["component_id"]),
                    "titel": v["titel"],
                    "stride_categorie": v["stride_categorie"],
                    "toelichting": v.get("toelichting", ""),
                    "bron_referentie": v.get("bron_referentie", ""),
                    "status": v.get("status", "actief"),
                    "exposure_voorstel": v["exposure_voorstel"],
                    "impact_voorstel": v["impact_voorstel"],
                    "risk_level_voorstel": v["risk_level_voorstel"],
                    "scoring_rationale": v.get("scoring_rationale", ""),
                    "resterend": len(unrated_vulns),
                    "rev": rev
                }

            # All ratings done -> advance to afgerond
            assessment = self.storage.update_assessment(assessment_id, rev, status="afgerond")
            status = "afgerond"
            rev = assessment["rev"]

        # ---------------------------------------------------------
        # FASE 5: AFGEROND
        # ---------------------------------------------------------
        vulns = self.storage.get_vulnerabilities(assessment_id)
        with self.storage._get_connection() as conn:
            cursor = conn.execute("SELECT risk_level FROM ratings WHERE assessment_id = ?", (assessment_id,))
            levels = [r["risk_level"] for r in cursor.fetchall()]

        matrix_summary = {"Kritiek": 0, "Hoog": 0, "Midden": 0, "Laag": 0}
        for lvl in levels:
            if lvl in matrix_summary:
                matrix_summary[lvl] += 1

        return {
            "fase": "afgerond",
            "steptype": "completed",
            "assessment_id": assessment_id,
            "naam": assessment["naam"],
            "depth": assessment["depth"],
            "totaal_kwetsbaarheden": len(vulns),
            "risico_matrix_telling": matrix_summary,
            "boodschap": "Assessment is volledig doorlopen en beoordeeld. Rapport en export kunnen worden gegenereerd.",
            "rev": rev
        }

    def submit_answer(
        self,
        assessment_id: str,
        component_id: str,
        question_id: str,
        choice_nr: Optional[int] = None,
        free_text: Optional[str] = None,
        rev: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Submits an answer to a question, extracts and stores normalized facts, and returns the next step.
        """
        assessment = self.storage.get_assessment(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} niet gevonden")

        if rev is not None and assessment["rev"] != rev:
            raise ConcurrencyConflictError(
                f"Assessment {assessment_id} is gewijzigd door een andere sessie (huidige rev: {assessment['rev']}, aangeleverd: {rev}). Haal get_next_step opnieuw op."
            )

        # Find question in YAML library to extract facts
        components = {c["id"]: c for c in self.storage.get_components(assessment_id)}
        comp = components.get(component_id)
        if not comp:
            raise ValueError(f"Component {component_id} niet gevonden")

        ctype = comp["type"]
        questions = self.evaluator.questions.get(ctype, [])
        target_q = next((q for q in questions if q["id"] == question_id), None)
        if not target_q:
            raise ValueError(f"Vraag {question_id} niet gevonden in bibliotheek voor {ctype}")

        # Extract facts from chosen option
        facts_to_save: Dict[str, Any] = {}
        if choice_nr is not None:
            opties = target_q.get("opties", [])
            selected_opt = next((opt for opt in opties if opt["nr"] == choice_nr), None)
            if selected_opt and "facts" in selected_opt:
                facts_to_save.update(selected_opt["facts"])

        # Save to storage with rev check
        effective_rev = rev if rev is not None else assessment["rev"]
        updated_assessment = self.storage.save_answer_and_facts(
            assessment_id=assessment_id,
            component_id=component_id,
            question_id=question_id,
            chosen_option=choice_nr,
            free_text=free_text,
            facts=facts_to_save,
            rev=effective_rev
        )

        return self.get_next_step(assessment_id)

    def derive_and_save_vulnerabilities(self, assessment_id: str) -> List[Dict[str, Any]]:
        """Runs the rule evaluator over all facts in the assessment and saves vulnerabilities."""
        assessment = self.storage.get_assessment(assessment_id)
        components = self.storage.get_components(assessment_id)
        all_vulns = []

        unacceptable_outcomes = assessment.get("unacceptable_outcomes", [])
        has_unacceptable_outcomes = len(unacceptable_outcomes) > 0

        for comp in components:
            facts = self.storage.get_facts(assessment_id, comp["id"])
            vulns = self.evaluator.derive_vulnerabilities(
                component_id=comp["id"],
                component_name=comp["naam"],
                component_type=comp["type"],
                facts=facts,
                is_crown_jewel=comp["is_crown_jewel"],
                unacceptable_outcomes_hit=has_unacceptable_outcomes
            )
            all_vulns.extend(vulns)

        self.storage.save_vulnerabilities(assessment_id, all_vulns)
        return all_vulns

    def check_completeness(self, assessment_id: str) -> Dict[str, Any]:
        """
        Returns a detailed completeness audit of the assessment across all phases.
        """
        assessment = self.storage.get_assessment(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} niet gevonden")

        components = self.storage.get_components(assessment_id)
        answers = self.storage.get_answers(assessment_id)
        answered_set = {(a["component_id"], a["question_id"]) for a in answers}

        total_questions = 0
        total_answered = 0
        component_breakdown = []

        for comp in components:
            app_q = self.get_applicable_questions_for_component(assessment, comp)
            comp_total = len(app_q)
            comp_answered = sum(1 for q in app_q if (comp["id"], q["id"]) in answered_set)
            total_questions += comp_total
            total_answered += comp_answered
            component_breakdown.append({
                "component_id": comp["id"],
                "naam": comp["naam"],
                "type": comp["type"],
                "totaal_vragen": comp_total,
                "beantwoord": comp_answered,
                "resterend": comp_total - comp_answered
            })

        missing_items = []
        if len(assessment.get("unacceptable_outcomes", [])) == 0:
            missing_items.append("Scoping: 3 onaanvaardbare uitkomsten ontbreken")
        if total_answered < total_questions:
            missing_items.append(f"Elicitatie: {total_questions - total_answered} vragen nog onbeantwoord")

        vulns = self.storage.get_vulnerabilities(assessment_id)
        with self.storage._get_connection() as conn:
            cursor = conn.execute("SELECT vulnerability_id FROM ratings WHERE assessment_id = ?", (assessment_id,))
            rated_count = len(cursor.fetchall())

        if len(vulns) > 0 and rated_count < len(vulns):
            missing_items.append(f"Beoordeling: {len(vulns) - rated_count} kwetsbaarheden nog niet beoordeeld")

        is_complete = (len(missing_items) == 0 and assessment["status"] == "afgerond")

        return {
            "assessment_id": assessment_id,
            "naam": assessment["naam"],
            "depth": assessment["depth"],
            "status": assessment["status"],
            "rev": assessment["rev"],
            "totaal_vragen": total_questions,
            "totaal_beantwoord": total_answered,
            "vragen_resterend": total_questions - total_answered,
            "componenten": component_breakdown,
            "ontbrekend": missing_items,
            "is_compleet": is_complete
        }

    def upgrade_depth(self, assessment_id: str, new_depth: str, rev: int) -> Dict[str, Any]:
        """Upgrades assessment depth (e.g. quick -> standard), only asking additional questions."""
        if new_depth not in DEPTH_LEVELS:
            raise ValueError(f"Ongeldige depth: {new_depth}")

        assessment = self.storage.get_assessment(assessment_id)
        curr_depth_val = DEPTH_LEVELS.get(assessment["depth"], 1)
        new_depth_val = DEPTH_LEVELS.get(new_depth, 1)
        if new_depth_val <= curr_depth_val:
            raise ValueError(f"Nieuwe depth ({new_depth}) moet hoger zijn dan huidige depth ({assessment['depth']})")

        # Reset status to elicitatie if it was afgerond/beoordeling to ask additional questions
        return self.storage.update_assessment(
            assessment_id=assessment_id,
            rev=rev,
            depth=new_depth,
            status="elicitatie"
        )
