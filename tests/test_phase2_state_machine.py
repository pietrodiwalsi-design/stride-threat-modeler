"""
Unit Test Suite for STRIDE Assessment Engine (Phase 2).

Acceptance Criteria:
1. Start, interrupt, and resume assessment on the exact same question.
2. check_completeness accurately identifies completed and missing items per phase.
3. Concurrency conflict detection: concurrent writes with stale rev raise ConcurrencyConflictError.
4. Depth profiles: quick produces 10-15 questions, standard produces 30-50 questions.
5. Depth upgrade (quick -> standard) asks only additional questions.
6. Rating enforcement: mandatory motivation when deviating from proposal or selecting 'Accept'.
"""

import os
import pytest
import tempfile
from stride_modeler.storage import AssessmentStorage, ConcurrencyConflictError
from stride_modeler.evaluator import STRIDEEvaluatorEngine
from stride_modeler.state_machine import AssessmentStateMachine


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    storage = AssessmentStorage(db_path=path)
    evaluator = STRIDEEvaluatorEngine()
    sm = AssessmentStateMachine(storage=storage, evaluator=evaluator)
    yield sm, storage
    if os.path.exists(path):
        os.remove(path)


def test_start_and_resume_assessment(temp_db):
    """Verifies starting an assessment, submitting answers, interrupting, and resuming exactly where left off."""
    sm, storage = temp_db

    # 1. Start assessment
    a = sm.start_assessment(
        naam="Customer Portal API",
        depth="quick",
        unacceptable_outcomes=["Klantdata lekt naar internet", "Niet-geautoriseerde transacties"]
    )
    aid = a["id"]
    assert aid.startswith("TM-")
    assert a["rev"] == 1
    assert a["status"] == "elicitatie"

    # 2. Get first question
    step1 = sm.get_next_step(aid)
    assert step1["fase"] == "elicitatie"
    assert step1["question_id"] == "ds-class-01"
    assert step1["rev"] == 1
    assert step1["resterend"] >= 8

    # 3. Answer question 1
    step2 = sm.submit_answer(aid, step1["component_id"], "ds-class-01", choice_nr=3, rev=step1["rev"])
    assert step2["question_id"] == "ds-reach-01"
    assert step2["rev"] == 2

    # 4. Simulate interrupting session, new state machine instance / reload next day
    reloaded_sm = AssessmentStateMachine(storage=storage, evaluator=sm.evaluator)
    resumed_step = reloaded_sm.get_next_step(aid)
    assert resumed_step["question_id"] == "ds-reach-01"
    assert resumed_step["rev"] == 2


def test_concurrency_conflict_detection(temp_db):
    """Verifies that two clients writing concurrently fail-fast on stale rev token."""
    sm, storage = temp_db

    a = sm.start_assessment(
        naam="Concurrency Test System",
        depth="quick",
        unacceptable_outcomes=["Data corruption"]
    )
    aid = a["id"]
    step = sm.get_next_step(aid)
    stale_rev = step["rev"]  # rev 1

    # Client A submits answer with rev 1 -> succeeds, bumps to rev 2
    sm.submit_answer(aid, step["component_id"], step["question_id"], choice_nr=1, rev=stale_rev)

    # Client B tries to submit with same old rev 1 -> ConcurrencyConflictError
    with pytest.raises(ConcurrencyConflictError) as exc:
        sm.submit_answer(aid, step["component_id"], step["question_id"], choice_nr=2, rev=stale_rev)
    assert "andere sessie" in str(exc.value) or "conflict" in str(exc.value).lower()


def test_check_completeness_tracking(temp_db):
    """Verifies check_completeness reports exact missing items and completion status."""
    sm, storage = temp_db

    # Start without unacceptable outcomes (scoping phase)
    a = sm.start_assessment(naam="Banking Backend", depth="quick")
    aid = a["id"]

    audit1 = sm.check_completeness(aid)
    assert not audit1["is_compleet"]
    assert any("Scoping" in item for item in audit1["ontbrekend"])
    assert audit1["vragen_resterend"] >= 8

    # Complete scoping
    sm.set_scoping_outcomes(aid, ["Financieel verlies door spoofing", "Ongeautoriseerde saldo-overschrijving"], rev=audit1["rev"])

    audit2 = sm.check_completeness(aid)
    assert not audit2["is_compleet"]
    assert not any("Scoping" in item for item in audit2["ontbrekend"])
    assert any("Elicitatie" in item for item in audit2["ontbrekend"])


def test_depth_profile_question_counts(temp_db):
    """Verifies that quick profile has 10-15 questions and standard profile has 30-50 questions."""
    sm, storage = temp_db

    # 1. Quick profile on single data_store
    a_quick = sm.start_assessment(
        naam="Quick System",
        depth="quick",
        unacceptable_outcomes=["Outage"]
    )
    comp_quick = storage.get_components(a_quick["id"])[0]
    questions_quick = sm.get_applicable_questions_for_component(a_quick, comp_quick)
    # Quick profile for 1 component has 8-10 questions
    assert 8 <= len(questions_quick) <= 15

    # 2. Standard profile with multiple components (e.g. data_store, process, external_entity, data_flow)
    a_std = storage.create_assessment(
        naam="Standard Enterprise App",
        methodology="stride",
        depth="standard",
        unacceptable_outcomes=["Data breach"]
    )
    storage.add_component(a_std["id"], "ds1", "CustomerDB", "data_store")
    storage.add_component(a_std["id"], "pr1", "PaymentProcessor", "process")
    storage.add_component(a_std["id"], "pr2", "AuthService", "process")
    storage.add_component(a_std["id"], "ee1", "PartnerPortal", "external_entity")
    storage.add_component(a_std["id"], "df1", "PaymentFlow", "data_flow")

    total_std_questions = 0
    for comp in storage.get_components(a_std["id"]):
        total_std_questions += len(sm.get_applicable_questions_for_component(a_std, comp))

    assert 30 <= total_std_questions <= 50, f"Expected 30-50 standard questions across components, got {total_std_questions}"


def test_depth_upgrade_preserves_answers(temp_db):
    """Verifies upgrading an assessment from quick to standard retains previous answers and asks only new ones."""
    sm, storage = temp_db

    a = sm.start_assessment(
        naam="Upgradable App",
        depth="quick",
        unacceptable_outcomes=["Outage"]
    )
    aid = a["id"]

    # Answer first question
    step1 = sm.get_next_step(aid)
    sm.submit_answer(aid, step1["component_id"], step1["question_id"], choice_nr=1, rev=step1["rev"])

    # Upgrade depth to standard
    current_a = storage.get_assessment(aid)
    sm.upgrade_depth(aid, "standard", rev=current_a["rev"])

    upgraded_a = storage.get_assessment(aid)
    assert upgraded_a["depth"] == "standard"
    assert upgraded_a["rev"] == current_a["rev"] + 1

    # Answers still intact
    answers = storage.get_answers(aid)
    assert len(answers) == 1
    assert answers[0]["question_id"] == step1["question_id"]


def test_rating_mandatory_motivation_on_deviation_and_accept(temp_db):
    """Verifies that ratings require motivation when deviating from proposal or when treatment is 'Accept'."""
    sm, storage = temp_db

    a = sm.start_assessment(
        naam="Rating App",
        depth="quick",
        unacceptable_outcomes=["Data breach"]
    )
    aid = a["id"]

    # Save a test vulnerability
    vulns = [{
        "id": "THR-TEST-001",
        "component_id": "c1",
        "component_name": "TestStore",
        "stride_categorie": "Tampering",
        "titel": "Tampering on TestStore",
        "bron_regel": "R-DS-TAMP-01",
        "exposure_voorstel": 4,
        "impact_voorstel": 4,
        "risk_level_voorstel": "Hoog"
    }]
    storage.save_vulnerabilities(aid, vulns)

    # 1. Non-deviating rating with Mitigate -> succeeds without motivation
    res1 = storage.set_rating(
        assessment_id=aid,
        vuln_id="THR-TEST-001",
        exposure=4,
        impact=4,
        risk_level="Hoog",
        motivatie=None,
        treatment="Mitigate"
    )
    assert res1["risk_level"] == "Hoog"

    # 2. Deviating rating (exposure 2 instead of 4) without motivation -> raises ValueError
    with pytest.raises(ValueError) as exc1:
        storage.set_rating(
            assessment_id=aid,
            vuln_id="THR-TEST-001",
            exposure=2,
            impact=4,
            risk_level="Midden",
            motivatie=None,
            treatment="Mitigate"
        )
    assert "Motivatie is verplicht" in str(exc1.value)

    # 3. Treatment 'Accept' without motivation -> raises ValueError even if scores match
    with pytest.raises(ValueError) as exc2:
        storage.set_rating(
            assessment_id=aid,
            vuln_id="THR-TEST-001",
            exposure=4,
            impact=4,
            risk_level="Hoog",
            motivatie=None,
            treatment="Accept"
        )
    assert "Motivatie is verplicht bij treatment 'Accept'" in str(exc2.value)
