"""
CLI Interface for STRIDE Assessment Engine (Phase 3).

Supports full interactive assessment lifecycle:
  stride start <naam> [--depth quick|standard|deep] [--outcomes "O1,O2,O3"]
  stride next <assessment_id>
  stride answer <assessment_id> <component_id> <question_id> <choice_nr> [--rev <int>]
  stride component <assessment_id> <comp_id> <naam> <type> [--crown-jewel]
  stride derive <assessment_id>
  stride propose <assessment_id> <vuln_id>
  stride rate <assessment_id> <vuln_id> <exp> <imp> <level> [--motivatie "text"] [--treatment Mitigate|Accept] [--besluit "text"]
  stride confirm <assessment_id> <vuln_id>
  stride check <assessment_id>
  stride show <assessment_id>
  stride matrix <assessment_id>
  stride report <assessment_id> [-o <path>]
  stride export <assessment_id> [-o <path>]
"""

import sys
import os
import argparse
import json
from typing import List, Optional

from stride_modeler.storage import AssessmentStorage, ConcurrencyConflictError
from stride_modeler.state_machine import AssessmentStateMachine
from stride_modeler.evaluator import STRIDEEvaluatorEngine
from stride_modeler.dashboard_generator import STRIDEDashboardGenerator
from stride_modeler.models import ThreatModelReport, STRIDECategory, RiskLevel, Threat


def get_cli_engine():
    storage = AssessmentStorage()
    evaluator = STRIDEEvaluatorEngine()
    sm = AssessmentStateMachine(storage=storage, evaluator=evaluator)
    return storage, evaluator, sm


def cmd_start(args):
    storage, evaluator, sm = get_cli_engine()
    outcomes = [o.strip() for o in args.outcomes.split(",")] if args.outcomes else []
    a = sm.start_assessment(
        naam=args.naam,
        depth=args.depth,
        methodology=args.methodology,
        unacceptable_outcomes=outcomes
    )
    print(f"✅ Assessment aangemaakt: {a['id']} (rev {a['rev']})")
    print(f"   Naam: {a['naam']} | Depth: {a['depth']} | Status: {a['status']}")
    step = sm.get_next_step(a["id"])
    _print_step(step)


def cmd_next(args):
    storage, evaluator, sm = get_cli_engine()
    step = sm.get_next_step(args.assessment_id)
    _print_step(step)


def cmd_answer(args):
    storage, evaluator, sm = get_cli_engine()
    try:
        step = sm.submit_answer(
            assessment_id=args.assessment_id,
            component_id=args.component_id,
            question_id=args.question_id,
            choice_nr=args.keuze,
            free_text=args.text,
            rev=args.rev
        )
        print("✅ Antwoord opgeslagen.")
        _print_step(step)
    except ConcurrencyConflictError as cce:
        print(f"❌ Concurrency Conflict: {cce}")
        sys.exit(1)


def cmd_component(args):
    storage, evaluator, sm = get_cli_engine()
    try:
        res = storage.add_component(
            assessment_id=args.assessment_id,
            comp_id=args.component_id,
            naam=args.naam,
            comp_type=args.type,
            trust_zone=args.trust_zone,
            is_crown_jewel=args.crown_jewel,
            rev=args.rev
        )
        print(f"✅ Component {res['id']} ({res['naam']}) toegevoegd aan {args.assessment_id}")
    except ConcurrencyConflictError as cce:
        print(f"❌ Concurrency Conflict: {cce}")
        sys.exit(1)


def cmd_derive(args):
    storage, evaluator, sm = get_cli_engine()
    vulns = sm.derive_and_save_vulnerabilities(args.assessment_id)
    print(f"✅ {len(vulns)} kwetsbaarheden afgeleid uit feiten:")
    for v in vulns:
        print(f"   [{v['id']}] {v['stride_categorie']} - {v['titel']}")
        print(f"         Voorstel: Exposure {v['exposure_voorstel']}, Impact {v['impact_voorstel']} -> {v['risk_level_voorstel']}")
        print(f"         Bron: {v['bron_regel']} ({v.get('bron_referentie', '')})")


def cmd_propose(args):
    storage, evaluator, sm = get_cli_engine()
    vulns = storage.get_vulnerabilities(args.assessment_id)
    v = next((item for item in vulns if item["id"] == args.vulnerability_id), None)
    if not v:
        print(f"❌ Kwetsbaarheid {args.vulnerability_id} niet gevonden.")
        sys.exit(1)

    print(f"📋 Scoringsvoorstel voor {v['id']}:")
    print(f"   Titel: {v['titel']}")
    print(f"   Categorie: {v['stride_categorie']}")
    print(f"   Exposure Voorstel: {v['exposure_voorstel']}/5")
    print(f"   Impact Voorstel:   {v['impact_voorstel']}/5")
    print(f"   Risiconiveau:      {v['risk_level_voorstel']}")
    print(f"   Onderbouwing:      {v.get('scoring_rationale', '-')}")


def cmd_rate(args):
    storage, evaluator, sm = get_cli_engine()
    try:
        res = storage.set_rating(
            assessment_id=args.assessment_id,
            vuln_id=args.vulnerability_id,
            exposure=args.exposure,
            impact=args.impact,
            risk_level=args.risk_level,
            motivatie=args.motivatie,
            treatment=args.treatment,
            eigenaar=args.eigenaar,
            besluit=args.besluit,
            rev=args.rev
        )
        print(f"✅ Beoordeling vastgelegd voor {res['vulnerability_id']}: {res['risk_level']} (Treatment: {res['treatment']})")
    except ValueError as ve:
        print(f"❌ Validatiefout: {ve}")
        sys.exit(1)
    except ConcurrencyConflictError as cce:
        print(f"❌ Concurrency Conflict: {cce}")
        sys.exit(1)


def cmd_check(args):
    storage, evaluator, sm = get_cli_engine()
    audit = sm.check_completeness(args.assessment_id)
    print(f"📊 Volledigheidsaudit voor {audit['assessment_id']} ({audit['naam']}):")
    print(f"   Status: {audit['status']} | Rev: {audit['rev']} | Compleet: {'JA' if audit['is_compleet'] else 'NEE'}")
    print(f"   Vragen beantwoord: {audit['totaal_beantwoord']}/{audit['totaal_vragen']} (Resterend: {audit['vragen_resterend']})")
    if audit["ontbrekend"]:
        print("   ⚠️  Openstaande acties:")
        for item in audit["ontbrekend"]:
            print(f"      - {item}")
    else:
        print("   🎉 Alle fasen zijn volledig afgerond!")


def cmd_matrix(args):
    storage, evaluator, sm = get_cli_engine()
    with storage._get_connection() as conn:
        cursor = conn.execute("SELECT risk_level FROM ratings WHERE assessment_id = ?", (args.assessment_id,))
        levels = [r["risk_level"] for r in cursor.fetchall()]
    summary = {"Kritiek": 0, "Hoog": 0, "Midden": 0, "Laag": 0}
    for lvl in levels:
        if lvl in summary:
            summary[lvl] += 1
    print(f"🎯 5x5 Risicomatrix telling voor {args.assessment_id}:")
    print(f"   🔴 Kritiek: {summary['Kritiek']}")
    print(f"   🟠 Hoog:    {summary['Hoog']}")
    print(f"   🟡 Midden:  {summary['Midden']}")
    print(f"   🟢 Laag:    {summary['Laag']}")


def cmd_show(args):
    storage, evaluator, sm = get_cli_engine()
    a = storage.get_assessment(args.assessment_id)
    if not a:
        print(f"❌ Assessment {args.assessment_id} niet gevonden.")
        sys.exit(1)
    comps = storage.get_components(args.assessment_id)
    vulns = storage.get_vulnerabilities(args.assessment_id)
    print(json.dumps({
        "assessment": a,
        "components": comps,
        "vulnerabilities": vulns
    }, indent=2, ensure_ascii=False))


def cmd_report(args):
    storage, evaluator, sm = get_cli_engine()
    out_path = args.output or f"rapport_{args.assessment_id}.html"
    try:
        html_out = STRIDEDashboardGenerator.generate_assessment_html(
            assessment_id=args.assessment_id,
            storage=storage,
            evaluator=evaluator,
            out_path=out_path
        )
        print(f"✅ HTML Rapport gegenereerd voor {args.assessment_id}: {out_path}")
    except ValueError as ve:
        print(f"❌ Fout: {ve}")
        sys.exit(1)


def cmd_export(args):
    storage, evaluator, sm = get_cli_engine()
    from stride_modeler.exporter import AssessmentExporter
    try:
        data = AssessmentExporter.export_assessment(
            assessment_id=args.assessment_id,
            storage=storage,
            evaluator=evaluator
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"✅ Assessment geëxporteerd naar {args.output} (Schema v1.0)")
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
    except ValueError as ve:
        print(f"❌ Fout: {ve}")
        sys.exit(1)


def _print_step(step: dict):
    fase = step.get("fase", "")
    print(f"\n👉 [Stap: {fase.upper()}] (rev {step.get('rev', 1)} | Resterend: {step.get('resterend', 0)})")

    if fase == "scoping":
        print(f"   {step.get('vraag')}")
        print(f"   💡 {step.get('instructie')}")
    elif fase == "elicitatie":
        print(f"   Component: {step.get('component')} ({step.get('component_type')}) [{step.get('question_id')}]")
        print(f"   Vraag: {step.get('vraag')}")
        if step.get("bron"):
            print(f"   Bron:  {step.get('bron')}")
        print("   Opties:")
        for opt in step.get("opties", []):
            print(f"     [{opt['nr']}] {opt['label']}")
    elif fase == "beoordeling":
        print(f"   Kwetsbaarheid: [{step.get('vulnerability_id')}] {step.get('titel')}")
        print(f"   Categorie:     {step.get('stride_categorie')}")
        print(f"   Voorstel:      Exposure {step.get('exposure_voorstel')}, Impact {step.get('impact_voorstel')} -> {step.get('risk_level_voorstel')}")
        print(f"   Rationale:     {step.get('scoring_rationale')}")
    elif fase == "afgerond":
        print(f"   🎉 {step.get('boodschap')}")
        print(f"   Totaal kwetsbaarheden: {step.get('totaal_kwetsbaarheden')}")
        print(f"   Risicoverdeling: {step.get('risico_matrix_telling')}")


def main():
    parser = argparse.ArgumentParser(description="STRIDE Assessment Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # start
    p_start = subparsers.add_parser("start", help="Start a new assessment")
    p_start.add_argument("naam", type=str, help="System name")
    p_start.add_argument("--depth", type=str, choices=["quick", "standard", "deep"], default="quick")
    p_start.add_argument("--methodology", type=str, choices=["stride", "linddun", "agentic"], default="stride")
    p_start.add_argument("--outcomes", type=str, help="Comma-separated unacceptable outcomes")
    p_start.set_defaults(func=cmd_start)

    # next
    p_next = subparsers.add_parser("next", help="Get single next step")
    p_next.add_argument("assessment_id", type=str)
    p_next.set_defaults(func=cmd_next)

    # answer
    p_ans = subparsers.add_parser("answer", help="Submit answer to a question")
    p_ans.add_argument("assessment_id", type=str)
    p_ans.add_argument("component_id", type=str)
    p_ans.add_argument("question_id", type=str)
    p_ans.add_argument("keuze", type=int, help="Option number (1-5)")
    p_ans.add_argument("--text", type=str, help="Optional free text")
    p_ans.add_argument("--rev", type=int, help="Revision check")
    p_ans.set_defaults(func=cmd_answer)

    # component
    p_comp = subparsers.add_parser("component", help="Add component to assessment")
    p_comp.add_argument("assessment_id", type=str)
    p_comp.add_argument("component_id", type=str)
    p_comp.add_argument("naam", type=str)
    p_comp.add_argument("type", type=str, choices=["data_store", "process", "external_entity", "data_flow"])
    p_comp.add_argument("--trust-zone", type=str, default="Internal")
    p_comp.add_argument("--crown-jewel", action="store_true")
    p_comp.add_argument("--rev", type=int)
    p_comp.set_defaults(func=cmd_component)

    # derive
    p_der = subparsers.add_parser("derive", help="Derive vulnerabilities from facts")
    p_der.add_argument("assessment_id", type=str)
    p_der.set_defaults(func=cmd_derive)

    # propose
    p_prop = subparsers.add_parser("propose", help="Get scoring proposal for vulnerability")
    p_prop.add_argument("assessment_id", type=str)
    p_prop.add_argument("vulnerability_id", type=str)
    p_prop.set_defaults(func=cmd_propose)

    # rate
    p_rate = subparsers.add_parser("rate", help="Set human rating for vulnerability")
    p_rate.add_argument("assessment_id", type=str)
    p_rate.add_argument("vulnerability_id", type=str)
    p_rate.add_argument("exposure", type=int, choices=[1, 2, 3, 4, 5])
    p_rate.add_argument("impact", type=int, choices=[1, 2, 3, 4, 5])
    p_rate.add_argument("risk_level", type=str, choices=["Laag", "Midden", "Hoog", "Kritiek"])
    p_rate.add_argument("--motivatie", type=str, help="Mandatory if deviating from proposal or treatment is Accept")
    p_rate.add_argument("--treatment", type=str, choices=["Mitigate", "Transfer", "Accept", "Eliminate"], default="Mitigate")
    p_rate.add_argument("--eigenaar", type=str)
    p_rate.add_argument("--besluit", type=str)
    p_rate.add_argument("--rev", type=int)
    p_rate.set_defaults(func=cmd_rate)

    # check
    p_chk = subparsers.add_parser("check", help="Check completeness of assessment")
    p_chk.add_argument("assessment_id", type=str)
    p_chk.set_defaults(func=cmd_check)

    # matrix
    p_mat = subparsers.add_parser("matrix", help="Show 5x5 matrix summary")
    p_mat.add_argument("assessment_id", type=str)
    p_mat.set_defaults(func=cmd_matrix)

    # show
    p_show = subparsers.add_parser("show", help="Show full assessment JSON")
    p_show.add_argument("assessment_id", type=str)
    p_show.set_defaults(func=cmd_show)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
