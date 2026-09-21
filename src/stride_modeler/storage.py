"""
SQLite Storage Engine for STRIDE Assessment Engine (Phase 2).

Manages persistent SQLite storage (assessments.db) with human-friendly IDs (TM-001),
optimistic concurrency control via revision counter (rev), and normalized relational entities.
"""

import sqlite3
import json
import os
import datetime
from typing import Dict, Any, List, Optional, Tuple


class ConcurrencyConflictError(Exception):
    """Raised when an update is attempted with a stale revision token."""
    pass


class AssessmentStorage:
    """Manages SQLite storage for assessments, components, answers, facts, and vulnerabilities."""

    def __init__(self, db_path: str = "assessments.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    naam TEXT NOT NULL,
                    methodology TEXT NOT NULL DEFAULT 'stride',
                    depth TEXT NOT NULL DEFAULT 'quick',
                    status TEXT NOT NULL DEFAULT 'scoping',
                    unacceptable_outcomes TEXT NOT NULL DEFAULT '[]',
                    rev INTEGER NOT NULL DEFAULT 1,
                    aangemaakt TEXT NOT NULL,
                    gewijzigd TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS components (
                    id TEXT NOT NULL,
                    assessment_id TEXT NOT NULL,
                    naam TEXT NOT NULL,
                    type TEXT NOT NULL,
                    trust_zone TEXT NOT NULL DEFAULT 'Internal',
                    is_crown_jewel INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (id, assessment_id),
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS answers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    question_id TEXT NOT NULL,
                    gekozen_optie INTEGER,
                    vrije_tekst TEXT,
                    beantwoord_op TEXT NOT NULL,
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS facts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    sleutel TEXT NOT NULL,
                    waarde TEXT NOT NULL,
                    bron_answer_id INTEGER,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT NOT NULL,
                    assessment_id TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    titel TEXT NOT NULL,
                    toelichting TEXT,
                    stride_categorie TEXT NOT NULL,
                    bron_regel TEXT NOT NULL,
                    bron_referentie TEXT,
                    herkomst TEXT NOT NULL DEFAULT 'rule',
                    status TEXT NOT NULL DEFAULT 'actief',
                    triggering_facts TEXT NOT NULL DEFAULT '{}',
                    exposure_voorstel INTEGER NOT NULL,
                    impact_voorstel INTEGER NOT NULL,
                    risk_level_voorstel TEXT NOT NULL,
                    scoring_rationale TEXT,
                    PRIMARY KEY (id, assessment_id),
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS ratings (
                    vulnerability_id TEXT NOT NULL,
                    assessment_id TEXT NOT NULL,
                    exposure INTEGER NOT NULL,
                    impact INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    motivatie TEXT,
                    treatment TEXT NOT NULL DEFAULT 'Mitigate',
                    eigenaar TEXT,
                    besluit TEXT,
                    beoordeeld_op TEXT NOT NULL,
                    PRIMARY KEY (vulnerability_id, assessment_id),
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS recommendations (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    vulnerability_ids TEXT NOT NULL DEFAULT '[]',
                    tekst TEXT NOT NULL,
                    model TEXT NOT NULL,
                    model_versie TEXT,
                    fallback_van TEXT,
                    gegenereerd_op TEXT NOT NULL,
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS abuse_scenarios (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    titel TEXT NOT NULL,
                    beschrijving TEXT NOT NULL,
                    betrokken_componenten TEXT NOT NULL DEFAULT '[]',
                    geraakte_unacceptable_outcomes TEXT NOT NULL DEFAULT '[]',
                    model TEXT NOT NULL,
                    gegenereerd_op TEXT NOT NULL,
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                );
            """)

    def _next_assessment_id(self, conn: sqlite3.Connection) -> str:
        cursor = conn.execute("SELECT id FROM assessments WHERE id LIKE 'TM-%' ORDER BY rowid DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            return "TM-001"
        try:
            num = int(row["id"].split("-")[1])
            return f"TM-{num + 1:03d}"
        except Exception:
            return f"TM-{datetime.datetime.utcnow().strftime('%H%M%S')}"

    def create_assessment(
        self,
        naam: str,
        methodology: str = "stride",
        depth: str = "quick",
        unacceptable_outcomes: Optional[List[str]] = None,
        status: str = "scoping"
    ) -> Dict[str, Any]:
        """Creates a new assessment with initial rev=1 and a clean ID (e.g. TM-001)."""
        now = datetime.datetime.utcnow().isoformat() + "Z"
        outcomes_json = json.dumps(unacceptable_outcomes or [])

        with self._get_connection() as conn:
            aid = self._next_assessment_id(conn)
            conn.execute(
                """
                INSERT INTO assessments (id, naam, methodology, depth, status, unacceptable_outcomes, rev, aangemaakt, gewijzigd)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (aid, naam, methodology, depth, status, outcomes_json, now, now)
            )
            conn.commit()

        return self.get_assessment(aid)

    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
            row = cursor.fetchone()
            if not row:
                return None

            data = dict(row)
            data["unacceptable_outcomes"] = json.loads(data["unacceptable_outcomes"])
            return data

    def update_assessment(self, assessment_id: str, rev: int, **fields) -> Dict[str, Any]:
        """Updates assessment fields with optimistic locking verification on rev."""
        now = datetime.datetime.utcnow().isoformat() + "Z"
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT rev FROM assessments WHERE id = ?", (assessment_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Assessment {assessment_id} not found")
            if row["rev"] != rev:
                raise ConcurrencyConflictError(
                    f"Concurrency conflict on {assessment_id}: current rev is {row['rev']}, provided rev was {rev}"
                )

            set_clauses = ["rev = rev + 1", "gewijzigd = ?"]
            params: List[Any] = [now]

            for k, v in fields.items():
                if k == "unacceptable_outcomes" and isinstance(v, list):
                    set_clauses.append("unacceptable_outcomes = ?")
                    params.append(json.dumps(v))
                else:
                    set_clauses.append(f"{k} = ?")
                    params.append(v)

            params.append(assessment_id)
            params.append(rev)

            conn.execute(
                f"UPDATE assessments SET {', '.join(set_clauses)} WHERE id = ? AND rev = ?",
                params
            )
            conn.commit()

        return self.get_assessment(assessment_id)

    def add_component(
        self,
        assessment_id: str,
        comp_id: str,
        naam: str,
        comp_type: str,
        trust_zone: str = "Internal",
        is_crown_jewel: bool = False,
        rev: Optional[int] = None
    ) -> Dict[str, Any]:
        with self._get_connection() as conn:
            if rev is not None:
                cursor = conn.execute("SELECT rev FROM assessments WHERE id = ?", (assessment_id,))
                row = cursor.fetchone()
                if not row or row["rev"] != rev:
                    raise ConcurrencyConflictError("Assessment rev mismatch")

            conn.execute(
                """
                INSERT OR REPLACE INTO components (id, assessment_id, naam, type, trust_zone, is_crown_jewel)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (comp_id, assessment_id, naam, comp_type, trust_zone, 1 if is_crown_jewel else 0)
            )
            if rev is not None:
                conn.execute(
                    "UPDATE assessments SET rev = rev + 1, gewijzigd = ? WHERE id = ?",
                    (datetime.datetime.utcnow().isoformat() + "Z", assessment_id)
                )
            conn.commit()

        return {"id": comp_id, "naam": naam, "type": comp_type, "trust_zone": trust_zone, "is_crown_jewel": is_crown_jewel}

    def get_components(self, assessment_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM components WHERE assessment_id = ?", (assessment_id,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "naam": r["naam"],
                    "type": r["type"],
                    "trust_zone": r["trust_zone"],
                    "is_crown_jewel": bool(r["is_crown_jewel"])
                }
                for r in rows
            ]

    def save_answer_and_facts(
        self,
        assessment_id: str,
        component_id: str,
        question_id: str,
        chosen_option: Optional[int],
        free_text: Optional[str],
        facts: Dict[str, Any],
        rev: int
    ) -> Dict[str, Any]:
        """Atomically saves the raw answer, derives and stores normalized facts, and increments assessment rev."""
        now = datetime.datetime.utcnow().isoformat() + "Z"

        with self._get_connection() as conn:
            cursor = conn.execute("SELECT rev FROM assessments WHERE id = ?", (assessment_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Assessment {assessment_id} not found")
            if row["rev"] != rev:
                raise ConcurrencyConflictError(
                    f"Concurrency conflict: current rev is {row['rev']}, submit_answer was called with rev {rev}"
                )

            # Insert raw answer
            cursor = conn.execute(
                """
                INSERT INTO answers (assessment_id, component_id, question_id, gekozen_optie, vrije_tekst, beantwoord_op)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (assessment_id, component_id, question_id, chosen_option, free_text, now)
            )
            ans_id = cursor.lastrowid

            # Insert or replace normalized facts
            for k, v in facts.items():
                v_str = "true" if v is True else ("false" if v is False else str(v))
                # Remove existing fact for same component and key if present
                conn.execute(
                    "DELETE FROM facts WHERE assessment_id = ? AND component_id = ? AND sleutel = ?",
                    (assessment_id, component_id, k)
                )
                conn.execute(
                    """
                    INSERT INTO facts (assessment_id, component_id, sleutel, waarde, bron_answer_id, confidence)
                    VALUES (?, ?, ?, ?, ?, 1.0)
                    """,
                    (assessment_id, component_id, k, v_str, ans_id)
                )

            # Increment rev
            conn.execute(
                "UPDATE assessments SET rev = rev + 1, gewijzigd = ? WHERE id = ?",
                (now, assessment_id)
            )
            conn.commit()

        return self.get_assessment(assessment_id)

    def get_answers(self, assessment_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM answers WHERE assessment_id = ? ORDER BY id ASC", (assessment_id,))
            return [dict(r) for r in cursor.fetchall()]

    def get_facts(self, assessment_id: str, component_id: Optional[str] = None) -> Dict[str, Any]:
        with self._get_connection() as conn:
            if component_id:
                cursor = conn.execute(
                    "SELECT sleutel, waarde FROM facts WHERE assessment_id = ? AND component_id = ?",
                    (assessment_id, component_id)
                )
            else:
                cursor = conn.execute(
                    "SELECT sleutel, waarde FROM facts WHERE assessment_id = ?",
                    (assessment_id,)
                )
            facts = {}
            for r in cursor.fetchall():
                val = r["waarde"]
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                facts[r["sleutel"]] = val
            return facts

    def save_vulnerabilities(self, assessment_id: str, vulnerabilities: List[Dict[str, Any]]) -> None:
        with self._get_connection() as conn:
            for v in vulnerabilities:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities
                    (id, assessment_id, component_id, titel, toelichting, stride_categorie, bron_regel, bron_referentie,
                     herkomst, status, triggering_facts, exposure_voorstel, impact_voorstel, risk_level_voorstel, scoring_rationale)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        v["id"],
                        assessment_id,
                        v["component_id"],
                        v["titel"],
                        v.get("toelichting", ""),
                        v["stride_categorie"],
                        v["bron_regel"],
                        v.get("bron_referentie", ""),
                        v.get("herkomst", "rule"),
                        v.get("status", "actief"),
                        json.dumps(v.get("triggering_facts", {})),
                        v.get("exposure_voorstel", 3),
                        v.get("impact_voorstel", 3),
                        v.get("risk_level_voorstel", "Midden"),
                        v.get("scoring_rationale", "")
                    )
                )
            conn.commit()

    def get_vulnerabilities(self, assessment_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM vulnerabilities WHERE assessment_id = ?", (assessment_id,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["triggering_facts"] = json.loads(item["triggering_facts"])
                results.append(item)
            return results

    def set_rating(
        self,
        assessment_id: str,
        vuln_id: str,
        exposure: int,
        impact: int,
        risk_level: str,
        motivatie: Optional[str],
        treatment: str = "Mitigate",
        eigenaar: Optional[str] = None,
        besluit: Optional[str] = None,
        rev: Optional[int] = None
    ) -> Dict[str, Any]:
        """Sets rating for a vulnerability with mandatory motivation if deviating or accepting risk."""
        now = datetime.datetime.utcnow().isoformat() + "Z"

        with self._get_connection() as conn:
            if rev is not None:
                cursor = conn.execute("SELECT rev FROM assessments WHERE id = ?", (assessment_id,))
                row = cursor.fetchone()
                if not row or row["rev"] != rev:
                    raise ConcurrencyConflictError("Assessment rev mismatch")

            # Check vulnerability proposal
            cursor = conn.execute(
                "SELECT exposure_voorstel, impact_voorstel FROM vulnerabilities WHERE id = ? AND assessment_id = ?",
                (vuln_id, assessment_id)
            )
            v_row = cursor.fetchone()
            if not v_row:
                raise ValueError(f"Vulnerability {vuln_id} not found in assessment {assessment_id}")

            prop_exp = v_row["exposure_voorstel"]
            prop_imp = v_row["impact_voorstel"]

            is_deviating = (exposure != prop_exp or impact != prop_imp)
            if is_deviating and not motivatie:
                raise ValueError("Motivatie is verplicht wanneer het oordeel afwijkt van het scoringsvoorstel")
            if treatment == "Accept" and not motivatie:
                raise ValueError("Motivatie is verplicht bij treatment 'Accept'")

            conn.execute(
                """
                INSERT OR REPLACE INTO ratings
                (vulnerability_id, assessment_id, exposure, impact, risk_level, motivatie, treatment, eigenaar, besluit, beoordeeld_op)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (vuln_id, assessment_id, exposure, impact, risk_level, motivatie, treatment, eigenaar, besluit, now)
            )

            if rev is not None:
                conn.execute(
                    "UPDATE assessments SET rev = rev + 1, gewijzigd = ? WHERE id = ?",
                    (now, assessment_id)
                )
            conn.commit()

        return {
            "vulnerability_id": vuln_id,
            "exposure": exposure,
            "impact": impact,
            "risk_level": risk_level,
            "treatment": treatment,
            "besluit": besluit
        }
