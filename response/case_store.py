#!/usr/bin/env python3
"""
================================================================================
response/case_store.py
EIRP-EMR  |  Tier 3  |  Case Management Store (SQLite)
================================================================================

PURPOSE
-------
Persistence layer for the Tier-3 incident response engine. Implements the
5-table schema from the EIRP-EMR architecture doc Section E3 using stdlib
sqlite3 (no SQLAlchemy dependency).

TABLES
------
  incidents              one row per detected incident
  playbook_execution     one row per playbook step executed
  evidence_chain         forensic-artefact references (SHA-256 hashed)
  audit_trail            immutable audit log of every action
  notifications_log      record of every email / SMS / dashboard alert

PUBLIC API
----------
    store = CaseStore("eirp_cases.db")
    store.init_schema()

    inc_id = store.create_incident(...)
    store.update_incident_status(inc_id, "CONTAINED")
    store.add_evidence(inc_id, source_type, file_hash, file_path)
    store.log_audit(inc_id, action, performed_by, ip_address, change_summary)
    store.log_notification(inc_id, channel, recipient, delivery_status)
    store.log_playbook_step(inc_id, step_id, executed_by, outcome,
                             deadline_met, notes)

    open_cases = store.list_open_incidents()
    inc        = store.get_incident(inc_id)
    timeline   = store.get_incident_timeline(inc_id)

THESIS NOTE
-----------
Stdlib sqlite3 was chosen over SQLAlchemy for two reasons:
  1. Zero additional dependency at deployment (Nigerian hospital IT
     environments commonly have constrained venv update privileges).
  2. The 5-table schema is small enough that ORM mapping adds more
     complexity than it removes.
Future migration to SQLAlchemy is a one-shot refactor; the table
definitions in this module's DDL are intentionally compatible with
sqlalchemy.Column declarations.

RESEARCH CITATION
-----------------
Alozie, O. C. (2023-2026). EIRP-EMR. EBSU/PG/PhD/2023/11861.
================================================================================
"""
from __future__ import annotations

import sqlite3
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "eirp_cases.db"


# ---------------------------------------------------------------------------
@dataclass
class Incident:
    incident_id:       str
    incident_type:     str
    detected_at:       str          # ISO-8601 string
    its_score:         float
    severity:          str          # LOW / MEDIUM / HIGH / CRITICAL
    attack_tactic:     str
    attack_technique:  str
    status:            str          # OPEN / CONTAINED / CLOSED / ABANDONED
    assigned_to:       str
    playbook_id:       str
    summary:           str          = ""
    closed_at:         Optional[str] = None
    # Source attribution -- which log produced this incident.
    # source_kind = inference source arg ("lira", "access", "evtx", "error")
    # source_name = user-friendly name from the dashboard's SourceRegistry
    #               (e.g. "LIRA 2026") OR blank when persisted from a one-shot
    #               CLI ml_inference run.
    # source_path = the actual file/dir that was scanned for this incident.
    source_kind:       str          = ""
    source_name:       str          = ""
    source_path:       str          = ""
    # source_csv_path = the EXACT parser-output CSV that was scored to
    # produce this incident (e.g. LIRA_dispatch/2026_log_031214/..master..csv).
    # source_path above is the user-facing origin (the raw .txt/.evtx); this
    # pins the precise dispatch CSV so the detail view reads the right row
    # instead of re-discovering a stale sibling run. Empty for incidents
    # persisted before this column existed -- the detail view then falls back
    # to hash-validated discovery.
    source_csv_path:   str          = ""
    # Traceability -- pin the incident to the EXACT event that produced it.
    # source_row_index   = positional row in the parser-output CSV (0-based).
    # source_event_hash  = sha1 of canonical event fields (or the parser's
    #                       own `fingerprint` column for LIRA). Survives
    #                       parser re-runs that preserve event identity.
    # supervised_model_id= which of the 7 supervised models produced the
    #                       winning verdict for this row (0 = none).
    source_row_index:    int          = -1
    source_event_hash:   str          = ""
    supervised_model_id: int          = 0
    # Dedup attribution -- when the same (source_host, incident_type,
    # attack_technique) recurs on an OPEN incident, we MERGE into the
    # existing row instead of creating duplicates:
    #   source_host       -- host/IP/computer name extracted from the event row
    #   dedup_key         -- sha1(host|type|technique)[:16]; empty when host
    #                          is unknown (each unknown-host event stays unique)
    #   occurrence_count  -- 1 for fresh incidents; incremented on each merge
    #   first_seen_at     -- detected_at of the first event in this incident
    #   last_seen_at      -- detected_at of the most recent merged event
    #   base_its          -- ITS of the first event; its_score is the
    #                          escalated value (base + log10(count)*0.05,
    #                          capped at 1.0). Keeping base separate so a
    #                          recount can be replayed deterministically.
    source_host:         str          = ""
    dedup_key:           str          = ""
    occurrence_count:    int          = 1
    first_seen_at:       str          = ""
    last_seen_at:        str          = ""
    base_its:            float        = 0.0
    # AI-vs-Rule dual verdict (see incident_classifier.IncidentDecision).
    # detection_driver  = "AI" | "RULE" -- which verdict set the persisted
    #                     type/severity/score above.
    # verdict_agreement = AGREE | DISAGREE | AI_ONLY | RULE_ONLY
    # ai_* / rule_*     = each detector's standalone verdict, recorded for the
    #                     dashboard + thesis compare-and-contrast.
    detection_driver:    str          = ""
    verdict_agreement:   str          = ""
    ai_incident_type:    str          = ""
    ai_label:            str          = ""
    ai_confidence:       float        = 0.0
    ai_model_id:         int          = 0
    ai_severity:         str          = ""
    rule_incident_type:  str          = ""
    rule_label:          str          = ""
    rule_severity:       str          = ""
    rule_id:             str          = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# ITS-driven severity bands. The merge path re-derives severity from the
# ESCALATED its_score so a MEDIUM that recurs 300 times naturally climbs
# into HIGH/CRITICAL. Bands kept conservative to match the SOC convention
# used elsewhere in the dashboard's Open Incidents filter.
_SEVERITY_BANDS = (
    (0.85, "CRITICAL"),
    (0.65, "HIGH"),
    (0.40, "MEDIUM"),
    (0.00, "LOW"),
)


def _severity_from_its(its: float) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if its >= threshold:
            return label
    return "LOW"


# Cap the per-incident forensic ledger (incident_occurrences). A high-volume
# EVTX scan can merge tens of thousands of events into one OPEN incident; the
# incident's occurrence_count stays exact, but we stop persisting individual
# occurrence rows past this cap so the table (and the audit trail) don't grow
# without bound. The first N raw events are kept as a representative sample.
_MAX_OCCURRENCES_PER_INCIDENT = 200


def _compute_dedup_key(source_host: str, incident_type: str,
                       attack_technique: str) -> str:
    """Hash (host, type, technique) into a 16-char dedup key. Returns ''
    when host is empty -- caller should then skip the merge lookup and
    treat each event as a unique incident. Without a known host, merging
    by (type, technique) alone would collapse genuine independent
    incidents on different machines into one row."""
    if not source_host or not source_host.strip():
        return ""
    raw = f"{source_host.strip().casefold()}|{incident_type}|{attack_technique}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _escalated_its(base_its: float, occurrence_count: int) -> float:
    """Escalate ITS as occurrences accumulate.
        effective = min(1.0, base + log10(count) * 0.05)
    Count=1   -> base
    Count=10  -> base + 0.05
    Count=100 -> base + 0.10
    Count=1000-> base + 0.15  (so a 1000-event burst on a MEDIUM=0.45
                                  climbs to 0.60, into HIGH territory).
    Keeps the original signal (base_its) while making volume visible in
    severity."""
    import math as _m
    if occurrence_count <= 1:
        return float(base_its)
    return min(1.0, float(base_its) + _m.log10(int(occurrence_count)) * 0.05)


# ---------------------------------------------------------------------------
DDL = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id       TEXT PRIMARY KEY,
    incident_type     TEXT NOT NULL,
    detected_at       TEXT NOT NULL,
    its_score         REAL NOT NULL,
    severity          TEXT NOT NULL,
    attack_tactic     TEXT,
    attack_technique  TEXT,
    status            TEXT NOT NULL DEFAULT 'OPEN',
    assigned_to       TEXT,
    playbook_id       TEXT,
    summary           TEXT,
    closed_at         TEXT,
    source_kind       TEXT DEFAULT '',
    source_name       TEXT DEFAULT '',
    source_path       TEXT DEFAULT '',
    source_csv_path   TEXT DEFAULT '',
    source_row_index  INTEGER DEFAULT -1,
    source_event_hash TEXT DEFAULT '',
    supervised_model_id INTEGER DEFAULT 0,
    source_host       TEXT DEFAULT '',
    dedup_key         TEXT DEFAULT '',
    occurrence_count  INTEGER DEFAULT 1,
    first_seen_at     TEXT DEFAULT '',
    last_seen_at      TEXT DEFAULT '',
    base_its          REAL DEFAULT 0.0,
    detection_driver  TEXT DEFAULT '',
    verdict_agreement TEXT DEFAULT '',
    ai_incident_type  TEXT DEFAULT '',
    ai_label          TEXT DEFAULT '',
    ai_confidence     REAL DEFAULT 0.0,
    ai_model_id       INTEGER DEFAULT 0,
    ai_severity       TEXT DEFAULT '',
    rule_incident_type TEXT DEFAULT '',
    rule_label        TEXT DEFAULT '',
    rule_severity     TEXT DEFAULT '',
    rule_id           TEXT DEFAULT ''
);

-- One row per raw event behind an incident. When a new event merges into
-- an existing OPEN incident via (source_host, incident_type, attack_technique),
-- the incident's occurrence_count gets bumped and a new occurrence row
-- preserves the forensic detail. The incident table stays compact; the
-- ledger lives here.
CREATE TABLE IF NOT EXISTS incident_occurrences (
    occ_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id       TEXT NOT NULL,
    observed_at       TEXT NOT NULL,
    its_score         REAL,
    source_path       TEXT,
    source_row_index  INTEGER,
    source_event_hash TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS playbook_execution (
    exec_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id       TEXT NOT NULL,
    step_id           TEXT NOT NULL,
    executed_at       TEXT NOT NULL,
    executed_by       TEXT,
    outcome           TEXT NOT NULL,
    deadline_met      INTEGER,
    notes             TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS evidence_chain (
    evidence_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id       TEXT NOT NULL,
    source_type       TEXT NOT NULL,
    file_hash         TEXT NOT NULL,
    collected_at      TEXT NOT NULL,
    file_path         TEXT,
    description       TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id       TEXT,
    action            TEXT NOT NULL,
    performed_by      TEXT,
    performed_at      TEXT NOT NULL,
    ip_address        TEXT,
    change_summary    TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS notifications_log (
    notif_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id       TEXT NOT NULL,
    channel           TEXT NOT NULL,
    recipient         TEXT NOT NULL,
    sent_at           TEXT NOT NULL,
    delivery_status   TEXT NOT NULL,
    subject           TEXT,
    body_excerpt      TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_inc_status      ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_inc_type        ON incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_pe_inc          ON playbook_execution(incident_id);
CREATE INDEX IF NOT EXISTS idx_ec_inc          ON evidence_chain(incident_id);
CREATE INDEX IF NOT EXISTS idx_at_inc          ON audit_trail(incident_id);
CREATE INDEX IF NOT EXISTS idx_nl_inc          ON notifications_log(incident_id);

-- Perf indexes: dashboard widgets filter by these constantly.
--   source_path: per-source count refresh + Rescan purge
--   detected_at: Open Incidents tab ORDER BY DESC, Home recent strip
--   severity:    Home KPI tiles + Open Incidents severity filter
--   audit_trail.timestamp: Audit Forensics tab ORDER BY DESC
CREATE INDEX IF NOT EXISTS idx_inc_source_path ON incidents(source_path);
CREATE INDEX IF NOT EXISTS idx_inc_detected_at ON incidents(detected_at);
CREATE INDEX IF NOT EXISTS idx_inc_severity    ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_at_performed_at ON audit_trail(performed_at);
-- Dedup lookup index. The merge path filters WHERE dedup_key = ? AND
-- status = 'OPEN' on every new event; without this index a 14k-incident
-- DB makes each new event scan the full table.
CREATE INDEX IF NOT EXISTS idx_inc_dedup_open  ON incidents(dedup_key, status);
CREATE INDEX IF NOT EXISTS idx_occ_inc         ON incident_occurrences(incident_id);
CREATE INDEX IF NOT EXISTS idx_occ_observed    ON incident_occurrences(observed_at);
"""


# ---------------------------------------------------------------------------
class CaseStore:
    """SQLite-backed persistence for incidents and their lifecycle artefacts."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        # Monotonic write watermark. Dashboard widgets cache their
        # last-seen value and skip refreshing when it hasn't changed,
        # turning idle ticks into 1-attribute-access no-ops.
        self.data_version: int = 0

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            # check_same_thread=False: the worker-pool daemon uses a
            # ThreadingHTTPServer, so /score POSTs come in on per-request
            # threads while the connection is opened on the engine-load
            # thread. Without this flag every persist raises
            # "SQLite objects created in a thread can only be used in
            # that same thread" and incident counts silently stick at 0.
            # Safe because ml_inference_daemon._score_one serialises all
            # writes behind a global lock; no concurrent access can occur.
            self._conn = sqlite3.connect(str(self.db_path),
                                         isolation_level=None,
                                         check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            # WAL mode enables safe concurrent writers across processes,
            # required when the dashboard's worker_pool spawns multiple
            # ml_inference_daemon subprocesses that all write incidents
            # to the same case-store file.
            try:
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
                self._conn.execute("PRAGMA busy_timeout = 5000")
            except sqlite3.OperationalError:
                pass        # not all SQLite builds support WAL
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def init_schema(self) -> None:
        conn = self.connect()
        conn.executescript(DDL)
        # Backwards-compatible migration: case-store DBs created before the
        # source-attribution feature lack source_* columns. SQLite has no
        # `ADD COLUMN IF NOT EXISTS`, so we check + ALTER one-by-one.
        existing = {r[1] for r in conn.execute(
            "PRAGMA table_info(incidents)").fetchall()}
        for col, ddl in [
            ("source_kind",         "ALTER TABLE incidents ADD COLUMN source_kind TEXT DEFAULT ''"),
            ("source_name",         "ALTER TABLE incidents ADD COLUMN source_name TEXT DEFAULT ''"),
            ("source_path",         "ALTER TABLE incidents ADD COLUMN source_path TEXT DEFAULT ''"),
            ("source_csv_path",     "ALTER TABLE incidents ADD COLUMN source_csv_path TEXT DEFAULT ''"),
            ("source_row_index",    "ALTER TABLE incidents ADD COLUMN source_row_index INTEGER DEFAULT -1"),
            ("source_event_hash",   "ALTER TABLE incidents ADD COLUMN source_event_hash TEXT DEFAULT ''"),
            ("supervised_model_id", "ALTER TABLE incidents ADD COLUMN supervised_model_id INTEGER DEFAULT 0"),
            ("source_host",         "ALTER TABLE incidents ADD COLUMN source_host TEXT DEFAULT ''"),
            ("dedup_key",           "ALTER TABLE incidents ADD COLUMN dedup_key TEXT DEFAULT ''"),
            ("occurrence_count",    "ALTER TABLE incidents ADD COLUMN occurrence_count INTEGER DEFAULT 1"),
            ("first_seen_at",       "ALTER TABLE incidents ADD COLUMN first_seen_at TEXT DEFAULT ''"),
            ("last_seen_at",        "ALTER TABLE incidents ADD COLUMN last_seen_at TEXT DEFAULT ''"),
            ("base_its",            "ALTER TABLE incidents ADD COLUMN base_its REAL DEFAULT 0.0"),
            ("detection_driver",    "ALTER TABLE incidents ADD COLUMN detection_driver TEXT DEFAULT ''"),
            ("verdict_agreement",   "ALTER TABLE incidents ADD COLUMN verdict_agreement TEXT DEFAULT ''"),
            ("ai_incident_type",    "ALTER TABLE incidents ADD COLUMN ai_incident_type TEXT DEFAULT ''"),
            ("ai_label",            "ALTER TABLE incidents ADD COLUMN ai_label TEXT DEFAULT ''"),
            ("ai_confidence",       "ALTER TABLE incidents ADD COLUMN ai_confidence REAL DEFAULT 0.0"),
            ("ai_model_id",         "ALTER TABLE incidents ADD COLUMN ai_model_id INTEGER DEFAULT 0"),
            ("ai_severity",         "ALTER TABLE incidents ADD COLUMN ai_severity TEXT DEFAULT ''"),
            ("rule_incident_type",  "ALTER TABLE incidents ADD COLUMN rule_incident_type TEXT DEFAULT ''"),
            ("rule_label",          "ALTER TABLE incidents ADD COLUMN rule_label TEXT DEFAULT ''"),
            ("rule_severity",       "ALTER TABLE incidents ADD COLUMN rule_severity TEXT DEFAULT ''"),
            ("rule_id",             "ALTER TABLE incidents ADD COLUMN rule_id TEXT DEFAULT ''"),
        ]:
            if col not in existing:
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass        # column already exists in a parallel writer
        # Backfill base_its = its_score for pre-existing rows so the merge
        # path's escalation math works on legacy incidents. Idempotent --
        # only touches rows where base_its is still the default 0.0.
        try:
            conn.execute("UPDATE incidents SET base_its = its_score "
                         "WHERE base_its = 0.0 AND its_score > 0.0")
            # first_seen / last_seen default to detected_at for legacy rows
            conn.execute("UPDATE incidents SET first_seen_at = detected_at "
                         "WHERE first_seen_at IS NULL OR first_seen_at = ''")
            conn.execute("UPDATE incidents SET last_seen_at = detected_at "
                         "WHERE last_seen_at IS NULL OR last_seen_at = ''")
        except sqlite3.OperationalError:
            pass

    def reset(self) -> None:
        """Drop all rows from every table (preserves schema).

        Wrapped in BEGIN IMMEDIATE with PRAGMA foreign_keys = OFF so a
        concurrent writer (worker-pool daemon in another process, or a
        scanner thread that's still mid-job) can't re-introduce child
        rows between our DELETE FROM audit_trail and DELETE FROM
        incidents and trip "FOREIGN KEY constraint failed". The deletes
        commit atomically; FKs are restored before we return.
        """
        conn = self.connect()
        try:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("BEGIN IMMEDIATE")
            for tbl in ("notifications_log", "audit_trail", "evidence_chain",
                        "playbook_execution", "incident_occurrences",
                        "incidents"):
                conn.execute(f"DELETE FROM {tbl}")
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            try:
                conn.execute("PRAGMA foreign_keys = ON")
            except Exception:
                pass
        self._invalidate_summary_cache()

    def _candidate_source_paths(self, source_path: str) -> list:
        """Return every plausible textual variant of a source_path so the
        purge / count logic survives Windows/POSIX slash drift and case
        differences. SQLite '=' is byte-exact so we must enumerate variants
        rather than rely on string equality alone."""
        if not source_path:
            return []
        try:
            resolved = str(Path(source_path).resolve())
        except Exception:
            resolved = source_path
        out = set()
        for v in (source_path, resolved):
            out.add(v)
            out.add(v.replace("\\", "/"))
            out.add(v.replace("/", "\\"))
        return list(out)

    def count_source_incidents(self, source_path: str,
                               match_by_filename: bool = False) -> int:
        """Count incidents tied to a source_path (with slash-variant
        tolerance). If match_by_filename=True, also count incidents whose
        source_path BASENAME matches -- catches orphans left when a source
        was renamed or re-added under a new path."""
        cands = self._candidate_source_paths(source_path)
        if not cands:
            return 0
        conn = self.connect()
        placeholders = ",".join("?" * len(cands))
        # Build one OR'd WHERE so each matching row is counted exactly once
        # (no additive double-counting across clauses).
        clauses = [f"source_path IN ({placeholders})"]
        params = list(cands)
        if match_by_filename:
            base = Path(source_path).name
            # Same-basename rows -- catches a source re-added under a new path.
            clauses.append("source_path LIKE ? OR source_path LIKE ?")
            params += [f"%/{base}", f"%\\{base}"]
            # Directory sources: a folder source (e.g. an EVTX directory) stores
            # its incidents under the per-FILE paths that live inside it, so the
            # exact/basename matches above never hit. Count descendants of the
            # folder too. LIKE wildcards are escaped because EVTX filenames
            # legitimately contain '%' (e.g. "...SMBServer%4Security.evtx").
            norm = source_path.replace("\\", "/").rstrip("/")
            if norm:
                esc = (norm.replace("\\", "\\\\")
                           .replace("%", "\\%").replace("_", "\\_"))
                clauses.append(r"source_path LIKE ? ESCAPE '\'")
                params.append(esc + "/%")
        sql = ("SELECT COUNT(*) FROM incidents WHERE "
               + " OR ".join(f"({c})" for c in clauses))
        return int(conn.execute(sql, params).fetchone()[0])

    def count_orphan_incidents(self, active_source_paths: list) -> int:
        """How many incidents are NOT tied to any path in active_source_paths
        (path equality across slash variants). Used by the Rescan flow to
        offer cleanup of incidents whose source has been removed/renamed."""
        active_variants = set()
        for p in active_source_paths or []:
            for v in self._candidate_source_paths(p):
                active_variants.add(v)
        active_variants.discard("")
        conn = self.connect()
        if not active_variants:
            # No registered sources -- ALL incidents are orphans by definition.
            return int(conn.execute(
                "SELECT COUNT(*) FROM incidents").fetchone()[0])
        placeholders = ",".join("?" * len(active_variants))
        params = list(active_variants)
        return int(conn.execute(
            f"SELECT COUNT(*) FROM incidents "
            f"WHERE source_path NOT IN ({placeholders}) "
            f"OR source_path IS NULL OR source_path = ''",
            params).fetchone()[0])

    def purge_orphan_incidents(self, active_source_paths: list) -> int:
        """Delete every incident (and its child rows) whose source_path does
        not match any path in active_source_paths. Returns the count removed."""
        active_variants = set()
        for p in active_source_paths or []:
            for v in self._candidate_source_paths(p):
                active_variants.add(v)
        active_variants.discard("")
        conn = self.connect()
        if active_variants:
            placeholders = ",".join("?" * len(active_variants))
            sel = (f"SELECT incident_id FROM incidents "
                   f"WHERE source_path NOT IN ({placeholders}) "
                   f"OR source_path IS NULL OR source_path = ''")
            params: list = list(active_variants)
        else:
            sel = "SELECT incident_id FROM incidents"
            params = []
        cur = conn.execute(sel, params)
        inc_ids = [row[0] for row in cur.fetchall()]
        if not inc_ids:
            return 0
        ph_inc = ",".join("?" * len(inc_ids))
        for tbl in ("notifications_log", "audit_trail", "evidence_chain",
                    "playbook_execution", "incident_occurrences"):
            conn.execute(
                f"DELETE FROM {tbl} WHERE incident_id IN ({ph_inc})",
                inc_ids)
        conn.execute(
            f"DELETE FROM incidents WHERE incident_id IN ({ph_inc})",
            inc_ids)
        self._invalidate_summary_cache()
        return len(inc_ids)

    def purge_source(self, source_path: str,
                     match_by_filename: bool = False) -> int:
        """Delete every incident (and its child rows) created from a given
        source_path. Used by the Data Sources tab's Rescan button.

        Path comparison is slash-variant tolerant (Windows file paths get
        persisted with backslashes in some code paths and forward slashes
        in others -- equality alone misses ~half the matches).

        Set match_by_filename=True to ALSO sweep incidents whose
        source_path BASENAME matches (e.g. cleans up orphans from a source
        that was renamed or re-added under a new path).

        Returns the number of incidents removed.
        """
        cands = self._candidate_source_paths(source_path)
        if not cands:
            return 0
        conn = self.connect()
        placeholders = ",".join("?" * len(cands))
        sel = (f"SELECT incident_id FROM incidents WHERE source_path IN "
               f"({placeholders})")
        params: list = list(cands)
        if match_by_filename:
            base = Path(source_path).name
            sel = (f"SELECT incident_id FROM incidents "
                   f"WHERE source_path IN ({placeholders}) "
                   f"OR source_path LIKE ? OR source_path LIKE ?")
            params = list(cands) + [f"%/{base}", f"%\\{base}"]
        cur = conn.execute(sel, params)
        inc_ids = [row[0] for row in cur.fetchall()]
        if not inc_ids:
            return 0
        # Delete child rows first (FKs are on but no ON DELETE CASCADE).
        ph_inc = ",".join("?" * len(inc_ids))
        for tbl in ("notifications_log", "audit_trail", "evidence_chain",
                    "playbook_execution", "incident_occurrences"):
            conn.execute(
                f"DELETE FROM {tbl} WHERE incident_id IN ({ph_inc})",
                inc_ids)
        conn.execute(
            f"DELETE FROM incidents WHERE incident_id IN ({ph_inc})",
            inc_ids)
        self._invalidate_summary_cache()
        return len(inc_ids)

    # ------------------------------------------------------------------
    # Incident CRUD
    # ------------------------------------------------------------------
    def next_incident_id(self, prefix: str = "INC") -> str:
        """Generate the next incident_id in the form INC-YYYY-NNNNNN.

        Iterates all current-year IDs and picks the NUMERIC max + 1.
        The naive "ORDER BY incident_id DESC LIMIT 1" approach lexically
        sorts "INC-YYYY-9999" above "INC-YYYY-10000" (because '9' > '1'),
        so once the sequence crosses 9999 every subsequent call hands
        out a colliding 10000 and every insert dies with
        "UNIQUE constraint failed: incidents.incident_id". A 10-k-row
        scan is a few ms in SQLite, so iterate.

        Suffix width widened from 4 -> 6 digits for forward-compat;
        existing 4-digit IDs are still recognised because we split on
        '-' rather than slicing fixed offsets.
        """
        year = datetime.now().year
        conn = self.connect()
        cur  = conn.execute(
            "SELECT incident_id FROM incidents WHERE incident_id LIKE ?",
            (f"{prefix}-{year}-%",))
        max_n = 0
        for (existing_id,) in cur.fetchall():
            try:
                n_val = int(existing_id.rsplit("-", 1)[-1])
            except (ValueError, IndexError):
                continue
            if n_val > max_n:
                max_n = n_val
        return f"{prefix}-{year}-{max_n + 1:06d}"

    def create_incident(self,
                        incident_type:       str,
                        its_score:           float,
                        severity:            str,
                        attack_tactic:       str  = "",
                        attack_technique:    str  = "",
                        assigned_to:         str  = "",
                        playbook_id:         str  = "",
                        summary:             str  = "",
                        detected_at:         Optional[datetime] = None,
                        incident_id:         Optional[str] = None,
                        source_kind:         str  = "",
                        source_name:         str  = "",
                        source_path:         str  = "",
                        source_csv_path:     str  = "",
                        source_row_index:    int  = -1,
                        source_event_hash:   str  = "",
                        supervised_model_id: int  = 0,
                        source_host:         str  = "",
                        detection_driver:    str  = "",
                        verdict_agreement:   str  = "",
                        ai_incident_type:    str  = "",
                        ai_label:            str  = "",
                        ai_confidence:       float = 0.0,
                        ai_model_id:         int  = 0,
                        ai_severity:         str  = "",
                        rule_incident_type:  str  = "",
                        rule_label:          str  = "",
                        rule_severity:       str  = "",
                        rule_id:             str  = "",
                        return_status:       bool = False,
                        ):
        """Persist an incident, merging into an existing OPEN incident when
        (source_host, incident_type, attack_technique) collides.

        Merge semantics:
          - dedup_key = sha1(host|type|technique)[:16]; empty when host is
            blank, in which case we always insert a fresh row (can't safely
            collapse cross-host incidents)
          - On merge: incident_id of the existing row is returned. its_score
            escalates via `_escalated_its(base_its, new_count)`, severity is
            re-derived from the escalated value, last_seen_at is bumped,
            occurrence_count increments, and a row lands in
            `incident_occurrences` carrying the per-event traceability so
            forensics still has the full event ledger.
          - Audit log records DEDUP_MERGE rather than INCIDENT_CREATED.
        Returns the incident_id (existing on merge, new on create).
        """
        conn = self.connect()
        ts = (detected_at or datetime.now()).isoformat()
        # Normalize source_path to forward slashes so case-store lookups
        # don't get split across slash-style variants. Different write
        # paths (in-process worker, worker-pool daemon, bulk subprocess)
        # otherwise persist the same logical file under two textual forms.
        if source_path:
            source_path = source_path.replace("\\", "/")
        if source_csv_path:
            source_csv_path = source_csv_path.replace("\\", "/")
        dedup_key = _compute_dedup_key(source_host, incident_type,
                                       attack_technique)

        # --- Merge path ----------------------------------------------------
        if dedup_key:
            row = conn.execute(
                "SELECT incident_id, occurrence_count, base_its FROM incidents "
                "WHERE dedup_key = ? AND status = 'OPEN' LIMIT 1",
                (dedup_key,)).fetchone()
            if row is not None:
                existing_id = row["incident_id"]
                new_count = int(row["occurrence_count"] or 1) + 1
                base = float(row["base_its"] or its_score)
                eff_its = _escalated_its(base, new_count)
                new_sev = _severity_from_its(eff_its)
                conn.execute(
                    "UPDATE incidents SET occurrence_count = ?, "
                    "  last_seen_at = ?, its_score = ?, severity = ? "
                    "WHERE incident_id = ?",
                    (new_count, ts, eff_its, new_sev, existing_id))
                # A merge mutates occurrence_count / its_score / last_seen_at,
                # so the dashboard watermark MUST bump even though we only
                # write an audit row once (below). Without this, every merge
                # past the 2nd left data_version unchanged and the Incidents
                # tab never re-rendered -- the count column froze while the
                # real occurrence_count kept climbing into the thousands.
                self._invalidate_summary_cache()
                # Forensic ledger: keep only the first N raw events per
                # incident (occurrence_count above stays exact). A 29k-event
                # EVTX burst would otherwise write 29k occurrence rows.
                if new_count <= _MAX_OCCURRENCES_PER_INCIDENT:
                    self._log_occurrence(existing_id, ts, its_score,
                                         source_path, source_row_index,
                                         source_event_hash)
                # Audit ONCE per incident (on the first merge), not per event.
                # Writing a DEDUP_MERGE row for every merged event ballooned
                # the audit_trail to 100k+ rows on a single EVTX scan; the
                # incident's occurrence_count + last_seen_at already record
                # the running tally for any later reader.
                if new_count == 2:
                    self.log_audit(
                        existing_id, action="DEDUP_MERGE",
                        performed_by="system",
                        change_summary=(
                            f"recurring event merged (host={source_host} "
                            f"type={incident_type}); further merges update "
                            f"occurrence_count silently"))
                return (existing_id, "merged") if return_status else existing_id

        # --- Fresh-insert path --------------------------------------------
        inc_id = incident_id or self.next_incident_id()
        conn.execute(
            "INSERT INTO incidents (incident_id, incident_type, detected_at, "
            "  its_score, severity, attack_tactic, attack_technique, status, "
            "  assigned_to, playbook_id, summary, "
            "  source_kind, source_name, source_path, source_csv_path, "
            "  source_row_index, source_event_hash, supervised_model_id, "
            "  source_host, dedup_key, occurrence_count, "
            "  first_seen_at, last_seen_at, base_its, "
            "  detection_driver, verdict_agreement, ai_incident_type, "
            "  ai_label, ai_confidence, ai_model_id, ai_severity, "
            "  rule_incident_type, rule_label, rule_severity, rule_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "        ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (inc_id, incident_type, ts, float(its_score), severity,
             attack_tactic, attack_technique, assigned_to, playbook_id, summary,
             source_kind, source_name, source_path, source_csv_path,
             int(source_row_index), source_event_hash, int(supervised_model_id),
             source_host, dedup_key, ts, ts, float(its_score),
             detection_driver, verdict_agreement, ai_incident_type,
             ai_label, float(ai_confidence), int(ai_model_id), ai_severity,
             rule_incident_type, rule_label, rule_severity, rule_id))
        self._log_occurrence(inc_id, ts, its_score, source_path,
                             source_row_index, source_event_hash)
        # Include the source in the audit change_summary so chain readers
        # can reconstruct origin even from the audit log alone.
        src_tag = (f" source_kind={source_kind}" if source_kind else "") + \
                  (f" source_name={source_name}" if source_name else "") + \
                  (f" host={source_host}" if source_host else "")
        self.log_audit(inc_id, action="INCIDENT_CREATED",
                       performed_by="system",
                       change_summary=f"type={incident_type} its={its_score:.3f} "
                                      f"severity={severity}{src_tag}")
        return (inc_id, "created") if return_status else inc_id

    def _log_occurrence(self, incident_id: str, observed_at: str,
                        its_score: float, source_path: str,
                        source_row_index: int, source_event_hash: str) -> None:
        """Insert one row into incident_occurrences. Called from both the
        fresh-create and merge branches of create_incident so the forensic
        ledger captures every raw event regardless of how the parent
        incident was persisted."""
        try:
            self.connect().execute(
                "INSERT INTO incident_occurrences "
                "(incident_id, observed_at, its_score, source_path, "
                " source_row_index, source_event_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (incident_id, observed_at, float(its_score),
                 source_path, int(source_row_index), source_event_hash))
        except sqlite3.OperationalError:
            # Table missing on a very old DB that skipped init_schema().
            # Don't let the ledger insert break the parent persistence.
            pass

    def get_occurrences(self, incident_id: str) -> List[Dict[str, Any]]:
        """Return the chronological list of raw events behind an incident.
        Used by the Incident Detail view to show 'this incident represents
        N events between T0 and T1'."""
        conn = self.connect()
        rows = conn.execute(
            "SELECT * FROM incident_occurrences WHERE incident_id = ? "
            "ORDER BY observed_at ASC", (incident_id,)).fetchall()
        return [dict(r) for r in rows]

    def exists_by_event_hash(self, event_hash: str) -> bool:
        """Return True if any incident already carries this
        source_event_hash. Used by the EVTX episode promoter to avoid
        re-persisting the same episode on re-scan."""
        if not event_hash:
            return False
        conn = self.connect()
        row = conn.execute(
            "SELECT 1 FROM incidents WHERE source_event_hash = ? LIMIT 1",
            (event_hash,)).fetchone()
        return row is not None

    def update_incident_status(self, incident_id: str, status: str,
                               performed_by: str = "system") -> None:
        if status not in ("OPEN", "CONTAINED", "CLOSED", "ABANDONED"):
            raise ValueError(f"Invalid status: {status}")
        conn = self.connect()
        if status == "CLOSED":
            conn.execute(
                "UPDATE incidents SET status=?, closed_at=? WHERE incident_id=?",
                (status, datetime.now().isoformat(), incident_id))
        else:
            conn.execute(
                "UPDATE incidents SET status=? WHERE incident_id=?",
                (status, incident_id))
        self.log_audit(incident_id, action=f"STATUS_CHANGE",
                       performed_by=performed_by,
                       change_summary=f"new_status={status}")

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        conn = self.connect()
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?",
            (incident_id,)).fetchone()
        if row is None:
            return None
        return Incident(**{k: row[k] for k in row.keys()})

    def list_incidents(self, status: Optional[str] = None,
                       incident_type: Optional[str] = None,
                       limit: int = 100) -> List[Incident]:
        conn  = self.connect()
        where, params = [], []
        if status:
            where.append("status=?"); params.append(status)
        if incident_type:
            where.append("incident_type=?"); params.append(incident_type)
        sql = "SELECT * FROM incidents"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [Incident(**{k: r[k] for k in r.keys()}) for r in rows]

    def list_open_incidents(self) -> List[Incident]:
        return self.list_incidents(status="OPEN")

    # ------------------------------------------------------------------
    # Playbook execution log
    # ------------------------------------------------------------------
    def log_playbook_step(self, incident_id: str, step_id: str,
                          executed_by: str = "system",
                          outcome: str = "COMPLETED",
                          deadline_met: Optional[bool] = None,
                          notes: str = "",
                          executed_at: Optional[datetime] = None) -> int:
        conn = self.connect()
        ts   = (executed_at or datetime.now()).isoformat()
        dm   = None if deadline_met is None else (1 if deadline_met else 0)
        cur  = conn.execute(
            "INSERT INTO playbook_execution "
            "(incident_id, step_id, executed_at, executed_by, outcome, "
            " deadline_met, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (incident_id, step_id, ts, executed_by, outcome, dm, notes))
        self._invalidate_summary_cache()
        return cur.lastrowid

    def get_playbook_executions(self, incident_id: str,
                                limit: Optional[int] = None
                                ) -> List[Dict[str, Any]]:
        conn = self.connect()
        if limit and int(limit) > 0:
            rows = conn.execute(
                "SELECT * FROM playbook_execution WHERE incident_id=? "
                "ORDER BY executed_at DESC LIMIT ?",
                (incident_id, int(limit))).fetchall()
            rows = list(reversed(rows))
        else:
            rows = conn.execute(
                "SELECT * FROM playbook_execution WHERE incident_id=? "
                "ORDER BY executed_at ASC", (incident_id,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Evidence chain
    # ------------------------------------------------------------------
    @staticmethod
    def sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def add_evidence(self, incident_id: str, source_type: str,
                     file_path: str, description: str = "",
                     file_hash: Optional[str] = None,
                     collected_at: Optional[datetime] = None) -> int:
        if file_hash is None and Path(file_path).exists():
            file_hash = self.sha256(Path(file_path))
        file_hash = file_hash or "missing"
        conn = self.connect()
        ts   = (collected_at or datetime.now()).isoformat()
        cur  = conn.execute(
            "INSERT INTO evidence_chain "
            "(incident_id, source_type, file_hash, collected_at, "
            " file_path, description) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, source_type, file_hash, ts, file_path, description))
        self.log_audit(incident_id, action="EVIDENCE_ADDED",
                       performed_by="system",
                       change_summary=f"hash={file_hash[:16]}... path={file_path}")
        return cur.lastrowid

    def get_evidence_chain(self, incident_id: str,
                           limit: Optional[int] = None
                           ) -> List[Dict[str, Any]]:
        conn = self.connect()
        if limit and int(limit) > 0:
            rows = conn.execute(
                "SELECT * FROM evidence_chain WHERE incident_id=? "
                "ORDER BY collected_at DESC LIMIT ?",
                (incident_id, int(limit))).fetchall()
            rows = list(reversed(rows))
        else:
            rows = conn.execute(
                "SELECT * FROM evidence_chain WHERE incident_id=? "
                "ORDER BY collected_at ASC", (incident_id,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------
    def log_audit(self, incident_id: Optional[str], action: str,
                  performed_by: str = "system", ip_address: str = "",
                  change_summary: str = "",
                  performed_at: Optional[datetime] = None) -> int:
        conn = self.connect()
        ts   = (performed_at or datetime.now()).isoformat()
        cur  = conn.execute(
            "INSERT INTO audit_trail "
            "(incident_id, action, performed_by, performed_at, "
            " ip_address, change_summary) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, action, performed_by, ts, ip_address, change_summary))
        self._invalidate_summary_cache()
        return cur.lastrowid

    def get_audit_trail(self, incident_id: str,
                        limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Audit rows for an incident, chronological (ASC). `limit` caps to the
        most-recent N rows (still returned ASC) -- used by the dashboard to
        avoid loading a legacy incident's 80k+ trail into the UI. Reports pass
        no limit and get the full trail."""
        conn = self.connect()
        if limit and int(limit) > 0:
            rows = conn.execute(
                "SELECT * FROM audit_trail WHERE incident_id=? "
                "ORDER BY performed_at DESC LIMIT ?",
                (incident_id, int(limit))).fetchall()
            rows = list(reversed(rows))
        else:
            rows = conn.execute(
                "SELECT * FROM audit_trail WHERE incident_id=? "
                "ORDER BY performed_at ASC", (incident_id,)).fetchall()
        return [dict(r) for r in rows]

    def count_audit_trail(self, incident_id: str) -> int:
        """Cheap COUNT(*) of audit rows for an incident -- avoids pulling the
        whole trail just to display 'N entries'."""
        conn = self.connect()
        return int(conn.execute(
            "SELECT COUNT(*) FROM audit_trail WHERE incident_id=?",
            (incident_id,)).fetchone()[0])

    # ------------------------------------------------------------------
    # Notifications log
    # ------------------------------------------------------------------
    def log_notification(self, incident_id: str, channel: str,
                         recipient: str, delivery_status: str = "SENT",
                         subject: str = "", body_excerpt: str = "",
                         sent_at: Optional[datetime] = None) -> int:
        if channel not in ("EMAIL", "SMS", "DASHBOARD", "PAGE"):
            raise ValueError(f"Invalid channel: {channel}")
        if delivery_status not in ("SENT", "FAILED", "PENDING"):
            raise ValueError(f"Invalid delivery_status: {delivery_status}")
        conn = self.connect()
        ts   = (sent_at or datetime.now()).isoformat()
        cur  = conn.execute(
            "INSERT INTO notifications_log "
            "(incident_id, channel, recipient, sent_at, delivery_status, "
            " subject, body_excerpt) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (incident_id, channel, recipient, ts, delivery_status,
             subject, body_excerpt[:200]))
        self._invalidate_summary_cache()
        return cur.lastrowid

    def get_notifications(self, incident_id: str,
                          limit: Optional[int] = None
                          ) -> List[Dict[str, Any]]:
        conn = self.connect()
        if limit and int(limit) > 0:
            rows = conn.execute(
                "SELECT * FROM notifications_log WHERE incident_id=? "
                "ORDER BY sent_at DESC LIMIT ?",
                (incident_id, int(limit))).fetchall()
            rows = list(reversed(rows))
        else:
            rows = conn.execute(
                "SELECT * FROM notifications_log WHERE incident_id=? "
                "ORDER BY sent_at ASC", (incident_id,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Composite timeline
    # ------------------------------------------------------------------
    def get_incident_timeline(self, incident_id: str,
                              limit: Optional[int] = None
                              ) -> List[Dict[str, Any]]:
        """Returns a chronologically-merged timeline of audit_trail +
        playbook_execution + evidence_chain + notifications_log events
        for the incident. `limit` caps the audit pull AND the merged result to
        the most-recent N events (the audit trail is the only source that can
        balloon). Default None = full timeline (reports rely on this)."""
        events: List[Dict[str, Any]] = []
        for r in self.get_audit_trail(incident_id, limit=limit):
            events.append({"ts": r["performed_at"], "type": "AUDIT",
                           "summary": f"{r['action']}: {r['change_summary']}",
                           "by": r["performed_by"]})
        for r in self.get_playbook_executions(incident_id, limit=limit):
            events.append({"ts": r["executed_at"], "type": "PLAYBOOK",
                           "summary": f"Step {r['step_id']} -> {r['outcome']}",
                           "by": r["executed_by"]})
        for r in self.get_evidence_chain(incident_id, limit=limit):
            events.append({"ts": r["collected_at"], "type": "EVIDENCE",
                           "summary": f"{r['source_type']} hash={r['file_hash'][:16]}...",
                           "by": "system"})
        for r in self.get_notifications(incident_id, limit=limit):
            events.append({"ts": r["sent_at"], "type": "NOTIFY",
                           "summary": f"{r['channel']} -> {r['recipient']} ({r['delivery_status']})",
                           "by": "system"})
        events.sort(key=lambda e: e["ts"])
        if limit and int(limit) > 0 and len(events) > int(limit):
            events = events[-int(limit):]
        return events

    # ------------------------------------------------------------------
    # Summary statistics
    # ------------------------------------------------------------------
    # Summary stats are queried by every dashboard widget on every tick.
    # We cache the result for a short TTL (default 1s) so a 6-widget
    # refresh hits SQLite once instead of six times. The cache is
    # invalidated on any write (create_incident, log_audit, etc.) below.
    _summary_cache_ttl_s = 1.0

    def _invalidate_summary_cache(self) -> None:
        if hasattr(self, "_summary_cache"):
            self._summary_cache = None
        # Bump the write watermark so dashboard widgets know to re-render.
        self.data_version += 1

    def bump_data_version(self) -> int:
        """Externally announce that the underlying SQLite file changed
        beneath us (e.g. a worker-pool daemon wrote to it in another
        process). The dashboard calls this after a successful pool
        dispatch so widgets refresh from the new rows."""
        self._invalidate_summary_cache()
        return self.data_version

    def summarise(self, force: bool = False) -> dict:
        import time
        if not force and getattr(self, "_summary_cache", None):
            ts, payload = self._summary_cache
            if (time.monotonic() - ts) < self._summary_cache_ttl_s:
                return payload

        conn = self.connect()
        n_inc = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        per_status = {r[0]: r[1] for r in conn.execute(
            "SELECT status, COUNT(*) FROM incidents GROUP BY status")}
        per_type = {r[0]: r[1] for r in conn.execute(
            "SELECT incident_type, COUNT(*) FROM incidents GROUP BY incident_type")}
        n_steps = conn.execute("SELECT COUNT(*) FROM playbook_execution").fetchone()[0]
        n_evidence = conn.execute("SELECT COUNT(*) FROM evidence_chain").fetchone()[0]
        n_audit = conn.execute("SELECT COUNT(*) FROM audit_trail").fetchone()[0]
        n_notify = conn.execute("SELECT COUNT(*) FROM notifications_log").fetchone()[0]
        payload = {
            "n_incidents":            n_inc,
            "incidents_by_status":    per_status,
            "incidents_by_type":      per_type,
            "n_playbook_steps":       n_steps,
            "n_evidence_artefacts":   n_evidence,
            "n_audit_events":         n_audit,
            "n_notifications":        n_notify,
        }
        self._summary_cache = (time.monotonic(), payload)
        return payload


# ---------------------------------------------------------------------------
# CLI smoke test (uses a throwaway db in /tmp-like location)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile
    tmp = Path(tempfile.gettempdir()) / "eirp_cases_smoke.db"
    if tmp.exists():
        tmp.unlink()

    store = CaseStore(tmp)
    store.init_schema()

    # Create three incidents
    inc1 = store.create_incident("INC-01", 0.78, "HIGH",
        attack_tactic="TA0010", attack_technique="T1041",
        assigned_to="IT_SECURITY+DPO", playbook_id="PB-01",
        summary="PHI exposure detected from external IP")
    inc2 = store.create_incident("INC-02", 0.92, "CRITICAL",
        attack_tactic="TA0040", attack_technique="T1486",
        assigned_to="IT_SECURITY", playbook_id="PB-02",
        summary="Ransomware encryption indicator")
    inc3 = store.create_incident("INC-04", 0.65, "HIGH",
        attack_tactic="TA0006", attack_technique="T1078.001",
        assigned_to="IT_SECURITY+HR", playbook_id="PB-04",
        summary="Insider abuse pattern detected")

    print(f"Created incidents: {inc1}, {inc2}, {inc3}")

    # Walk through PB-01 for inc1
    pb01_steps = ["PB-01-S01","PB-01-S02","PB-01-S03","PB-01-S04",
                  "PB-01-S05","PB-01-S06"]
    for s in pb01_steps:
        store.log_playbook_step(inc1, s, executed_by="alice",
                                 outcome="COMPLETED", deadline_met=True)
    store.add_evidence(inc1, "LIRA", "/var/log/lira_2026.csv",
                       description="LIRA parser output snapshot",
                       file_hash="a" * 64)
    store.log_notification(inc1, "EMAIL", "dpo@hospital.gov.ng",
                           subject="PHI breach alert", delivery_status="SENT")
    store.log_notification(inc1, "SMS", "+2348012345678",
                           delivery_status="SENT")
    store.update_incident_status(inc1, "CONTAINED")

    print(f"\nSummary: {store.summarise()}")
    print(f"\nTimeline for {inc1}:")
    for ev in store.get_incident_timeline(inc1):
        print(f"  {ev['ts'][:19]}  [{ev['type']:<8}]  {ev['summary']}")

    store.close()
    print(f"\nSmoke test passed. Temp db at: {tmp}")
