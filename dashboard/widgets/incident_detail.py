"""dashboard/widgets/incident_detail.py

A modal QDialog that surfaces EVERYTHING the dashboard knows about one
incident in a single place. Opens via double-click on any incident row
across the dashboard (Open Incidents table, Live Stream, Notification
Center, Audit & Forensics).

Layout: tabbed
  - Overview       summary, ITS, severity, ATT&CK, source attribution
  - Playbook       per-step status with deadline + automation flag
  - Response       containment actions + recovery checklist (side-by-side)
  - Compliance     NDPR articles per-finding + audit chain hash
  - Timeline       full chronological audit_trail for this incident

Pure read-only consumer of the existing backend singletons. No writes.
Per-incident PDF export is wired here too (see ReportButton) so any
auditor can pull a single-incident NDPR report straight from the dialog.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QBrush, QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QTabWidget, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QPlainTextEdit, QPushButton, QFileDialog, QMessageBox,
    QSizePolicy, QScrollArea, QGraphicsDropShadowEffect, QComboBox,
)

from response.case_store import CaseStore, Incident
from response.playbook_engine import PlaybookEngine
from recovery.containment_advisor import ContainmentAdvisor
from recovery.recovery_checklist import RecoveryChecklist
from reporting.ndpr_mapper import NdprMapper


# ---------------------------------------------------------------------------
def _pill_html(label: str, kind: str = "INFO") -> str:
    """Theme-aware pill (resolves PILL_BG at call time)."""
    from dashboard.theme import PILL_BG, TEXT_SECONDARY
    kind = (kind or "").upper()
    bg = PILL_BG.get(kind, PILL_BG.get("INFO", "#1f2a3a"))
    fg = PILL_BG.get(kind + "_FG", TEXT_SECONDARY)
    return (f"<span style='background:{bg};color:{fg};"
            f"padding:3px 12px;border-radius:10px;"
            f"font-size:9pt;font-weight:600;"
            f"letter-spacing:0.4px;'>{label}</span>")


# ---------------------------------------------------------------------------
class IncidentDetailDialog(QDialog):
    """Read-only deep-dive on a single incident."""

    def __init__(self,
                 incident_id: str,
                 case_store: CaseStore,
                 playbook_engine: PlaybookEngine,
                 containment_advisor: ContainmentAdvisor,
                 recovery_checklist: RecoveryChecklist,
                 ndpr_mapper: NdprMapper,
                 audit_manager=None,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.inc_id           = incident_id
        self.case_store       = case_store
        self.engine           = playbook_engine
        self.advisor          = containment_advisor
        self.checklist        = recovery_checklist
        self.ndpr             = ndpr_mapper
        self.audit_manager    = audit_manager

        self.setWindowTitle(f"Incident {incident_id} — full detail")
        self.setMinimumSize(QSize(900, 640))
        self.resize(1100, 760)
        self.setModal(False)               # let the user reference other tabs

        self.inc: Optional[Incident] = self.case_store.get_incident(incident_id)
        if self.inc is None:
            self._build_missing_ui()
            return

        self._build_ui()
        self._populate()

    # ------------------------------------------------------------------
    def _build_missing_ui(self) -> None:
        lay = QVBoxLayout(self)
        lbl = QLabel(f"Incident {self.inc_id} not found in case store.")
        lbl.setObjectName("H2")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(lbl)
        btn = QPushButton("Close")
        btn.clicked.connect(self.accept)
        lay.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        # --- Header: ID + type + severity pill + status pill -----------
        header = QFrame()
        header.setObjectName("CardHero")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.setSpacing(20)

        lbl_id = QLabel(self.inc.incident_id)
        lbl_id.setObjectName("H1")
        hl.addWidget(lbl_id)

        lbl_type = QLabel(self.inc.incident_type)
        lbl_type.setObjectName("H2")
        hl.addWidget(lbl_type)

        hl.addStretch(1)

        self.lbl_sev = QLabel("")
        self.lbl_sev.setTextFormat(Qt.TextFormat.RichText)
        hl.addWidget(self.lbl_sev)

        self.lbl_status = QLabel("")
        self.lbl_status.setTextFormat(Qt.TextFormat.RichText)
        hl.addWidget(self.lbl_status)

        # Drop shadow for depth
        eff = QGraphicsDropShadowEffect(self)
        eff.setBlurRadius(20)
        eff.setColor(QColor(0, 0, 0, 80))
        eff.setOffset(0, 4)
        header.setGraphicsEffect(eff)
        root.addWidget(header)

        # --- Tab content -----------------------------------------------
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._build_overview_tab(),  "Overview")
        # Show the Occurrences tab only when this incident actually merged
        # events -- a single-event incident doesn't need a 1-row table.
        if int(getattr(self.inc, "occurrence_count", 1) or 1) > 1:
            self.tabs.addTab(self._build_occurrences_tab(), "Occurrences")
        self.tabs.addTab(self._build_playbook_tab(),  "Playbook")
        self.tabs.addTab(self._build_response_tab(),  "Response")
        self.tabs.addTab(self._build_compliance_tab(), "Compliance")
        self.tabs.addTab(self._build_timeline_tab(),  "Timeline")
        root.addWidget(self.tabs, 1)

        # --- Bottom action bar ----------------------------------------
        bar = QHBoxLayout()
        bar.addStretch(1)
        self.btn_export_pdf = QPushButton("Export PDF…")
        self.btn_export_pdf.setObjectName("Primary")
        self.btn_export_pdf.clicked.connect(self._export_pdf)
        bar.addWidget(self.btn_export_pdf)
        self.btn_copy = QPushButton("Copy incident ID")
        self.btn_copy.clicked.connect(self._copy_id)
        bar.addWidget(self.btn_copy)
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.accept)
        bar.addWidget(self.btn_close)
        root.addLayout(bar)

    # ------------------------------------------------------------------
    # Tab builders
    # ------------------------------------------------------------------
    def _build_overview_tab(self) -> QWidget:
        w = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer = QVBoxLayout(w)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        inner = QWidget()
        scroll.setWidget(inner)
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(8, 12, 8, 12)
        lay.setSpacing(14)

        # Two-column grid of key facts
        facts = QFrame()
        facts.setObjectName("Card")
        fl = QGridLayout(facts)
        fl.setContentsMargins(20, 18, 20, 18)
        fl.setHorizontalSpacing(28)
        fl.setVerticalSpacing(10)

        src_kind = getattr(self.inc, "source_kind", "") or ""
        src_name = getattr(self.inc, "source_name", "") or ""
        src_label = (f"{src_name} ({src_kind})" if src_name and src_kind
                     else src_name or src_kind or "—")
        # Dedup signals -- present for new (post-migration) incidents,
        # safely default for legacy ones.
        occ_count = int(getattr(self.inc, "occurrence_count", 1) or 1)
        host      = str(getattr(self.inc, "source_host", "") or "—")
        first_seen = (getattr(self.inc, "first_seen_at", "")
                      or self.inc.detected_at or "")
        last_seen  = (getattr(self.inc, "last_seen_at", "")
                      or self.inc.detected_at or "")
        base_its   = float(getattr(self.inc, "base_its", 0.0) or 0.0)
        its_cell = f"{self.inc.its_score:.3f}"
        if occ_count > 1 and base_its > 0 and base_its < self.inc.its_score:
            its_cell += f"  (base {base_its:.3f} → escalated by {occ_count} events)"
        rows = [
            ("Detected",         self._format_ts(self.inc.detected_at)),
            ("Closed",           self._format_ts(self.inc.closed_at) if self.inc.closed_at else "—"),
            ("ITS score",        its_cell),
            ("Severity",         self.inc.severity),
            ("Occurrences",      f"{occ_count:,}"),
            ("Host",             host),
            ("First seen",       self._format_ts(first_seen)),
            ("Last seen",        self._format_ts(last_seen)),
            ("Source",           src_label),
            ("ATT&CK tactic",    self.inc.attack_tactic or "(none)"),
            ("ATT&CK technique", self.inc.attack_technique or "(none)"),
            ("Playbook",         self.inc.playbook_id or "(none)"),
            ("Assigned to",      self.inc.assigned_to or "(unassigned)"),
        ]
        for i, (k, v) in enumerate(rows):
            kl = QLabel(k); kl.setObjectName("KpiLabel")
            vl = QLabel(str(v)); vl.setWordWrap(True)
            fl.addWidget(kl, i // 2, (i % 2) * 2)
            fl.addWidget(vl, i // 2, (i % 2) * 2 + 1)
        lay.addWidget(facts)

        # Detection comparison (AI vs Rule) -- only when the dual-verdict
        # pipeline recorded a driver. Legacy incidents skip this card.
        cmp_card = self._build_comparison_card()
        if cmp_card is not None:
            lay.addWidget(cmp_card)

        # Summary card
        sum_card = QFrame(); sum_card.setObjectName("Card")
        sl = QVBoxLayout(sum_card)
        sl.setContentsMargins(20, 16, 20, 16)
        st = QLabel("Detection summary"); st.setObjectName("H3")
        sl.addWidget(st)
        body = QLabel(self.inc.summary or "(no summary captured)")
        body.setObjectName("Caption")
        body.setWordWrap(True)
        sl.addWidget(body)
        lay.addWidget(sum_card)

        # Source attribution (best-effort — derived from audit_trail rows)
        src_card = QFrame(); src_card.setObjectName("Card")
        sc = QVBoxLayout(src_card)
        sc.setContentsMargins(20, 16, 20, 16)
        sct = QLabel("Source attribution"); sct.setObjectName("H3")
        sc.addWidget(sct)
        src_text = self._derive_source_attribution()
        src_lbl = QLabel(src_text); src_lbl.setObjectName("Caption")
        src_lbl.setWordWrap(True)
        src_lbl.setTextFormat(Qt.TextFormat.RichText)
        sc.addWidget(src_lbl)
        lay.addWidget(src_card)

        # Source event -- the actual parsed row that triggered this incident.
        # Loaded once; the analyst toggles between a curated "Key fields" view
        # (eye-catching essentials), "All fields" (every column, nothing
        # hidden), and "JSON" -- so there's no need to open a CSV viewer.
        ev_card = QFrame(); ev_card.setObjectName("Card")
        evl = QVBoxLayout(ev_card)
        evl.setContentsMargins(20, 16, 20, 16)
        evl.setSpacing(8)
        evt_title_row = QHBoxLayout()
        evt = QLabel("Source event"); evt.setObjectName("H3")
        evt_title_row.addWidget(evt)
        evt_title_row.addStretch(1)
        row_info = self._source_row_info()
        if row_info:
            row_pill = QLabel(
                f"<span style='color:#7c8aa1;font-size:9pt;'>row "
                f"#{row_info} in parsed CSV</span>")
            row_pill.setTextFormat(Qt.TextFormat.RichText)
            evt_title_row.addWidget(row_pill)
        evl.addLayout(evt_title_row)

        # Load the row once; the toggle re-renders from the cached dict.
        self._src_event_row, self._src_event_status = \
            self._load_source_event_row()

        if self._src_event_row:
            view_row = QHBoxLayout()
            view_row.setSpacing(8)
            vlab = QLabel("View:"); vlab.setObjectName("Caption")
            view_row.addWidget(vlab)
            self._ev_view = QComboBox()
            self._ev_view.addItem("Key fields", "key")
            self._ev_view.addItem(
                f"All fields ({self._src_event_field_count()})", "all")
            self._ev_view.addItem("JSON", "json")
            self._ev_view.currentIndexChanged.connect(
                lambda _i: self._set_source_event_view(
                    self._ev_view.currentData()))
            view_row.addWidget(self._ev_view)
            view_row.addStretch(1)
            evl.addLayout(view_row)

        self._ev_body = QLabel()
        self._ev_body.setObjectName("Caption")
        self._ev_body.setWordWrap(True)
        self._ev_body.setTextFormat(Qt.TextFormat.RichText)
        self._ev_body.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        evl.addWidget(self._ev_body)
        self._set_source_event_view("key")
        lay.addWidget(ev_card)

        # ATT&CK reference (link-friendly text)
        if self.inc.attack_technique:
            attack_card = QFrame(); attack_card.setObjectName("Card")
            ac = QVBoxLayout(attack_card)
            ac.setContentsMargins(20, 16, 20, 16)
            at = QLabel("ATT&CK reference"); at.setObjectName("H3")
            ac.addWidget(at)
            attack_text = (
                f"<b>{self.inc.attack_tactic}</b> · {self.inc.attack_technique}<br>"
                f"<span style='color:#7c8aa1;font-size:9pt;'>"
                f"MITRE reference: https://attack.mitre.org/techniques/"
                f"{self.inc.attack_technique.replace('.', '/')}/</span>")
            al = QLabel(attack_text); al.setTextFormat(Qt.TextFormat.RichText)
            al.setWordWrap(True)
            al.setObjectName("Caption")
            ac.addWidget(al)
            lay.addWidget(attack_card)

        lay.addStretch(1)
        return w

    # ------------------------------------------------------------------
    def _build_comparison_card(self) -> Optional[QWidget]:
        """AI-vs-Rule verdict comparison. Returns None for legacy incidents
        that pre-date the dual-verdict pipeline (no detection_driver set)."""
        driver = (getattr(self.inc, "detection_driver", "") or "").upper()
        agreement = (getattr(self.inc, "verdict_agreement", "") or "").upper()
        if not driver and not agreement:
            return None

        ai_type  = getattr(self.inc, "ai_incident_type", "") or "—"
        ai_label = getattr(self.inc, "ai_label", "") or "—"
        ai_conf  = float(getattr(self.inc, "ai_confidence", 0.0) or 0.0)
        ai_mid   = int(getattr(self.inc, "ai_model_id", 0) or 0)
        ai_sev   = getattr(self.inc, "ai_severity", "") or "—"
        rule_type = getattr(self.inc, "rule_incident_type", "") or "—"
        rule_lbl  = getattr(self.inc, "rule_label", "") or "—"
        rule_sev  = getattr(self.inc, "rule_severity", "") or "—"
        rule_rid  = getattr(self.inc, "rule_id", "") or "—"

        # Agreement pill colour: AGREE green, DISAGREE amber, *_ONLY grey-blue.
        agree_kind = {"AGREE": "LOW", "DISAGREE": "HIGH",
                      "AI_ONLY": "INFO", "RULE_ONLY": "INFO"}.get(
                          agreement, "INFO")

        card = QFrame(); card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 16, 20, 16)
        cl.setSpacing(10)

        head = QHBoxLayout()
        title = QLabel("Detection comparison — AI vs Rule")
        title.setObjectName("H3")
        head.addWidget(title)
        head.addStretch(1)
        driver_lbl = QLabel(_pill_html(f"DRIVER: {driver or '—'}",
                                       "CRITICAL" if driver == "AI" else "INFO"))
        driver_lbl.setTextFormat(Qt.TextFormat.RichText)
        head.addWidget(driver_lbl)
        agree_lbl = QLabel(_pill_html(agreement or "—", agree_kind))
        agree_lbl.setTextFormat(Qt.TextFormat.RichText)
        head.addWidget(agree_lbl)
        cl.addLayout(head)

        ai_conf_s = f"{ai_conf*100:.1f}%" if ai_conf > 0 else "—"
        ai_model_s = f"Model {ai_mid}" if ai_mid else "Model B (meta)"
        grid_html = (
            "<table cellspacing='0' cellpadding='0' style='border:0;width:100%;'>"
            "<tr>"
            "<td style='padding:0 24px 0 0;vertical-align:top;width:50%;'>"
            "<div style='color:#5aa9ff;font-weight:700;font-size:10pt;"
            "margin-bottom:4px;'>AI verdict</div>"
            f"<div style='font-size:9.5pt;line-height:1.6;'>"
            f"<b>Incident:</b> {ai_type}<br>"
            f"<b>Label:</b> {ai_label}<br>"
            f"<b>Severity:</b> {ai_sev}<br>"
            f"<b>Confidence:</b> {ai_conf_s}<br>"
            f"<b>Source:</b> {ai_model_s}</div></td>"
            "<td style='padding:0 0 0 24px;vertical-align:top;width:50%;"
            "border-left:1px solid #2a3340;'>"
            "<div style='color:#c8a24a;font-weight:700;font-size:10pt;"
            "margin-bottom:4px;'>Rule verdict</div>"
            f"<div style='font-size:9.5pt;line-height:1.6;'>"
            f"<b>Incident:</b> {rule_type}<br>"
            f"<b>Label:</b> {rule_lbl}<br>"
            f"<b>Severity:</b> {rule_sev}<br>"
            f"<b>Rule:</b> {rule_rid}</div></td>"
            "</tr></table>")
        grid = QLabel(grid_html)
        grid.setTextFormat(Qt.TextFormat.RichText)
        grid.setWordWrap(True)
        cl.addWidget(grid)

        # On DISAGREE, driver==RULE means the severity guardrail fired (the
        # rule flagged CRITICAL and the AI would have down-graded it).
        if agreement == "DISAGREE" and driver == "RULE":
            note = ("Severity guardrail: the rule engine flagged this event "
                    "CRITICAL and the AI verdict would have down-graded it, so "
                    "the rule verdict drove this incident.")
        else:
            note = {
                "AGREE":     "Both detectors independently reached the same "
                             "incident class.",
                "DISAGREE":  "The AI and rule engine reached different classes — "
                             "the AI verdict drove this incident (AI-primary).",
                "AI_ONLY":   "Only the AI flagged this event; the deterministic "
                             "rules stayed silent.",
                "RULE_ONLY": "Only the rule engine flagged this event (AI was "
                             "silent) — raised via the rule safety net.",
            }.get(agreement, "")
        if note:
            nl = QLabel(note); nl.setObjectName("Caption"); nl.setWordWrap(True)
            cl.addWidget(nl)
        return card

    # ------------------------------------------------------------------
    def _build_playbook_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 12, 0, 0)
        lay.setSpacing(10)

        if not self.inc.playbook_id:
            empty = QLabel("No playbook is attached to this incident.")
            empty.setObjectName("Caption")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(empty)
            lay.addStretch(1)
            return w

        try:
            pb = self.engine.get_playbook(self.inc.playbook_id)
        except KeyError:
            err = QLabel(f"Playbook {self.inc.playbook_id} not found in engine.")
            err.setObjectName("Caption")
            lay.addWidget(err); lay.addStretch(1)
            return w

        # Header summary
        meta = QLabel(
            f"<b>{pb.playbook_id} — {pb.name}</b><br>"
            f"<span style='color:#7c8aa1;'>RTO target: {pb.rto_hours:.1f} h · "
            f"Regulatory anchor: {pb.regulatory_anchor}</span>")
        meta.setTextFormat(Qt.TextFormat.RichText)
        meta.setObjectName("Caption")
        lay.addWidget(meta)

        # Steps table
        rows = self.case_store.get_playbook_executions(self.inc_id)
        outcome_by_step: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            outcome_by_step[r["step_id"]] = r

        tbl = QTableWidget(len(pb.steps), 6)
        tbl.setHorizontalHeaderLabels(
            ["Step", "Phase", "Deadline (h)", "Auto", "Status", "Action"])
        tbl.verticalHeader().setVisible(False)
        tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl.setAlternatingRowColors(True)
        tbl.setShowGrid(False)
        hdr = tbl.horizontalHeader()
        for c in (0, 1, 2, 3, 4):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        from dashboard.theme import outcome_color, phase_color
        for r, step in enumerate(pb.steps):
            state = outcome_by_step.get(step.step_id)
            outcome = (state or {}).get("outcome", "PENDING")
            ddl = (f"{step.deadline_hours:.1f}"
                   if step.deadline_hours is not None else "POST")
            items = [
                QTableWidgetItem(step.step_id),
                QTableWidgetItem(step.phase),
                QTableWidgetItem(ddl),
                QTableWidgetItem("AUTO" if step.automated else "MANUAL"),
                QTableWidgetItem(outcome),
                QTableWidgetItem(step.action),
            ]
            items[1].setForeground(QBrush(QColor(phase_color(step.phase))))
            items[4].setForeground(QBrush(QColor(outcome_color(outcome))))
            if (state or {}).get("deadline_met") == 0:
                items[2].setForeground(QBrush(QColor("#ff3b3b")))
            for c, it in enumerate(items):
                tbl.setItem(r, c, it)
        lay.addWidget(tbl, 1)

        # Footer: completion summary
        n_done = sum(1 for r in pb.steps
                     if outcome_by_step.get(r.step_id, {}).get("outcome",
                         "PENDING") != "PENDING")
        pct = int(round(100 * n_done / max(len(pb.steps), 1)))
        footer = QLabel(
            f"<b>{n_done} of {len(pb.steps)} steps completed ({pct}%)</b>")
        footer.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(footer)
        return w

    # ------------------------------------------------------------------
    def _build_response_tab(self) -> QWidget:
        w = QWidget()
        outer = QHBoxLayout(w)
        outer.setContentsMargins(0, 12, 0, 0)
        outer.setSpacing(14)

        # ---- LEFT: containment actions ----
        c_card = QFrame(); c_card.setObjectName("Card")
        cl = QVBoxLayout(c_card)
        cl.setContentsMargins(16, 14, 16, 14)
        ct = QLabel("Containment recommendations"); ct.setObjectName("H3")
        cl.addWidget(ct)

        try:
            actions = self.advisor.recommend(self.inc.incident_type,
                                             self.inc.severity or "HIGH")
        except Exception:
            actions = []

        if actions:
            tbl_c = QTableWidget(len(actions), 4)
            tbl_c.setHorizontalHeaderLabels(
                ["#", "Action", "Auto?", "RTO saved (h)"])
            tbl_c.verticalHeader().setVisible(False)
            tbl_c.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            tbl_c.setAlternatingRowColors(True)
            tbl_c.setShowGrid(False)
            tbl_c.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.ResizeMode.ResizeToContents)
            tbl_c.horizontalHeader().setSectionResizeMode(
                1, QHeaderView.ResizeMode.Stretch)
            for c in (2, 3):
                tbl_c.horizontalHeader().setSectionResizeMode(
                    c, QHeaderView.ResizeMode.ResizeToContents)
            for r, a in enumerate(actions):
                tbl_c.setItem(r, 0, QTableWidgetItem(str(
                    getattr(a, "priority", r + 1))))
                tbl_c.setItem(r, 1, QTableWidgetItem(a.action))
                tbl_c.setItem(r, 2, QTableWidgetItem(
                    "AUTO" if getattr(a, "automatable", False) else "MANUAL"))
                tbl_c.setItem(r, 3, QTableWidgetItem(
                    f"{getattr(a, 'rto_impact_h', 0.0):.1f}"))
            cl.addWidget(tbl_c, 1)
            saved = sum(getattr(a, "rto_impact_h", 0.0) for a in actions)
            total = QLabel(
                f"<b>Potential RTO savings: {saved:.1f} h</b>")
            total.setTextFormat(Qt.TextFormat.RichText)
            cl.addWidget(total)
        else:
            none = QLabel("No containment actions recommended for this type.")
            none.setObjectName("Caption")
            cl.addWidget(none); cl.addStretch(1)

        outer.addWidget(c_card, 1)

        # ---- RIGHT: recovery checklist ----
        r_card = QFrame(); r_card.setObjectName("Card")
        rl = QVBoxLayout(r_card)
        rl.setContentsMargins(16, 14, 16, 14)
        rt = QLabel("Recovery checklist"); rt.setObjectName("H3")
        rl.addWidget(rt)

        try:
            steps = self.checklist.checklist_for(self.inc.incident_type)
        except Exception:
            steps = []

        if steps:
            tbl_r = QTableWidget(len(steps), 4)
            tbl_r.setHorizontalHeaderLabels(
                ["#", "Action", "Owner", "Target (h)"])
            tbl_r.verticalHeader().setVisible(False)
            tbl_r.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            tbl_r.setAlternatingRowColors(True)
            tbl_r.setShowGrid(False)
            tbl_r.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.ResizeMode.ResizeToContents)
            tbl_r.horizontalHeader().setSectionResizeMode(
                1, QHeaderView.ResizeMode.Stretch)
            for c in (2, 3):
                tbl_r.horizontalHeader().setSectionResizeMode(
                    c, QHeaderView.ResizeMode.ResizeToContents)
            for i, st in enumerate(steps):
                tbl_r.setItem(i, 0, QTableWidgetItem(str(
                    getattr(st, "order", i + 1))))
                tbl_r.setItem(i, 1, QTableWidgetItem(
                    getattr(st, "action", str(st))))
                tbl_r.setItem(i, 2, QTableWidgetItem(
                    getattr(st, "owner", "-") or "-"))
                tbl_r.setItem(i, 3, QTableWidgetItem(
                    f"{getattr(st, 'target_hours', 0.0):.1f}"))
            rl.addWidget(tbl_r, 1)
            # RTO footer
            try:
                rto = self.checklist.rto_target(self.inc.incident_type)
                ft = QLabel(f"<b>RTO target: {rto:.1f} h</b>")
                ft.setTextFormat(Qt.TextFormat.RichText)
                rl.addWidget(ft)
            except Exception:
                pass
        else:
            none = QLabel("No recovery checklist available for this type.")
            none.setObjectName("Caption")
            rl.addWidget(none); rl.addStretch(1)

        outer.addWidget(r_card, 1)
        return w

    # ------------------------------------------------------------------
    def _build_compliance_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 12, 0, 0)
        lay.setSpacing(12)

        # NDPR assessment
        try:
            assessment = self.ndpr.assess(self.inc_id)
        except Exception as exc:
            err = QLabel(f"NDPR assessment failed: {exc}")
            err.setObjectName("Caption")
            lay.addWidget(err)
            assessment = None

        if assessment is not None:
            band = self._compliance_band(assessment.overall_compliance)
            band_pill = _pill_html(band, band)
            top = QLabel(
                f"<b>Overall NDPR compliance:</b> "
                f"{assessment.overall_compliance * 100:.1f}% &nbsp; {band_pill}")
            top.setTextFormat(Qt.TextFormat.RichText)
            lay.addWidget(top)

            if not assessment.applicable_articles:
                none = QLabel(
                    f"NDPR has no articles directly applicable to "
                    f"{self.inc.incident_type}. Trivially compliant.")
                none.setObjectName("Caption")
                lay.addWidget(none)
            else:
                tbl = QTableWidget(len(assessment.findings), 4)
                tbl.setHorizontalHeaderLabels(
                    ["Article", "Title", "Status", "Notes"])
                tbl.verticalHeader().setVisible(False)
                tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
                tbl.setAlternatingRowColors(True)
                tbl.setShowGrid(False)
                hdr = tbl.horizontalHeader()
                for c in (0, 2):
                    hdr.setSectionResizeMode(
                        c, QHeaderView.ResizeMode.ResizeToContents)
                hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
                hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
                for r, f in enumerate(assessment.findings):
                    tbl.setItem(r, 0, QTableWidgetItem(f.article))
                    tbl.setItem(r, 1, QTableWidgetItem(
                        getattr(f, "title", "")))
                    st = QTableWidgetItem(f.status)
                    st.setForeground(QBrush(QColor(
                        self._status_color(f.status))))
                    tbl.setItem(r, 2, st)
                    # evidence is the "why this PASS/FAIL" trace; fall back
                    # to remediation hint if the article passed.
                    notes = getattr(f, "evidence", "") or getattr(
                        f, "remediation", "")
                    tbl.setItem(r, 3, QTableWidgetItem(notes))
                lay.addWidget(tbl, 1)

        # Audit chain link state
        if self.audit_manager is not None:
            chain_card = QFrame(); chain_card.setObjectName("Card")
            ccl = QVBoxLayout(chain_card)
            ccl.setContentsMargins(16, 14, 16, 14)
            ct = QLabel("Audit chain")
            ct.setObjectName("H3")
            ccl.addWidget(ct)
            try:
                # Just the per-incident audit count; chain verify is a global
                # operation and lives in the Audit & Forensics tab. Use a
                # COUNT(*) -- a legacy incident can carry 80k+ audit rows and
                # pulling them all just to call len() froze the modal.
                n_audit = self.case_store.count_audit_trail(self.inc_id)
                txt = (f"{n_audit} audit entries recorded for this incident. "
                       "Verify the full chain on the Audit & Forensics tab.")
            except Exception as exc:
                txt = f"Could not read audit trail: {exc}"
            lbl = QLabel(txt); lbl.setObjectName("Caption")
            lbl.setWordWrap(True)
            ccl.addWidget(lbl)
            lay.addWidget(chain_card)

        return w

    # ------------------------------------------------------------------
    def _build_occurrences_tab(self) -> QWidget:
        """Forensic ledger: one row per raw event merged into this incident.
        Shows observed_at + per-event ITS + the source row/hash so an
        auditor can reconcile the merged incident against the parsed CSV."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 12, 0, 0)
        lay.setSpacing(8)
        hdr = QLabel(
            f"This incident merged "
            f"{int(getattr(self.inc, 'occurrence_count', 1) or 1):,} "
            f"events on host "
            f"<b>{getattr(self.inc, 'source_host', '—') or '—'}</b>. "
            f"Each row below is one raw event preserved for forensics.")
        hdr.setTextFormat(Qt.TextFormat.RichText)
        hdr.setWordWrap(True)
        hdr.setObjectName("Caption")
        lay.addWidget(hdr)

        try:
            occurrences = self.case_store.get_occurrences(self.inc.incident_id)
        except Exception:
            occurrences = []

        tbl = QTableWidget(len(occurrences), 4)
        tbl.setHorizontalHeaderLabels(
            ["Observed at", "ITS", "Source row", "Event hash"])
        tbl.verticalHeader().setVisible(False)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tbl.setAlternatingRowColors(True)
        tbl.setShowGrid(False)
        h = tbl.horizontalHeader()
        for c in (0, 1, 2):
            h.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for r, occ in enumerate(occurrences):
            ts = str(occ.get("observed_at", ""))[:19].replace("T", " ")
            its = occ.get("its_score")
            its_s = f"{float(its):.3f}" if its is not None else ""
            ri = occ.get("source_row_index", -1)
            ri_s = "—" if ri in (None, -1) else f"#{int(ri)}"
            eh = str(occ.get("source_event_hash", "") or "")
            cells = [
                QTableWidgetItem(ts),
                QTableWidgetItem(its_s),
                QTableWidgetItem(ri_s),
                QTableWidgetItem(eh),
            ]
            cells[1].setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            for c, it in enumerate(cells):
                tbl.setItem(r, c, it)
        lay.addWidget(tbl, 1)
        return w

    def _build_timeline_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 12, 0, 0)

        # Cap the rendered timeline: a legacy incident can carry 80k+ audit
        # rows, and building one QTableWidget row (4 items) each froze the UI.
        # Show the most-recent TIMELINE_LIMIT and note how many were omitted.
        TIMELINE_LIMIT = 500
        events = self.case_store.get_incident_timeline(
            self.inc_id, limit=TIMELINE_LIMIT)
        if not events:
            empty = QLabel("No timeline events recorded.")
            empty.setObjectName("Caption")
            lay.addWidget(empty); lay.addStretch(1)
            return w

        if len(events) >= TIMELINE_LIMIT:
            note = QLabel(
                f"Showing the most recent {len(events):,} timeline events — "
                f"older history truncated for performance. This incident has "
                f"{self.case_store.count_audit_trail(self.inc_id):,} audit "
                f"entries; use Export / the Audit & Forensics tab for the full "
                f"record.")
            note.setObjectName("Caption")
            note.setWordWrap(True)
            lay.addWidget(note)

        tbl = QTableWidget(len(events), 4)
        tbl.setHorizontalHeaderLabels(["Time", "Source", "By", "Summary"])
        tbl.verticalHeader().setVisible(False)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl.setAlternatingRowColors(True)
        tbl.setShowGrid(False)
        hdr = tbl.horizontalHeader()
        for c in (0, 1, 2):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for r, ev in enumerate(events):
            ts = (ev.get("ts") or "")[:19].replace("T", " ")
            tbl.setItem(r, 0, QTableWidgetItem(ts))
            tbl.setItem(r, 1, QTableWidgetItem(ev.get("source", "")))
            tbl.setItem(r, 2, QTableWidgetItem(ev.get("by", "")))
            tbl.setItem(r, 3, QTableWidgetItem(ev.get("summary", "")))
        lay.addWidget(tbl)
        return w

    # ------------------------------------------------------------------
    # Populate header (severity + status pills)
    # ------------------------------------------------------------------
    def _populate(self) -> None:
        self.lbl_sev.setText(_pill_html(self.inc.severity, self.inc.severity))
        self.lbl_status.setText(_pill_html(self.inc.status, self.inc.status))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _format_ts(ts: Optional[str]) -> str:
        if not ts:
            return "—"
        try:
            return ts.replace("T", " ")[:19]
        except Exception:
            return str(ts)

    @staticmethod
    def _compliance_band(v: float) -> str:
        if v >= 0.95: return "LOW"          # excellent -> LOW risk
        if v >= 0.80: return "MEDIUM"
        if v >= 0.60: return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _status_color(status: str) -> str:
        return {
            "PASS":      "#3ec46d",
            "PARTIAL":   "#ffc83d",
            "FAIL":      "#ff5e6d",
            "N/A":       "#7c8aa1",
        }.get(status, "#7c8aa1")

    # ------------------------------------------------------------------
    # Source event lookup -- load the parsed-CSV row that produced this
    # incident so the analyst sees the ACTUAL log line, not just INC-ID.
    # ------------------------------------------------------------------
    def _source_row_info(self) -> str:
        """Return the row index as a string, or empty if not set."""
        try:
            ri = int(getattr(self.inc, "source_row_index", -1))
        except (TypeError, ValueError):
            return ""
        return str(ri) if ri >= 0 else ""

    def _candidate_source_csvs(self) -> list:
        """Ordered list of CSV files that might be the one this incident was
        scored from. The authoritative pinned path (`source_csv_path`, written
        by the inference engine since 2026-05-25) comes first; older incidents
        fall back to glob-discovery of the dispatch dir for the same log stem.

        Returning a LIST rather than a single 'largest file' is the fix for
        the source-event mismatch bug: when several dispatch runs exist for
        one log stem, the largest is often a stale sibling whose row at
        `source_row_index` is a completely different event. The caller
        hash-validates each candidate and uses the one that actually matches
        the incident."""
        from pathlib import Path as _P
        out: list = []
        seen: set = set()

        def _add(p) -> None:
            try:
                rp = _P(p)
            except Exception:
                return
            key = str(rp)
            if key in seen:
                return
            try:
                if rp.is_file() and rp.stat().st_size > 0:
                    seen.add(key)
                    out.append(rp)
            except OSError:
                return

        pinned = getattr(self.inc, "source_csv_path", "") or ""
        if pinned:
            _add(pinned)
        for c in self._discover_source_csvs():
            _add(c)
        return out

    def _discover_source_csvs(self) -> list:
        """Glob-discover every plausible parsed-CSV for this incident's log
        stem. Returns a size-sorted list (largest first) -- legacy fallback
        for incidents that pre-date `source_csv_path` pinning. The dispatch
        dir layout differs per source kind; this matches parsers_runner."""
        from pathlib import Path as _P
        src_path = getattr(self.inc, "source_path", "") or ""
        src_kind = (getattr(self.inc, "source_kind", "") or "").lower()
        if not src_path:
            return []
        # parsers_runner writes everything under <repo>/LIRA_dispatch/.
        # The dialog runs inside the dashboard package; resolve relative
        # to the file we're in, not cwd (the user can launch from anywhere).
        base = _P(__file__).resolve().parents[2] / "LIRA_dispatch"
        if not base.is_dir():
            return None
        stem = _P(src_path).stem
        candidates: list = []
        if src_kind == "lira":
            # All-years mode wins (merged CSV is the one that was scored)
            ay = base / f"allyears_{stem}"
            if ay.is_dir():
                candidates.extend(ay.glob("*master*.csv"))
            # Year-routed mode: 2023_<stem>, 2024_<stem>, ...
            for sub in base.glob(f"*_{stem}"):
                if sub.is_dir() and sub != ay:
                    candidates.extend(sub.glob("*master_all_events*.csv"))
        elif src_kind == "evtx":
            # EVTX writes per-channel dirs named after the .evtx basename
            channel_dir = base / "windows_evtx" / _P(src_path).stem
            if channel_dir.is_dir():
                candidates.extend(channel_dir.glob("all_labeled_events*.csv"))
        elif src_kind == "access":
            d = base / "access_log" / stem
            if d.is_dir():
                candidates.extend(d.glob("*.csv"))
        elif src_kind == "error":
            d = base / "error_log" / stem
            if d.is_dir():
                candidates.extend(d.glob("*.csv"))
        if not candidates:
            return []
        # Largest-first ordering (master files are the richest). This is only
        # a tiebreak now -- the caller hash-validates before trusting any row.
        candidates = [c for c in candidates if c.stat().st_size > 0]
        candidates.sort(key=lambda p: p.stat().st_size, reverse=True)
        return candidates

    @staticmethod
    def _read_csv_row(csv_path, ri: int):
        """Read exactly one row (positional index `ri`) from a CSV. Returns a
        dict or None. skiprows=range(1, ri+1) keeps the header and skips lines
        1..ri so nrows=1 reads only the wanted row -- memory-cheap even on a
        multi-million-row master file."""
        try:
            import pandas as _pd
            df = _pd.read_csv(csv_path,
                              skiprows=range(1, ri + 1),
                              nrows=1, low_memory=False)
            if df.empty:
                return None
            return df.iloc[0].to_dict()
        except Exception:
            return None

    def _load_source_event_row(self):
        """Resolve the parser-CSV row that produced this incident.

        Returns (row_dict, status). status is:
          'verified'    row's event hash matches the incident's stored hash
          'pinned'      read from the exact engine-pinned CSV (no hash to check)
          'unchecked'   no stored hash to validate against (can't confirm, but
                        not necessarily wrong) -- e.g. legacy / error-log rows
          'unverified'  a stored hash EXISTED but no candidate reproduced it
                        (genuinely suspicious -- likely a stale sibling CSV)
        Both are None when no row is readable at all.

        The hash check is what kills the 'AI says CRITICAL, source event says
        LOW' confusion: when multiple dispatch runs share a log stem, a stale
        sibling's row at the same index is a different event. We only show a
        row whose canonical event hash reproduces the one stored at scoring
        time; otherwise we flag it as unverified rather than mislead."""
        self._source_row_status = None
        try:
            ri = int(getattr(self.inc, "source_row_index", -1))
        except (TypeError, ValueError):
            return None, None
        if ri < 0:
            return None, None
        candidates = self._candidate_source_csvs()
        if not candidates:
            return None, None

        stored_hash = str(getattr(self.inc, "source_event_hash", "") or "")
        src_kind = (getattr(self.inc, "source_kind", "") or "").lower()
        pinned = (getattr(self.inc, "source_csv_path", "") or "").replace("\\", "/")

        fallback_row = None
        fallback_csv = None
        for csv_path in candidates:
            row = self._read_csv_row(csv_path, ri)
            if row is None:
                continue
            if fallback_row is None:
                fallback_row, fallback_csv = row, csv_path
            if stored_hash:
                try:
                    from ml_inference import _canonical_event_hash
                    if _canonical_event_hash(row, src_kind) == stored_hash:
                        self._source_row_status = "verified"
                        return row, "verified"
                except Exception:
                    pass

        if fallback_row is None:
            return None, None
        same_as_pinned = (pinned and
                          str(fallback_csv).replace("\\", "/") == pinned)
        if stored_hash:
            # A fingerprint existed but nothing reproduced it -> suspicious.
            status = "unverified"
        elif same_as_pinned:
            status = "pinned"
        else:
            # Nothing to validate against; show it, don't cry wolf.
            status = "unchecked"
        self._source_row_status = status
        return fallback_row, status

    # Curated, ordered set of the most operationally useful columns across all
    # parser schemas (LIRA / Access / Error / EVTX). The "Key fields" view
    # surfaces these (when present + non-empty); everything else lives in the
    # "All fields" / "JSON" views so nothing is ever hidden from the analyst.
    _SOURCE_FIELD_PRIORITY = (
        # when
        "timestamp", "timestamp_iso", "timestamp_raw", "datetime", "date",
        "time", "TimeCreated",
        # what / severity
        "level", "severity", "severity_label", "severity_score",
        "label", "sublabel", "rule_id",
        "event_id", "event_type", "EventID", "event_category",
        # apache / php error specifics
        "module", "module_level", "ah_code", "ah_description",
        "php_error_type", "php_exception_class", "php_message_short",
        "source_script",
        # actors / network
        "user", "username", "TargetUserName", "SubjectUserName",
        "client_ip", "src_ip", "dst_ip", "IpAddress", "remote_addr",
        "target_db_user", "target_db_host", "target_db_name",
        "host", "hostname", "Computer", "computer",
        # web request
        "status", "http_status", "method", "url", "request",
        # process / channel
        "process", "ProcessName", "CallerProcessName",
        "channel", "channel_key", "provider",
        # flags
        "is_incident", "is_external_host", "is_basoft", "event_flags",
        # human-readable message (eye-catcher) + scores
        "message", "message_raw", "msg", "notes",
        "anomaly_score", "its_score",
    )

    _EMPTY_CELL = "<i style='color:#7c8aa1;'>—</i>"

    def _src_event_field_count(self) -> int:
        row = getattr(self, "_src_event_row", None) or {}
        return len([k for k in row if not str(k).startswith("Unnamed:")])

    @staticmethod
    def _source_event_banner(status) -> str:
        """Only the genuinely-suspicious 'unverified' state earns a warning;
        'unchecked' (no fingerprint to compare) stays quiet."""
        if status == "unverified":
            return (
                "<div style='background:#3a2a1f;color:#ffc83d;"
                "padding:6px 12px;border-radius:8px;margin-bottom:8px;"
                "font-size:9pt;'>⚠ Could not confirm this is the exact event "
                "that produced the incident — several parser runs exist for "
                "this log and none reproduced the recorded event fingerprint. "
                "Trust the incident's own severity over these fields.</div>")
        return ""

    @classmethod
    def _fmt_cell(cls, value, clip: int = 0) -> str:
        try:
            import pandas as _pd
            if value is None or (not isinstance(value, (list, dict))
                                 and _pd.isna(value)):
                return cls._EMPTY_CELL
        except Exception:
            if value is None:
                return cls._EMPTY_CELL
        txt = str(value)
        if clip and len(txt) > clip:
            txt = txt[:clip] + " …"
        return (txt.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;"))

    @staticmethod
    def _kv_row_html(key: str, val_html: str) -> str:
        return (f"<tr>"
                f"<td style='color:#7c8aa1;padding:2px 14px 2px 0;"
                f"vertical-align:top;white-space:nowrap;'><b>{key}</b></td>"
                f"<td style='font-family:Cascadia Mono,Consolas,monospace;"
                f"font-size:9.5pt;padding:2px 0;vertical-align:top;'>"
                f"{val_html}</td></tr>")

    def _set_source_event_view(self, which: str) -> None:
        """Render the cached source-event row in the chosen view."""
        body = getattr(self, "_ev_body", None)
        if body is None:
            return
        row = getattr(self, "_src_event_row", None)
        status = getattr(self, "_src_event_status", None)
        if not row:
            try:
                ri = int(getattr(self.inc, "source_row_index", -1))
            except (TypeError, ValueError):
                ri = -1
            if ri < 0:
                # source_row_index == -1 means this incident is a span of many
                # events (episode detection), not a single parsed row -- there
                # was never one source line to show. Don't blame a missing CSV.
                body.setText(
                    "<span style='color:#7c8aa1;'>(this incident represents a "
                    "span of multiple events detected as an episode, so there "
                    "is no single source row — see the Occurrences tab for the "
                    "underlying events)</span>")
            else:
                body.setText(
                    "<span style='color:#7c8aa1;'>(no source event available — "
                    "the original parsed CSV is no longer on disk, or this "
                    "incident pre-dates source-row tracking)</span>")
            return
        banner = self._source_event_banner(status)
        if which == "all":
            body.setText(banner + self._render_all_fields(row))
        elif which == "json":
            body.setText(banner + self._render_json(row))
        else:
            body.setText(banner + self._render_key_fields(row))

    def _render_key_fields(self, row: Dict[str, Any]) -> str:
        """Curated eye-catching essentials (priority fields that are present
        and non-empty)."""
        rows_html = []
        for k in self._SOURCE_FIELD_PRIORITY:
            if k not in row:
                continue
            val = self._fmt_cell(row[k], clip=240)
            if val == self._EMPTY_CELL:
                continue
            rows_html.append(self._kv_row_html(k, val))
        n_total = self._src_event_field_count()
        if not rows_html:
            return ("<span style='color:#7c8aa1;'>(no key fields populated — "
                    "switch to “All fields” for the full row)</span>")
        out = ["<table cellspacing='0' cellpadding='0' style='border:0;'>"]
        out += rows_html
        out.append("</table>")
        out.append(
            f"<div style='color:#637085;font-size:8.5pt;margin-top:6px;"
            f"font-style:italic;'>Showing key fields · this event has "
            f"{n_total} columns total — use “All fields” or “JSON” for every "
            f"column.</div>")
        return "".join(out)

    def _render_all_fields(self, row: Dict[str, Any]) -> str:
        """Every column, nothing hidden. Priority fields first (in their
        curated order), then the remainder alphabetically. Full values."""
        keys = [k for k in row.keys() if not str(k).startswith("Unnamed:")]
        prio = [k for k in self._SOURCE_FIELD_PRIORITY if k in keys]
        rest = sorted(k for k in keys if k not in self._SOURCE_FIELD_PRIORITY)
        rows_html = [self._kv_row_html(k, self._fmt_cell(row[k]))
                     for k in (prio + rest)]
        return ("<table cellspacing='0' cellpadding='0' style='border:0;'>"
                + "".join(rows_html) + "</table>")

    def _render_json(self, row: Dict[str, Any]) -> str:
        """Pretty JSON of the full row (numpy/NaN-safe), monospace."""
        import json as _json
        clean: Dict[str, Any] = {}
        for k, v in row.items():
            if str(k).startswith("Unnamed:"):
                continue
            try:
                import pandas as _pd
                if not isinstance(v, (list, dict)) and _pd.isna(v):
                    clean[k] = None
                    continue
            except Exception:
                pass
            if hasattr(v, "item"):          # numpy scalar -> python scalar
                try:
                    v = v.item()
                except Exception:
                    v = str(v)
            clean[k] = v
        try:
            txt = _json.dumps(clean, indent=2, ensure_ascii=False, default=str)
        except Exception:
            txt = str(clean)
        esc = (txt.replace("&", "&amp;").replace("<", "&lt;")
                  .replace(">", "&gt;").replace(" ", "&nbsp;")
                  .replace("\n", "<br>"))
        return (f"<div style='font-family:Cascadia Mono,Consolas,monospace;"
                f"font-size:9pt;'>{esc}</div>")

    def _derive_source_attribution(self) -> str:
        """Show the structured source columns first (set by the live worker
        / inference daemon since 2026-05-19), then fall back to scraping
        the audit trail for legacy rows that pre-date the migration."""
        src_kind = getattr(self.inc, "source_kind", "") or ""
        src_name = getattr(self.inc, "source_name", "") or ""
        src_path = getattr(self.inc, "source_path", "") or ""

        if src_kind or src_name or src_path:
            parts = []
            if src_name:
                parts.append(f"<b>Name:</b> {src_name}")
            if src_kind:
                parts.append(f"<b>Kind:</b> {src_kind}")
            if src_path:
                parts.append(
                    f"<b>Path:</b> <span style='font-family:Cascadia Mono,"
                    f"Consolas,monospace;font-size:9pt;'>{src_path}</span>")
            return "<br>".join(parts)

        # Legacy fallback -- mine the audit trail for INCIDENT_CREATED
        rows = self.case_store.get_audit_trail(self.inc_id)
        if not rows:
            return ("(no audit rows yet — incident was loaded directly "
                    "from the case-store without a recorded ingest path)")
        creation = next(
            (r for r in rows if r.get("action") == "INCIDENT_CREATED"),
            rows[0])
        summary = creation.get("change_summary", "") or ""
        who = creation.get("performed_by", "system")
        return (f"<i>Legacy incident (pre-migration). Best-effort:</i><br>"
                f"Recorded by <b>{who}</b> at "
                f"<b>{(creation.get('performed_at') or '')[:19].replace('T', ' ')}</b>"
                f"<br>{summary or '(no source tokens in audit trail)'}")

    # ------------------------------------------------------------------
    def _copy_id(self) -> None:
        QGuiApplication.clipboard().setText(self.inc_id)

    def _export_pdf(self) -> None:
        """Generate a single-incident NDPR PDF via the existing reporting
        pipeline. ReportGenerator writes into its own dated output dir;
        we then copy the produced PDF to the user's chosen location."""
        import shutil
        try:
            from reporting.report_generator import ReportGenerator
        except Exception as exc:
            QMessageBox.warning(
                self, "Export PDF",
                f"Report generator not available:\n{exc}")
            return
        default = f"incident_{self.inc_id}_report.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export incident PDF", default,
            "PDF (*.pdf);;All Files (*)")
        if not path:
            return
        try:
            gen = ReportGenerator(case_store=self.case_store,
                                  ndpr_mapper=self.ndpr,
                                  audit_manager=self.audit_manager)
            produced = gen.generate_incident_pdf(self.inc_id)
            shutil.copy(produced, path)
            QMessageBox.information(
                self, "Export PDF",
                f"Saved single-incident NDPR report to:\n{path}\n\n"
                f"(also kept the dated copy at:\n{produced})")
        except Exception as exc:
            QMessageBox.warning(
                self, "Export PDF",
                f"Generation failed:\n{type(exc).__name__}: {exc}")
