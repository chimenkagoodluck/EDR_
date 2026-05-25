"""dashboard/widgets/audit_forensics.py

Filterable audit_trail browser + NDPR compliance gauge + signed-chain
verification button.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame, QComboBox, QLineEdit, QSplitter,
    QPlainTextEdit, QProgressBar, QMessageBox, QFileDialog,
)

from response.case_store import CaseStore
from reporting.audit_manager import AuditManager
from reporting.ndpr_mapper import NdprMapper, NDPR_ARTICLES, INC_TO_ARTICLES
from dashboard.theme import (
    BG_PANEL, BG_RAISED, TEXT_PRIMARY, TEXT_SECONDARY, ACCENT, BORDER,
)


ACTION_TYPES = [
    "(any)", "INCIDENT_CREATED", "STATUS_CHANGE", "STEP_COMPLETED",
    "STEP_SKIPPED", "STEP_FAILED", "EVIDENCE_ADDED", "BCP_ACTIVATED",
    "NOTIFY_NDPC", "ALERT_DPO", "HR_HANDOVER",
]


class AuditForensicsWidget(QWidget):
    def __init__(self, case_store: CaseStore, audit_manager: AuditManager,
                 ndpr_mapper: NdprMapper, bus, parent=None):
        super().__init__(parent)
        self.case_store = case_store
        self.audit_manager = audit_manager
        self.ndpr_mapper = ndpr_mapper
        self.bus = bus
        self.selected_incident_id: Optional[str] = None
        self._last_data_version = -1
        self._last_filter_sig: Optional[tuple] = None
        from dashboard.prefs import get_prefs
        self._prefs = get_prefs()
        self._build_ui()
        self._restore_filters()
        self.cb_action.currentTextChanged.connect(self._on_filter_changed)
        self.le_inc.textChanged.connect(self._on_filter_changed)
        self.le_q.textChanged.connect(self._on_filter_changed)
        self.bus.tick.connect(self._poll)
        self.bus.refresh_requested.connect(self._refresh)
        self.bus.incident_selected.connect(self._on_incident_selected)
        self.bus.chain_verified.connect(self._set_chain_badge)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # ---- filter bar ----------------------------------------------
        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addWidget(QLabel("Action:"))
        self.cb_action = QComboBox()
        self.cb_action.addItems(ACTION_TYPES)
        bar.addWidget(self.cb_action)
        bar.addSpacing(12)

        bar.addWidget(QLabel("Incident:"))
        self.le_inc = QLineEdit()
        self.le_inc.setPlaceholderText("incident_id contains...")
        self.le_inc.setMaximumWidth(220)
        bar.addWidget(self.le_inc)
        bar.addSpacing(12)

        bar.addWidget(QLabel("Search:"))
        self.le_q = QLineEdit()
        self.le_q.setPlaceholderText("summary contains...")
        bar.addWidget(self.le_q, 1)

        self.lbl_count = QLabel("0 rows")
        self.lbl_count.setObjectName("Caption")
        bar.addWidget(self.lbl_count)
        root.addLayout(bar)

        # ---- splitter: table + side-panel ----------------------------
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        split.setChildrenCollapsible(False)

        # ---- audit table ---------------------------------------------
        tbl_frame = QFrame()
        tbl_frame.setObjectName("Card")
        t_lay = QVBoxLayout(tbl_frame)
        t_lay.setContentsMargins(8, 8, 8, 8)
        t_title = QLabel("Audit Trail")
        t_title.setObjectName("H2")
        t_lay.addWidget(t_title)

        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(
            ["Time", "Audit ID", "Incident", "Action", "By", "Summary"])
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setShowGrid(False)
        hdr = self.tbl.horizontalHeader()
        for c in (0, 1, 2, 3, 4):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tbl.itemSelectionChanged.connect(self._on_row_selected)
        t_lay.addWidget(self.tbl, 1)
        split.addWidget(tbl_frame)

        # ---- side panel: NDPR gauge + chain verify -------------------
        side = QFrame()
        side.setObjectName("Card")
        s_lay = QVBoxLayout(side)
        s_lay.setContentsMargins(10, 10, 10, 10)
        s_lay.setSpacing(10)

        # NDPR compliance
        ndpr_title = QLabel("NDPR Compliance")
        ndpr_title.setObjectName("H2")
        s_lay.addWidget(ndpr_title)
        self.bar_ndpr = QProgressBar()
        self.bar_ndpr.setRange(0, 100)
        self.bar_ndpr.setValue(0)
        self.bar_ndpr.setFormat("%p%  mean compliance")
        s_lay.addWidget(self.bar_ndpr)

        self.lbl_ndpr_breakdown = QLabel(
            "(select an incident for per-article detail)")
        self.lbl_ndpr_breakdown.setObjectName("Caption")
        self.lbl_ndpr_breakdown.setWordWrap(True)
        s_lay.addWidget(self.lbl_ndpr_breakdown)

        # NDPR 72-hour breach-notification deadline tracker (per incident).
        self.lbl_ndpr_deadline = QLabel("")
        self.lbl_ndpr_deadline.setTextFormat(Qt.TextFormat.RichText)
        self.lbl_ndpr_deadline.setWordWrap(True)
        s_lay.addWidget(self.lbl_ndpr_deadline)

        self.txt_findings = QPlainTextEdit()
        self.txt_findings.setReadOnly(True)
        self.txt_findings.setMaximumHeight(220)
        s_lay.addWidget(self.txt_findings)

        self.btn_inc_pdf = QPushButton("Export this incident (signed PDF)")
        self.btn_inc_pdf.setToolTip(
            "Generate the NDPR-aligned PDF report for the selected incident.")
        self.btn_inc_pdf.clicked.connect(self._export_incident_pdf)
        s_lay.addWidget(self.btn_inc_pdf)

        # Chain verify
        chain_title = QLabel("Tamper-Evident Audit Chain")
        chain_title.setObjectName("H2")
        s_lay.addWidget(chain_title)
        self.lbl_chain_badge = QLabel("NOT VERIFIED")
        self._set_chain_badge(None, 0)
        s_lay.addWidget(self.lbl_chain_badge)
        chain_row = QHBoxLayout()
        self.btn_export = QPushButton("Export Chain")
        self.btn_export.clicked.connect(self._export_chain)
        self.btn_verify = QPushButton("Verify Chain")
        self.btn_verify.setObjectName("Primary")
        self.btn_verify.clicked.connect(self._verify_chain)
        self.btn_report = QPushButton("Generate Full Report…")
        self.btn_report.clicked.connect(self._generate_full_report)
        self.btn_report.setToolTip(
            "Run the complete reporting pipeline:\n"
            "  • per-incident PDFs (NDPR-aligned)\n"
            "  • aggregate Excel workbook (per-INC SLAs, NDPR, evidence)\n"
            "  • signed audit chain export with root SHA-256\n"
            "  • NDPR compliance summary JSON\n"
            "Output lands in reporting/runs/<timestamp>/")
        chain_row.addWidget(self.btn_export)
        chain_row.addWidget(self.btn_verify)
        chain_row.addWidget(self.btn_report)
        chain_row.addStretch(1)
        s_lay.addLayout(chain_row)

        self.lbl_chain = QLabel("(chain not yet verified this session)")
        self.lbl_chain.setObjectName("Caption")
        self.lbl_chain.setWordWrap(True)
        s_lay.addWidget(self.lbl_chain)

        self.lbl_root = QLabel("")
        self.lbl_root.setStyleSheet(
            f"font-family:'Cascadia Mono','Consolas',monospace;"
            f"color:{ACCENT};font-size:8.5pt;")
        self.lbl_root.setWordWrap(True)
        s_lay.addWidget(self.lbl_root)

        s_lay.addStretch(1)
        split.addWidget(side)

        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        root.addWidget(split, 1)

    # ------------------------------------------------------------------
    def _restore_filters(self) -> None:
        username = (self.bus.parent().session.username
                    if hasattr(self.bus.parent(), "session") else "anonymous")
        f = self._prefs.get_user_filter(
            username, "audit",
            default={"action": "(any)", "incident": "", "search": ""})
        action = f.get("action", "(any)")
        if action in ACTION_TYPES:
            self.cb_action.blockSignals(True)
            self.cb_action.setCurrentText(action)
            self.cb_action.blockSignals(False)
        self.le_inc.blockSignals(True)
        self.le_inc.setText(str(f.get("incident", "")))
        self.le_inc.blockSignals(False)
        self.le_q.blockSignals(True)
        self.le_q.setText(str(f.get("search", "")))
        self.le_q.blockSignals(False)

    def _on_filter_changed(self, _txt: str) -> None:
        username = (self.bus.parent().session.username
                    if hasattr(self.bus.parent(), "session") else "anonymous")
        self._prefs.set_user_filter(username, "audit", {
            "action":   self.cb_action.currentText(),
            "incident": self.le_inc.text(),
            "search":   self.le_q.text(),
        })
        self._refresh()

    def _on_incident_selected(self, inc_id: str) -> None:
        self.selected_incident_id = inc_id
        # auto-populate the filter and refresh
        if not self.le_inc.text():
            self.le_inc.blockSignals(True)
            self.le_inc.setText(inc_id)
            self.le_inc.blockSignals(False)
        self._refresh()

    def _poll(self, _seq: int) -> None:
        if not self.isVisible():
            return
        v = getattr(self.case_store, "data_version", None)
        if v is not None and v == self._last_data_version:
            return
        self._refresh()

    def _refresh(self) -> None:
        filter_sig = (
            self.cb_action.currentText(),
            self.le_inc.text().strip(),
            self.le_q.text().strip(),
        )
        v = getattr(self.case_store, "data_version", None)
        if (v is not None and v == self._last_data_version
                and filter_sig == self._last_filter_sig):
            return
        rows = self._query_audit()
        self._render_table(rows)
        self._render_ndpr()
        self._last_data_version = getattr(self.case_store, "data_version", 0)
        self._last_filter_sig = filter_sig

    # ------------------------------------------------------------------
    def _query_audit(self) -> List[Dict[str, Any]]:
        conn = self.case_store.connect()
        where, params = [], []
        action = self.cb_action.currentText()
        if action and action != "(any)":
            where.append("action = ?"); params.append(action)
        inc_q = self.le_inc.text().strip()
        if inc_q:
            where.append("incident_id LIKE ?"); params.append(f"%{inc_q}%")
        q_text = self.le_q.text().strip()
        if q_text:
            where.append("change_summary LIKE ?"); params.append(f"%{q_text}%")
        sql = ("SELECT audit_id, incident_id, action, performed_by, "
               "       performed_at, change_summary FROM audit_trail")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY audit_id DESC LIMIT 500"
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def _render_table(self, rows: List[Dict[str, Any]]) -> None:
        self.tbl.setUpdatesEnabled(False)
        try:
            self.tbl.setRowCount(len(rows))
            for r, row in enumerate(rows):
                ts = (row.get("performed_at") or "")[:19].replace("T", " ")
                items = [
                    QTableWidgetItem(ts),
                    QTableWidgetItem(str(row.get("audit_id") or "")),
                    QTableWidgetItem(row.get("incident_id") or "-"),
                    QTableWidgetItem(row.get("action") or ""),
                    QTableWidgetItem(row.get("performed_by") or ""),
                    QTableWidgetItem(row.get("change_summary") or ""),
                ]
                items[1].setTextAlignment(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                for c, it in enumerate(items):
                    self.tbl.setItem(r, c, it)
        finally:
            self.tbl.setUpdatesEnabled(True)
        self.lbl_count.setText(
            f"{len(rows)} row{'s' if len(rows) != 1 else ''}")

    def _on_row_selected(self) -> None:
        sel = self.tbl.selectedItems()
        if not sel:
            return
        row = sel[0].row()
        inc_item = self.tbl.item(row, 2)
        if inc_item and inc_item.text() and inc_item.text() != "-":
            self.bus.incident_selected.emit(inc_item.text())

    # ------------------------------------------------------------------
    def _render_ndpr(self) -> None:
        # If an incident is selected, show its per-article findings
        if self.selected_incident_id:
            inc = self.case_store.get_incident(self.selected_incident_id)
            if inc is None:
                return
            try:
                assessment = self.ndpr_mapper.assess(self.selected_incident_id)
            except Exception as exc:
                self.txt_findings.setPlainText(f"(NDPR assess error: {exc})")
                return
            pct = int(round(assessment.overall_compliance * 100))
            self.bar_ndpr.setValue(pct)
            self.bar_ndpr.setFormat(
                f"{self.selected_incident_id}  •  {pct}%  compliance")
            self.lbl_ndpr_breakdown.setText(
                f"Applicable articles for {inc.incident_type}: "
                f"{', '.join(assessment.applicable_articles) or '(none — NDPR n/a)'}\n"
                f"PASS={assessment.n_pass}  PARTIAL={assessment.n_partial}  "
                f"FAIL={assessment.n_fail}")
            lines = []
            for f in assessment.findings:
                lines.append(f"  [{f.status:<7}] Art {f.article}  ({f.title})")
                if f.evidence:
                    lines.append(f"      evidence: {f.evidence}")
                if f.status != "PASS" and f.remediation:
                    lines.append(f"      remediation: {f.remediation}")
            self.txt_findings.setPlainText(
                "\n".join(lines) if lines
                else "(no applicable NDPR articles for this incident type)")
            self.lbl_ndpr_deadline.setText(self._ndpr_deadline_html(inc))
        else:
            self.lbl_ndpr_deadline.setText("")
            # aggregate dashboard
            try:
                dash = self.ndpr_mapper.compliance_dashboard()
            except Exception as exc:
                self.txt_findings.setPlainText(f"(NDPR dashboard error: {exc})")
                return
            n = dash.get("n_incidents", 0)
            if not n:
                self.bar_ndpr.setValue(0)
                self.bar_ndpr.setFormat("no incidents")
                self.lbl_ndpr_breakdown.setText(
                    "(no persisted incidents — NDPR baseline 0)")
                self.txt_findings.setPlainText("")
                return
            mean = dash.get("mean_compliance",
                            dash.get("overall_compliance", 0.0))
            pct = int(round((mean or 0.0) * 100))
            self.bar_ndpr.setValue(pct)
            self.bar_ndpr.setFormat(
                f"AGGREGATE  •  {pct}%  mean across {n} incidents")
            self.lbl_ndpr_breakdown.setText(
                "Aggregate compliance across all persisted incidents. "
                "Select an incident for per-article detail.")
            self.txt_findings.setPlainText("")

    # ------------------------------------------------------------------
    def _export_chain(self) -> None:
        try:
            path = self.audit_manager.export_chain()
            self.bus.status_message.emit(
                f"Chain exported -> {path.name}", 4000)
            self.lbl_chain.setText(f"Exported to {path}")
            root_h = self.audit_manager.compute_root_hash(path)
            self.lbl_root.setText(f"root_hash: {root_h}")
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", str(exc))

    # ------------------------------------------------------------------
    def _ndpr_deadline_html(self, inc) -> str:
        """NDPR mandates breach notification to the regulator within 72 hours
        of awareness. Show elapsed/remaining against detected_at, red when
        breached. Only meaningful while the incident is still being handled."""
        try:
            detected = datetime.fromisoformat(inc.detected_at)
        except Exception:
            return ""
        elapsed_h = (datetime.now() - detected).total_seconds() / 3600.0
        remaining = 72.0 - elapsed_h
        if remaining <= 0:
            return (f"<span style='color:#ff3b3b;font-weight:700;'>"
                    f"NDPR 72h deadline BREACHED</span> — "
                    f"{abs(remaining):.1f} h overdue "
                    f"(detected {detected:%Y-%m-%d %H:%M}).")
        color = "#3ec46d" if remaining > 24 else "#ffc83d"
        return (f"<span style='color:{color};font-weight:600;'>"
                f"NDPR 72h notification: {remaining:.1f} h remaining</span> "
                f"({elapsed_h:.1f} h elapsed since detection).")

    def _set_chain_badge(self, ok, n_viol: int = 0) -> None:
        if ok is None:
            text, color, bg = "CHAIN: NOT VERIFIED", "#7c8aa1", "transparent"
        elif ok:
            text, color, bg = "CHAIN INTACT ✓", "#3ec46d", "rgba(62,196,109,0.12)"
        else:
            text = f"CHAIN BROKEN — {n_viol} violation(s)"
            color, bg = "#ff3b3b", "rgba(255,59,59,0.12)"
        self.lbl_chain_badge.setText(text)
        self.lbl_chain_badge.setStyleSheet(
            f"font-size:12pt;font-weight:700;color:{color};"
            f"background:{bg};border-radius:6px;padding:6px 10px;")

    def _export_incident_pdf(self) -> None:
        """Generate the NDPR-aligned PDF for the currently-selected incident."""
        inc_id = self.selected_incident_id
        if not inc_id:
            QMessageBox.information(
                self, "Export incident PDF",
                "Select an incident first (click an audit row, or pick one on "
                "the Incidents tab).")
            return
        import shutil
        try:
            from reporting.report_generator import ReportGenerator
        except Exception as exc:
            QMessageBox.warning(self, "Export PDF",
                                f"Report generator not available:\n{exc}")
            return
        dest, _ = QFileDialog.getSaveFileName(
            self, "Export incident PDF",
            f"incident_{inc_id}_report.pdf", "PDF (*.pdf);;All Files (*)")
        if not dest:
            return
        try:
            gen = ReportGenerator(case_store=self.case_store,
                                  ndpr_mapper=self.ndpr_mapper,
                                  audit_manager=self.audit_manager)
            produced = gen.generate_incident_pdf(inc_id)
            shutil.copyfile(str(produced), dest)
            self.bus.status_message.emit(f"Exported {inc_id} PDF -> {dest}", 4500)
        except Exception as exc:
            QMessageBox.warning(
                self, "Export PDF",
                f"PDF generation failed:\n{type(exc).__name__}: {exc}")

    def _verify_chain(self) -> None:
        # Default path is reporting/audit_signed/audit_chain.jsonl
        default = self.audit_manager.output_dir / "audit_chain.jsonl"
        if not default.exists():
            try:
                default = self.audit_manager.export_chain()
            except Exception as exc:
                QMessageBox.warning(self, "Verify failed", str(exc))
                return
        try:
            ok, violations = self.audit_manager.verify_chain(default)
        except Exception as exc:
            QMessageBox.warning(self, "Verify failed", str(exc))
            return
        self.bus.chain_verified.emit(ok, len(violations))
        if ok:
            self.lbl_chain.setText(
                f"<span style='color:#3ec46d;font-weight:600;'>"
                f"CHAIN INTACT</span>  ({default.name})")
            self.bus.status_message.emit(
                f"Audit chain verified: INTACT", 4000)
        else:
            self.lbl_chain.setText(
                f"<span style='color:#ff3b3b;font-weight:600;'>"
                f"CHAIN BROKEN</span>  {len(violations)} violation(s)")
            self.bus.status_message.emit(
                f"Audit chain BROKEN: {len(violations)} violations", 5000)
        try:
            root_h = self.audit_manager.compute_root_hash(default)
            self.lbl_root.setText(f"root_hash: {root_h}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _generate_full_report(self) -> None:
        """Run the complete reporting pipeline (per-incident PDFs +
        aggregate Excel + signed-audit + NDPR JSON). Opens the output
        folder in the OS file manager when done."""
        try:
            from reporting.report_generator import ReportGenerator
        except Exception as exc:
            QMessageBox.warning(
                self, "Generate report",
                f"Report generator unavailable:\n{exc}")
            return

        # Stop the user from running it on an empty DB
        try:
            n = self.case_store.summarise().get("n_incidents", 0)
        except Exception:
            n = 0
        if n == 0:
            QMessageBox.information(
                self, "Generate report",
                "No incidents in the case store yet.\n\n"
                "Attach a log source on the Data Sources tab so the "
                "engine can populate the case store before exporting "
                "reports.")
            return

        if QMessageBox.question(
                self, "Generate full report",
                f"Run the full reporting pipeline on {n} incident(s)?\n\n"
                "Output:\n"
                "  • per_incident/*.pdf  (NDPR-aligned)\n"
                "  • per_incident/*.txt  (plain-text summary)\n"
                "  • aggregate.xlsx       (SLA + NDPR sheets)\n"
                "  • signed_audit/        (chain.jsonl + root_hash.txt)\n"
                "  • ndpr_compliance_summary.json\n\n"
                "On a large case store this can take a couple of minutes."
                ) != QMessageBox.StandardButton.Yes:
            return

        try:
            gen = ReportGenerator(
                case_store=self.case_store,
                audit_manager=self.audit_manager,
                ndpr_mapper=self.ndpr_mapper)
            result = gen.generate_all(
                include_pdf=True, include_text=True,
                include_excel=True, include_audit=True)
        except Exception as exc:
            QMessageBox.warning(
                self, "Generate report",
                f"Report generation failed:\n{type(exc).__name__}: {exc}")
            return

        out_dir = result["output_dir"]
        n_pdf = len(result.get("per_incident_pdfs", []))
        n_xl  = "yes" if "aggregate_excel" in result else "no"
        n_err = len(result.get("errors", []) or [])
        msg = (f"Report run complete.\n\n"
               f"Output folder: {out_dir}\n"
               f"Per-incident PDFs: {n_pdf}\n"
               f"Aggregate Excel: {n_xl}\n"
               f"NDPR summary JSON: yes\n"
               f"Signed audit chain: yes\n"
               f"Errors: {n_err}\n\n"
               "Open the folder?")
        if QMessageBox.question(
                self, "Generate report", msg) == QMessageBox.StandardButton.Yes:
            self._open_folder(out_dir)

    @staticmethod
    def _open_folder(path: str) -> None:
        """Open a folder in the OS file manager."""
        import os, subprocess, sys
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass
