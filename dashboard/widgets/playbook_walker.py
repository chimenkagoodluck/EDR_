"""dashboard/widgets/playbook_walker.py

Guided incident-response view. A left "Incidents" browser auto-loads the
case-store incidents (status filter + live completion %); selecting one shows
its playbook steps on the right with a "Do this next" banner, per-step status
(PENDING / COMPLETED / SKIPPED / FAILED), one-click completion, and an Unmark
option for already-actioned steps. When every step is actioned the incident is
auto-advanced OPEN -> CONTAINED; Mark CONTAINED / CLOSED buttons let the analyst
finalize manually. Every action is logged to the audit trail.

Entry points:
  * showEvent / tick          -- auto-loads + refreshes the incident list.
  * load_response_queue(ids)  -- "Respond" from the Incidents tab focuses the
                                 selection here (SignalBus.respond_requested).
  * incident_selected(id)     -- single-row selection mirrors here.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame, QProgressBar, QSplitter,
    QPlainTextEdit, QInputDialog, QMessageBox, QListWidget, QListWidgetItem,
    QMenu, QComboBox,
)

from response.case_store import CaseStore
from response.playbook_engine import PlaybookEngine, Playbook, PlaybookStep
from dashboard.theme import (
    BG_PANEL, BG_RAISED, TEXT_PRIMARY, TEXT_SECONDARY, ACCENT, BORDER,
    severity_color, outcome_color, phase_color,
)

STATUS_FILTERS = ["(any)", "OPEN", "CONTAINED", "CLOSED", "ABANDONED"]


class PlaybookWalkerWidget(QWidget):
    def __init__(self, case_store: CaseStore, playbook_engine: PlaybookEngine,
                 bus, parent=None):
        super().__init__(parent)
        self.case_store = case_store
        self.engine = playbook_engine
        self.bus = bus
        self.selected_incident_id: Optional[str] = None
        self._pending_select: Optional[str] = None
        self._status_filter = "(any)"
        self._last_data_version = -1
        self._last_rendered_inc: Optional[str] = None
        self._build_ui()
        self.bus.incident_selected.connect(self._on_incident_selected)
        self.bus.tick.connect(self._poll)
        self.bus.refresh_requested.connect(self._on_refresh_requested)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        outer = QSplitter(Qt.Orientation.Horizontal)
        outer.setHandleWidth(2)
        outer.setChildrenCollapsible(False)

        # ---- left: incident browser -------------------------------
        list_frame = QFrame()
        list_frame.setObjectName("Card")
        q_lay = QVBoxLayout(list_frame)
        q_lay.setContentsMargins(8, 8, 8, 8)
        q_title = QLabel("Incidents")
        q_title.setObjectName("H2")
        q_lay.addWidget(q_title)
        filt_row = QHBoxLayout()
        filt_row.addWidget(QLabel("Status:"))
        self.cb_filter = QComboBox()
        self.cb_filter.addItems(STATUS_FILTERS)
        self.cb_filter.setCurrentText(self._status_filter)
        self.cb_filter.currentTextChanged.connect(self._on_filter_changed)
        filt_row.addWidget(self.cb_filter, 1)
        q_lay.addLayout(filt_row)
        q_hint = QLabel("Pick an incident to work its playbook steps.")
        q_hint.setObjectName("Muted")
        q_hint.setWordWrap(True)
        q_lay.addWidget(q_hint)
        self.lst_queue = QListWidget()
        self.lst_queue.currentItemChanged.connect(self._on_queue_item)
        q_lay.addWidget(self.lst_queue, 1)
        outer.addWidget(list_frame)

        # ---- right: header + steps + log --------------------------
        right = QWidget()
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(0, 0, 0, 0)
        r_lay.setSpacing(10)

        header = QFrame()
        header.setObjectName("Card")
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(12, 8, 12, 8)
        self.lbl_inc = QLabel("No incident selected")
        self.lbl_inc.setObjectName("H2")
        h_lay.addWidget(self.lbl_inc)
        self.lbl_meta = QLabel("")
        self.lbl_meta.setObjectName("Caption")
        h_lay.addSpacing(20)
        h_lay.addWidget(self.lbl_meta)
        h_lay.addStretch(1)
        self.bar_completion = QProgressBar()
        self.bar_completion.setRange(0, 100)
        self.bar_completion.setValue(0)
        self.bar_completion.setFormat("%p%  completed")
        self.bar_completion.setMaximumWidth(280)
        h_lay.addWidget(self.bar_completion)
        r_lay.addWidget(header)

        # "Do this next" guidance banner
        self.lbl_next = QLabel("")
        self.lbl_next.setObjectName("Card")
        self.lbl_next.setTextFormat(Qt.TextFormat.RichText)
        self.lbl_next.setWordWrap(True)
        self.lbl_next.setContentsMargins(12, 10, 12, 10)
        self.lbl_next.setVisible(False)
        r_lay.addWidget(self.lbl_next)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        split.setChildrenCollapsible(False)

        steps_frame = QFrame()
        steps_frame.setObjectName("Card")
        s_lay = QVBoxLayout(steps_frame)
        s_lay.setContentsMargins(8, 8, 8, 8)
        s_title = QLabel("Playbook Steps")
        s_title.setObjectName("H2")
        s_lay.addWidget(s_title)

        self.tbl = QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels([
            "Step", "Phase", "Deadline", "Auto", "Status",
            "Action", "Responsible"])
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setShowGrid(False)
        self.tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._steps_context_menu)
        hdr = self.tbl.horizontalHeader()
        for c in (0, 1, 2, 3, 4):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        s_lay.addWidget(self.tbl, 1)

        action_bar = QHBoxLayout()
        self.btn_complete = QPushButton("Mark Step COMPLETED")
        self.btn_complete.setObjectName("Primary")
        self.btn_complete.clicked.connect(
            lambda: self._mark_step("COMPLETED", prompt=False))
        action_bar.addWidget(self.btn_complete)
        self.btn_skip = QPushButton("Skip Step")
        self.btn_skip.clicked.connect(
            lambda: self._mark_step("SKIPPED", prompt=False))
        action_bar.addWidget(self.btn_skip)
        self.btn_fail = QPushButton("Mark FAILED")
        self.btn_fail.setObjectName("Danger")
        self.btn_fail.clicked.connect(
            lambda: self._mark_step("FAILED", prompt=True))
        action_bar.addWidget(self.btn_fail)
        self.btn_unmark = QPushButton("Unmark Step")
        self.btn_unmark.clicked.connect(self._unmark_step)
        action_bar.addWidget(self.btn_unmark)
        action_bar.addStretch(1)
        # Incident-level status actions (so completion reflects on Home/Incidents)
        self.btn_contain = QPushButton("Incident → CONTAINED")
        self.btn_contain.clicked.connect(lambda: self._set_incident_status("CONTAINED"))
        action_bar.addWidget(self.btn_contain)
        self.btn_close = QPushButton("Incident → CLOSED")
        self.btn_close.clicked.connect(lambda: self._set_incident_status("CLOSED"))
        action_bar.addWidget(self.btn_close)
        s_lay.addLayout(action_bar)
        split.addWidget(steps_frame)

        log_frame = QFrame()
        log_frame.setObjectName("Card")
        l_lay = QVBoxLayout(log_frame)
        l_lay.setContentsMargins(8, 8, 8, 8)
        l_title = QLabel("Execution Log")
        l_title.setObjectName("H2")
        l_lay.addWidget(l_title)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        l_lay.addWidget(self.txt_log, 1)
        split.addWidget(log_frame)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        r_lay.addWidget(split, 1)

        outer.addWidget(right)
        outer.setStretchFactor(0, 1)
        outer.setStretchFactor(1, 4)
        root.addWidget(outer, 1)

    # ------------------------------------------------------------------
    # Incident browser (left panel)
    # ------------------------------------------------------------------
    def _username(self) -> str:
        return (self.bus.parent().session.username
                if hasattr(self.bus.parent(), "session") else "dashboard_user")

    def _completion(self, inc) -> Tuple[int, int]:
        """(#done, #total) playbook steps. done = any non-PENDING outcome."""
        if inc is None or not inc.playbook_id:
            return (0, 0)
        try:
            pb = self.engine.get_playbook(inc.playbook_id)
        except KeyError:
            return (0, 0)
        rows = self.case_store.get_playbook_executions(inc.incident_id)
        last: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            last[r["step_id"]] = r
        n_done = sum(1 for s in pb.steps
                     if (last.get(s.step_id) or {}).get("outcome", "PENDING")
                     != "PENDING")
        return (n_done, len(pb.steps))

    def _load_incidents(self) -> None:
        """(Re)populate the left incident list from the case-store, honoring
        the status filter, preserving the current/target selection."""
        try:
            incidents = self.case_store.list_incidents(
                status=None if self._status_filter == "(any)" else self._status_filter,
                limit=200)
        except Exception:
            incidents = []
        target = self._pending_select or self.selected_incident_id
        self.lst_queue.blockSignals(True)
        self.lst_queue.clear()
        match_item = None
        for inc in incidents:
            done, total = self._completion(inc)
            pct = int(round(100 * done / total)) if total else 0
            tick = " ✓" if total and done >= total else ""
            label = (f"{inc.incident_id}\n  {inc.incident_type} · "
                     f"{inc.severity} · {inc.status} · "
                     f"{done}/{total} ({pct}%){tick}")
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, inc.incident_id)
            item.setForeground(QBrush(QColor(severity_color(inc.severity))))
            self.lst_queue.addItem(item)
            if inc.incident_id == target:
                match_item = item
        self.lst_queue.blockSignals(False)
        if match_item is not None:
            self.lst_queue.setCurrentItem(match_item)
            self.selected_incident_id = match_item.data(Qt.ItemDataRole.UserRole)
            self._pending_select = None
        elif self.lst_queue.count() and not self.selected_incident_id:
            self.lst_queue.setCurrentRow(0)
            self.selected_incident_id = self.lst_queue.item(0).data(
                Qt.ItemDataRole.UserRole)

    def showEvent(self, e) -> None:
        super().showEvent(e)
        self._load_incidents()
        self._refresh()

    def _on_filter_changed(self, txt: str) -> None:
        self._status_filter = txt
        self._load_incidents()
        self._refresh()

    def _on_queue_item(self, cur, _prev) -> None:
        if cur is None:
            return
        inc_id = cur.data(Qt.ItemDataRole.UserRole)
        if inc_id and inc_id != self.selected_incident_id:
            self.selected_incident_id = inc_id
            self._refresh()

    # ------------------------------------------------------------------
    def load_response_queue(self, incident_ids: List[str]) -> None:
        """'Respond' from the Incidents tab -> focus the first selected
        incident in the browser (others remain a click away in the list)."""
        ids = [i for i in (incident_ids or []) if i]
        if not ids:
            return
        # Make sure the target is visible regardless of the current filter.
        if self._status_filter != "(any)":
            self.cb_filter.blockSignals(True)
            self.cb_filter.setCurrentText("(any)")
            self.cb_filter.blockSignals(False)
            self._status_filter = "(any)"
        self.selected_incident_id = ids[0]
        self._pending_select = ids[0]
        self._load_incidents()
        self._refresh()
        self.bus.status_message.emit(
            f"Responding to {len(ids)} incident{'s' if len(ids) != 1 else ''} "
            f"— starting with {ids[0]}", 3000)

    def _on_incident_selected(self, inc_id: str) -> None:
        self.selected_incident_id = inc_id
        self._pending_select = inc_id
        if self.isVisible():
            self._load_incidents()
            self._refresh()

    def _on_refresh_requested(self) -> None:
        self._load_incidents()
        self._refresh()

    def _poll(self, _seq: int) -> None:
        if not self.isVisible():
            return
        v = getattr(self.case_store, "data_version", None)
        if (v is not None and v == self._last_data_version
                and self.selected_incident_id == self._last_rendered_inc):
            return
        self._load_incidents()
        self._refresh()

    # ------------------------------------------------------------------
    def _refresh(self) -> None:
        inc_id = self.selected_incident_id
        if not inc_id:
            self.tbl.setRowCount(0)
            self.txt_log.clear()
            self.bar_completion.setValue(0)
            self.lbl_inc.setText("No incident selected")
            self.lbl_meta.setText("")
            self.lbl_next.setVisible(False)
            return
        inc = self.case_store.get_incident(inc_id)
        if inc is None:
            self.lbl_inc.setText(f"{inc_id} — not found")
            return

        from dashboard import theme as _t
        self.lbl_inc.setText(f"{inc_id}  •  {inc.incident_type}")
        sev_html = (f"<span style='color:{severity_color(inc.severity)};"
                    f"font-weight:600;'>{inc.severity}</span>")
        self.lbl_meta.setText(
            f"<span style='color:{_t.TEXT_SECONDARY};'>Severity:</span> {sev_html}"
            f"  &nbsp;  <span style='color:{_t.TEXT_SECONDARY};'>Status:</span> "
            f"<b>{inc.status}</b>  &nbsp;  "
            f"<span style='color:{_t.TEXT_SECONDARY};'>Playbook:</span> "
            f"<b>{inc.playbook_id or '(none)'}</b>")

        pb: Optional[Playbook] = None
        if inc.playbook_id:
            try:
                pb = self.engine.get_playbook(inc.playbook_id)
            except KeyError:
                pb = None
        if pb is None:
            self.tbl.setRowCount(0)
            self.txt_log.setPlainText(
                f"No playbook attached to {inc_id}. "
                f"(incident.playbook_id = {inc.playbook_id!r})")
            self.bar_completion.setValue(0)
            self.lbl_next.setVisible(False)
            self._last_data_version = getattr(self.case_store, "data_version", 0)
            self._last_rendered_inc = inc_id
            return

        rows = self.case_store.get_playbook_executions(inc_id)
        last_outcome: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            last_outcome[r["step_id"]] = r

        self.tbl.setUpdatesEnabled(False)
        next_pending_row: Optional[int] = None
        next_step: Optional[PlaybookStep] = None
        try:
            self.tbl.setRowCount(len(pb.steps))
            n_done = 0
            for r_idx, step in enumerate(pb.steps):
                state = last_outcome.get(step.step_id)
                outcome = (state or {}).get("outcome", "PENDING")
                if outcome != "PENDING":
                    n_done += 1
                elif next_pending_row is None:
                    next_pending_row = r_idx
                    next_step = step
                deadline = (f"{step.deadline_hours:.1f} h"
                            if step.deadline_hours is not None else "POST")
                items = [
                    QTableWidgetItem(step.step_id),
                    QTableWidgetItem(step.phase),
                    QTableWidgetItem(deadline),
                    QTableWidgetItem("AUTO" if step.automated else "MANUAL"),
                    QTableWidgetItem(outcome),
                    QTableWidgetItem(step.action),
                    QTableWidgetItem(step.responsible),
                ]
                items[1].setForeground(QBrush(QColor(phase_color(step.phase))))
                items[4].setForeground(QBrush(QColor(outcome_color(outcome))))
                if step.automated:
                    items[3].setForeground(QBrush(QColor(ACCENT)))
                if (state or {}).get("deadline_met") == 0:
                    items[2].setForeground(QBrush(QColor("#ff3b3b")))
                for c, it in enumerate(items):
                    self.tbl.setItem(r_idx, c, it)
            pct = int(round(100 * n_done / max(len(pb.steps), 1)))
            self.bar_completion.setValue(pct)
            self.bar_completion.setFormat(f"{n_done}/{len(pb.steps)} steps  ({pct}%)")
        finally:
            self.tbl.setUpdatesEnabled(True)

        if next_step is not None:
            self.tbl.selectRow(next_pending_row)
            dl = (f"{next_step.deadline_hours:.1f} h"
                  if next_step.deadline_hours is not None else "post-incident")
            auto = (" <i>(automated — auto-completes on scan)</i>"
                    if next_step.automated else "")
            self.lbl_next.setText(
                f"<b style='color:{ACCENT};'>Do this next:</b> "
                f"<b>{next_step.step_id}</b> — {next_step.action}<br>"
                f"<span style='color:{_t.TEXT_SECONDARY};'>Responsible:</span> "
                f"{next_step.responsible or '—'} &nbsp;·&nbsp; "
                f"<span style='color:{_t.TEXT_SECONDARY};'>Deadline:</span> "
                f"{dl}{auto}")
            self.lbl_next.setVisible(True)
        else:
            self.lbl_next.setText(
                f"<b style='color:{outcome_color('COMPLETED')};'>"
                f"All {len(pb.steps)} steps actioned ✓</b> — playbook complete"
                f"{' (incident auto-advanced to CONTAINED)' if inc.status != 'OPEN' else ''}."
                f" Use Incident → CONTAINED / CLOSED to finalize.")
            self.lbl_next.setVisible(True)

        self._last_data_version = getattr(self.case_store, "data_version", 0)
        self._last_rendered_inc = inc_id

        log_lines = [f"Playbook: {pb.playbook_id} — {pb.name}",
                     f"RTO target: {pb.rto_hours:.1f} h",
                     f"Regulatory anchor: {pb.regulatory_anchor}",
                     "-" * 64]
        for r in rows:
            ts = (r["executed_at"] or "")[:19].replace("T", " ")
            dmet = r.get("deadline_met")
            dmark = "" if dmet is None else (" [on time]" if dmet else " [LATE]")
            log_lines.append(
                f"  {ts}  {r['step_id']}  {r['outcome']:<10}  "
                f"by {r['executed_by'] or '-'}{dmark}")
            if r.get("notes"):
                log_lines.append(f"      note: {r['notes']}")
        self.txt_log.setPlainText("\n".join(log_lines))

    # ------------------------------------------------------------------
    # Step actions
    # ------------------------------------------------------------------
    def _selected_step_id(self) -> Optional[str]:
        sel = self.tbl.selectedItems()
        if not sel:
            return None
        return self.tbl.item(sel[0].row(), 0).text()

    def _selected_step_outcome(self) -> Optional[str]:
        sel = self.tbl.selectedItems()
        if not sel:
            return None
        it = self.tbl.item(sel[0].row(), 4)
        return it.text() if it else None

    def _steps_context_menu(self, pos) -> None:
        row = self.tbl.rowAt(pos.y())
        if row >= 0:
            self.tbl.selectRow(row)
        step_id = self._selected_step_id()
        if not step_id:
            return
        outcome = self._selected_step_outcome() or "PENDING"
        menu = QMenu(self)
        a_unmark = a_done = a_note = a_skip = a_fail = None
        if outcome != "PENDING":
            a_unmark = menu.addAction(f"Unmark — revert {outcome} → PENDING")
            menu.addSeparator()
            a_done = menu.addAction("Re-mark COMPLETED")
            a_note = menu.addAction("Complete with note…")
            a_skip = menu.addAction("Mark SKIPPED")
            a_fail = menu.addAction("Mark FAILED…")
        else:
            a_done = menu.addAction("Mark COMPLETED")
            a_note = menu.addAction("Complete with note…")
            a_skip = menu.addAction("Skip step")
            a_fail = menu.addAction("Mark FAILED…")
        chosen = menu.exec(self.tbl.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen is a_unmark:
            self._mark_step("PENDING", prompt=False)
        elif chosen is a_done:
            self._mark_step("COMPLETED", prompt=False)
        elif chosen is a_note:
            self._mark_step("COMPLETED", prompt=True)
        elif chosen is a_skip:
            self._mark_step("SKIPPED", prompt=False)
        elif chosen is a_fail:
            self._mark_step("FAILED", prompt=True)

    def _unmark_step(self) -> None:
        outcome = self._selected_step_outcome()
        if outcome is None:
            self.bus.status_message.emit("Select a step row first", 3000)
            return
        if outcome == "PENDING":
            self.bus.status_message.emit("Step is already PENDING", 2500)
            return
        self._mark_step("PENDING", prompt=False)

    def _mark_step(self, outcome: str, prompt: bool = False) -> None:
        inc_id = self.selected_incident_id
        if not inc_id:
            self.bus.status_message.emit(
                "Select an incident first", 3500)
            return
        step_id = self._selected_step_id()
        if not step_id:
            self.bus.status_message.emit("Select a step row first", 3000)
            return
        notes = ""
        if prompt:
            notes, ok = QInputDialog.getText(
                self, f"Mark {step_id} as {outcome}", "Notes (optional):")
            if not ok:
                return

        inc = self.case_store.get_incident(inc_id)
        pb = self.engine.get_playbook(inc.playbook_id) if inc and inc.playbook_id else None
        step = pb.step_by_id(step_id) if pb else None
        deadline_met: Optional[bool] = None
        if step and step.deadline_hours is not None and inc and outcome != "PENDING":
            try:
                detected = datetime.fromisoformat(inc.detected_at)
                elapsed_h = (datetime.now() - detected).total_seconds() / 3600
                deadline_met = elapsed_h <= step.deadline_hours
            except Exception:
                deadline_met = None

        user = self._username()
        action = "STEP_UNMARKED" if outcome == "PENDING" else f"STEP_{outcome}"
        try:
            self.case_store.log_playbook_step(
                incident_id=inc_id, step_id=step_id, executed_by=user,
                outcome=outcome, deadline_met=deadline_met, notes=notes or "")
            self.case_store.log_audit(
                inc_id, action=action, performed_by=user,
                change_summary=f"step={step_id}")
            self.bus.status_message.emit(
                f"{inc_id} step {step_id} -> {outcome}", 3000)
            if outcome != "PENDING":
                self._maybe_autoadvance(inc_id)
            self._load_incidents()
            self._refresh()
        except Exception as exc:
            QMessageBox.warning(self, "Step update failed", str(exc))

    def _maybe_autoadvance(self, inc_id: str) -> None:
        """When every playbook step is actioned, advance OPEN -> CONTAINED so
        Home/Incidents reflect that response is underway."""
        inc = self.case_store.get_incident(inc_id)
        if inc is None or inc.status != "OPEN":
            return
        done, total = self._completion(inc)
        if total and done >= total:
            try:
                self.case_store.update_incident_status(
                    inc_id, "CONTAINED", performed_by=self._username())
                self.bus.status_message.emit(
                    f"{inc_id}: all steps actioned → auto-advanced to CONTAINED",
                    4500)
            except Exception:
                pass

    def _set_incident_status(self, status: str) -> None:
        inc_id = self.selected_incident_id
        if not inc_id:
            self.bus.status_message.emit("Select an incident first", 3000)
            return
        try:
            self.case_store.update_incident_status(
                inc_id, status, performed_by=self._username())
            self.bus.status_message.emit(f"{inc_id} -> {status}", 3000)
            self._load_incidents()
            self._refresh()
        except Exception as exc:
            QMessageBox.warning(self, "Status update failed", str(exc))
