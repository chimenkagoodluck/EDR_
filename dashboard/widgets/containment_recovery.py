"""dashboard/widgets/containment_recovery.py

Side-by-side view of containment recommendations + recovery checklist for the
currently-selected incident, plus the evidence chain (SHA-256 hashes).
"""
from __future__ import annotations

from typing import Optional, List

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QSplitter, QPlainTextEdit, QPushButton,
    QListWidget, QListWidgetItem, QComboBox,
)

from response.case_store import CaseStore
from recovery.containment_advisor import ContainmentAdvisor
from recovery.recovery_checklist import RecoveryChecklist
from dashboard.theme import (
    BG_PANEL, BG_RAISED, TEXT_PRIMARY, TEXT_SECONDARY, ACCENT, BORDER,
    severity_color,
)

STATUS_FILTERS = ["(any)", "OPEN", "CONTAINED", "CLOSED", "ABANDONED"]


class ContainmentRecoveryWidget(QWidget):
    def __init__(self, case_store: CaseStore,
                 advisor: ContainmentAdvisor,
                 checklist: RecoveryChecklist,
                 bus, parent=None):
        super().__init__(parent)
        self.case_store = case_store
        self.advisor = advisor
        self.checklist = checklist
        self.bus = bus
        self.selected_incident_id: Optional[str] = None
        self._pending_select: Optional[str] = None
        self._status_filter = "(any)"
        self._last_data_version = -1
        self._last_rendered_inc: Optional[str] = None
        self._build_ui()
        self.bus.incident_selected.connect(self._on_incident_selected)
        self.bus.refresh_requested.connect(self._refresh)
        self.bus.tick.connect(self._poll)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        outer = QSplitter(Qt.Orientation.Horizontal)
        outer.setHandleWidth(2)
        outer.setChildrenCollapsible(False)

        # ---- left: incident browser ---------------------------------
        list_frame = QFrame()
        list_frame.setObjectName("Card")
        ll = QVBoxLayout(list_frame)
        ll.setContentsMargins(8, 8, 8, 8)
        lt = QLabel("Incidents")
        lt.setObjectName("H2")
        ll.addWidget(lt)
        frow = QHBoxLayout()
        frow.addWidget(QLabel("Status:"))
        self.cb_filter = QComboBox()
        self.cb_filter.addItems(STATUS_FILTERS)
        self.cb_filter.setCurrentText(self._status_filter)
        self.cb_filter.currentTextChanged.connect(self._on_filter_changed)
        frow.addWidget(self.cb_filter, 1)
        ll.addLayout(frow)
        hint = QLabel("Pick an incident to see its containment actions, "
                      "recovery checklist, and evidence.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        ll.addWidget(hint)
        self.lst_inc = QListWidget()
        self.lst_inc.currentItemChanged.connect(self._on_list_item)
        ll.addWidget(self.lst_inc, 1)
        outer.addWidget(list_frame)

        # ---- right: existing containment / recovery / evidence -------
        right = QWidget()
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(0, 0, 0, 0)
        r_lay.setSpacing(10)

        # header
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
        self.lbl_rto_savings = QLabel("")
        self.lbl_rto_savings.setObjectName("Accent")
        h_lay.addWidget(self.lbl_rto_savings)
        r_lay.addWidget(header)

        # body: two-column splitter
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        split.setChildrenCollapsible(False)

        # ---- Containment column -------------------------------------
        cont_frame = QFrame()
        cont_frame.setObjectName("Card")
        cl = QVBoxLayout(cont_frame)
        cl.setContentsMargins(8, 8, 8, 8)
        cl_title = QLabel("Containment Actions")
        cl_title.setObjectName("H2")
        cl.addWidget(cl_title)
        self.tbl_cont = QTableWidget(0, 5)
        self.tbl_cont.setHorizontalHeaderLabels(
            ["#", "Action", "Auto", "RTO Save", "Description"])
        self.tbl_cont.verticalHeader().setVisible(False)
        self.tbl_cont.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_cont.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_cont.setAlternatingRowColors(True)
        self.tbl_cont.setShowGrid(False)
        self.tbl_cont.setWordWrap(True)
        hdr = self.tbl_cont.horizontalHeader()
        for c in (0, 1, 2, 3):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        cl.addWidget(self.tbl_cont, 1)
        split.addWidget(cont_frame)

        # ---- Recovery column ----------------------------------------
        rec_frame = QFrame()
        rec_frame.setObjectName("Card")
        rl = QVBoxLayout(rec_frame)
        rl.setContentsMargins(8, 8, 8, 8)
        rl_top = QHBoxLayout()
        rl_title = QLabel("Recovery Checklist")
        rl_title.setObjectName("H2")
        rl_top.addWidget(rl_title)
        rl_top.addStretch(1)
        self.lbl_rto = QLabel("")
        self.lbl_rto.setObjectName("Accent")
        rl_top.addWidget(self.lbl_rto)
        rl.addLayout(rl_top)

        self.tbl_rec = QTableWidget(0, 4)
        self.tbl_rec.setHorizontalHeaderLabels(
            ["Step", "Target", "Owner", "Action"])
        self.tbl_rec.verticalHeader().setVisible(False)
        self.tbl_rec.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_rec.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_rec.setAlternatingRowColors(True)
        self.tbl_rec.setShowGrid(False)
        self.tbl_rec.setWordWrap(True)
        hdr2 = self.tbl_rec.horizontalHeader()
        for c in (0, 1, 2):
            hdr2.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr2.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        rl.addWidget(self.tbl_rec, 1)
        split.addWidget(rec_frame)

        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 1)
        r_lay.addWidget(split, 1)

        # ---- Evidence chain (bottom) --------------------------------
        ev_frame = QFrame()
        ev_frame.setObjectName("Card")
        el = QVBoxLayout(ev_frame)
        el.setContentsMargins(8, 8, 8, 8)
        et = QHBoxLayout()
        et_title = QLabel("Evidence Chain (SHA-256)")
        et_title.setObjectName("H2")
        et.addWidget(et_title)
        et.addStretch(1)
        self.lbl_ev_count = QLabel("0 artefacts")
        self.lbl_ev_count.setObjectName("Caption")
        et.addWidget(self.lbl_ev_count)
        el.addLayout(et)
        self.txt_evidence = QPlainTextEdit()
        self.txt_evidence.setReadOnly(True)
        self.txt_evidence.setMaximumHeight(180)
        el.addWidget(self.txt_evidence)
        r_lay.addWidget(ev_frame)

        outer.addWidget(right)
        outer.setStretchFactor(0, 1)
        outer.setStretchFactor(1, 4)
        root.addWidget(outer, 1)

    # ------------------------------------------------------------------
    # Incident browser (left panel)
    # ------------------------------------------------------------------
    def _load_incidents(self) -> None:
        try:
            incidents = self.case_store.list_incidents(
                status=None if self._status_filter == "(any)" else self._status_filter,
                limit=200)
        except Exception:
            incidents = []
        target = self._pending_select or self.selected_incident_id
        self.lst_inc.blockSignals(True)
        self.lst_inc.clear()
        match = None
        for inc in incidents:
            label = (f"{inc.incident_id}\n  {inc.incident_type} · "
                     f"{inc.severity} · {inc.status}")
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, inc.incident_id)
            item.setForeground(QBrush(QColor(severity_color(inc.severity))))
            self.lst_inc.addItem(item)
            if inc.incident_id == target:
                match = item
        self.lst_inc.blockSignals(False)
        if match is not None:
            self.lst_inc.setCurrentItem(match)
            self.selected_incident_id = match.data(Qt.ItemDataRole.UserRole)
            self._pending_select = None
        elif self.lst_inc.count() and not self.selected_incident_id:
            self.lst_inc.setCurrentRow(0)
            self.selected_incident_id = self.lst_inc.item(0).data(
                Qt.ItemDataRole.UserRole)

    def showEvent(self, e) -> None:
        super().showEvent(e)
        self._load_incidents()
        self._refresh()

    def _on_filter_changed(self, txt: str) -> None:
        self._status_filter = txt
        self._load_incidents()
        self._refresh()

    def _on_list_item(self, cur, _prev) -> None:
        if cur is None:
            return
        inc_id = cur.data(Qt.ItemDataRole.UserRole)
        if inc_id and inc_id != self.selected_incident_id:
            self.selected_incident_id = inc_id
            self._refresh()

    # ------------------------------------------------------------------
    def _on_incident_selected(self, inc_id: str) -> None:
        self.selected_incident_id = inc_id
        self._pending_select = inc_id
        if self.isVisible():
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

    def _refresh(self) -> None:
        inc_id = self.selected_incident_id
        self._last_data_version = getattr(self.case_store, "data_version", 0)
        self._last_rendered_inc = inc_id
        if not inc_id:
            self.tbl_cont.setRowCount(0)
            self.tbl_rec.setRowCount(0)
            self.txt_evidence.clear()
            self.lbl_inc.setText("No incident selected")
            self.lbl_meta.setText("")
            self.lbl_rto.setText("")
            self.lbl_rto_savings.setText("")
            self.lbl_ev_count.setText("0 artefacts")
            return

        inc = self.case_store.get_incident(inc_id)
        if inc is None:
            self.lbl_inc.setText(f"{inc_id} — not found")
            return

        # header -- resolve theme colours at call time (post-swap correctness)
        from dashboard import theme as _t
        self.lbl_inc.setText(f"{inc_id}  •  {inc.incident_type}")
        sev_html = (f"<span style='color:{severity_color(inc.severity)};"
                    f"font-weight:600;'>{inc.severity}</span>")
        self.lbl_meta.setText(
            f"<span style='color:{_t.TEXT_SECONDARY};'>Severity:</span> {sev_html}"
            f"  &nbsp;  <span style='color:{_t.TEXT_SECONDARY};'>Status:</span> "
            f"<b>{inc.status}</b>")

        # containment recommendations
        actions = self.advisor.recommend(inc.incident_type, inc.severity or "HIGH")
        total_save = sum(a.rto_impact_h for a in actions)
        self.lbl_rto_savings.setText(
            f"Potential RTO savings: {total_save:.1f} h")
        self.tbl_cont.setRowCount(len(actions))
        for r, act in enumerate(actions):
            items = [
                QTableWidgetItem(str(act.priority)),
                QTableWidgetItem(act.action),
                QTableWidgetItem("AUTO" if act.automatable else "MANUAL"),
                QTableWidgetItem(f"{act.rto_impact_h:.1f} h"),
                QTableWidgetItem(act.description),
            ]
            if act.automatable:
                items[2].setForeground(QBrush(QColor(ACCENT)))
            items[3].setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            for c, it in enumerate(items):
                self.tbl_cont.setItem(r, c, it)
        self.tbl_cont.resizeRowsToContents()

        # recovery checklist
        steps = self.checklist.checklist_for(inc.incident_type)
        rto = self.checklist.rto_target(inc.incident_type)
        self.lbl_rto.setText(f"RTO target: {rto:.1f} h")
        self.tbl_rec.setRowCount(len(steps))
        for r, step in enumerate(steps):
            items = [
                QTableWidgetItem(step.step_id),
                QTableWidgetItem(f"+{step.target_hours:.1f} h"),
                QTableWidgetItem(step.owner),
                QTableWidgetItem(step.action + "\n" + step.description),
            ]
            items[1].setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            for c, it in enumerate(items):
                self.tbl_rec.setItem(r, c, it)
        self.tbl_rec.resizeRowsToContents()

        # evidence chain
        chain = self.case_store.get_evidence_chain(inc_id)
        self.lbl_ev_count.setText(
            f"{len(chain)} artefact{'s' if len(chain) != 1 else ''}")
        if not chain:
            self.txt_evidence.setPlainText(
                "(no evidence captured for this incident yet)")
        else:
            lines = []
            for ev in chain:
                ts = (ev.get("collected_at") or "")[:19].replace("T", " ")
                hsh = (ev.get("file_hash") or "")[:24]
                lines.append(
                    f"  {ts}  [{ev.get('source_type','?'):<18}] "
                    f"hash={hsh}...  {ev.get('description') or ev.get('file_path','')}")
            self.txt_evidence.setPlainText("\n".join(lines))
