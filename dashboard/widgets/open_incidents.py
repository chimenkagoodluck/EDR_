"""dashboard/widgets/open_incidents.py

Tabular view of incidents (default filter: status=OPEN). Severity is colour-
coded, ITS shown numerically. Selecting a row emits SignalBus.incident_selected.
"""
from __future__ import annotations

from typing import List, Optional

from PyQt6.QtCore import Qt, QItemSelectionModel
from PyQt6.QtGui import QColor, QBrush, QGuiApplication
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame, QMenu,
)

from response.case_store import CaseStore, Incident
from dashboard.theme import (
    BG_PANEL, BG_RAISED, TEXT_PRIMARY, TEXT_SECONDARY, ACCENT, BORDER,
    severity_color, status_color,
)


STATUS_OPTIONS = ["OPEN", "CONTAINED", "CLOSED", "ABANDONED", "(any)"]
TYPE_OPTIONS   = ["(any)", "INC-01", "INC-02", "INC-03",
                  "INC-04", "INC-05", "INC-06"]


class OpenIncidentsWidget(QWidget):
    def __init__(self, case_store: CaseStore, bus, parent=None):
        super().__init__(parent)
        self.case_store = case_store
        self.bus = bus
        self._last_data_version = -1
        self._last_filter_sig: Optional[tuple] = None
        # Load persisted filter preferences (per signed-in user)
        from dashboard.prefs import get_prefs
        self._prefs = get_prefs()
        self._build_ui()
        # Apply persisted filter values before wiring change signals
        self._restore_filters()
        self.cb_status.currentTextChanged.connect(self._on_filter_changed)
        self.cb_type.currentTextChanged.connect(self._on_filter_changed)
        self.bus.tick.connect(self._poll)
        self.bus.refresh_requested.connect(self._refresh)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # ---- filter bar ----------------------------------------------
        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addWidget(QLabel("Status:"))
        self.cb_status = QComboBox()
        self.cb_status.addItems(STATUS_OPTIONS)
        self.cb_status.setCurrentText("OPEN")
        bar.addWidget(self.cb_status)

        bar.addSpacing(12)
        bar.addWidget(QLabel("INC Type:"))
        self.cb_type = QComboBox()
        self.cb_type.addItems(TYPE_OPTIONS)
        bar.addWidget(self.cb_type)

        bar.addSpacing(12)
        self.lbl_count = QLabel("0 rows")
        self.lbl_count.setObjectName("Caption")
        bar.addWidget(self.lbl_count)
        bar.addStretch(1)

        self.btn_contain = QPushButton("Mark CONTAINED")
        self.btn_contain.clicked.connect(lambda: self._update_status("CONTAINED"))
        bar.addWidget(self.btn_contain)
        self.btn_close = QPushButton("Mark CLOSED")
        self.btn_close.setObjectName("Primary")
        self.btn_close.clicked.connect(lambda: self._update_status("CLOSED"))
        bar.addWidget(self.btn_close)
        root.addLayout(bar)

        # ---- table ---------------------------------------------------
        frame = QFrame()
        frame.setObjectName("Card")
        f_lay = QVBoxLayout(frame)
        f_lay.setContentsMargins(8, 8, 8, 8)

        # 12 columns. Count + Host are inserted right after ITS so the
        # at-a-glance scan of severity / score / volume / affected host
        # reads naturally before the timestamp + summary columns.
        self.tbl = QTableWidget(0, 12)
        self.tbl.setHorizontalHeaderLabels([
            "Incident ID", "Type", "Severity", "ITS", "Count", "Host",
            "Detected", "Status", "Source", "Tactic", "Technique", "Summary"])
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        # Extended selection so the analyst can Ctrl/Shift-pick several
        # incidents and respond to / triage them as a batch.
        self.tbl.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setShowGrid(False)
        hdr = self.tbl.horizontalHeader()
        for c in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(11, QHeaderView.ResizeMode.Stretch)
        self.tbl.itemSelectionChanged.connect(self._on_selected)
        # Double-click any row -> open the full incident-detail dialog
        self.tbl.itemDoubleClicked.connect(self._on_double_clicked)
        # Right-click -> context menu (Respond, status actions, copy)
        self.tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._show_context_menu)
        f_lay.addWidget(self.tbl)

        # Hint label so the user knows the row is clickable
        hint = QLabel("Double-click a row for full detail · right-click (or "
                      "select several with Ctrl/Shift) to Respond with a "
                      "guided playbook or change status.")
        hint.setObjectName("Muted")
        f_lay.addWidget(hint)

        root.addWidget(frame, 1)

    # ------------------------------------------------------------------
    def _restore_filters(self) -> None:
        username = (self.bus.parent().session.username
                    if hasattr(self.bus.parent(), "session") else "anonymous")
        f = self._prefs.get_user_filter(
            username, "open_incidents",
            default={"status": "OPEN", "type": "(any)"})
        status = f.get("status", "OPEN")
        inc_type = f.get("type", "(any)")
        if status in STATUS_OPTIONS:
            self.cb_status.blockSignals(True)
            self.cb_status.setCurrentText(status)
            self.cb_status.blockSignals(False)
        if inc_type in TYPE_OPTIONS:
            self.cb_type.blockSignals(True)
            self.cb_type.setCurrentText(inc_type)
            self.cb_type.blockSignals(False)

    def _on_filter_changed(self, _txt: str) -> None:
        username = (self.bus.parent().session.username
                    if hasattr(self.bus.parent(), "session") else "anonymous")
        self._prefs.set_user_filter(username, "open_incidents", {
            "status": self.cb_status.currentText(),
            "type":   self.cb_type.currentText(),
        })
        self._refresh()

    # ------------------------------------------------------------------
    def _poll(self, _seq: int) -> None:
        if not self.isVisible():
            return
        v = getattr(self.case_store, "data_version", None)
        if v is not None and v == self._last_data_version:
            return
        self._refresh()

    def _refresh(self) -> None:
        status = self.cb_status.currentText()
        inc_type = self.cb_type.currentText()
        # Skip rebuild entirely if neither filters nor DB watermark moved.
        v = getattr(self.case_store, "data_version", None)
        filter_sig = (status, inc_type)
        if (v is not None and v == self._last_data_version
                and filter_sig == self._last_filter_sig):
            return
        try:
            incidents = self.case_store.list_incidents(
                status=None if status == "(any)" else status,
                incident_type=None if inc_type == "(any)" else inc_type,
                limit=200,
            )
        except Exception as exc:
            self.bus.status_message.emit(f"DB read failed: {exc}", 4000)
            return

        # Preserve the FULL selection (not just one row) -- otherwise a
        # multi-select collapses to a single row on the next refresh tick.
        keep_ids = set(self._selected_incident_ids())

        self.tbl.blockSignals(True)
        self.tbl.setUpdatesEnabled(False)
        try:
            self.tbl.setRowCount(len(incidents))
            keep_rows: List[int] = []
            for r, inc in enumerate(incidents):
                self._populate_row(r, inc)
                if inc.incident_id in keep_ids:
                    keep_rows.append(r)
            sm = self.tbl.selectionModel()
            sm.clearSelection()
            for r in keep_rows:
                sm.select(
                    self.tbl.model().index(r, 0),
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows)
        finally:
            self.tbl.setUpdatesEnabled(True)
            self.tbl.blockSignals(False)
        # Show total incidents matching the same filters so the admin
        # knows the table is windowed (200 most recent). Cheap COUNT(*)
        # query -- idx_inc_status / idx_inc_type cover it.
        try:
            import sqlite3 as _sq
            with _sq.connect(str(self.case_store.db_path)) as _c:
                _c.execute("PRAGMA busy_timeout = 500")
                where, params = [], []
                if status and status != "(any)":
                    where.append("status=?"); params.append(status)
                if inc_type and inc_type != "(any)":
                    where.append("incident_type=?"); params.append(inc_type)
                sql = "SELECT COUNT(*) FROM incidents"
                if where:
                    sql += " WHERE " + " AND ".join(where)
                total = int(_c.execute(sql, params).fetchone()[0])
        except Exception:
            total = -1
        if total > len(incidents):
            self.lbl_count.setText(
                f"Showing {len(incidents):,} most recent of {total:,} "
                f"total — apply filters to narrow")
        else:
            self.lbl_count.setText(
                f"{len(incidents)} row{'s' if len(incidents) != 1 else ''}")
        self._last_data_version = getattr(self.case_store, "data_version", 0)
        self._last_filter_sig = filter_sig

    # ------------------------------------------------------------------
    def _populate_row(self, r: int, inc: Incident) -> None:
        ts = (inc.detected_at or "")[:19].replace("T", " ")
        its_str = f"{inc.its_score:.3f}" if inc.its_score is not None else ""
        # Compact source label: prefer the user-friendly name; fall back to
        # kind; show "—" for legacy rows that pre-date the migration.
        source_label = (getattr(inc, "source_name", "") or
                        getattr(inc, "source_kind", "") or "—")
        # Dedup signals: occurrence_count + host. Legacy rows missing the
        # column read as 1 / "" via the dataclass defaults.
        count = int(getattr(inc, "occurrence_count", 1) or 1)
        host  = str(getattr(inc, "source_host", "") or "—")
        count_str = f"{count:,}"
        items = [
            QTableWidgetItem(inc.incident_id),
            QTableWidgetItem(inc.incident_type),
            QTableWidgetItem(inc.severity),
            QTableWidgetItem(its_str),
            QTableWidgetItem(count_str),
            QTableWidgetItem(host),
            QTableWidgetItem(ts),
            QTableWidgetItem(inc.status),
            QTableWidgetItem(source_label),
            QTableWidgetItem(inc.attack_tactic or ""),
            QTableWidgetItem(inc.attack_technique or ""),
            QTableWidgetItem(inc.summary or ""),
        ]
        items[2].setForeground(QBrush(QColor(severity_color(inc.severity))))
        items[7].setForeground(QBrush(QColor(status_color(inc.status))))
        # Make a high occurrence count pop visually -- the operator needs
        # to see "this is the 312-event host" at a glance. Plain number
        # under 5 stays neutral.
        if count >= 100:
            items[4].setForeground(QBrush(QColor("#ff3b3b")))
        elif count >= 10:
            items[4].setForeground(QBrush(QColor("#ffae5a")))
        elif count > 1:
            items[4].setForeground(QBrush(QColor("#4cb1ff")))
        # right-align ITS + Count
        items[3].setTextAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        items[4].setTextAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        # Count tooltip: spell out first/last seen so the analyst sees the
        # time span of the merged events without opening Detail.
        first_seen = (getattr(inc, "first_seen_at", "")
                      or inc.detected_at or "")[:19].replace("T", " ")
        last_seen  = (getattr(inc, "last_seen_at", "")
                      or inc.detected_at or "")[:19].replace("T", " ")
        if count > 1:
            items[4].setToolTip(
                f"{count:,} occurrences\nfirst: {first_seen}\nlast:  {last_seen}")
        else:
            items[4].setToolTip("Single occurrence")
        # tooltip for the source column shows the full path (forensic-grade)
        full_src_tip = (f"name: {getattr(inc, 'source_name', '') or '—'}\n"
                        f"kind: {getattr(inc, 'source_kind', '') or '—'}\n"
                        f"path: {getattr(inc, 'source_path', '') or '—'}")
        items[8].setToolTip(full_src_tip)
        for c, it in enumerate(items):
            self.tbl.setItem(r, c, it)

    # ------------------------------------------------------------------
    def _selected_incident_id(self) -> Optional[str]:
        sel = self.tbl.selectedItems()
        if not sel:
            return None
        row = sel[0].row()
        item = self.tbl.item(row, 0)
        return item.text() if item else None

    def _selected_incident_ids(self) -> List[str]:
        """All selected incident IDs, in row order (de-duplicated)."""
        rows = sorted({i.row() for i in self.tbl.selectedItems()})
        ids = []
        for r in rows:
            it = self.tbl.item(r, 0)
            if it and it.text():
                ids.append(it.text())
        return ids

    def _on_selected(self) -> None:
        # Broadcast the primary (first) selection so follower widgets
        # (walker, audit, containment) track it as before.
        inc_id = self._selected_incident_id()
        if inc_id:
            self.bus.incident_selected.emit(inc_id)

    def _on_double_clicked(self, _item) -> None:
        inc_id = self._selected_incident_id()
        if inc_id:
            self.bus.incident_details.emit(inc_id)

    # ------------------------------------------------------------------
    def _show_context_menu(self, pos) -> None:
        ids = self._selected_incident_ids()
        if not ids:
            return
        menu = QMenu(self)
        n = len(ids)
        respond = menu.addAction(
            f"Respond — guided playbook ({n})" if n > 1
            else "Respond — guided playbook")
        detail = menu.addAction("Open full detail")
        detail.setEnabled(n == 1)
        menu.addSeparator()
        act_contain = menu.addAction(f"Mark CONTAINED ({n})" if n > 1 else "Mark CONTAINED")
        act_close   = menu.addAction(f"Mark CLOSED ({n})" if n > 1 else "Mark CLOSED")
        act_abandon = menu.addAction(f"Mark ABANDONED ({n})" if n > 1 else "Mark ABANDONED")
        menu.addSeparator()
        act_copy = menu.addAction(f"Copy ID{'s' if n > 1 else ''}")

        chosen = menu.exec(self.tbl.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen is respond:
            self._respond(ids)
        elif chosen is detail:
            self.bus.incident_details.emit(ids[0])
        elif chosen is act_contain:
            self._update_status("CONTAINED")
        elif chosen is act_close:
            self._update_status("CLOSED")
        elif chosen is act_abandon:
            self._update_status("ABANDONED")
        elif chosen is act_copy:
            QGuiApplication.clipboard().setText("\n".join(ids))
            self.bus.status_message.emit(
                f"Copied {len(ids)} incident ID{'s' if len(ids) != 1 else ''}", 2500)

    def _respond(self, ids: List[str]) -> None:
        self.bus.respond_requested.emit(list(ids))

    def _update_status(self, new_status: str) -> None:
        ids = self._selected_incident_ids()
        if not ids:
            self.bus.status_message.emit("Select an incident first", 3000)
            return
        user = (self.bus.parent().session.username
                if hasattr(self.bus.parent(), "session") else "dashboard_user")
        ok, failed = 0, 0
        for inc_id in ids:
            try:
                self.case_store.update_incident_status(
                    inc_id, new_status, performed_by=user)
                ok += 1
            except Exception:
                failed += 1
        msg = f"{ok} incident{'s' if ok != 1 else ''} -> {new_status}"
        if failed:
            msg += f" ({failed} failed)"
        self.bus.status_message.emit(msg, 3500)
        self._refresh()
