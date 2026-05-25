"""dashboard/widgets/bcp_status_board.py

Status board of Business-Continuity-Protocol activations. The BCPMonitor
is in-memory only, so this widget reconstructs activations from
audit_trail rows (action='BCP_ACTIVATED') plus protocol files in bcp_output/.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush, QPainter
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QPushButton, QSplitter, QPlainTextEdit, QListWidget,
    QListWidgetItem, QFileDialog, QInputDialog, QMessageBox,
)
from PyQt6.QtCharts import (
    QChart, QChartView, QPieSeries, QPieSlice,
)

from response.case_store import CaseStore
from recovery.bcp_monitor import BCPMonitor, DEFAULT_WARDS
from dashboard.theme import (
    BG_PANEL, BG_RAISED, TEXT_PRIMARY, TEXT_SECONDARY, ACCENT, BORDER,
    severity_color, status_color,
)

# Pie palette per ward (10 wards × distinct colours)
WARD_PALETTE = [
    "#3da9fc", "#ff8a1f", "#3ec46d", "#ffc83d", "#9d7cff",
    "#22c1c3", "#f06292", "#7c8aa1", "#ff3b3b", "#5cb6ff",
]


class BCPStatusBoardWidget(QWidget):
    def __init__(self, case_store: CaseStore, bcp_monitor: BCPMonitor,
                 bus, parent=None):
        super().__init__(parent)
        self.case_store = case_store
        self.bcp = bcp_monitor
        self.bus = bus
        self.activations: List[Dict[str, Any]] = []
        self._last_data_version = -1
        self._build_ui()
        self.bus.tick.connect(self._poll)
        self.bus.refresh_requested.connect(self._refresh)
        self.bus.incident_selected.connect(self._on_incident_selected)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # KPI strip
        kpi = QHBoxLayout()
        kpi.setSpacing(10)
        self.kpi_active = self._mini_kpi("ACTIVE BCPs", "0", "#ff3b3b")
        self.kpi_resolved = self._mini_kpi("Resolved", "0", "#3ec46d")
        self.kpi_total = self._mini_kpi("Total Activations", "0", ACCENT)
        self.kpi_wards = self._mini_kpi("Wards Covered", str(len(DEFAULT_WARDS)),
                                         ACCENT)
        self.kpi_files = self._mini_kpi("Protocol Files", "0", ACCENT)
        for k in (self.kpi_active, self.kpi_resolved, self.kpi_total,
                  self.kpi_wards, self.kpi_files):
            kpi.addWidget(k)
        root.addLayout(kpi)

        # body: list of activations + ward pie + protocol viewer
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        split.setChildrenCollapsible(False)

        # left: activations table
        act_frame = QFrame()
        act_frame.setObjectName("Card")
        a_lay = QVBoxLayout(act_frame)
        a_lay.setContentsMargins(8, 8, 8, 8)
        a_top = QHBoxLayout()
        a_title = QLabel("BCP Activations")
        a_title.setObjectName("H2")
        a_top.addWidget(a_title)
        a_top.addStretch(1)
        self.btn_simulate = QPushButton("Simulate Activation…")
        self.btn_simulate.setToolTip(
            "Activate a BCP for a chosen incident (tabletop / drill).")
        self.btn_simulate.clicked.connect(self._simulate_bcp)
        a_top.addWidget(self.btn_simulate)
        self.btn_deactivate = QPushButton("Mark RESOLVED")
        self.btn_deactivate.setToolTip(
            "Stand down the selected BCP activation (wards recovered).")
        self.btn_deactivate.clicked.connect(self._deactivate_bcp)
        a_top.addWidget(self.btn_deactivate)
        a_lay.addLayout(a_top)

        self.lbl_empty = QLabel(
            "No BCP activations recorded. A BCP fires automatically on a "
            "CRITICAL availability/ransomware incident — or use "
            "“Simulate Activation…” to run a continuity drill.")
        self.lbl_empty.setObjectName("Muted")
        self.lbl_empty.setWordWrap(True)
        self.lbl_empty.setVisible(False)
        a_lay.addWidget(self.lbl_empty)

        self.tbl_act = QTableWidget(0, 6)
        self.tbl_act.setHorizontalHeaderLabels(
            ["Activation ID", "Incident", "Type", "Activated", "Status", "Wards"])
        self.tbl_act.verticalHeader().setVisible(False)
        self.tbl_act.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_act.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_act.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection)
        self.tbl_act.setAlternatingRowColors(True)
        self.tbl_act.setShowGrid(False)
        hdr = self.tbl_act.horizontalHeader()
        for c in (0, 1, 2, 3, 4, 5):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tbl_act.itemSelectionChanged.connect(self._on_activation_selected)
        a_lay.addWidget(self.tbl_act, 1)
        split.addWidget(act_frame)

        # middle: ward pie chart
        pie_frame = QFrame()
        pie_frame.setObjectName("Card")
        p_lay = QVBoxLayout(pie_frame)
        p_lay.setContentsMargins(8, 8, 8, 8)
        p_title = QLabel("Wards Covered")
        p_title.setObjectName("H2")
        p_lay.addWidget(p_title)
        self.chart = QChart()
        self.chart.setBackgroundVisible(False)
        self.chart.legend().setLabelColor(QColor(TEXT_SECONDARY))
        self.chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.chart_view.setStyleSheet("background:transparent;border:none;")
        p_lay.addWidget(self.chart_view, 1)
        split.addWidget(pie_frame)

        # right: protocol file viewer
        proto_frame = QFrame()
        proto_frame.setObjectName("Card")
        pr_lay = QVBoxLayout(proto_frame)
        pr_lay.setContentsMargins(8, 8, 8, 8)
        pr_top = QHBoxLayout()
        pr_title = QLabel("Protocol Files")
        pr_title.setObjectName("H2")
        pr_top.addWidget(pr_title)
        pr_top.addStretch(1)
        self.btn_open_dir = QPushButton("Open bcp_output/")
        self.btn_open_dir.clicked.connect(self._open_output_dir)
        pr_top.addWidget(self.btn_open_dir)
        pr_lay.addLayout(pr_top)

        self.lst_files = QListWidget()
        self.lst_files.setMaximumHeight(160)
        self.lst_files.itemSelectionChanged.connect(self._on_file_selected)
        pr_lay.addWidget(self.lst_files)
        self.txt_protocol = QPlainTextEdit()
        self.txt_protocol.setReadOnly(True)
        pr_lay.addWidget(self.txt_protocol, 1)
        split.addWidget(proto_frame)

        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setStretchFactor(2, 3)
        root.addWidget(split, 1)

    def _mini_kpi(self, label: str, value: str, color: str) -> QFrame:
        f = QFrame()
        f.setObjectName("Card")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(2)
        lv = QLabel(value)
        lv.setStyleSheet(f"font-size:20pt;font-weight:700;color:{color};")
        lv.setObjectName("KpiValue")
        ll = QLabel(label)
        ll.setObjectName("KpiLabel")
        lay.addWidget(lv)
        lay.addWidget(ll)
        f.value_label = lv
        return f

    # ------------------------------------------------------------------
    def _on_incident_selected(self, inc_id: str) -> None:
        # auto-jump to that incident's BCP activation if one exists
        for row in range(self.tbl_act.rowCount()):
            item = self.tbl_act.item(row, 1)
            if item and item.text() == inc_id:
                self.tbl_act.selectRow(row)
                return

    def _poll(self, _seq: int) -> None:
        if not self.isVisible():
            return
        v = getattr(self.case_store, "data_version", None)
        if v is not None and v == self._last_data_version:
            return
        self._refresh()

    def _refresh(self) -> None:
        v = getattr(self.case_store, "data_version", None)
        if v is not None and v == self._last_data_version:
            return
        self.activations = self._fetch_activations()
        self._render_table()
        self._render_kpis()
        self._render_pie()
        self._last_data_version = getattr(self.case_store, "data_version", 0)

    # ------------------------------------------------------------------
    def _fetch_activations(self) -> List[Dict[str, Any]]:
        """Reconstruct activations from audit_trail BCP_ACTIVATED rows."""
        conn = self.case_store.connect()
        rows = conn.execute(
            "SELECT a.audit_id, a.incident_id, a.performed_at, a.change_summary, "
            "       i.incident_type, i.severity, i.status "
            "FROM audit_trail a "
            "LEFT JOIN incidents i ON i.incident_id = a.incident_id "
            "WHERE a.action='BCP_ACTIVATED' "
            "ORDER BY a.performed_at DESC").fetchall()
        # Incidents whose BCP was explicitly stood down (persisted across
        # sessions, unlike the in-memory monitor).
        deact = {r[0] for r in conn.execute(
            "SELECT DISTINCT incident_id FROM audit_trail "
            "WHERE action='BCP_DEACTIVATED'").fetchall()}
        out = []
        for r in rows:
            summary = r["change_summary"] or ""
            act_id = ""
            wards = 0
            for token in summary.split():
                if token.startswith("activation_id="):
                    act_id = token.split("=", 1)[1]
                elif token.startswith("wards="):
                    try:
                        wards = int(token.split("=", 1)[1])
                    except ValueError:
                        pass
            inc_id = r["incident_id"] or ""
            inc_type = r["incident_type"] or ""
            sev = r["severity"] or ""
            inc_status = r["status"] or ""
            # Status precedence: explicit BCP_DEACTIVATED > in-memory monitor >
            # derived from the incident's own status.
            live = self.bcp.active.get(inc_id)
            if inc_id in deact:
                bcp_status = "RESOLVED"
                deactivated = None
            elif live is not None:
                bcp_status = live.status
                deactivated = live.deactivated_at
            else:
                bcp_status = "ACTIVE" if inc_status not in ("CLOSED", "ABANDONED") else "RESOLVED"
                deactivated = None
            out.append({
                "activation_id":  act_id or f"BCP-{inc_id}",
                "incident_id":    inc_id,
                "incident_type":  inc_type,
                "severity":       sev,
                "activated_at":   r["performed_at"] or "",
                "deactivated_at": deactivated,
                "status":         bcp_status,
                "wards":          wards or len(DEFAULT_WARDS),
            })
        return out

    def _render_table(self) -> None:
        self.lbl_empty.setVisible(not self.activations)
        self.tbl_act.setVisible(bool(self.activations))
        self.tbl_act.setUpdatesEnabled(False)
        try:
            self.tbl_act.setRowCount(len(self.activations))
            for r, act in enumerate(self.activations):
                ts = (act["activated_at"] or "")[:19].replace("T", " ")
                items = [
                    QTableWidgetItem(act["activation_id"]),
                    QTableWidgetItem(act["incident_id"]),
                    QTableWidgetItem(act["incident_type"]),
                    QTableWidgetItem(ts),
                    QTableWidgetItem(act["status"]),
                    QTableWidgetItem(str(act["wards"])),
                ]
                if act["status"] == "ACTIVE":
                    items[4].setForeground(QBrush(QColor("#ff3b3b")))
                elif act["status"] == "RESOLVED":
                    items[4].setForeground(QBrush(QColor("#3ec46d")))
                if act["severity"]:
                    items[2].setForeground(
                        QBrush(QColor(severity_color(act["severity"]))))
                items[5].setTextAlignment(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                for c, it in enumerate(items):
                    self.tbl_act.setItem(r, c, it)
        finally:
            self.tbl_act.setUpdatesEnabled(True)

    def _render_kpis(self) -> None:
        n_act = sum(1 for a in self.activations if a["status"] == "ACTIVE")
        n_res = sum(1 for a in self.activations if a["status"] == "RESOLVED")
        self.kpi_active.value_label.setText(str(n_act))
        self.kpi_resolved.value_label.setText(str(n_res))
        self.kpi_total.value_label.setText(str(len(self.activations)))
        # count protocol files on disk
        out_dir = self.bcp.output_dir
        try:
            n_files = len(list(out_dir.glob("BCP_*.txt"))) if out_dir.exists() else 0
        except Exception:
            n_files = 0
        self.kpi_files.value_label.setText(str(n_files))

    def _render_pie(self) -> None:
        self.chart.removeAllSeries()
        series = QPieSeries()
        # show one slice per ward; if no activations, just show empty wards in muted colour
        n_active = sum(1 for a in self.activations if a["status"] == "ACTIVE")
        for i, ward in enumerate(DEFAULT_WARDS):
            slc = series.append(ward, 1)
            color = (QColor(WARD_PALETTE[i % len(WARD_PALETTE)])
                     if n_active else QColor(TEXT_SECONDARY))
            slc.setBrush(QBrush(color))
            slc.setBorderColor(QColor(BG_PANEL))
            slc.setLabelColor(QColor(TEXT_PRIMARY))
            slc.setLabelVisible(True)
        series.setHoleSize(0.45)
        self.chart.addSeries(series)
        self.chart.legend().setVisible(False)
        self.chart.setTitle(
            "" if n_active else "(no active BCP)")
        self.chart.setTitleBrush(QBrush(QColor(TEXT_SECONDARY)))

    # ------------------------------------------------------------------
    def _on_activation_selected(self) -> None:
        sel = self.tbl_act.selectedItems()
        if not sel:
            self.lst_files.clear()
            self.txt_protocol.clear()
            return
        row = sel[0].row()
        inc_id = self.tbl_act.item(row, 1).text()
        # find protocol files matching this incident
        out_dir = self.bcp.output_dir
        self.lst_files.clear()
        if not out_dir.exists():
            self.txt_protocol.setPlainText(
                f"(bcp_output/ not found at {out_dir})")
            return
        files = sorted(out_dir.glob(f"BCP_{inc_id}_*.txt"))
        if not files:
            files = sorted(out_dir.glob("BCP_*.txt"))[:10]
        for fp in files:
            it = QListWidgetItem(fp.name)
            it.setData(Qt.ItemDataRole.UserRole, str(fp))
            self.lst_files.addItem(it)
        if self.lst_files.count():
            self.lst_files.setCurrentRow(0)

    def _on_file_selected(self) -> None:
        it = self.lst_files.currentItem()
        if not it:
            return
        path = Path(it.data(Qt.ItemDataRole.UserRole))
        try:
            self.txt_protocol.setPlainText(
                path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            self.txt_protocol.setPlainText(f"(read error: {exc})")

    def _open_output_dir(self) -> None:
        import os
        out = self.bcp.output_dir
        out.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(out))   # Windows
        except AttributeError:
            self.bus.status_message.emit(str(out), 5000)

    # ------------------------------------------------------------------
    def _username(self) -> str:
        return (self.bus.parent().session.username
                if hasattr(self.bus.parent(), "session") else "dashboard_user")

    def _deactivate_bcp(self) -> None:
        """Stand down the selected activation (wards recovered). Persists a
        BCP_DEACTIVATED audit row so it survives restarts."""
        sel = self.tbl_act.selectedItems()
        if not sel:
            self.bus.status_message.emit("Select an activation row first", 3000)
            return
        inc_id = self.tbl_act.item(sel[0].row(), 1).text()
        if QMessageBox.question(
                self, "Stand down BCP",
                f"Mark the BCP for {inc_id} as RESOLVED (wards recovered)?"
                ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.bcp.deactivate(inc_id)   # in-memory (no-op if not live)
            self.case_store.log_audit(
                inc_id, action="BCP_DEACTIVATED", performed_by=self._username(),
                change_summary="wards recovered; EMR resumption signed off")
            self.bus.status_message.emit(f"BCP for {inc_id} -> RESOLVED", 3500)
            self._refresh()
        except Exception as exc:
            QMessageBox.warning(self, "Deactivate failed", str(exc))

    def _simulate_bcp(self) -> None:
        """Activate a BCP for a chosen incident — a tabletop / drill aid that
        generates the per-ward paper protocols and records the activation."""
        try:
            incidents = self.case_store.list_incidents(limit=200)
        except Exception as exc:
            QMessageBox.warning(self, "Simulate BCP", f"Could not list incidents:\n{exc}")
            return
        if not incidents:
            QMessageBox.information(
                self, "Simulate BCP",
                "No incidents in the case store to attach a BCP to.")
            return
        labels = [f"{i.incident_id} · {i.incident_type} · {i.severity}"
                  for i in incidents]
        choice, ok = QInputDialog.getItem(
            self, "Simulate BCP Activation",
            "Activate continuity protocol for incident:", labels, 0, False)
        if not ok or not choice:
            return
        inc = incidents[labels.index(choice)]
        try:
            activation = self.bcp.activate(
                incident_id=inc.incident_id, incident_type=inc.incident_type)
            self.case_store.log_audit(
                inc.incident_id, action="BCP_ACTIVATED",
                performed_by=self._username(),
                change_summary=(f"activation_id={activation.activation_id} "
                                f"wards={len(activation.wards_affected)} "
                                f"protocol_files={len(activation.protocol_files)} "
                                f"(drill)"))
            self.bus.status_message.emit(
                f"BCP activated for {inc.incident_id}: "
                f"{len(activation.wards_affected)} wards, "
                f"{len(activation.protocol_files)} protocol files", 4500)
            self._refresh()
        except Exception as exc:
            QMessageBox.warning(self, "Simulate BCP", str(exc))
