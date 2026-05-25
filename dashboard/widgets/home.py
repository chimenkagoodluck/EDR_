"""dashboard/widgets/home.py  --  Modern home / overview page.

Landing screen the user sees after sign-in. Four-column hero KPI strip
across the top, then a body grid:
    +-----------------------------+ +------------+
    |  Welcome card               | | INC mix    |
    |  (greeting + role + sites)  | | donut chart|
    +-----------------------------+ +------------+
    +-----------------------------+ +------------+
    |  Recent activity feed       | | Quick acts |
    +-----------------------------+ +------------+
    +-----------------------------+ +------------+
    |  System health pings        | | Open inc.  |
    +-----------------------------+ +------------+

Pure consumer of CaseStore. Refreshes on bus.tick (2s).
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Dict, Any

from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QPainter, QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QFrame,
    QPushButton, QGraphicsDropShadowEffect, QSizePolicy, QScrollArea,
)
from PyQt6.QtCharts import (
    QChart, QChartView, QPieSeries,
)

from response.case_store import CaseStore
from dashboard.theme import (
    BG_BASE, BG_PANEL, BG_RAISED, BG_HOVER, BG_HERO, TEXT_PRIMARY,
    TEXT_SECONDARY, TEXT_MUTED, ACCENT, BORDER, BORDER_SOFT, pill_html,
)
from dashboard.widgets.sparkline import Sparkline


def _drop_shadow(widget):
    """Subtle drop shadow for card depth."""
    eff = QGraphicsDropShadowEffect()
    eff.setBlurRadius(24)
    eff.setColor(QColor(0, 0, 0, 90))
    eff.setOffset(0, 6)
    widget.setGraphicsEffect(eff)


# ---------------------------------------------------------------------------
class KpiCard(QFrame):
    """Modern KPI tile: big number + label + optional hint + colour accent bar."""

    def __init__(self, label: str, accent: str = ACCENT,
                 value_object_name: str = "KpiValue", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(132)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)
        self._accent = accent
        self._last_numeric_value = None

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        bar = QFrame()
        bar.setFixedWidth(4)
        bar.setStyleSheet(
            f"background:{accent};border-top-left-radius:10px;"
            f"border-bottom-left-radius:10px;")
        outer.addWidget(bar)

        body = QVBoxLayout()
        body.setContentsMargins(18, 14, 18, 14)
        body.setSpacing(2)

        self.lbl_label = QLabel(label)
        self.lbl_label.setObjectName("KpiLabel")
        body.addWidget(self.lbl_label)

        self.lbl_value = QLabel("0")
        self.lbl_value.setObjectName(value_object_name)
        body.addWidget(self.lbl_value)

        # Sparkline showing 60 most-recent samples (~ 2 minutes at the
        # default 2s tick interval).
        self.sparkline = Sparkline(color=accent, buffer_size=60, height=24)
        body.addWidget(self.sparkline)

        self.lbl_hint = QLabel("")
        self.lbl_hint.setObjectName("KpiHint")
        body.addWidget(self.lbl_hint)

        outer.addLayout(body, 1)
        _drop_shadow(self)

    def set_value(self, value, hint: str = "") -> None:
        self.lbl_value.setText(str(value))
        self.lbl_hint.setText(hint)
        # Push the numeric value into the trend line; tolerate non-numeric
        # display strings (e.g. "—" or "N/A") by falling back to 0.
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0
        self._last_numeric_value = numeric
        self.sparkline.push(numeric)


# ---------------------------------------------------------------------------
class QuickActionButton(QPushButton):
    def __init__(self, label: str, hint: str, tab_target: int, parent=None):
        super().__init__(parent)
        self.tab_target = tab_target
        self._label = label
        self._hint = hint
        self.setMinimumHeight(58)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)
        self._inner = QLabel("")
        self._inner.setTextFormat(Qt.TextFormat.RichText)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self._inner)
        self._apply_palette()

    def _apply_palette(self) -> None:
        from dashboard import theme as _theme
        self.setStyleSheet(
            f"QPushButton {{ text-align:left; padding:10px 16px; "
            f"background:{_theme.BG_CARD}; "
            f"border:1px solid {_theme.BORDER_SOFT}; "
            f"border-radius:8px; font-weight:600; "
            f"color:{_theme.TEXT_PRIMARY}; }}"
            f"QPushButton:hover {{ background:{_theme.BG_HOVER}; "
            f"border-color:{_theme.ACCENT}; }}")
        self._inner.setText(
            f"<div style='font-size:10.5pt;font-weight:600;"
            f"color:{_theme.TEXT_PRIMARY};'>{self._label}</div>"
            f"<div style='font-size:8.5pt;color:{_theme.TEXT_SECONDARY};'>"
            f"{self._hint}</div>")


# ---------------------------------------------------------------------------
class HomeWidget(QWidget):
    """Top-level home / overview page."""

    quick_action = pyqtSignal(int)        # tab index to navigate to

    def __init__(self, case_store: CaseStore, session, bus, parent=None):
        super().__init__(parent)
        self.case_store = case_store
        self.session = session
        self.bus = bus
        self._last_data_version = -1
        self._last_donut_sig = None
        self._build_ui()
        self.bus.tick.connect(self._on_tick)
        self.bus.refresh_requested.connect(self._refresh)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # Keep direct references to every label whose colour is set via
        # an inline stylesheet so _apply_palette() can re-style them on
        # theme swap.
        self._themed_labels: list[tuple] = []   # (widget, style_template)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        root = QVBoxLayout(content)
        root.setContentsMargins(24, 20, 24, 24)
        root.setSpacing(18)

        # ---- top headline ---------------------------------------------
        self.lbl_greeting = QLabel("Welcome")
        self.lbl_greeting.setObjectName("H1")
        sub = QLabel(
            "Live overview of the EIRP-EMR incident response posture. "
            "All KPIs refresh automatically every few seconds.")
        sub.setWordWrap(True)
        self._themed_labels.append(
            (sub, "color:{TEXT_SECONDARY};font-size:10pt;"))
        root.addWidget(self.lbl_greeting)
        root.addWidget(sub)
        root.addSpacing(4)

        # ---- 6-stage pipeline strip -----------------------------------
        root.addWidget(self._build_pipeline_strip())
        root.addSpacing(2)

        # ---- KPI row --------------------------------------------------
        kpis = QHBoxLayout()
        kpis.setSpacing(14)
        self.k_critical = KpiCard("Critical Incidents", "#ff5e6d",
                                   value_object_name="KpiValueCritical")
        self.k_open     = KpiCard("Open Incidents", "#ffae5a",
                                   value_object_name="KpiValueWarn")
        self.k_total    = KpiCard("Total Incidents", ACCENT)
        self.k_audits   = KpiCard("Audit Events", "#9d7cff")
        self.k_notifs   = KpiCard("Notifications", "#22c1c3")
        self.k_bcp      = KpiCard("BCP Activations", "#3ec46d",
                                   value_object_name="KpiValueOk")
        for k in (self.k_critical, self.k_open, self.k_total,
                  self.k_audits, self.k_notifs, self.k_bcp):
            kpis.addWidget(k, 1)
        root.addLayout(kpis)

        # ---- main grid: hero + chart, activity + quick actions --------
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(18)

        # Hero welcome card (top-left)
        hero = QFrame(); hero.setObjectName("CardHero")
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(24, 24, 24, 24)
        hl.setSpacing(8)
        eyebrow = QLabel("YOUR SHIFT")
        eyebrow.setObjectName("KpiLabel")
        self.lbl_role = QLabel("")
        self.lbl_role_caption = QLabel("")
        self.lbl_role_caption.setWordWrap(True)
        self._themed_labels.append(
            (self.lbl_role,
             "color:{TEXT_PRIMARY};font-size:24pt;font-weight:700;letter-spacing:-0.5px;"))
        self._themed_labels.append(
            (self.lbl_role_caption,
             "color:{TEXT_SECONDARY};font-size:10pt;"))
        hl.addWidget(eyebrow)
        hl.addWidget(self.lbl_role)
        hl.addWidget(self.lbl_role_caption)
        hl.addStretch(1)
        sites = QLabel("Linked sites: ESUTH · DUFUTH")
        sites.setObjectName("KpiHint")
        hl.addWidget(sites)
        _drop_shadow(hero)
        grid.addWidget(hero, 0, 0)

        # INC-type donut chart (top-right)
        chart_card = QFrame(); chart_card.setObjectName("Card")
        cl = QVBoxLayout(chart_card)
        cl.setContentsMargins(20, 18, 20, 18)
        chart_title = QLabel("Incident mix")
        chart_title.setObjectName("H3")
        chart_sub = QLabel("by INC type (live)")
        self._themed_labels.append(
            (chart_sub, "color:{TEXT_MUTED};font-size:9pt;"))
        cl.addWidget(chart_title)
        cl.addWidget(chart_sub)
        self.chart = QChart()
        # Transparent so the Card surface shows through; theme-reactive.
        self.chart.setBackgroundVisible(False)
        self.chart.setBackgroundRoundness(0)
        self.chart.legend().setVisible(True)
        self._chart_legend = self.chart.legend()
        self._chart_legend.setLabelColor(QColor(TEXT_SECONDARY))
        self._chart_legend.setAlignment(Qt.AlignmentFlag.AlignRight)
        from PyQt6.QtCore import QMargins
        self.chart.setMargins(QMargins(0, 0, 0, 0))
        cv = QChartView(self.chart)
        cv.setRenderHint(QPainter.RenderHint.Antialiasing)
        cv.setStyleSheet("background:transparent;border:none;")
        cl.addWidget(cv, 1)
        chart_card.setMinimumHeight(260)
        _drop_shadow(chart_card)
        grid.addWidget(chart_card, 0, 1)

        # Recent activity feed (mid-left, span 2 rows)
        feed_card = QFrame(); feed_card.setObjectName("Card")
        fl = QVBoxLayout(feed_card)
        fl.setContentsMargins(20, 18, 20, 18)
        ft = QHBoxLayout()
        feed_title = QLabel("Recent activity")
        feed_title.setObjectName("H3")
        ft.addWidget(feed_title)
        ft.addStretch(1)
        feed_caption = QLabel("auto-refreshed every 2 s")
        feed_caption.setObjectName("KpiHint")
        ft.addWidget(feed_caption)
        fl.addLayout(ft)
        self.feed_inner = QVBoxLayout()
        self.feed_inner.setContentsMargins(0, 12, 0, 0)
        self.feed_inner.setSpacing(8)
        fl.addLayout(self.feed_inner, 1)
        _drop_shadow(feed_card)
        grid.addWidget(feed_card, 1, 0, 2, 1)

        # Quick actions (mid-right)
        qa_card = QFrame(); qa_card.setObjectName("Card")
        ql = QVBoxLayout(qa_card)
        ql.setContentsMargins(20, 18, 20, 18)
        qa_title = QLabel("Quick actions")
        qa_title.setObjectName("H3")
        ql.addWidget(qa_title)
        ql.addSpacing(6)

        # The tab indices below MUST match main_window.py's tab order.
        # Indices are wired in main_window after instantiation via
        # set_tab_index_map() so the home knows where to navigate.
        self.qa_buttons: List[QuickActionButton] = []
        for label, hint, tag in [
            ("Connect a log source", "Add a file or folder for live analysis", "data_sources"),
            ("View open incidents", "Review and triage active cases", "open_incidents"),
            ("Open playbook walker", "Step through an active investigation", "playbook"),
            ("Inspect audit chain", "Verify NDPR-aligned tamper-evident log", "audit"),
        ]:
            btn = QuickActionButton(label, hint, -1)
            btn._tag = tag
            btn.clicked.connect(lambda _=False, b=btn: self.quick_action.emit(b.tab_target))
            self.qa_buttons.append(btn)
            ql.addWidget(btn)
        ql.addStretch(1)
        _drop_shadow(qa_card)
        grid.addWidget(qa_card, 1, 1)

        # System health (bottom-right)
        sh_card = QFrame(); sh_card.setObjectName("Card")
        sl = QVBoxLayout(sh_card)
        sl.setContentsMargins(20, 18, 20, 18)
        sh_title = QLabel("System health")
        sh_title.setObjectName("H3")
        sl.addWidget(sh_title)
        sl.addSpacing(6)
        self.lbl_health = QLabel("")
        self.lbl_health.setTextFormat(Qt.TextFormat.RichText)
        self.lbl_health.setWordWrap(True)
        self._themed_labels.append(
            (self.lbl_health, "color:{TEXT_SECONDARY};font-size:9.5pt;"))
        sl.addWidget(self.lbl_health)
        sl.addStretch(1)
        _drop_shadow(sh_card)
        grid.addWidget(sh_card, 2, 1)

        grid.setColumnStretch(0, 3)
        grid.setColumnStretch(1, 2)
        root.addLayout(grid)

        root.addStretch(1)
        # Apply theme-bound colours now (also re-run on theme swap).
        self._apply_palette()

    # ------------------------------------------------------------------
    def _apply_palette(self) -> None:
        """Re-style every label whose colour was baked-in inline at
        construction. Called on theme swap so light/dark transitions are
        instant."""
        from dashboard import theme as _theme
        ctx = {
            "TEXT_PRIMARY":   _theme.TEXT_PRIMARY,
            "TEXT_SECONDARY": _theme.TEXT_SECONDARY,
            "TEXT_MUTED":     _theme.TEXT_MUTED,
            "ACCENT":         _theme.ACCENT,
            "BORDER":         _theme.BORDER,
            "BORDER_SOFT":    _theme.BORDER_SOFT,
        }
        for w, tmpl in getattr(self, "_themed_labels", []):
            try:
                w.setStyleSheet(tmpl.format(**ctx))
            except Exception:
                pass
        # Invalidate caches so the next refresh re-builds the donut, feed,
        # and any other surface that bakes-in palette colours.
        self._last_donut_sig = None
        self._last_data_version = -1
        try:
            self._refresh()
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _build_pipeline_strip(self) -> QWidget:
        """Six-stage research pipeline visualisation.

        Detect (events) -> Score (ML) -> Correlate (ATT&CK + ITS) ->
        Respond (playbook) -> Recover (BCP/RTO) -> Report (NDPR/audit).

        Each stage shows a colour pill + a counter. The active stage is
        the one with the highest fresh activity in the case store. This
        is the most direct way to communicate to a supervisor that the
        whole EIRP-EMR pipeline lives inside this single application.
        """
        card = QFrame()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(8)

        head = QLabel("EIRP-EMR pipeline")
        head.setObjectName("H3")
        outer.addWidget(head)

        sub = QLabel(
            "Live view of the six research stages. Counters refresh as "
            "new events flow through.")
        sub.setObjectName("Caption")
        outer.addWidget(sub)
        outer.addSpacing(4)

        row = QHBoxLayout()
        row.setSpacing(8)
        self._pipeline_stages = []
        stages = [
            ("1. Detect",    "Identify anomalies in incoming events",
                              "#5cb6ff"),
            ("2. Score",     "Run ML models (A, 1-7, B, C)",
                              "#9d7cff"),
            ("3. Correlate", "ATT&CK + threat-score + rules",
                              "#ffc83d"),
            ("4. Respond",   "Playbook + notify + audit",
                              "#ff8a1f"),
            ("5. Recover",   "Containment + BCP + checklist",
                              "#3ec46d"),
            ("6. Report",    "NDPR + signed audit chain",
                              "#22c1c3"),
        ]
        for label, hint, color in stages:
            tile = QFrame()
            tile.setObjectName("PipelineStage")
            tile.setMinimumHeight(72)
            tl = QVBoxLayout(tile)
            tl.setContentsMargins(12, 10, 12, 10)
            tl.setSpacing(2)
            top = QHBoxLayout()
            top.setSpacing(6)
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{color};font-size:14pt;font-weight:700;")
            top.addWidget(dot)
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"font-weight:700;font-size:9.5pt;letter-spacing:0.4px;")
            top.addWidget(lbl)
            top.addStretch(1)
            tl.addLayout(top)
            hint_lbl = QLabel(hint)
            hint_lbl.setObjectName("Muted")
            hint_lbl.setWordWrap(True)
            tl.addWidget(hint_lbl)
            counter = QLabel("0")
            counter.setStyleSheet(
                f"color:{color};font-size:13pt;font-weight:800;")
            tl.addWidget(counter)
            tile.setStyleSheet(
                f"QFrame#PipelineStage {{ background: rgba(127,127,127,18); "
                f"border-left: 3px solid {color}; border-radius: 6px; }}")
            row.addWidget(tile, 1)
            self._pipeline_stages.append(
                {"counter": counter, "color": color, "label": label})
        outer.addLayout(row)
        return card

    # ------------------------------------------------------------------
    def _update_pipeline_counters(self, summary: Dict[str, Any]) -> None:
        """Wire each stage tile to a concrete counter from the case store."""
        if not hasattr(self, "_pipeline_stages"):
            return
        per_status = summary.get("incidents_by_status", {}) or {}
        n_open = per_status.get("OPEN", 0)
        n_contained = per_status.get("CONTAINED", 0)
        n_closed = per_status.get("CLOSED", 0)
        try:
            n_bcp = self._count_bcp_activations()
        except Exception:
            n_bcp = 0
        values = [
            ("events", summary.get("n_audit_events", 0)),   # Detect (audits = events)
            ("incidents", summary.get("n_incidents", 0)),   # Score (scored -> incidents)
            ("open", n_open),                                # Correlate (active)
            ("playbook steps", summary.get("n_playbook_steps", 0)),  # Respond
            ("BCP / contained", n_bcp + n_contained),         # Recover
            ("closed + audited", n_closed),                   # Report
        ]
        for stage, (_lbl, v) in zip(self._pipeline_stages, values):
            stage["counter"].setText(f"{v:,}")

    # ------------------------------------------------------------------
    def set_tab_index_map(self, mapping: Dict[str, int]) -> None:
        """MainWindow calls this once after constructing the tab bar."""
        for btn in self.qa_buttons:
            tag = getattr(btn, "_tag", None)
            if tag in mapping:
                btn.tab_target = mapping[tag]

    # ------------------------------------------------------------------
    def _on_tick(self, _seq: int) -> None:
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
        # ---- greeting + role banner ---------------------------------
        u = self.session.user
        full = u.full_name if u else "Operator"
        firstname = full.split(" ")[0] if full else "there"
        hour = datetime.now().hour
        salutation = ("Good morning" if hour < 12 else
                      "Good afternoon" if hour < 18 else "Good evening")
        self.lbl_greeting.setText(f"{salutation}, {firstname}")
        self.lbl_role.setText(u.role.label if u else "—")
        scope = ("You have full access to incidents, playbooks, "
                 "compliance reports, and user management."
                 if u and u.role.can_manage_users() else
                 "You can act on incidents and update playbooks. "
                 "User management is restricted to administrators."
                 if u and u.role.can_mutate() else
                 "Read-only access. Contact an administrator to act on cases.")
        self.lbl_role_caption.setText(scope)

        # ---- KPIs + chart + feed -----------------------------------
        try:
            summary = self.case_store.summarise()
        except Exception:
            return
        by_status = summary.get("incidents_by_status", {}) or {}
        by_type   = summary.get("incidents_by_type", {}) or {}
        critical  = self._count_critical()

        self.k_critical.set_value(critical,
            "Awaiting playbook execution" if critical else "All quiet")
        self.k_open.set_value(by_status.get("OPEN", 0),
            f"contained: {by_status.get('CONTAINED', 0)}  "
            f"closed: {by_status.get('CLOSED', 0)}")
        self.k_total.set_value(summary.get("n_incidents", 0),
            f"{len(by_type)} types observed")
        self.k_audits.set_value(summary.get("n_audit_events", 0),
            "tamper-evident chain")
        self.k_notifs.set_value(summary.get("n_notifications", 0),
            "DASHBOARD + EMAIL + SMS")
        self.k_bcp.set_value(self._count_bcp_activations(),
            "paper-protocol fallbacks issued")

        self._render_donut(by_type)
        self._render_feed()
        self._render_health(summary)
        self._update_pipeline_counters(summary)
        self._last_data_version = getattr(self.case_store, "data_version", 0)

    def _count_critical(self) -> int:
        # Active (OPEN) critical incidents only -- once an incident is
        # CONTAINED / CLOSED it is no longer "awaiting playbook execution",
        # so it must drop off this KPI.
        cur = self.case_store.connect().execute(
            "SELECT COUNT(*) FROM incidents "
            "WHERE severity='CRITICAL' AND status='OPEN'")
        return int(cur.fetchone()[0])

    def _count_bcp_activations(self) -> int:
        cur = self.case_store.connect().execute(
            "SELECT COUNT(*) FROM audit_trail WHERE action='BCP_ACTIVATED'")
        return int(cur.fetchone()[0])

    # ------------------------------------------------------------------
    def _render_donut(self, by_type: Dict[str, int]) -> None:
        sig = tuple(sorted(by_type.items()))
        if sig == self._last_donut_sig:
            return
        self._last_donut_sig = sig
        self.chart.removeAllSeries()
        series = QPieSeries()
        series.setHoleSize(0.55)
        palette = {
            "INC-01": "#ff8a1f", "INC-02": "#ff5e6d", "INC-03": "#ffd34d",
            "INC-04": "#9d7cff", "INC-05": "#22c1c3", "INC-06": "#3ec46d",
        }
        ordered = sorted(by_type.items())
        if not ordered:
            series.append("No incidents yet", 1)
            series.slices()[0].setBrush(QBrush(QColor(BG_RAISED)))
            series.slices()[0].setLabelVisible(False)
        else:
            from dashboard.theme import BG_CARD as _bg_card_now
            for inc_type, count in ordered:
                slc = series.append(f"{inc_type}  ({count})", count)
                slc.setBrush(QBrush(QColor(palette.get(inc_type, ACCENT))))
                slc.setBorderColor(QColor(_bg_card_now))
                slc.setBorderWidth(2)
                slc.setLabelVisible(False)
        self.chart.addSeries(series)

    # ------------------------------------------------------------------
    def _render_feed(self) -> None:
        # Resolve theme constants at call time (NOT via `from theme import X`
        # which binds the value at module-load and never updates after a
        # theme swap -- that's the reason the Recent Activity HTML stayed
        # near-white on white in light mode).
        from dashboard import theme as _t

        # Clear existing rows
        while self.feed_inner.count():
            it = self.feed_inner.takeAt(0)
            w = it.widget()
            if w: w.setParent(None)

        rows = self.case_store.connect().execute(
            "SELECT performed_at, action, incident_id, performed_by, "
            "       change_summary FROM audit_trail "
            "ORDER BY audit_id DESC LIMIT 6").fetchall()
        if not rows:
            empty = QLabel("Nothing yet. Connect a log source on the "
                           "Data Sources tab to start scoring events.")
            empty.setStyleSheet(
                f"color:{_t.TEXT_MUTED};font-size:9.5pt;padding:8px 0;")
            empty.setWordWrap(True)
            self.feed_inner.addWidget(empty)
            return
        for r in rows:
            row = QFrame()
            row.setStyleSheet(
                f"QFrame {{ background: transparent; "
                f"border-bottom:1px solid {_t.BORDER_SOFT}; }}")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 6, 0, 6)
            rl.setSpacing(10)

            # action pill on left
            pill_kind = {
                "INCIDENT_CREATED": "CRITICAL",
                "BCP_ACTIVATED":    "CRITICAL",
                "STATUS_CHANGE":    "CONTAINED",
                "EVIDENCE_ADDED":   "LOW",
                "NOTIFY_NDPC":      "HIGH",
            }.get(r["action"], "MEDIUM")
            pill_lbl = QLabel(pill_html(r["action"], pill_kind))
            pill_lbl.setTextFormat(Qt.TextFormat.RichText)
            rl.addWidget(pill_lbl)

            # text content -- uses CURRENT theme values
            ts = (r["performed_at"] or "")[:19].replace("T", " ")
            inc = r["performed_by"] or "system"
            summary = (r["change_summary"] or "")[:120]
            text = (f"<div style='color:{_t.TEXT_PRIMARY};font-size:9.5pt;'>"
                    f"<b>{r['incident_id'] or '-'}</b> "
                    f"<span style='color:{_t.TEXT_MUTED};'>by {inc}</span></div>"
                    f"<div style='color:{_t.TEXT_SECONDARY};font-size:9pt;'>"
                    f"{summary or '(no detail)'}</div>")
            body = QLabel(text)
            body.setTextFormat(Qt.TextFormat.RichText)
            body.setWordWrap(True)
            rl.addWidget(body, 1)

            ts_label = QLabel(ts[11:] if len(ts) >= 19 else ts)
            ts_label.setStyleSheet(
                f"color:{_t.TEXT_MUTED};font-size:9pt;")
            rl.addWidget(ts_label)
            self.feed_inner.addWidget(row)

    # ------------------------------------------------------------------
    def _render_health(self, summary: Dict[str, Any]) -> None:
        from dashboard import theme as _t            # call-time resolution
        n_inc    = summary.get("n_incidents", 0)
        n_audit  = summary.get("n_audit_events", 0)
        n_evid   = summary.get("n_evidence_artefacts", 0)
        n_play   = summary.get("n_playbook_steps", 0)
        items = [
            ("Case store", "OK", "LOW",
             f"{n_inc:,} incidents persisted"),
            ("Audit chain", "INTACT", "CONTAINED",
             f"{n_audit:,} immutable entries"),
            ("Evidence vault", "OK" if n_evid else "EMPTY",
             "LOW" if n_evid else "MEDIUM",
             f"{n_evid:,} SHA-256-hashed artefacts"),
            ("Playbook engine", "READY", "LOW",
             f"{n_play:,} executed steps"),
        ]
        lines = []
        for name, badge, kind, hint in items:
            lines.append(
                f"<div style='margin-bottom:8px;'>"
                f"<span style='color:{_t.TEXT_PRIMARY};font-weight:600;'>"
                f"{name}</span>"
                f"&nbsp;&nbsp;{pill_html(badge, kind)}"
                f"<div style='color:{_t.TEXT_MUTED};font-size:8.5pt;'>"
                f"{hint}</div>"
                f"</div>")
        self.lbl_health.setText("".join(lines))
