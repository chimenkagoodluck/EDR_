"""dashboard/main_window.py  --  QMainWindow shell + top nav + poll timer.

Modern design (2026-05-18 refresh):
  - Login gate via dashboard.widgets.login.LoginDialog (mandatory).
  - Home page added as Tab 0 (greeting, KPI cards, donut, activity feed).
  - Users tab added (admin only, hidden for other roles).
  - Top bar carries the brand, a clock, and a profile-menu dropdown
    (sign out / change password).
  - Audit attribution: every case-store write uses session.username.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional, Dict

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QLabel, QStatusBar, QToolBar, QWidget,
    QHBoxLayout, QFileDialog, QMessageBox, QMenu, QPushButton, QFrame,
    QVBoxLayout, QInputDialog, QLineEdit,
)

from response.case_store import CaseStore
from response.playbook_engine import PlaybookEngine
from recovery.containment_advisor import ContainmentAdvisor
from recovery.recovery_checklist import RecoveryChecklist
from recovery.bcp_monitor import BCPMonitor
from reporting.audit_manager import AuditManager
from reporting.ndpr_mapper import NdprMapper

from dashboard.signal_bus import SignalBus
from dashboard.theme import (
    GLOBAL_QSS, TEXT_SECONDARY, TEXT_MUTED, ACCENT, BG_HERO, BORDER,
    apply_theme, current_theme,
)
from dashboard.auth import UserStore, Session, Role
from dashboard.prefs import get_prefs
from dashboard.widgets import (
    DataSourcesWidget,
    LiveEventStreamWidget, OpenIncidentsWidget, PlaybookWalkerWidget,
    ContainmentRecoveryWidget, BCPStatusBoardWidget, AuditForensicsWidget,
)
from dashboard.widgets.home   import HomeWidget
from dashboard.widgets.login  import LoginDialog
from dashboard.widgets.users  import UsersWidget
from dashboard.widgets.toast      import ToastManager
from dashboard.widgets.onboarding import OnboardingTour
from dashboard.widgets.notification_center import (
    NotificationBell, NotificationPopover,
)
from dashboard.notifications import NotificationStore
from dashboard.engine import (
    SourceRegistry, FileWatcher, BulkInferenceWorker,
)
from dashboard.engine.inference_worker import (
    LiveInferenceWorker, LiveInferenceThread,
)


POLL_INTERVAL_MS = 2000


class MainWindow(QMainWindow):
    """Hosts six widget tabs over a single shared backend stack."""

    def __init__(self, db_path: Path, poll_interval_ms: int = POLL_INTERVAL_MS,
                 session: Optional[Session] = None,
                 user_store: Optional[UserStore] = None,
                 worker_pool_config: Optional[Dict] = None,
                 live_max_incidents: int = 0,
                 bulk_max_incidents: int = 0,
                 demo_mode: bool = False):
        super().__init__()
        self.db_path = Path(db_path)
        self.poll_ms = poll_interval_ms
        self._tick_seq = 0
        self.session = session or Session()
        self.user_store = user_store or UserStore()
        self.user_store.init_schema()
        self.worker_pool_config = worker_pool_config or {"enabled": False}
        self.worker_pool = None     # set in _start_engine if enabled
        self.live_max_incidents = int(live_max_incidents)
        self.bulk_max_incidents = int(bulk_max_incidents)
        self.demo_mode = demo_mode

        # Install stdout/stderr tee BEFORE anything else prints. The
        # Engine Activity Log on the Data Sources tab drains this queue
        # on its diag timer so the user sees engine [OK] load lines,
        # parser subprocess output, exceptions, etc. -- same content as
        # the terminal the dashboard was launched from.
        import queue as _queue
        from dashboard.stdio_tee import install as _install_tee
        self.stdout_queue: "_queue.Queue[str]" = _queue.Queue(maxsize=4000)
        _install_tee(self.stdout_queue)

        # ----- backend singletons ------------------------------------------------
        self.case_store         = CaseStore(self.db_path)
        self.case_store.init_schema()
        self.playbook_engine    = PlaybookEngine()
        self.containment        = ContainmentAdvisor()
        self.recovery_checklist = RecoveryChecklist()
        self.bcp_monitor        = BCPMonitor()
        self.audit_manager      = AuditManager(self.case_store)
        self.ndpr_mapper        = NdprMapper(self.case_store)

        # ----- engine (NEW: live + bulk inference workers) -----------------------
        self.source_registry  = SourceRegistry()
        self.file_watcher     = FileWatcher(self.source_registry, parent=self)
        self.bulk_worker      = BulkInferenceWorker(self)
        self.live_worker      = LiveInferenceWorker(
            self.source_registry, self.db_path, auto_respond=True,
            max_incidents=self.live_max_incidents)
        self.live_thread      = LiveInferenceThread(self.live_worker, parent=self)

        # ----- signal bus --------------------------------------------------------
        self.bus = SignalBus(self)
        self.bus.status_message.connect(self._on_status_message)
        self.bus.incident_selected.connect(self._on_incident_selected)
        self.bus.incident_details.connect(self._open_incident_detail)
        self.bus.respond_requested.connect(self._on_respond_requested)
        # Bag of open detail dialogs keyed by incident_id (so the user can
        # have several drill-down dialogs open at once without re-spawning).
        self._detail_dialogs: Dict[str, "QDialog"] = {}

        self._build_ui()
        self._wire_engine_signals()
        self._wire_timer()
        self._kick_initial_refresh()
        self._start_engine()

        # Toast notifications for new CRITICAL / HIGH incidents
        self.toasts = ToastManager(self)
        self.toasts.view_incident.connect(self._on_toast_view)
        self._toast_seen_max_audit_id = self._current_max_audit_id()
        # Watermark for progressive-refresh poll: detects external writers
        # (in-process worker's own CaseStore + out-of-process daemons) so
        # widgets refresh DURING a scoring run, not just at the end.
        self._last_known_max_audit = self._toast_seen_max_audit_id

        # First-run onboarding tour (one-shot per user)
        self._maybe_show_tour_on_first_run()

    # ------------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.setWindowTitle("EIRP-EMR  |  Incident Response Console")
        self.resize(1500, 920)
        # Do NOT set a local stylesheet on the window itself. A widget-local
        # stylesheet shadows the app-level QSS for all descendants, which
        # breaks live theme swap (the new QSS never reaches our children).
        # The QApplication-level stylesheet set by dashboard.theme.apply_theme()
        # already styles the whole tree.

        # ----- top header bar (modern flat) --------------------------------------
        header = QFrame(self)
        header.setObjectName("TopBar")
        header.setFixedHeight(56)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 16, 0)
        hl.setSpacing(16)

        self.lbl_brand = QLabel("EIRP-EMR")
        self.lbl_brand_sub = QLabel("Incident Response Console")
        hl.addWidget(self.lbl_brand)
        hl.addWidget(self.lbl_brand_sub)
        hl.addStretch(1)

        self.lbl_db = QLabel(f"DB · {self.db_path.name}")
        hl.addWidget(self.lbl_db)

        self.lbl_clock = QLabel("--:--:--")
        hl.addWidget(self.lbl_clock)
        self._apply_palette()

        # Notification bell + popover (in-session history of every alert)
        self.notif_store   = NotificationStore(self)
        self.notif_bell    = NotificationBell(self.notif_store, header)
        hl.addWidget(self.notif_bell)
        self.notif_popover = NotificationPopover(self.notif_store, self)
        self.notif_bell.clicked_signal.connect(
            lambda: self.notif_popover.show_below(self.notif_bell))
        # Notification click opens the full drill-down dialog.
        self.notif_popover.incident_clicked.connect(self._open_incident_detail)

        # Profile button + dropdown menu
        self.btn_profile = QPushButton()
        self.btn_profile.setObjectName("Ghost")
        self.btn_profile.setMinimumWidth(180)
        self.btn_profile.clicked.connect(self._show_profile_menu)
        hl.addWidget(self.btn_profile)

        # ----- tabs --------------------------------------------------------------
        self.tabs = QTabWidget(self)
        self.tabs.setDocumentMode(True)

        self.w_home        = HomeWidget(self.case_store, self.session, self.bus, self)
        self.w_sources     = DataSourcesWidget(self.source_registry,
                                                self.file_watcher,
                                                self.bulk_worker,
                                                self.db_path,
                                                self.bus, self,
                                                case_store=self.case_store,
                                                live_worker=self.live_worker,
                                                stdout_queue=self.stdout_queue)
        self.w_stream      = LiveEventStreamWidget(self.case_store, self.bus, self)
        self.w_incidents   = OpenIncidentsWidget(self.case_store, self.bus, self)
        self.w_playbook    = PlaybookWalkerWidget(self.case_store,
                                                   self.playbook_engine,
                                                   self.bus, self)
        self.w_containment = ContainmentRecoveryWidget(self.case_store,
                                                       self.containment,
                                                       self.recovery_checklist,
                                                       self.bus, self)
        self.w_bcp         = BCPStatusBoardWidget(self.case_store,
                                                   self.bcp_monitor,
                                                   self.bus, self)
        self.w_audit       = AuditForensicsWidget(self.case_store,
                                                   self.audit_manager,
                                                   self.ndpr_mapper,
                                                   self.bus, self)

        # Tabs with a one-line "what is this tab for" subtitle wrapped in
        # a thin caption strip above the actual widget. Helps supervisors
        # who don't read code understand which research stage each tab
        # implements.
        self.tabs.addTab(self._tab_with_caption(
            self.w_home, "Stage 0 · Overview",
            "Six-stage pipeline status, KPI strip, donut, activity feed."),
            "Home")
        self.tabs.addTab(self._tab_with_caption(
            self.w_sources, "Stage 1 · Ingestion",
            "Attach LIRA / Apache / Windows / database log sources for "
            "live scoring or one-shot bulk analysis."),
            "Data Sources")
        self.tabs.addTab(self._tab_with_caption(
            self.w_stream, "Stage 2 · Detect + Score",
            "Live audit-trail tail, KPI strip, and INC-type distribution "
            "as events flow through Model A + 1-7 + B."),
            "Live Stream")
        self.tabs.addTab(self._tab_with_caption(
            self.w_incidents, "Stage 3 · Classified incidents",
            "Filterable list of every incident the engine has classified. "
            "Double-click any row for the full drill-down."),
            "Incidents")
        self.tabs.addTab(self._tab_with_caption(
            self.w_playbook, "Stage 4 · Respond",
            "Step-by-step playbook execution per incident. Manual + "
            "automated actions with regulatory deadlines."),
            "Playbook")
        self.tabs.addTab(self._tab_with_caption(
            self.w_containment, "Stage 5a · Contain + Recover",
            "Containment recommendations + recovery checklist + evidence "
            "chain for the selected incident."),
            "Containment & Recovery")
        self.tabs.addTab(self._tab_with_caption(
            self.w_bcp, "Stage 5b · Business continuity",
            "BCP activations (paper-protocol fallbacks), ward coverage, "
            "protocol files issued."),
            "BCP Status")
        self.tabs.addTab(self._tab_with_caption(
            self.w_audit, "Stage 6 · Compliance + Report",
            "Tamper-evident audit chain + NDPR article-by-article gauge. "
            "Export signed reports here."),
            "Audit & Forensics")

        # Users tab: admin only
        self.w_users = None
        if self.session.can_manage_users():
            self.w_users = UsersWidget(self.user_store, self.session, self.bus, self)
            self.tabs.addTab(self._tab_with_caption(
                self.w_users, "Admin · Identity & access",
                "Create and manage analyst, DPO, and administrator accounts. "
                "Every case-store mutation is attributed by username."),
                "Users")

        # Switching tabs should fire an immediate refresh of the new visible
        # widget so the user doesn't have to wait for the next 2s tick.
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # Wire home quick-actions to tab navigation
        tab_map = {
            "data_sources":   1,
            "live_stream":    2,
            "open_incidents": 3,
            "playbook":       4,
            "containment":    5,
            "bcp":            6,
            "audit":          7,
        }
        self._tab_map = tab_map
        self.w_home.set_tab_index_map(tab_map)
        self.w_home.quick_action.connect(self._on_quick_action)

        # ----- central layout ---------------------------------------------------
        central = QWidget(self)
        cl = QVBoxLayout(central)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(header)
        cl.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

        self._refresh_profile_button()
        self._apply_role_gating()

        # ----- status bar --------------------------------------------------------
        self.setStatusBar(QStatusBar(self))
        self.statusBar().showMessage("Ready", 3000)

    # ------------------------------------------------------------------------
    def _tab_with_caption(self, inner: QWidget, stage: str,
                          caption: str) -> QWidget:
        """Wrap a tab widget in a thin (~36 px) caption strip that shows
        which research stage the tab implements, plus a one-line hint."""
        wrap = QWidget()
        v = QVBoxLayout(wrap)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        strip = QFrame()
        strip.setObjectName("TabCaption")
        sl = QHBoxLayout(strip)
        sl.setContentsMargins(20, 8, 20, 8)
        sl.setSpacing(14)
        lbl_stage = QLabel(stage)
        lbl_stage.setObjectName("Accent")
        sl.addWidget(lbl_stage)
        lbl_caption = QLabel(caption)
        lbl_caption.setObjectName("Caption")
        lbl_caption.setWordWrap(True)
        sl.addWidget(lbl_caption, 1)
        v.addWidget(strip)
        v.addWidget(inner, 1)
        return wrap

    # ------------------------------------------------------------------------
    # Poll timer
    # ------------------------------------------------------------------------
    def _wire_timer(self) -> None:
        self.timer = QTimer(self)
        self.timer.setInterval(self.poll_ms)
        self.timer.timeout.connect(self._on_tick)
        self.timer.start()

    def _on_tick(self) -> None:
        self._tick_seq += 1
        self.lbl_clock.setText(datetime.now().strftime("%H:%M:%S"))
        # Detect out-of-process writes (in-process worker uses its OWN
        # CaseStore instance; the worker-pool daemon writes from a
        # separate Python interpreter). Either way our local data_version
        # doesn't move unless we poll the DB. Cheap indexed lookup --
        # one row, no scan -- so OK to do every tick.
        self._poll_external_db_progress()
        self.bus.tick.emit(self._tick_seq)
        self._check_for_toastable_events()

    def _poll_external_db_progress(self) -> None:
        """Detect rows written by another process / another CaseStore
        instance and bump our data_version so the visible widget refreshes
        on the NEXT bus.tick. Without this, an in-flight scoring run shows
        no progress in the UI until job_finished fires.
        """
        try:
            cur = self.case_store.connect().execute(
                "SELECT COALESCE(MAX(audit_id), 0) FROM audit_trail")
            now_max = int(cur.fetchone()[0])
        except Exception:
            return
        last = getattr(self, "_last_known_max_audit", -1)
        if now_max != last:
            self._last_known_max_audit = now_max
            # Only bump when we actually advanced (not on first observation
            # so the toast watermark logic still gets a clean baseline).
            if last >= 0:
                self.case_store.bump_data_version()

    # ------------------------------------------------------------------------
    # Toast notification detection
    # ------------------------------------------------------------------------
    def _current_max_audit_id(self) -> int:
        """Snapshot the latest audit_id on startup so we don't re-fire toasts
        for incidents that existed BEFORE this dashboard session opened."""
        try:
            row = self.case_store.connect().execute(
                "SELECT MAX(audit_id) FROM audit_trail").fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        except Exception:
            return 0

    def _check_for_toastable_events(self) -> None:
        """Poll for new audit_trail rows that warrant an operator toast:
            - INCIDENT_CREATED of CRITICAL or HIGH severity
            - BCP_ACTIVATED (always)
            - NOTIFY_NDPC (compliance-relevant)
        Limits to the most recent few so a flood doesn't blow up the UI."""
        if not hasattr(self, "toasts"):
            return
        try:
            cur = self.case_store.connect().execute(
                "SELECT a.audit_id, a.action, a.incident_id, a.change_summary, "
                "       i.incident_type, i.severity, i.summary "
                "FROM audit_trail a "
                "LEFT JOIN incidents i ON i.incident_id = a.incident_id "
                "WHERE a.audit_id > ? "
                "ORDER BY a.audit_id ASC LIMIT 20",
                (self._toast_seen_max_audit_id,))
            rows = cur.fetchall()
        except Exception:
            return
        if not rows:
            return

        for r in rows:
            self._toast_seen_max_audit_id = max(
                self._toast_seen_max_audit_id, int(r["audit_id"]))
            action   = r["action"] or ""
            severity = (r["severity"] or "INFO").upper()
            inc_id   = r["incident_id"] or ""
            inc_type = r["incident_type"] or ""
            inc_sum  = r["summary"] or r["change_summary"] or ""

            fired_severity = None
            title = body = ""
            if action == "INCIDENT_CREATED" and severity in ("CRITICAL", "HIGH"):
                title = f"{severity}  ·  {inc_type or 'New incident'}"
                body  = inc_sum[:200] if inc_sum else "(no summary)"
                self.toasts.show(title, body, severity=severity,
                                 timeout_ms=8000 if severity == "CRITICAL" else 6000,
                                 incident_id=inc_id)
                fired_severity = severity
            elif action == "BCP_ACTIVATED":
                title = "BCP ACTIVATED"
                body  = f"{inc_type} — paper protocol issued to all wards."
                self.toasts.show(title, body, severity="CRITICAL",
                                 timeout_ms=9000, incident_id=inc_id)
                fired_severity = "CRITICAL"
            elif action == "NOTIFY_NDPC":
                title = "NDPC notification dispatched"
                body  = "72-hour breach-notification clock has started."
                self.toasts.show(title, body, severity="HIGH",
                                 timeout_ms=6000, incident_id=inc_id)
                fired_severity = "HIGH"

            # Mirror every toast into the persistent notification store so
            # the user can review history via the top-bar bell button.
            if fired_severity is not None:
                self.notif_store.add(
                    title=title, body=body,
                    severity=fired_severity,
                    incident_id=inc_id, action=action)

            if fired_severity == "CRITICAL":
                self._play_alert_sound()

    def _kick_initial_refresh(self) -> None:
        self.bus.refresh_requested.emit()

    # ------------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------------
    def _on_status_message(self, text: str, timeout_ms: int = 4000) -> None:
        self.statusBar().showMessage(text, timeout_ms)

    def _on_incident_selected(self, inc_id: str) -> None:
        self.statusBar().showMessage(f"Selected incident: {inc_id}", 2500)

    def _open_incident_detail(self, inc_id: str) -> None:
        """Open (or raise) the IncidentDetailDialog for a specific incident."""
        if not inc_id:
            return
        # Reuse an existing dialog if already open for this incident.
        existing = self._detail_dialogs.get(inc_id)
        if existing is not None and existing.isVisible():
            existing.raise_(); existing.activateWindow()
            return
        from dashboard.widgets.incident_detail import IncidentDetailDialog
        dlg = IncidentDetailDialog(
            incident_id=inc_id,
            case_store=self.case_store,
            playbook_engine=self.playbook_engine,
            containment_advisor=self.containment,
            recovery_checklist=self.recovery_checklist,
            ndpr_mapper=self.ndpr_mapper,
            audit_manager=self.audit_manager,
            parent=self)
        self._detail_dialogs[inc_id] = dlg
        dlg.finished.connect(
            lambda _r, _id=inc_id: self._detail_dialogs.pop(_id, None))
        dlg.show()
        dlg.raise_()

    def _on_open_db(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open EIRP-EMR Case DB",
            str(self.db_path.parent), "SQLite (*.db *.sqlite *.sqlite3);;All Files (*)")
        if not path:
            return
        QMessageBox.information(
            self, "Restart Required",
            "Re-launch the dashboard with --db pointing at the new database. "
            "Live DB swap inside one session isn't supported in this build.")
        self.statusBar().showMessage(f"Requested DB: {path}", 4000)

    def _on_quick_action(self, tab_index: int) -> None:
        if 0 <= tab_index < self.tabs.count():
            self.tabs.setCurrentIndex(tab_index)

    def _on_respond_requested(self, incident_ids) -> None:
        """Analyst chose 'Respond' on one or more incidents -> jump to the
        Playbook tab and load them into the walker's response queue."""
        ids = [i for i in (incident_ids or []) if i]
        if not ids:
            return
        idx = self._tab_map.get("playbook")
        if idx is not None and 0 <= idx < self.tabs.count():
            self.tabs.setCurrentIndex(idx)
        try:
            self.w_playbook.load_response_queue(ids)
        except Exception as exc:
            self.statusBar().showMessage(f"Could not open response queue: {exc}", 5000)

    def _notify(self, title: str, body: str, severity: str = "INFO",
                timeout_ms: int = 6000, incident_id: str = "",
                action: str = "", archive: bool = True) -> None:
        """Surface an alert via toast (immediate) + notification center
        (persistent in-session history). Use this instead of calling
        `self.toasts.show(...)` directly so the bell badge stays in sync."""
        if hasattr(self, "toasts"):
            self.toasts.show(title, body, severity=severity,
                             timeout_ms=timeout_ms, incident_id=incident_id)
        if archive and hasattr(self, "notif_store"):
            self.notif_store.add(title=title, body=body,
                                 severity=severity,
                                 incident_id=incident_id, action=action)

    def _on_toast_view(self, incident_id: str) -> None:
        """User clicked "View" on a toast: open the full drill-down dialog."""
        if not incident_id:
            return
        self._open_incident_detail(incident_id)
        self.statusBar().showMessage(f"Opened detail for {incident_id}", 3500)

    def _on_tab_changed(self, _idx: int) -> None:
        """Force-refresh the newly-visible tab. Other tabs' tick handlers
        are gated on isVisible() and skip work entirely while inactive.

        Tabs are wrapped in a caption-strip QWidget; descend into children
        until we find an object with _refresh / _refresh_full.
        """
        w = self.tabs.currentWidget()
        # Try the wrap first, then walk children for the actual widget
        candidates = [w] + list(w.findChildren(QWidget))
        for cand in candidates:
            for name in ("_refresh", "_refresh_full"):
                fn = getattr(cand, name, None)
                if callable(fn):
                    try:
                        fn()
                    except Exception:
                        pass
                    return

    # ------------------------------------------------------------------------
    # Profile button + menu
    # ------------------------------------------------------------------------
    def _refresh_profile_button(self) -> None:
        u = self.session.user
        if u is None:
            self.btn_profile.setText("Not signed in")
        else:
            self.btn_profile.setText(f"  {u.full_name}    {u.role.label}  v")
        # Always re-apply palette so colour follows the active theme.
        self._apply_profile_button_style()

    def _apply_profile_button_style(self) -> None:
        from dashboard.theme import TEXT_SECONDARY as _ts, ACCENT as _ac
        self.btn_profile.setStyleSheet(
            f"QPushButton {{ text-align:right; color:{_ts}; "
            f"background:transparent; border:none; padding:6px 10px; }}"
            f"QPushButton:hover {{ color:{_ac}; }}")

    def _apply_palette(self) -> None:
        """Re-apply inline-styled colours to top-bar elements after a theme
        swap. Top-bar widgets need this because their colours were baked in
        via setStyleSheet at construction; the global QSS doesn't reach
        them (they don't have an objectName the QSS targets)."""
        from dashboard.theme import (
            ACCENT as _ac, TEXT_MUTED as _tm,
        )
        if hasattr(self, "lbl_brand"):
            self.lbl_brand.setStyleSheet(
                f"color:{_ac};font-size:14pt;font-weight:800;letter-spacing:2px;")
        if hasattr(self, "lbl_brand_sub"):
            self.lbl_brand_sub.setStyleSheet(
                f"color:{_tm};font-size:9.5pt;")
        if hasattr(self, "lbl_db"):
            self.lbl_db.setStyleSheet(f"color:{_tm};font-size:9pt;")
        if hasattr(self, "lbl_clock"):
            self.lbl_clock.setStyleSheet(
                f"color:{_ac};font-weight:600;font-size:10pt;")
        if hasattr(self, "btn_profile"):
            self._apply_profile_button_style()

    def _show_profile_menu(self) -> None:
        menu = QMenu(self)
        u = self.session.user
        if u:
            head = QAction(f"Signed in as {u.username}", menu)
            head.setEnabled(False)
            menu.addAction(head)
            menu.addSeparator()
        a_pw = QAction("Change my password...", menu)
        a_pw.triggered.connect(self._on_change_password)
        menu.addAction(a_pw)
        a_ref = QAction("Refresh all (F5)", menu)
        a_ref.setShortcut("F5")
        a_ref.triggered.connect(self.bus.refresh_requested.emit)
        menu.addAction(a_ref)
        menu.addSeparator()

        prefs = get_prefs()
        opposite = "light" if current_theme() == "dark" else "dark"
        a_theme = QAction(f"Switch to {opposite} theme", menu)
        a_theme.triggered.connect(lambda: self._toggle_theme())
        menu.addAction(a_theme)

        a_sound = QAction("Sound alerts (CRITICAL)", menu)
        a_sound.setCheckable(True)
        a_sound.setChecked(prefs.get_sound_alerts())
        a_sound.toggled.connect(self._toggle_sound)
        menu.addAction(a_sound)

        a_tour = QAction("Show onboarding tour", menu)
        a_tour.triggered.connect(self._launch_tour)
        menu.addAction(a_tour)

        menu.addSeparator()
        a_db = QAction("Open different case DB...", menu)
        a_db.triggered.connect(self._on_open_db)
        menu.addAction(a_db)
        # Admin-only configuration + destructive actions
        if self.session.can_manage_users():
            a_workers = QAction("Inference workers — settings…", menu)
            a_workers.triggered.connect(self._show_worker_settings)
            menu.addAction(a_workers)
            a_reset = QAction("⚠  Reset case store (admin)…", menu)
            a_reset.triggered.connect(self._reset_case_store)
            menu.addAction(a_reset)
        menu.addSeparator()
        a_out = QAction("Sign out + quit", menu)
        a_out.triggered.connect(self.close)
        menu.addAction(a_out)
        menu.exec(self.btn_profile.mapToGlobal(
            self.btn_profile.rect().bottomLeft()))

    # ------------------------------------------------------------------------
    def _show_worker_settings(self) -> None:
        """Open the admin worker-pool config dialog. Settings persist to
        eirp_prefs.json and apply on the NEXT dashboard launch (the pool's
        subprocesses are process-level so we can't reload in-place)."""
        if not self.session.can_manage_users():
            return
        from dashboard.widgets.worker_settings import WorkerSettingsDialog
        dlg = WorkerSettingsDialog(self)
        if dlg.exec() == dlg.DialogCode.Accepted:
            self._notify(
                "Worker settings saved",
                "Close the dashboard and re-launch to apply.",
                severity="INFO", timeout_ms=4500, archive=False)

    # ------------------------------------------------------------------------
    def _reset_case_store(self) -> None:
        """Wipe every row from incidents / playbook_execution / evidence_chain
        / audit_trail / notifications_log. Double-confirm; admin-only."""
        if not self.session.can_manage_users():
            return
        confirm = QMessageBox.warning(
            self, "Reset case store",
            "This will DELETE every incident, audit row, evidence hash, "
            "notification, and playbook execution from the case store.\n\n"
            "The schema is preserved -- only the data is wiped.\n\n"
            "Use this to start a clean trial run. It does NOT touch user "
            "accounts or your log-source registry.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes:
            return
        second = QMessageBox.warning(
            self, "Reset case store -- final confirmation",
            "Last chance.\n\n"
            "Type-the-action confirmation isn't shown here, but this is "
            "IRREVERSIBLE. If you have valuable demo data, click No and "
            "use 'Open different case DB...' to switch to a fresh file.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if second != QMessageBox.StandardButton.Yes:
            return
        # Drain in-flight scans before wiping so a still-running parser
        # subprocess + score() can't re-populate audit_trail mid-reset and
        # leave dangling FK refs (the reset() transaction also disables FKs
        # for safety, but cancelling first stops new orphan incidents from
        # landing in the just-cleared tables).
        for sid in list(s.source_id
                        for s in self.source_registry.list_all()):
            try:
                self.source_registry.cancel(sid)
            except Exception:
                pass
        if hasattr(self, "_inflight_pool_keys") and \
                hasattr(self, "_inflight_lock"):
            try:
                with self._inflight_lock:
                    self._inflight_pool_keys.clear()
            except Exception:
                pass
        try:
            self.case_store.reset()
            self._toast_seen_max_audit_id = 0
            # Clear the cancel set so subsequent rescans of the SAME sources
            # aren't permanently flagged. Reset is the natural moment to
            # forget cancellation state.
            try:
                self.source_registry._cancelled.clear()
            except Exception:
                pass
            self.bus.refresh_requested.emit()
            self.statusBar().showMessage(
                "Case store reset -- ready for a fresh trial.", 6000)
            self._notify(
                "Case store reset",
                "Every incident, audit row, evidence hash, and notification "
                "was wiped. The schema, users, and log-source registry are "
                "untouched. Add a data source on the Data Sources tab to "
                "start a fresh trial.",
                severity="INFO", timeout_ms=6000, archive=False)
        except Exception as exc:
            QMessageBox.critical(
                self, "Reset failed", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------------
    # Theme / sound / tour wiring
    # ------------------------------------------------------------------------
    def _toggle_theme(self) -> None:
        from PyQt6.QtWidgets import QApplication
        new_name = "light" if current_theme() == "dark" else "dark"
        apply_theme(QApplication.instance(), new_name)
        get_prefs().set_theme(new_name)
        # apply_theme() walks all widgets and calls _apply_palette() on any
        # that opt-in. Bump the case-store watermark so widgets that DON'T
        # opt-in (those with inline rich-text spans like containment_recovery)
        # refresh on their next visible tick and re-render with fresh colours.
        self.case_store.bump_data_version()
        self._refresh_profile_button()
        # Re-fire a refresh_requested so the currently-visible tab repaints
        # immediately rather than waiting up to 2 s for the next tick.
        self.bus.refresh_requested.emit()
        # Don't archive theme/sound toggles -- they're transient confirmations,
        # not operational alerts.
        self._notify("Theme switched",
                     f"Now using the {new_name} theme.",
                     severity="INFO", timeout_ms=3000, archive=False)

    def _toggle_sound(self, enabled: bool) -> None:
        get_prefs().set_sound_alerts(enabled)
        self._notify(
            "Sound alerts " + ("enabled" if enabled else "muted"),
            "CRITICAL incidents will " +
            ("trigger the system bell." if enabled else "be silent."),
            severity="INFO", timeout_ms=3500, archive=False)

    def _launch_tour(self) -> None:
        tour = OnboardingTour(self.tabs, self)
        tour.exec()
        # Mark complete on this user's prefs
        if self.session.user:
            get_prefs().set_user_pref(
                self.session.user.username, "tour_completed", True)

    def _maybe_show_tour_on_first_run(self) -> None:
        """Auto-launch the tour the first time a user signs in (per-user)."""
        if not self.session.user:
            return
        prefs = get_prefs()
        done = prefs.get_user_pref(
            self.session.user.username, "tour_completed", False)
        if done:
            return
        # Defer one event-loop turn so the main window is fully painted.
        QTimer.singleShot(400, self._launch_tour)

    def _play_alert_sound(self) -> None:
        """Play a short attention-grabbing alert for CRITICAL events.

        Order of preference:
          1. Windows MessageBeep(MB_ICONHAND) -- a distinctive 'error' tone
             that bypasses muted application volume on most Windows boxes.
          2. QApplication.beep() -- generic system bell.
          3. Silent fallback if no sound device is available.
        """
        if not get_prefs().get_sound_alerts():
            return
        # 1. Windows-native attention tone
        try:
            import sys
            if sys.platform == "win32":
                import winsound
                # MB_ICONHAND = SystemHand sound (red-X error tone). Plays
                # asynchronously without blocking the UI thread.
                winsound.MessageBeep(winsound.MB_ICONHAND)
                return
        except Exception:
            pass
        # 2. Cross-platform fallback
        try:
            from PyQt6.QtWidgets import QApplication
            QApplication.beep()
        except Exception:
            pass

    # ------------------------------------------------------------------------
    # Role gating
    # ------------------------------------------------------------------------
    def _apply_role_gating(self) -> None:
        """Disable destructive controls in the read-only widgets if the
        signed-in user is a VIEWER. Visual cue is the button's :disabled
        QSS state (greyed out + non-interactive)."""
        can = self.session.can_mutate()

        # Open Incidents -- status-change buttons
        if hasattr(self.w_incidents, "btn_contain"):
            self.w_incidents.btn_contain.setEnabled(can)
            self.w_incidents.btn_close.setEnabled(can)
        # Playbook Walker -- step-state buttons
        if hasattr(self.w_playbook, "btn_complete"):
            self.w_playbook.btn_complete.setEnabled(can)
            self.w_playbook.btn_skip.setEnabled(can)
            self.w_playbook.btn_fail.setEnabled(can)
        # Data Sources -- add / remove / bulk-run
        if hasattr(self.w_sources, "btn_add_file"):
            self.w_sources.btn_add_file.setEnabled(can)
            self.w_sources.btn_add_dir.setEnabled(can)
            self.w_sources.btn_remove.setEnabled(can)
            self.w_sources.btn_bulk.setEnabled(can)

        if not can:
            self.statusBar().showMessage(
                "Read-only session: destructive actions are disabled for VIEWERs.",
                8000)

    def _on_change_password(self) -> None:
        u = self.session.user
        if u is None:
            return
        new_pw, ok = QInputDialog.getText(
            self, "Change my password",
            f"New password for {u.username} (min 6 chars):",
            echo=QLineEdit.EchoMode.Password)
        if not ok or not new_pw:
            return
        try:
            self.user_store.reset_password(u.user_id, new_pw)
            self.statusBar().showMessage("Password updated.", 3500)
        except ValueError as e:
            QMessageBox.warning(self, "Password change failed", str(e))

    # ------------------------------------------------------------------------
    def _wire_engine_signals(self) -> None:
        """Route engine events into the DataSourcesWidget and bus."""
        # File watcher -> live worker queue.
        # DirectConnection: enqueue() just puts to a thread-safe queue.Queue,
        # so cross-thread direct call is safe. A queued connection would
        # deadlock because the worker thread doesn't run a Qt event loop.
        from PyQt6.QtCore import Qt
        self.file_watcher.file_changed.connect(
            self.live_worker.enqueue,
            Qt.ConnectionType.DirectConnection)

        # Live worker -> data-sources tab (and a status-bar update)
        self.live_worker.engine_ready.connect(self.w_sources.on_engine_ready)
        self.live_worker.job_started.connect(self.w_sources.on_job_started)
        self.live_worker.job_finished.connect(self.w_sources.on_job_finished)
        self.live_worker.job_failed.connect(self.w_sources.on_job_failed)
        self.live_worker.parser_event.connect(self.w_sources.on_parser_event)

        # Live worker finishing a job nudges the read-only widgets to repaint
        self.live_worker.job_finished.connect(
            lambda _sid, n_rows, n_inc:
            self.bus.refresh_requested.emit() if (n_rows or n_inc) else None)

    def _start_engine(self) -> None:
        """Kick off live inference (pool or in-process) + file watcher.

        Auto-attaching a default LIRA source on first launch only happens
        when the dashboard is started with `--demo` (developer workflow).
        On a production / hospital deployment the registry stays empty
        and the admin attaches their own sources via the Data Sources
        tab; this keeps the dashboard portable across machines that have
        no LIRA dump in the project root.
        """
        cfg = self.worker_pool_config
        if cfg.get("enabled"):
            self._start_worker_pool(cfg)
        else:
            self.live_thread.start()
        self.file_watcher.start()
        if getattr(self, "demo_mode", False):
            self._auto_attach_default_source()
        else:
            self._show_empty_state_hint_if_needed()

    def _show_empty_state_hint_if_needed(self) -> None:
        """One-time status-bar hint when no log source is configured."""
        if self.source_registry.list_all():
            return
        self.statusBar().showMessage(
            "No log source attached. Open Data Sources → Add File / "
            "Add Folder to point the engine at your logs (.txt, .log, "
            ".evtx, .csv, or directories).", 12000)

    def _start_worker_pool(self, cfg: Dict) -> None:
        """Spawn ml_inference_daemon.py subprocesses and route the
        FileWatcher's file_changed signal through the pool instead of
        the in-process LiveInferenceWorker."""
        from dashboard.engine.worker_pool import WorkerPool
        from PyQt6.QtCore import QThread

        n = max(1, int(cfg.get("n_workers", 2)))
        # Default lane assignment: first daemon is the live fast-lane,
        # subsequent ones are bulk-lane. User can override later.
        lanes = ["live"] + ["bulk"] * (n - 1) if n > 1 else ["live"]
        self.worker_pool = WorkerPool(
            db_path=self.db_path,
            base_port=int(cfg.get("base_port", 8765)),
            n_workers=n,
            lanes=lanes,
        )
        self.statusBar().showMessage(
            f"Spawning {n} inference worker(s) on ports "
            f"{self.worker_pool.base_port}-"
            f"{self.worker_pool.base_port + n - 1}...", 6000)

        # Start workers in a background QThread so the UI stays responsive
        # while each daemon loads its EIRPInferenceEngine (~2 min cold).
        class _PoolStarter(QThread):
            def __init__(self, pool, host):
                super().__init__(host)
                self.pool = pool
                self.host = host
                self.error: str = ""
            def run(self):
                try:
                    self.pool.start_all()
                except Exception as exc:
                    self.error = str(exc)
                    print(f"[worker-pool] start_all failed: {exc}",
                          flush=True)

        self._pool_starter = _PoolStarter(self.worker_pool, self)
        self._pool_starter.finished.connect(self._on_pool_ready)
        self._pool_starter.start()

        # File-changed events now dispatch through the pool instead of
        # the in-process queue. Disconnect the old wire-up and replace.
        try:
            self.file_watcher.file_changed.disconnect(self.live_worker.enqueue)
        except (TypeError, RuntimeError):
            pass
        self.file_watcher.file_changed.connect(self._dispatch_to_pool)

    def _fallback_to_in_process(self, reason: str = "") -> None:
        """Tear down the dead pool and start the in-process LiveInferenceWorker
        so scoring still works. Called from _on_pool_ready when start_all
        produced no healthy workers."""
        print(f"[engine] worker pool failed ({reason}); "
              f"falling back to in-process scoring", flush=True)
        # 1. Drop pool-side dispatch wiring.
        try:
            self.file_watcher.file_changed.disconnect(self._dispatch_to_pool)
        except (TypeError, RuntimeError):
            pass
        # 2. Forget the pool object so _dispatch_to_pool no longer fires
        #    (its guard returns early when self.worker_pool is None).
        try:
            if self.worker_pool is not None:
                self.worker_pool.stop_all(graceful_timeout_s=2.0)
        except Exception:
            pass
        self.worker_pool = None
        # 3. Re-wire the in-process queue.
        from PyQt6.QtCore import Qt as _Qt
        try:
            self.file_watcher.file_changed.connect(
                self.live_worker.enqueue,
                _Qt.ConnectionType.DirectConnection)
        except (TypeError, RuntimeError):
            pass
        # 4. Start the live worker thread if it isn't running yet.
        try:
            if not self.live_thread.isRunning():
                self.live_thread.start()
        except Exception as exc:
            print(f"[engine] could not start in-process worker: {exc}",
                  flush=True)
            return
        self.statusBar().showMessage(
            f"Engine: in-process mode (pool fallback). Reason: {reason}",
            12000)

    def _on_pool_ready(self) -> None:
        # Plug the live pool into the Data Sources widget so its status
        # panel can poll /healthz + /stats on each daemon. The widget is
        # constructed before _start_worker_pool runs, so we set it here.
        if hasattr(self.w_sources, "pool_status"):
            self.w_sources.pool_status.pool = self.worker_pool
            if not self.w_sources.pool_status._timer.isActive():
                self.w_sources.pool_status._timer.start()
            self.w_sources.pool_status.tbl.setVisible(True)
            self.w_sources.pool_status._refresh()

        healthy = [w for w in (self.worker_pool.workers or []) if w.healthy]
        if healthy:
            ports = ", ".join(f"{w.port}({w.lane})" for w in healthy)
            msg = f"Worker pool ready: {len(healthy)}/{len(self.worker_pool.workers)} daemons online ({ports})"
            self.statusBar().showMessage(msg, 8000)
            # Flip the Data Sources tab's Engine: label. It only listens
            # to live_worker.engine_ready (which never fires in pool mode);
            # do it explicitly.
            try:
                self.w_sources.on_engine_ready(
                    True, f"pool: {len(healthy)}/{len(self.worker_pool.workers)} "
                          f"daemon(s) ready on {ports}")
            except Exception:
                pass
            self._notify(
                "Worker pool online",
                f"{len(healthy)} inference daemon(s) ready on ports "
                f"{ports}. Live scoring now runs in parallel processes.",
                severity="INFO", timeout_ms=5000)
        else:
            err = "; ".join(
                f"{w.port}={w.last_err or 'unknown'}"
                for w in (self.worker_pool.workers or []))
            starter_err = getattr(self._pool_starter, "error", "") if \
                hasattr(self, "_pool_starter") else ""
            reason = err or starter_err or "no daemons healthy"
            msg = f"Worker pool FAILED to come online: {reason}"
            self.statusBar().showMessage(msg, 12000)
            self._notify(
                "Worker pool offline — using in-process engine",
                "No inference daemons reached ready state. The dashboard "
                "has fallen back to in-process scoring so files still get "
                "processed.",
                severity="HIGH", timeout_ms=8000)
            # CRITICAL: actually start the fallback, don't just notify.
            self._fallback_to_in_process(reason)

    def _dispatch_to_pool(self, source_id: str, file_path: str) -> None:
        """Route a file-changed event to the worker pool.

        Guards:
          1. Dedupe in-flight requests for the same (source_id, file_path).
             Without this, the file_watcher's polling tick can fire
             redundant events that pile up against the daemon's per-process
             lock and time out.
          2. Skip dispatch when no daemon has finished loading its
             EIRPInferenceEngine. Cold start is ~120 s; firing /score
             before that returns 500 "engine not loaded yet" which used
             to surface as cryptic "HTTP error" lines in the terminal.
          3. Fire the existing live_worker.job_* signals so the Data
             Sources tab's activity log + sources table update exactly
             the same way they do in non-pool mode. Without this the
             user has no UI feedback while the pool is doing work.
          4. Adaptive timeout: 600 s (10 min). Inference on a 27k-row
             LIRA dump routinely takes 2-3 min; 120 s was too tight.
        """
        if not self.worker_pool:
            return
        src = self.source_registry.get(source_id)
        if src is None:
            return

        # ----- Guard 1: dedupe in-flight ----------------------------------
        if not hasattr(self, "_inflight_pool_keys"):
            self._inflight_pool_keys = set()
            self._inflight_lock = __import__("threading").Lock()
        key = (source_id, file_path)
        with self._inflight_lock:
            if key in self._inflight_pool_keys:
                # Same file already being scored -- drop this event silently.
                return
            self._inflight_pool_keys.add(key)

        # ----- Guard 2: pool readiness ------------------------------------
        ready = [w for w in (self.worker_pool.workers or [])
                 if w.healthy and w.engine_loaded]
        if not ready:
            self.bus.status_message.emit(
                "Worker pool is still loading models (~2 min cold start). "
                "File-change events are queued.", 4000)
            # Schedule a retry in 10 s rather than failing hard.
            from PyQt6.QtCore import QTimer
            def _retry():
                with self._inflight_lock:
                    self._inflight_pool_keys.discard(key)
                self._dispatch_to_pool(source_id, file_path)
            QTimer.singleShot(10_000, _retry)
            return

        # Lane routing: LIRA dumps -> bulk lane; everything else -> live lane.
        lane = "live"
        try:
            if src.kind.value in ("lira_output_dir", "lira_raw"):
                lane = "bulk"
        except Exception:
            pass

        # ----- Guard 3: fire job_started so the Data Sources log updates --
        try:
            self.live_worker.job_started.emit(source_id, file_path)
        except Exception:
            pass

        # ----- Guard 4: do EVERYTHING heavy in the background thread.
        # CRITICAL: resolve_csv_for_dispatch runs a parser subprocess via
        # Popen+wait. For an EVTX source pointing at a 172-file directory,
        # that's 172 sequential parser subprocesses. If we run any of it
        # on the GUI thread before spawning the thread, clicking the Data
        # Sources tab freezes for the duration of the parse (often
        # minutes). The background thread does the parse, the HTTP call,
        # and the registry update; the GUI thread returns immediately.
        import threading
        from urllib.error import HTTPError

        def _do(attempt=0):
            from dashboard.engine.parsers_runner import (
                resolve_csv_for_dispatch, count_csv_rows,
            )

            def _cancelled() -> bool:
                try:
                    return self.source_registry.is_cancelled(source_id)
                except Exception:
                    return False

            # Pre-flight: source already gone (e.g. Remove fired while we
            # were waiting for the worker-pool to load) -- skip parse + HTTP.
            if _cancelled():
                with self._inflight_lock:
                    self._inflight_pool_keys.discard(key)
                return
            csv_path = resolve_csv_for_dispatch(
                src, file_path, cancel_check=_cancelled)
            # Parser killed by cancel_check -- silently drop, don't surface
            # as a failure (the source no longer exists).
            if _cancelled():
                with self._inflight_lock:
                    self._inflight_pool_keys.discard(key)
                return
            if csv_path is None:
                try:
                    self.live_worker.job_failed.emit(
                        source_id,
                        f"could not parse {src.kind.label} at {file_path} "
                        "(parser missing or input malformed)")
                except Exception:
                    pass
                with self._inflight_lock:
                    self._inflight_pool_keys.discard(key)
                return
            csv_path_str = str(csv_path)

            # Optimistic SCORED update: count the parsed-CSV rows NOW so
            # the Configured Log Sources table shows a meaningful "Scored"
            # value immediately, even if the daemon's score() doesn't
            # return for 30+ minutes (HTTP timeout) or never does. Without
            # this the column would say 0 the whole time while incidents
            # climb in the Incidents column.
            try:
                from datetime import datetime as _dt_optim
                rows_in_csv = int(count_csv_rows(csv_path))
                if rows_in_csv > 0:
                    self.source_registry.update(
                        source_id,
                        n_scored=rows_in_csv,
                        last_scan_at=_dt_optim.now().isoformat())
            except Exception:
                pass
            # Final cancellation gate: skip the daemon HTTP call entirely
            # if the source was removed between the parse finishing and us
            # opening the socket. Without this the daemon spends 30s-1h
            # scoring a CSV whose source is already gone, and the
            # incidents land orphaned in the case_store.
            if _cancelled():
                with self._inflight_lock:
                    self._inflight_pool_keys.discard(key)
                return
            try:
                source_arg = src.kind.inference_source_arg
                max_inc = (self.bulk_max_incidents if lane == "bulk"
                           else self.live_max_incidents)
                # Differential timeout: bulk LIRA dumps can score for an
                # hour on a 237k-row file; live access/error/EVTX rarely
                # exceed 10 minutes. Bulk lane: 3600 s. Live lane: 600 s.
                # Going to "0 = unlimited" is tempting but would mask a
                # truly hung daemon -- the dispatcher would never give up.
                pool_timeout_s = 3600.0 if lane == "bulk" else 600.0
                result = self.worker_pool.score(
                    csv_path=csv_path_str,           # parsed CSV, not raw
                    source=source_arg,
                    lane=lane,
                    max_incidents=max_inc,
                    source_name=src.name,
                    source_path=file_path,            # keep the ORIGINAL
                                                      # path for forensics
                    timeout_s=pool_timeout_s)
                n_rows = int(result.get("rows", 0))
                n_inc  = int(result.get("incidents", 0))
                # Snapshot the parsed CSV's row count so the FileWatcher
                # doesn't refire on the same file the next launch. The
                # in-process LiveInferenceWorker writes last_row_count
                # from fetch_new_rows()'s `total`; the pool path bypasses
                # that helper so we count rows ourselves here.
                try:
                    new_total = count_csv_rows(csv_path)
                except Exception:
                    new_total = src.last_row_count + n_rows
                from datetime import datetime as _dt
                self.source_registry.update(
                    source_id,
                    last_row_count=new_total,
                    last_scan_at=_dt.now().isoformat(),
                    n_scored=src.n_scored + n_rows,
                    n_incidents=src.n_incidents + n_inc)
                if n_rows or n_inc:
                    self.case_store.bump_data_version()
                try:
                    self.live_worker.job_finished.emit(
                        source_id, n_rows, n_inc)
                except Exception:
                    pass
                self.bus.refresh_requested.emit()
                with self._inflight_lock:
                    self._inflight_pool_keys.discard(key)
                return
            except HTTPError as exc:
                if exc.code == 503 and attempt < 12:
                    # Daemon says "engine not loaded yet" -- wait + retry
                    # transparently. 12 attempts × 10 s = 2 min cap, which
                    # is the realistic upper bound on engine cold-start.
                    import time
                    time.sleep(10)
                    return _do(attempt + 1)
                msg = self._categorise_pool_error(exc)
                is_timeout = False
            except Exception as exc:
                import socket as _socket
                is_timeout = isinstance(exc, _socket.timeout)
                msg = self._categorise_pool_error(exc)
            print(f"[worker-pool] dispatch {('background' if is_timeout else 'failed')}: {msg}",
                  flush=True)
            if is_timeout:
                # The HTTP request gave up but the daemon is still running
                # score() and committing incidents to the case_store. The
                # Data Sources row stays in "scoring..." state; the diag
                # tick will keep refreshing INCIDENTS from the DB until
                # the count plateaus. Marking the row "failed" here would
                # be a lie -- the daemon hasn't failed at all.
                self.bus.status_message.emit(
                    f"{source_id}: HTTP timeout; daemon still scoring "
                    f"in background (DB will keep updating).", 8000)
            else:
                try:
                    self.live_worker.job_failed.emit(source_id, msg)
                except Exception:
                    pass
                self.bus.status_message.emit(
                    f"Pool dispatch failed for {source_id}: {msg}", 6000)
            with self._inflight_lock:
                self._inflight_pool_keys.discard(key)

        threading.Thread(target=_do, daemon=True).start()

    @staticmethod
    def _categorise_pool_error(exc: Exception) -> str:
        """Turn a urllib / socket exception into a human-readable string."""
        import socket
        from urllib.error import URLError, HTTPError
        if isinstance(exc, HTTPError):
            return f"HTTP {exc.code}: {exc.reason}"
        if isinstance(exc, socket.timeout):
            return ("HTTP timeout (>10 min). The daemon may still be "
                    "scoring; check /stats on the daemon port. Consider "
                    "splitting very large CSVs.")
        if isinstance(exc, URLError):
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ConnectionRefusedError) or (
                    isinstance(reason, OSError) and
                    "refused" in str(reason).lower()):
                return ("Connection refused -- the daemon may have crashed "
                        "or never started. Check the dashboard launch log.")
            if isinstance(reason, socket.timeout) or "timed out" in str(reason):
                return ("HTTP timeout. Daemon is still scoring or model "
                        "load is taking longer than usual.")
            return f"URLError: {reason}"
        return f"{type(exc).__name__}: {exc}"

    def _auto_attach_default_source(self) -> None:
        from dashboard.engine import LogKind
        if self.source_registry.list_all():
            return            # user already configured something -- leave it alone

        candidates = [
            ("LIRA 2026",  "LIRA_2026_Output/LIRA_2026_00_master_all_events.csv",
             LogKind.PARSED_CSV),
            ("LIRA 2025",  "LIRA_2025_Output/LIRA_2025_00_master_all_events.csv",
             LogKind.PARSED_CSV),
            ("LIRA 2024",  "LIRA_2024_Output/LIRA_2024_00_master_all_events.csv",
             LogKind.PARSED_CSV),
            ("LIRA 2023",  "LIRA_2023_Output/LIRA_2023_00_master_all_events.csv",
             LogKind.PARSED_CSV),
            ("Access logs", "Access_Log_Output/access_00_master_all_events.csv",
             LogKind.PARSED_CSV),
        ]
        from pathlib import Path
        base = Path(self.db_path).resolve().parent
        for name, rel, kind in candidates:
            p = base / rel
            if p.exists():
                self.source_registry.add(
                    name=name, path=str(p), kind=kind, realtime=True)
                self.file_watcher.reload_sources()
                self.statusBar().showMessage(
                    f"Auto-attached '{name}' for live analysis. "
                    f"Visit the Data Sources tab to add more or remove this one.",
                    8000)
                self.bus.status_message.emit(
                    f"Auto-attached {name}", 6000)
                return

    # ------------------------------------------------------------------------
    def resizeEvent(self, ev):
        # Keep toasts docked to the top-right corner on window resize.
        super().resizeEvent(ev)
        if hasattr(self, "toasts"):
            self.toasts.relayout()

    # ------------------------------------------------------------------------
    def closeEvent(self, event) -> None:
        try:
            self.file_watcher.stop()
            self.bulk_worker.stop()
            if self.worker_pool is not None:
                try:
                    self.worker_pool.stop_all(graceful_timeout_s=4.0)
                except Exception:
                    pass
            else:
                self.live_thread.stop_gracefully(timeout_ms=2000)
            self.case_store.close()
            self.user_store.close()
        finally:
            super().closeEvent(event)
