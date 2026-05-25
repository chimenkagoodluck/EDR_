"""dashboard/signal_bus.py  --  Central pub/sub for cross-widget messages.

Widgets read DB state directly via CaseStore, but coordinate selection and
refresh events through one shared SignalBus instance owned by MainWindow.
"""
from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal


class SignalBus(QObject):
    """Single shared instance broadcasts between widgets.

    Signals:
        incident_selected(str)     emitted when user clicks an incident row
        incident_details(str)      emitted when user requests the full
                                    drill-down dialog (double-click / "Open")
        respond_requested(object)  emitted with a list[str] of incident IDs the
                                    analyst chose to respond to (right-click ->
                                    Respond); routes to the Playbook walker
        tick(int)                  emitted by the global QTimer every poll (seq #)
        status_message(str, int)   emitted to push a transient status-bar message
        chain_verified(bool, int)  emitted after audit-chain verify (ok, n_viol)
        refresh_requested()        force-refresh all widgets (manual)
    """
    incident_selected = pyqtSignal(str)
    incident_details  = pyqtSignal(str)
    respond_requested = pyqtSignal(object)     # list[str] of incident IDs
    tick              = pyqtSignal(int)
    status_message    = pyqtSignal(str, int)   # text, timeout_ms
    chain_verified    = pyqtSignal(bool, int)
    refresh_requested = pyqtSignal()
