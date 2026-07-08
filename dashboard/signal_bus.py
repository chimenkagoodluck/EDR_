
from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal


class SignalBus(QObject):
     refresh_requested()        force-refresh all widgets (manual)

    incident_selected = pyqtSignal(str)
    incident_details  = pyqtSignal(str)
    respond_requested = pyqtSignal(object)     # list[str] of incident IDs
    tick              = pyqtSignal(int)
    status_message    = pyqtSignal(str, int)   # text, timeout_ms
    chain_verified    = pyqtSignal(bool, int)
    refresh_requested = pyqtSignal()
