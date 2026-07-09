from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

_engine = None
_engine_load_ts: Optional[float] = None
_lock = threading.Lock()
_stats = {
    "jobs_done":          0,
    "rows_scored":        0,
    "incidents_persisted": 0,
    "last_job_ms":        0.0,
    "avg_job_ms":         0.0,
    "errors":             0,
}
_start_ts = time.time()
_args: Optional[argparse.Namespace] = None
_shutdown_requested = False


def _load_engine() -> None:
    global _engine, _engine_load_ts
    if _engine is not None:
        return
    t0 = time.time()
    from ml_inference import EIRPInferenceEngine
    _engine = EIRPInferenceEngine(
        persist_incidents=True,
        db_path=Path(_args.db),
        dispatch_notifications=not _args.no_notify,
        auto_complete_automated_steps=not _args.no_auto_steps,
        recovery_modules_enabled=not _args.no_recovery,
        bcp_critical_only=True,
        max_incidents_per_run=_args.max_incidents,
    )
    _engine_load_ts = time.time() - t0


class InferenceHandler(BaseHTTPRequestHandler):
    
    server_version = "EIRP-Inference/1.0"

    # --- helpers ------------------------------------------------------
    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", "0"))
        if n <= 0:
            return {}
        raw = self.rfile.read(n).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"bad JSON: {exc}")

    def log_message(self, fmt, *args):
        
        return

    # --- GET handlers --------------------------------------------------
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._json(200, {
                "ok": _engine is not None,
                "engine_loaded": _engine is not None,
                "engine_load_s": _engine_load_ts,
                "uptime_s": round(time.time() - _start_ts, 1),
                "lane": _args.lane,
                "port": _args.port,
                "pid": os.getpid(),
            })
            return
        if self.path == "/stats":
            with _lock:
                self._json(200, dict(_stats))
            return
        self._json(404, {"ok": False, "error": "not found"})

    # --- POST handlers -------------------------------------------------
    def do_POST(self) -> None:
        global _shutdown_requested
        if self.path == "/shutdown":
            _shutdown_requested = True
            self._json(200, {"ok": True, "shutting_down": True})
            # Give the response time to flush before bringing down the server
            threading.Timer(0.5, self.server.shutdown).start()
            return
        if self.path == "/score":
            try:
                body = self._read_json()
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
                return
            csv = body.get("csv")
            source = body.get("source", "lira")
            max_inc = body.get("max_incidents")
            source_name = body.get("source_name", "")
            source_path = body.get("source_path", "")
            if not csv:
                self._json(400, {"ok": False, "error": "missing 'csv'"})
                return
            # Engine readiness check before acquiring the lock. Returns
            # 503 (Service Unavailable) with retry hint so the dispatcher
            # can back off cleanly instead of surfacing a 500.
            if _engine is None:
                self._json(503, {
                    "ok": False,
                    "error": "engine not loaded yet (cold start ~120 s)",
                    "retry_after_s": 10,
                })
                return
            try:
                result = _score_one(csv, source, max_inc,
                                    source_name=source_name,
                                    source_path=source_path)
                self._json(200, result)
            except Exception as exc:
                with _lock:
                    _stats["errors"] += 1
                tb = traceback.format_exc()
                print(f"[daemon:{_args.port}] /score ERROR: {exc}\n{tb}",
                      file=sys.stderr, flush=True)
                self._json(500, {"ok": False, "error": str(exc),
                                  "traceback": tb})
            return
        self._json(404, {"ok": False, "error": "not found"})


# ---------------------------------------------------------------------------
def _score_one(csv_path: str, source: str,
               max_incidents: Optional[int],
               source_name: str = "", source_path: str = "") -> dict:
   
    import pandas as pd
    p = Path(csv_path)
    if not p.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")
   
    try:
        df = pd.read_csv(p)
    except pd.errors.EmptyDataError:
        df = pd.DataFrame()
    if df.empty:
        with _lock:
            _stats["jobs_done"] += 1
        return {
            "ok":         True,
            "rows":       0,
            "incidents":  0,
            "elapsed_ms": 0.0,
            "csv":        str(p),
            "source":     source,
            "empty":      True,
        }
    with _lock:
        if _engine is None:
            raise RuntimeError("engine not loaded yet")
        if max_incidents is not None:
        
            _engine.max_incidents = int(max_incidents)
        t0 = time.time()
        scored = _engine.score(
            df, source=source,
            source_name=source_name or "",
            source_path=source_path or str(p),
            source_csv_path=str(p))
        elapsed_ms = (time.time() - t0) * 1000
        n_rows = len(scored)
        n_inc = len(
            _engine.last_lifecycle.get("incidents_created", []) or [])
        _stats["jobs_done"] += 1
        _stats["rows_scored"] += n_rows
        _stats["incidents_persisted"] += n_inc
        _stats["last_job_ms"] = round(elapsed_ms, 1)
        # rolling average
        n = _stats["jobs_done"]
        _stats["avg_job_ms"] = round(
            (_stats["avg_job_ms"] * (n - 1) + elapsed_ms) / n, 1)
    return {
        "ok":         True,
        "rows":       n_rows,
        "incidents":  n_inc,
        "elapsed_ms": round(elapsed_ms, 1),
        "csv":        str(p),
        "source":     source,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="EIRP-EMR HTTP inference daemon")
    p.add_argument("--port", type=int, default=8765,
                   help="TCP port to listen on (default 8765)")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default localhost)")
    p.add_argument("--db", required=True,
                   help="Path to the eirp_cases.db case-store")
    p.add_argument("--lane", choices=("live", "bulk"), default="live",
                   help="Daemon role label (live = fast lane, bulk = "
                        "batch/backfill). Currently only metadata.")
    p.add_argument("--max-incidents", type=int, default=0,
                   help="Per-run cap (0 = unlimited); the dispatcher "
                        "may override on each /score request.")
    p.add_argument("--no-notify", action="store_true",
                   help="Skip notification dispatch (testing)")
    p.add_argument("--no-auto-steps", action="store_true",
                   help="Skip auto-completing playbook steps")
    p.add_argument("--no-recovery", action="store_true",
                   help="Skip recovery / containment side effects")
    p.add_argument("--ready-marker", default="",
                   help="Path of a file to touch when the engine is loaded "
                        "(for parent process to wait on)")
    return p.parse_args()


def main() -> int:
    global _args
    _args = parse_args()
    print(f"[daemon:{_args.port}] {_args.lane}-lane starting...", flush=True)

    
    def _bg_load():
        try:
            _load_engine()
            print(f"[daemon:{_args.port}] engine loaded in "
                  f"{_engine_load_ts:.1f}s", flush=True)
            if _args.ready_marker:
                try:
                    Path(_args.ready_marker).write_text(
                        f"ready {time.time():.3f} {_engine_load_ts:.1f}",
                        encoding="utf-8")
                except Exception:
                    pass
        except Exception as exc:
            print(f"[daemon:{_args.port}] engine load FAILED: {exc}",
                  file=sys.stderr, flush=True)
            traceback.print_exc()

    threading.Thread(target=_bg_load, daemon=True).start()

    server = ThreadingHTTPServer((_args.host, _args.port), InferenceHandler)
    print(f"[daemon:{_args.port}] HTTP listening on "
          f"{_args.host}:{_args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    print(f"[daemon:{_args.port}] shutting down", flush=True)
    server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
