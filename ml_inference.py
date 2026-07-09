import os
import sys
import json
import hashlib
import warnings
import argparse
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import Optional, List, Dict, Any

import numpy as np
import pandas as pd
import joblib
from rundemo import run_demo


try:
    from model_c_engine import ResponseEngine, POLICY_PATH as MODEL_C_POLICY_PATH
    _MODEL_C_AVAILABLE = True
except Exception:
    ResponseEngine = None
    MODEL_C_POLICY_PATH = None
    _MODEL_C_AVAILABLE = False


try:
    from ml_threat_scorer     import ThreatScorer
    from ml_correlation_engine import CorrelationEngine
    from ml_attack_mapper     import AttackMapper
    _PHASE2_AVAILABLE = True
except Exception as _phase2_exc:
    ThreatScorer = None
    CorrelationEngine = None
    AttackMapper = None
    _PHASE2_AVAILABLE = False

try:
    from response import (
        IncidentClassifier, PlaybookEngine, CaseStore, Notifier,
    )
    _LIFECYCLE_AVAILABLE = True
except Exception:
    IncidentClassifier = None
    PlaybookEngine     = None
    CaseStore          = None
    Notifier           = None
    _LIFECYCLE_AVAILABLE = False


try:
    from recovery import ContainmentAdvisor, RecoveryChecklist, BCPMonitor
    _RECOVERY_AVAILABLE = True
except Exception:
    ContainmentAdvisor = None
    RecoveryChecklist  = None
    BCPMonitor         = None
    _RECOVERY_AVAILABLE = False


BCP_ACTIVATION_INC_TYPES = {"INC-02", "INC-03"}

try:
    from reporting import AuditManager, NdprMapper, ReportGenerator
    _REPORTING_AVAILABLE = True
except Exception:
    AuditManager     = None
    NdprMapper       = None
    ReportGenerator  = None
    _REPORTING_AVAILABLE = False

warnings.filterwarnings("ignore")

BASE_DIR    = Path(__file__).parent.resolve()
MODELS_DIR  = BASE_DIR / "models"
DATASETS_DIR= BASE_DIR / "ML_Datasets"


ITS_W_SEVERITY    = 0.40
ITS_W_ANOMALY     = 0.30
ITS_W_CORRELATION = 0.20   # reserved; 0.0 until correlation engine (Phase 2)
ITS_W_AFTER_HOURS = 0.10

ITS_THRESHOLDS = [
    (0.80, "CRITICAL", "Execute playbook immediately + notify"),
    (0.60, "HIGH",     "Open incident case"),
    (0.30, "MEDIUM",   "Dashboard alert"),
    (0.00, "LOW",      "Log only"),
]


MODEL_B_FILE         = "model_B_unified.pkl"
MODEL_B_ENCODER_FILE = "model_B_unified_encoder.pkl"

MODEL_B_FEATURES     = None  # set after CES_COLUMNS is defined (see below)


SUPERVISED_MODELS = {
    1: {"file": "model_01_downtime.pkl",                   "source": "lira",   "name": "DB Downtime"},
    2: {"file": "model_02_corruption.pkl",                 "source": "lira",   "name": "DB Corruption"},
    3: {"file": "model_03_unauthorized.pkl",               "source": "lira",   "name": "DB Unauthorized"},
    4: {"file": "model_04_web_anomaly_v4_stage1.pkl",      "source": "access", "name": "Web Suspicious (binary v4)"},
    5: {"file": "model_05_web_error_v2.pkl",               "source": "error",  "name": "Web Error v2"},
    6: {"file": "model_06_windows_security.pkl",           "source": "evtx",   "name": "Windows Security"},
    7: {"file": "model_07_endpoint_threat.pkl",            "source": "evtx",   "name": "Endpoint Threat"},
}

MODEL_6_CHANNELS = frozenset({
    "application", "defender", "firewall", "grouppolicy", "rdp",
    "security", "smb_operational", "smb_security", "system",
    "taskscheduler", "uac", "winlogon", "winrm",
})
MODEL_7_CHANNELS = frozenset({
    "application", "codeintegrity", "defender", "grouppolicy",
    "powershell", "powershell_classic", "rdp", "security",
    "smb_operational", "system", "taskscheduler", "winlogon", "wmi",
})


def _flag_contains(df: pd.DataFrame, flag: str) -> "pd.Series":
    if "model_flags" not in df.columns:
        return pd.Series(False, index=df.index)
    return df["model_flags"].fillna("").astype(str).str.contains(
        flag, regex=False, na=False)


def _channel_in(df: pd.DataFrame, channels: frozenset) -> "pd.Series":
    """True for rows whose channel_key is in the given allowed set."""
    if "channel_key" not in df.columns:
        return pd.Series(False, index=df.index)
    return df["channel_key"].fillna("").astype(str).isin(channels)


MODEL_ELIGIBILITY = {
    1: lambda df: _flag_contains(df, "downtime_events"),
    2: lambda df: _flag_contains(df, "data_corruption"),
    3: lambda df: (_flag_contains(df, "unauthorized_access")
                   | _flag_contains(df, "suspicious_review")),
    4: lambda df: pd.Series(True, index=df.index),
    5: lambda df: pd.Series(True, index=df.index),
    6: lambda df: _channel_in(df, MODEL_6_CHANNELS),
    7: lambda df: _channel_in(df, MODEL_7_CHANNELS),
}



CES_COLUMNS = [
    "ces_hour", "ces_day_of_week", "ces_is_weekend", "ces_is_after_hours",
    "ces_severity_norm", "ces_confidence_norm", "ces_auth_fail_flag",
    "ces_suspicious_flag", "ces_req_rate_norm",
    "ces_source_lira", "ces_source_access", "ces_source_error", "ces_source_evtx",
]


MODEL_B_FEATURES = CES_COLUMNS + ["anomaly_score"]

DAY_OF_WEEK_MAP = {
    "Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3,
    "Friday": 4, "Saturday": 5, "Sunday": 6,
}
MONTH_MAP = {
    "January": 1, "February": 2, "March": 3,  "April": 4,
    "May": 5,     "June": 6,     "July": 7,   "August": 8,
    "September": 9, "October": 10, "November": 11, "December": 12,
}
SEVERITY_ORDINAL = {"NORMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


SOURCE_SCHEMAS = {
    "lira": {
        "required": [
            "hour", "day_of_week", "is_after_hours",
            "severity_score", "confidence",
            "is_access_denied", "is_aborted_connection",
            "is_dns_failure", "is_crash_recovery",
            "severity", "timestamp",
        ],
        "recommended": [
            "model_flags", "fingerprint",
            "rule_id", "message_preview",
            "host_status", "user_status", "startup_context",
            "is_aria_recovery", "is_service_startup", "is_clean_shutdown",
            "month", "year",
        ],
    },
    "evtx": {
        "required": [
            "hour_of_day", "day_of_week", "is_weekend",
            "is_working_hours", "severity_weight",
            "channel_key", "timestamp",
        ],
        "recommended": [
            "event_id", "severity", "source_file",
        ],
    },
    "access": {
        "required": [
            "hour", "day_of_week", "is_weekend", "is_business_hours",
            "anomaly_score", "status_code", "timestamp",
        ],
        "recommended": [
            "ip", "method", "uri",
            "req_per_ip_last_60s", "credentials_in_url", "suspicious_path",
        ],
    },
    "error": {
        "required": [
            "hour", "day_of_week", "is_off_hours",
            "severity_score", "timestamp",
        ],
        "recommended": [
            "severity", "is_basoft", "is_external_host",
            "message_preview",
        ],
    },
}


def validate_source_schema(df: pd.DataFrame, source: str) -> dict:
    """

    
        {
          "source":               <str>,
          "n_rows":               <int>,
          "n_cols":               <int>,
          "missing_required":     [<str>, ...],   # may force wrong scores
          "missing_recommended":  [<str>, ...],   # quality degradation
          "unknown_source":       bool,           # source not in schema map
          "ok":                   bool,           # True iff no required miss
        }

   
    """
    schema = SOURCE_SCHEMAS.get(source)
    cols   = set(df.columns)
    if schema is None:
        return {
            "source": source, "n_rows": len(df), "n_cols": len(cols),
            "missing_required": [], "missing_recommended": [],
            "unknown_source": True, "ok": False,
        }
    missing_req = [c for c in schema["required"]    if c not in cols]
    missing_rec = [c for c in schema["recommended"] if c not in cols]
    return {
        "source": source, "n_rows": len(df), "n_cols": len(cols),
        "missing_required":    missing_req,
        "missing_recommended": missing_rec,
        "unknown_source":      False,
        "ok":                  len(missing_req) == 0,
    }



def detect_source(df: pd.DataFrame) -> str:
    
    cols = set(df.columns)
    if "is_crash_recovery" in cols and "startup_context" in cols:
        return "lira"
    if "uri_path" in cols and "anomaly_score" in cols:
        return "access"
    if "ah_code" in cols or ("module" in cols and "event_category" in cols):
        return "error"
    if "channel_key" in cols and "event_id" in cols:
        return "evtx"
    # Fallback: guess from column overlap
    scores = {
        "lira":   len(cols & {"severity_score","is_after_hours","startup_context","is_clean_shutdown"}),
        "access": len(cols & {"status_code","req_per_ip_last_60s","is_bot","credentials_in_url"}),
        "error":  len(cols & {"severity_label","is_off_hours","is_external_host","is_basoft"}),
        "evtx":   len(cols & {"severity_weight","hour_of_day","is_working_hours","logon_type"}),
    }
    return max(scores, key=scores.get)



def _norm(series: pd.Series) -> pd.Series:
    lo, hi = series.min(), series.max()
    if hi == lo:
        return pd.Series(np.zeros(len(series)), index=series.index)
    return (series - lo) / (hi - lo)


def _get(df: pd.DataFrame, col: str, default=0) -> pd.Series:
    if col in df.columns:
        return pd.to_numeric(df[col], errors="coerce").fillna(default)
    return pd.Series([default] * len(df), index=df.index, dtype=float)


def _encode_temporal(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "day_of_week" in df.columns:
        df["day_of_week"] = df["day_of_week"].map(DAY_OF_WEEK_MAP).fillna(
            pd.to_numeric(df["day_of_week"], errors="coerce")).fillna(0).astype(int)
    if "month" in df.columns:
        df["month"] = df["month"].map(MONTH_MAP).fillna(
            pd.to_numeric(df["month"], errors="coerce")).fillna(0).astype(int)
    return df


def extract_ces_features(df: pd.DataFrame, source: str) -> pd.DataFrame:
    
    ces = pd.DataFrame(index=df.index)

    if source == "lira":
        df = _encode_temporal(df)
        ces["ces_hour"]           = _get(df, "hour")
        ces["ces_day_of_week"]    = _get(df, "day_of_week")
        ces["ces_is_weekend"]     = ces["ces_day_of_week"].isin([5, 6]).astype(int)
        ces["ces_is_after_hours"] = _get(df, "is_after_hours").clip(0, 1).astype(int)
        ces["ces_severity_norm"]  = _norm(_get(df, "severity_score"))
        ces["ces_confidence_norm"]= _norm(_get(df, "confidence"))
        ces["ces_auth_fail_flag"] = ((_get(df,"is_access_denied") + _get(df,"is_aborted_connection")) > 0).astype(int)
        ces["ces_suspicious_flag"]= ((_get(df,"is_dns_failure") + _get(df,"is_crash_recovery")) > 0).astype(int)
        ces["ces_req_rate_norm"]  = 0.0
        ces["ces_source_lira"]    = 1; ces["ces_source_access"] = 0
        ces["ces_source_error"]   = 0; ces["ces_source_evtx"]   = 0

    elif source == "access":
        ces["ces_hour"]           = _get(df, "hour")
        ces["ces_day_of_week"]    = _get(df, "day_of_week")
        ces["ces_is_weekend"]     = _get(df, "is_weekend").clip(0,1).astype(int)
        biz = _get(df, "is_business_hours", default=1)
        ces["ces_is_after_hours"] = (1 - biz).clip(0,1).astype(int)
        ces["ces_severity_norm"]  = _norm(_get(df, "anomaly_score"))
        req = _get(df, "req_per_ip_last_60s")
        ces["ces_confidence_norm"]= _norm(req)
        ces["ces_auth_fail_flag"] = _get(df, "credentials_in_url").clip(0,1)
        ces["ces_suspicious_flag"]= _get(df, "suspicious_path").clip(0,1)
        ces["ces_req_rate_norm"]  = _norm(req)
        ces["ces_source_lira"]    = 0; ces["ces_source_access"] = 1
        ces["ces_source_error"]   = 0; ces["ces_source_evtx"]   = 0

    elif source == "error":
        ces["ces_hour"]           = _get(df, "hour")
        ces["ces_day_of_week"]    = _get(df, "day_of_week")
        ces["ces_is_weekend"]     = ces["ces_day_of_week"].isin([5, 6]).astype(int)
        ces["ces_is_after_hours"] = _get(df, "is_off_hours").clip(0,1).astype(int)
        ces["ces_severity_norm"]  = _norm(_get(df, "severity_score"))
        ces["ces_confidence_norm"]= 0.0
        ces["ces_auth_fail_flag"] = _get(df, "is_basoft").clip(0,1)
        ces["ces_suspicious_flag"]= _get(df, "is_external_host").clip(0,1)
        ces["ces_req_rate_norm"]  = 0.0
        ces["ces_source_lira"]    = 0; ces["ces_source_access"] = 0
        ces["ces_source_error"]   = 1; ces["ces_source_evtx"]   = 0

    elif source == "evtx":
        ces["ces_hour"]           = _get(df, "hour_of_day")
        ces["ces_day_of_week"]    = _get(df, "day_of_week")
        ces["ces_is_weekend"]     = _get(df, "is_weekend").clip(0,1).astype(int)
        working = _get(df, "is_working_hours", default=1)
        ces["ces_is_after_hours"] = (1 - working).clip(0,1).astype(int)
        ces["ces_severity_norm"]  = _norm(_get(df, "severity_weight"))
        ces["ces_confidence_norm"]= 0.0
        ces["ces_auth_fail_flag"] = 0.0
        ces["ces_suspicious_flag"]= 0.0
        ces["ces_req_rate_norm"]  = 0.0
        ces["ces_source_lira"]    = 0; ces["ces_source_access"] = 0
        ces["ces_source_error"]   = 0; ces["ces_source_evtx"]   = 1

    else:
        raise ValueError(f"Unknown source type: {source}")

    return ces[CES_COLUMNS].fillna(0).apply(pd.to_numeric, errors="coerce").fillna(0)



LIRA_SUPERVISED_FEATURES = [
    "hour", "day_of_week", "month", "year", "severity_score", "confidence",
    "is_crash_recovery", "is_aria_recovery", "is_service_startup",
    "is_clean_shutdown", "is_after_hours",
    "is_aborted_connection", "is_access_denied", "is_dns_failure",
    "severity", "host_status", "user_status", "startup_context",
]


ACCESS_SUPERVISED_FEATURES = [
    "hour", "day_of_week", "month", "year",
    "status_code", "response_bytes", "uri_depth", "uri_length",
    "query_param_count", "inter_request_seconds",
    "req_per_ip_last_60s", "req_per_ip_last_5min", "ua_length",
    "anomaly_score",
    "is_internal", "is_bot", "credentials_in_url", "suspicious_path",
    "is_weekend", "is_business_hours", "is_redirect", "is_error",
    "is_server_error", "has_referer", "is_duplicate", "basoft_date_mismatch",
    "method", "ip_type", "resource_type", "app_section",
    "status_category", "browser_family", "os_family",
]
ACCESS_CATEGORICAL_ENCODERS = {
    "method":          ["-", "GET", "OPTIONS", "POST", "PROPFIND"],
    "ip_type":         ["link_local", "loopback", "private"],
    "resource_type":   ["page", "php_page", "static_css", "static_doc",
                        "static_image", "static_js"],
    "app_section":     ["BASoft", "dashboard", "other", "phpMyAdmin", "root"],
    "status_category": ["2xx", "3xx", "4xx"],
    "browser_family":  ["Chrome", "Edge", "IE", "other", "unknown"],
    "os_family":       ["Windows", "other", "unknown"],
}


def _canonical_event_hash(row, source_kind: str) -> str:
   
    import hashlib

    def _g(field: str) -> str:
        try:
            v = row.get(field, "")
        except AttributeError:
            v = ""
        if v is None:
            return ""
        return str(v)

    
    fp = _g("fingerprint")
    if fp:
        return hashlib.sha1(fp.encode("utf-8")).hexdigest()[:16]

    if source_kind == "lira":
        parts = [_g("timestamp"), _g("rule_id"), _g("message_preview")]
    elif source_kind == "evtx":
        parts = [_g("source_file"), _g("channel_key"),
                 _g("event_id"), _g("timestamp")]
    elif source_kind == "access":
        parts = [_g("timestamp"), _g("ip"), _g("method"),
                 _g("uri"), _g("status_code")]
    elif source_kind == "error":
        parts = [_g("timestamp_iso") or _g("timestamp_raw") or _g("timestamp"),
                 _g("severity_label") or _g("severity"),
                 _g("message_raw") or _g("message_preview")
                 or _g("php_message_short"),
                 _g("line_number")]
    else:
        parts = [repr(row)]

    blob = "|".join(parts)
    if not blob.strip("|"):
        return ""
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def _load_model_metadata(mid: int) -> Optional[dict]:
 
    import json
    if not DATASETS_DIR.exists():
        return None
    try:
        candidates = sorted(DATASETS_DIR.glob(f"model_0{mid}_*/metadata.json"))
    except Exception:
        return None
    if not candidates:
        return None
    try:
        with open(candidates[0], "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _extract_features_for_model(df: pd.DataFrame, metadata: dict) -> np.ndarray:
   
    feature_names: list = list(metadata.get("feature_names") or [])
    cat_encoders:  dict = dict(metadata.get("categorical_encoders") or {})
    if not feature_names:
        
        return np.zeros((len(df), 0), dtype=float)

    work = df.copy()
    work = _encode_temporal(work)

    
    cat_maps = {col: {v: i for i, v in enumerate(cats)}
                for col, cats in cat_encoders.items()}

    out_cols: list = []
    for col in feature_names:
        if col in cat_maps:
            mapping = cat_maps[col]
            if col in work.columns:
                series = (work[col].fillna("").astype(str)
                          .map(mapping).fillna(-1))
            else:
                series = pd.Series([-1] * len(work), index=work.index)
        else:
            if col in work.columns:
                series = pd.to_numeric(work[col], errors="coerce").fillna(0)
            else:
                series = pd.Series([0] * len(work), index=work.index)
        out_cols.append(series.astype(float).values)

    if not out_cols:
        return np.zeros((len(work), 0), dtype=float)
    return np.column_stack(out_cols)


def extract_supervised_features(df: pd.DataFrame, source: str,
                                 model_id: int) -> np.ndarray:
    
    from sklearn.preprocessing import LabelEncoder

    df = df.copy()

    if source == "lira":
        df = _encode_temporal(df)
       
        if "severity" in df.columns:
            df["severity"] = df["severity"].map(SEVERITY_ORDINAL).fillna(0).astype(int)
        
        for col in ["host_status", "user_status", "startup_context"]:
            if col in df.columns:
                df[col] = LabelEncoder().fit_transform(df[col].astype(str))
        
        for col in ["is_crash_recovery","is_aria_recovery","is_service_startup",
                    "is_clean_shutdown","is_after_hours","is_aborted_connection",
                    "is_access_denied","is_dns_failure"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
        available = [f for f in LIRA_SUPERVISED_FEATURES if f in df.columns]
        X = df[available].apply(pd.to_numeric, errors="coerce").fillna(0)
        return X.values.astype(float)

    if source == "access":
        
        for col, cats in ACCESS_CATEGORICAL_ENCODERS.items():
            mapping = {v: i for i, v in enumerate(cats)}
            if col in df.columns:
                df[col] = df[col].fillna("unknown").astype(str).map(mapping).fillna(-1)
            else:
                df[col] = 0
        
        for f in ACCESS_SUPERVISED_FEATURES:
            if f not in df.columns:
                df[f] = 0
        X = df[ACCESS_SUPERVISED_FEATURES].apply(
            pd.to_numeric, errors="coerce").fillna(0)
        return X.values.astype(float)

    
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    return df[numeric_cols].fillna(0).values.astype(float)



def compute_its(severity_norm: float, anomaly_score: float,
                after_hours: float, cross_hits: float = 0.0) -> float:
    
    its = (severity_norm * ITS_W_SEVERITY
           + anomaly_score * ITS_W_ANOMALY
           + cross_hits    * ITS_W_CORRELATION
           + after_hours   * ITS_W_AFTER_HOURS)
    return float(np.clip(its, 0.0, 1.0))


def classify_its(its: float) -> tuple:
    ""
    for threshold, label, action in ITS_THRESHOLDS:
        if its >= threshold:
            return label, action
    return "LOW", "Log only"



class EIRPInferenceEngine:
 
    def __init__(self,
                 persist_incidents:        bool = True,
                 db_path:                  Optional[Path] = None,
                 dispatch_notifications:   bool = True,
                 auto_complete_automated_steps: bool = True,
                 max_incidents_per_run:    int  = 500,
                 recovery_modules_enabled: bool = True,
                 bcp_critical_only:        bool = True):
        
        self.iso_forest       = None
        self.model_b          = None
        self.model_b_encoder  = None
        self.response_engine  = None   
        self.supervised       = {}   

        
        self.incident_classifier      = None
        self.playbook_engine          = None
        self.case_store               = None
        self.notifier                 = None
        self.persist_incidents        = persist_incidents
        self.dispatch_notifications   = dispatch_notifications
        self.auto_complete_steps      = auto_complete_automated_steps
        self.max_incidents            = max_incidents_per_run
        self.db_path                  = Path(db_path) if db_path else (BASE_DIR / "eirp_cases.db")

        
        self.containment_advisor      = None
        self.recovery_checklist       = None
        self.bcp_monitor              = None
        self.recovery_modules_enabled = recovery_modules_enabled
        self.bcp_critical_only        = bcp_critical_only

        
        self.threat_scorer       = None
        self.correlation_engine  = None
        self.attack_mapper       = None
        self.last_phase2 = {
            "cor_total_fires":   0,
            "cor_events_w_fire": 0,
            "cor_per_rule":      {},
            "attack_coverage":   {},
            "its_summary":       {},
        }

       
        self.last_validation: dict = {}

        # Per-run lifecycle tracker (reset on each score() call)
        self.last_lifecycle = {
            "incidents_created":            [],
            "incidents_merged":             [],
            "playbooks_started":            [],
            "steps_auto_completed":         0,
            "notifications_sent":           0,
            "skipped_beyond_cap":           0,
            "containment_advisories_issued":0,
            "recovery_checklists_attached": 0,
            "bcp_activations":              [],
        }

        self._load_models()
        self._load_phase2_modules()
        self._load_lifecycle_stack()

    def _load_models(self):
        iso_path = MODELS_DIR / "isolation_forest.pkl"
        if iso_path.exists():
            self.iso_forest = joblib.load(iso_path)
            print(f"  [OK]  Isolation Forest (Model A) loaded  ({iso_path.name})")
        else:
            print(f"  [WARN] Isolation Forest not found at {iso_path}")
            print(f"         Run: python ml_dataset_builder.py --model A")

        b_path  = MODELS_DIR / MODEL_B_FILE
        be_path = MODELS_DIR / MODEL_B_ENCODER_FILE
        if b_path.exists() and be_path.exists():
            self.model_b         = joblib.load(b_path)
            self.model_b_encoder = joblib.load(be_path)
            classes = list(self.model_b_encoder.classes_)
            print(f"  [OK]  Tier 2 Model B (unified meta) loaded  ({b_path.name})")
            print(f"        Classes: {classes}")
        else:
            print(f"  [--]  Tier 2 Model B not found at {b_path}")
            print(f"        Run: python ml_train_model_b.py + ml_retrain_model_b_v2.py")

        
        if _MODEL_C_AVAILABLE and MODEL_C_POLICY_PATH and Path(MODEL_C_POLICY_PATH).exists():
            try:
                self.response_engine = ResponseEngine()
                v = self.response_engine.policy["policy_metadata"].get("version", "?")
                n_actions = len(self.response_engine.action_meta)
                print(f"  [OK]  Tier 3 Response Engine (Model C) loaded  "
                      f"(policy v{v}, {n_actions} actions, "
                      f"{len(self.response_engine.matrix)}-class matrix)")
            except Exception as exc:
                print(f"  [WARN] Tier 3 Response Engine policy load failed: {exc}")
        else:
            print(f"  [--]  Tier 3 Response Engine policy not found")
            print(f"        Expected: models/model_C_response_policy.json")

        for mid, info in SUPERVISED_MODELS.items():
            model_path   = MODELS_DIR / info["file"]
            encoder_path = MODELS_DIR / info["file"].replace(".pkl", "_encoder.pkl")
            if model_path.exists():
                m = {"model": joblib.load(model_path), "info": info}
                if encoder_path.exists():
                    m["encoder"] = joblib.load(encoder_path)
                
                meta = _load_model_metadata(mid)
                if meta is not None:
                    m["metadata"] = meta
                    n_feat = len(meta.get("feature_names", []))
                    n_cat  = len(meta.get("categorical_encoders", {}))
                    print(f"  [OK]  Model {mid} ({info['name']}) loaded  "
                          f"[metadata: {n_feat} features, "
                          f"{n_cat} categorical encoders]")
                else:
                    print(f"  [OK]  Model {mid} ({info['name']}) loaded  "
                          f"[no metadata.json -- legacy extraction]")
                self.supervised[mid] = m
            else:
                print(f"  [--]  Model {mid} ({info['name']}) — "
                      f"not yet trained (run ml_train_{info['name'].lower().replace(' ','_')}.py)")

    def _load_phase2_modules(self) -> None:
       
        if not _PHASE2_AVAILABLE:
            print(f"  [--]  Phase 2 enrichment stack unavailable "
                  f"(ml_threat_scorer/correlation/attack_mapper import failed)")
            return
        try:
            self.threat_scorer      = ThreatScorer()
            self.correlation_engine = CorrelationEngine()
            self.attack_mapper      = AttackMapper()
            print(f"  [OK]  Phase 2 enrichment ready "
                  f"(ThreatScorer + 10-rule CorrelationEngine + AttackMapper)")
        except Exception as exc:
            print(f"  [WARN] Phase 2 enrichment load failed: {exc}")
            self.threat_scorer = None
            self.correlation_engine = None
            self.attack_mapper = None

    def _prepare_phase2_input(self, df: pd.DataFrame,
                              source: str) -> pd.DataFrame:
      
        out = df.copy()

       
        if "timestamp" not in out.columns:
            for src_col in ("timestamp_iso", "event_time", "datetime",
                            "@timestamp", "time", "timestamp_epoch"):
                if src_col in out.columns:
                    if src_col == "timestamp_epoch":
                        out["timestamp"] = pd.to_datetime(
                            pd.to_numeric(out[src_col], errors="coerce"),
                            unit="s", errors="coerce")
                    else:
                        out["timestamp"] = pd.to_datetime(
                            out[src_col], errors="coerce")
                    break
            else:
                out["timestamp"] = pd.NaT

       
        out["source_type"] = source

      
        if "subcategory" not in out.columns:
            for src_col in ("event_subcategory", "incident_subcategory",
                            "sublabel", "category_name", "event_category",
                            "anomaly_flags", "rule_label", "category"):
                if src_col in out.columns:
                    out["subcategory"] = out[src_col].fillna("").astype(str)
                    break
            else:
                out["subcategory"] = ""

        
        if "rule_id" not in out.columns:
            for src_col in ("ruleid", "rule_code", "event_id"):
                if src_col in out.columns:
                    out["rule_id"] = out[src_col].astype(str)
                    break

        return out

    def _load_lifecycle_stack(self) -> None:
       
        if not _LIFECYCLE_AVAILABLE:
            print(f"  [--]  Incident lifecycle stack unavailable "
                  f"(response/ package import failed)")
            return

        # Stage 1: classifier (cheap, always loaded)
        try:
            self.incident_classifier = IncidentClassifier()
            print(f"  [OK]  Incident classifier loaded "
                  f"(6 INC types, priority cascade)")
        except Exception as exc:
            print(f"  [WARN] Incident classifier failed: {exc}")

        # Stage 2: playbook engine (loads PB-01..06 JSONs from playbooks/)
        try:
            self.playbook_engine = PlaybookEngine()
            n_pb = len(self.playbook_engine.playbooks)
            total_steps = sum(pb.n_steps() for pb in self.playbook_engine.playbooks.values())
            print(f"  [OK]  Playbook engine loaded ({n_pb} playbooks, "
                  f"{total_steps} total steps)")
        except Exception as exc:
            print(f"  [WARN] Playbook engine failed: {exc}")

        # Stage 3: case store (SQLite persistence)
        if self.persist_incidents:
            try:
                self.case_store = CaseStore(self.db_path)
                self.case_store.init_schema()
                n_existing = self.case_store.summarise()["n_incidents"]
                print(f"  [OK]  Case store opened: {self.db_path.name} "
                      f"({n_existing} historical incidents)")
            except Exception as exc:
                print(f"  [WARN] Case store init failed: {exc}")
                self.case_store = None
        else:
            print(f"  [--]  Case store disabled (--no-persist)")

        # Stage 4: notifier (severity-routed email + SMS; stub mode by default)
        if self.dispatch_notifications and self.case_store is not None:
            try:
                self.notifier = Notifier(case_store=self.case_store)
                email_mode = "SMTP" if self.notifier.smtp_host else "STUB"
                sms_mode   = "TERMII" if self.notifier.termii_key else "STUB"
                print(f"  [OK]  Notifier ready (email={email_mode}, sms={sms_mode})")
            except Exception as exc:
                print(f"  [WARN] Notifier failed: {exc}")
        elif not self.dispatch_notifications:
            print(f"  [--]  Notifier disabled (--no-notify)")

        # Stage 5: Tier-4 recovery + continuity (advisor + checklist + BCP)
        if not self.recovery_modules_enabled:
            print(f"  [--]  Tier-4 recovery modules disabled (--no-recovery)")
        elif not _RECOVERY_AVAILABLE:
            print(f"  [--]  Tier-4 recovery modules unavailable "
                  f"(recovery/ package import failed)")
        else:
            try:
                self.containment_advisor = ContainmentAdvisor()
                self.recovery_checklist  = RecoveryChecklist()
                print(f"  [OK]  Containment advisor + recovery checklist loaded "
                      f"(6 INC types each)")
            except Exception as exc:
                print(f"  [WARN] Tier-4 advisor/checklist failed: {exc}")

            try:
                self.bcp_monitor = BCPMonitor()
                trigger = ("CRITICAL severity only for "
                           f"{sorted(BCP_ACTIVATION_INC_TYPES)}"
                           if self.bcp_critical_only
                           else f"any severity for {sorted(BCP_ACTIVATION_INC_TYPES)}")
                print(f"  [OK]  BCP monitor ready (auto-activates on {trigger}; "
                      f"output -> bcp_output/)")
            except Exception as exc:
                print(f"  [WARN] BCP monitor failed: {exc}")

    def generate_reports(self,
                         report_dir: Optional[Path] = None,
                         incident_ids: Optional[List[str]] = None,
                         include_pdf:   bool = True,
                         include_excel: bool = True,
                         include_audit: bool = True) -> Optional[Dict[str, Any]]:
      
        if not _REPORTING_AVAILABLE:
            print("  [WARN] Tier-5 reporting modules not available "
                  "(reporting/ package import failed)")
            return None
        if self.case_store is None:
            print("  [WARN] Tier-5 reporting needs a case_store; "
                  "re-run without --no-persist.")
            return None

        if incident_ids is None:
           
            _touched = (self.last_lifecycle.get("incidents_created", [])
                        + self.last_lifecycle.get("incidents_merged", []))
            incident_ids = [iid for iid in dict.fromkeys(_touched)
                            if iid and not iid.startswith("error:")]
        if not incident_ids:
            incident_ids = [i.incident_id
                            for i in self.case_store.list_incidents(limit=10_000)]

        if not incident_ids:
            print("  [--]  No incidents in case_store to report on.")
            return None

        am = AuditManager(self.case_store)
        nm = NdprMapper(self.case_store)
        rg = ReportGenerator(
            self.case_store,
            audit_manager=am,
            ndpr_mapper=nm,
            output_dir=Path(report_dir) if report_dir else None,
        )
        result = rg.generate_all(
            incident_ids=incident_ids,
            include_pdf=include_pdf,
            include_text=True,
            include_excel=include_excel,
            include_audit=include_audit,
        )
        return result

    def _run_incident_lifecycle(self, df_scored: pd.DataFrame) -> pd.DataFrame:
       
       
        self.last_lifecycle = {
            "incidents_created":             [],
            "incidents_merged":              [],
            "playbooks_started":             [],
            "steps_auto_completed":          0,
            "notifications_sent":            0,
            "skipped_beyond_cap":            0,
            "containment_advisories_issued": 0,
            "recovery_checklists_attached":  0,
            "bcp_activations":               [],
        }

        if self.incident_classifier is None:
            df_scored["incident_type"]     = ""
            df_scored["incident_name"]     = ""
            df_scored["playbook_id"]       = ""
            df_scored["incident_rationale"]= ""
            df_scored["incident_id"]          = ""
            df_scored["playbook_execution_id"]= ""
            return df_scored

      
        df_scored = self.incident_classifier.classify_batch(df_scored)

        incident_ids       = [""] * len(df_scored)
        playbook_exec_ids  = [""] * len(df_scored)
        classified_mask    = df_scored["incident_type"].astype(str) != ""
        n_classified       = int(classified_mask.sum())

       
        if (n_classified == 0
                or self.case_store is None
                or self.playbook_engine is None):
            df_scored["incident_id"]           = incident_ids
            df_scored["playbook_execution_id"] = playbook_exec_ids
            return df_scored

        persisted = 0
      
        _cap_msg = "unlimited" if self.max_incidents <= 0 \
                                  else f"{self.max_incidents}"
        print(f"[engine.score] persist gate: cap={_cap_msg} "
              f"classified={int(classified_mask.sum())} "
              f"source={getattr(self, '_current_source_kind', '?')}",
              flush=True)
        
        for orig_idx, row in df_scored[classified_mask].iterrows():
            row_pos = df_scored.index.get_loc(orig_idx)

            
            if self.max_incidents > 0 and persisted >= self.max_incidents:
                self.last_lifecycle["skipped_beyond_cap"] += 1
                continue

            inc_type    = str(row["incident_type"])
            inc_name    = str(row.get("incident_name", ""))
            playbook_id = str(row["playbook_id"])
            its_score   = float(row.get("its_score", 0.0) or 0.0)
            severity    = str(row.get("its_severity", "LOW"))
            rationale   = str(row.get("incident_rationale", ""))
            att_tactic  = str(row.get("attack_tactic", "") or "")
            att_tech    = str(row.get("attack_technique", "") or "")
            mb_label    = str(row.get("model_b_label", "") or "")

          
            event_hash = _canonical_event_hash(
                row, getattr(self, "_current_source_kind", ""))
            try:
                model_id = int(row.get("supervised_model_id", 0) or 0)
            except (TypeError, ValueError):
                model_id = 0

            
            host_val = ""
            for _host_col in ("host", "computer_name", "computer",
                              "hostname", "client_ip", "src_host",
                              "source_host"):
                v = row.get(_host_col, "")
                if v and str(v).strip() and str(v).strip().lower() not in (
                        "no_host", "nan", "none", "-"):
                    host_val = str(v).strip()
                    break

            # Stage 2 -- persist incident
            try:
                inc_id, _persist_status = self.case_store.create_incident(
                    return_status       = True,
                    incident_type       = inc_type,
                    its_score           = its_score,
                    severity            = severity,
                    attack_tactic       = att_tactic,
                    attack_technique    = att_tech,
                    playbook_id         = playbook_id,
                    summary             = f"{inc_name} | model_b={mb_label} | {rationale}",
                    source_kind         = getattr(self, "_current_source_kind", ""),
                    source_name         = getattr(self, "_current_source_name", ""),
                    source_path         = getattr(self, "_current_source_path", ""),
                    source_csv_path     = getattr(self, "_current_source_csv_path", ""),
                    source_row_index    = int(row_pos),
                    source_event_hash   = event_hash,
                    supervised_model_id = model_id,
                    source_host         = host_val,
                    detection_driver    = str(row.get("detection_driver", "") or ""),
                    verdict_agreement   = str(row.get("verdict_agreement", "") or ""),
                    ai_incident_type    = str(row.get("ai_incident_type", "") or ""),
                    ai_label            = str(row.get("ai_label", "") or ""),
                    ai_confidence       = float(row.get("ai_confidence", 0.0) or 0.0),
                    ai_model_id         = int(row.get("ai_model_id", 0) or 0),
                    ai_severity         = str(row.get("ai_severity", "") or ""),
                    rule_incident_type  = str(row.get("rule_incident_type", "") or ""),
                    rule_label          = str(row.get("rule_label", "") or ""),
                    rule_severity       = str(row.get("rule_severity", "") or ""),
                    rule_id             = str(row.get("rule_id", "") or ""),
                )
                incident_ids[row_pos] = inc_id
               
                if _persist_status == "merged":
                    self.last_lifecycle["incidents_merged"].append(inc_id)
                else:
                    self.last_lifecycle["incidents_created"].append(inc_id)
                persisted += 1
            except Exception as exc:
                incident_ids[row_pos] = f"error:{exc}"
                continue

           
            if _persist_status == "merged":
                continue

            # Stage 3 -- start playbook execution + auto-complete automated steps
            try:
                execution = self.playbook_engine.start(playbook_id, inc_id)
                playbook_exec_ids[row_pos] = execution.execution_id
                self.last_lifecycle["playbooks_started"].append(execution.execution_id)

                if self.auto_complete_steps:
                    pb = self.playbook_engine.get_playbook(playbook_id)
                    for step in pb.steps:
                        if step.automated:
                            self.playbook_engine.complete_step(
                                execution, step.step_id,
                                outcome="COMPLETED",
                                executed_by="ml_inference_auto",
                                notes="auto-completed (automated=true)")
                            self.case_store.log_playbook_step(
                                incident_id  = inc_id,
                                step_id      = step.step_id,
                                executed_by  = "ml_inference_auto",
                                outcome      = "COMPLETED",
                                deadline_met = True,
                                notes        = "auto-completed (automated=true)")
                            self.last_lifecycle["steps_auto_completed"] += 1
            except Exception as exc:
                try:
                    self.case_store.log_audit(
                        inc_id, action="PLAYBOOK_START_FAILED",
                        performed_by="ml_inference",
                        change_summary=str(exc))
                except Exception:
                    pass

           
            if self.notifier is not None:
                try:
                    self.notifier.dispatch(
                        incident_id   = inc_id,
                        severity      = severity,
                        incident_type = inc_type,
                        subject       = f"[EIRP-EMR {severity}] {inc_name} {inc_id}",
                        body          = rationale or f"{inc_name} detected via {mb_label}",
                    )
                    self.last_lifecycle["notifications_sent"] += 1
                except Exception:
                    pass  # Notifier logs its own failures via case_store

           
            if self.containment_advisor is not None:
                try:
                    actions = self.containment_advisor.recommend(inc_type, severity)
                    top_actions = "|".join(a.action for a in actions[:5])
                    self.case_store.log_audit(
                        inc_id, action="CONTAINMENT_ADVISED",
                        performed_by="ml_inference",
                        change_summary=f"actions={top_actions} "
                                       f"rto_savings_h={sum(a.rto_impact_h for a in actions):.1f}")
                    self.last_lifecycle["containment_advisories_issued"] += 1
                except Exception:
                    pass

            if self.recovery_checklist is not None:
                try:
                    rto_h    = self.recovery_checklist.rto_target(inc_type)
                    steps    = self.recovery_checklist.checklist_for(inc_type)
                    text     = self.recovery_checklist.render_text(inc_type)
                    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
                    self.case_store.add_evidence(
                        inc_id, source_type="RECOVERY_CHECKLIST",
                        file_path=f"virtual:checklist:{inc_type}",
                        description=f"{len(steps)}-step checklist, RTO target {rto_h:.1f}h",
                        file_hash=text_hash)
                    self.last_lifecycle["recovery_checklists_attached"] += 1
                except Exception:
                    pass

            if (self.bcp_monitor is not None
                    and inc_type in BCP_ACTIVATION_INC_TYPES
                    and (not self.bcp_critical_only or severity.upper() == "CRITICAL")):
                try:
                    rto_h = (self.recovery_checklist.rto_target(inc_type)
                             if self.recovery_checklist else None)
                    activation = self.bcp_monitor.activate(
                        incident_id=inc_id,
                        incident_type=inc_type,
                        estimated_rto_h=rto_h)
                    self.last_lifecycle["bcp_activations"].append(activation.activation_id)
                    self.case_store.log_audit(
                        inc_id, action="BCP_ACTIVATED",
                        performed_by="ml_inference",
                        change_summary=f"activation_id={activation.activation_id} "
                                       f"wards={len(activation.wards_affected)} "
                                       f"protocol_files={len(activation.protocol_files)}")
                except Exception as exc:
                    self.case_store.log_audit(
                        inc_id, action="BCP_ACTIVATION_FAILED",
                        performed_by="ml_inference",
                        change_summary=str(exc))

        df_scored["incident_id"]           = incident_ids
        df_scored["playbook_execution_id"] = playbook_exec_ids
        return df_scored

    def _persist_evtx_episodes(self, source_path: str,
                                source_name: str) -> int:
       
        if self.case_store is None or not source_path:
            return 0

        sp = Path(source_path)
        
        ep_csv = (BASE_DIR / "LIRA_dispatch" / "windows_evtx"
                  / sp.stem / "episodes.csv")
        if not ep_csv.exists():
            return 0
        try:
            eps = pd.read_csv(ep_csv)
        except Exception as exc:
            print(f"  [WARN] episodes: failed to read {ep_csv.name}: {exc}",
                  flush=True)
            return 0
        if eps.empty:
            return 0

        # Lazy import to avoid a circular dep at module load time.
        try:
            from response.incident_classifier import INCIDENT_METADATA
        except Exception:
            return 0

        # Map episode_type -> (inc_id, its_proxy, derived severity)
        _EP_TO_INC = {
            "BRUTE_FORCE_EPISODE": ("INC-04", 0.85, "HIGH"),
            "SMB_ACCESS_STORM":    ("INC-04", 0.75, "HIGH"),
            "CREDENTIAL_STUFFING": ("INC-04", 0.90, "CRITICAL"),
        }

        import hashlib as _hashlib
        n_created = 0
        for _, ep in eps.iterrows():
            ep_type = str(ep.get("episode_type", "") or "").upper()
            mapping = _EP_TO_INC.get(ep_type)
            if mapping is None:
                continue
            inc_id, its_proxy, derived_sev = mapping
           
            canon = (f"{sp.name}|{ep.get('start_time','')}|"
                     f"{ep_type}|{ep.get('source','')}")
            ep_hash = _hashlib.sha1(canon.encode("utf-8")).hexdigest()[:16]
            try:
                if self.case_store.exists_by_event_hash(ep_hash):
                    continue
            except Exception:
                pass        # if dedup check fails, try to create anyway
            meta = INCIDENT_METADATA[inc_id]
            severity = str(ep.get("severity", "") or derived_sev).upper() or derived_sev
            summary = (f"{meta['name']} | {ep_type} from "
                       f"{ep.get('source','?')} @ {ep.get('start_time','')}: "
                       f"{ep.get('event_count','?')} events affecting "
                       f"{ep.get('affected_accounts','-')}")
         
            ep_host = str(ep.get("source", "") or "").strip()
            try:
                inc_id_created = self.case_store.create_incident(
                    incident_type     = inc_id,
                    its_score         = its_proxy,
                    severity          = severity,
                    playbook_id       = meta["playbook"],
                    summary           = summary,
                    source_kind       = "evtx",
                    source_name       = source_name,
                    source_path       = source_path,
                    source_row_index  = -1,        # episode is a span, not a row
                    source_event_hash = ep_hash,
                    supervised_model_id = 0,
                    source_host       = ep_host,
                )
                self.case_store.log_audit(
                    inc_id_created, action="EPISODE_INCIDENT_CREATED",
                    performed_by="evtx_episode_detector",
                    change_summary=(f"episode={ep_type} rule={ep.get('rule_id','')} "
                                    f"events={ep.get('event_count','?')} "
                                    f"source={ep.get('source','?')} "
                                    f"hash={ep_hash}"))
                self.last_lifecycle["incidents_created"].append(inc_id_created)
                n_created += 1
            except Exception as exc:
                print(f"  [WARN] episodes: failed to persist {ep_type}: {exc}",
                      flush=True)
                continue
        if n_created:
            print(f"  [OK]  episodes: persisted {n_created} new incident(s) "
                  f"from {ep_csv.name}", flush=True)
        return n_created

    def score(self, df: pd.DataFrame, source: str,
              source_name: str = "", source_path: str = "",
              source_csv_path: str = "") -> pd.DataFrame:
       
        # Stash for use inside the incident-persistence loop further down.
        self._current_source_kind = source
        self._current_source_name = source_name
        self._current_source_path = source_path
        self._current_source_csv_path = source_csv_path

      
        self.last_validation = validate_source_schema(df, source)
        v = self.last_validation
        if v.get("unknown_source"):
            print(f"  [WARN] schema: unknown source '{source}' -- no "
                  f"validation contract; scoring proceeds blind", flush=True)
        else:
            if v["missing_required"]:
                print(f"  [WARN] schema/{source}: parser output missing "
                      f"{len(v['missing_required'])} REQUIRED column(s) -- "
                      f"scores will be biased toward 0 for these features: "
                      f"{', '.join(v['missing_required'])}", flush=True)
            if v["missing_recommended"]:
                print(f"  [INFO] schema/{source}: missing "
                      f"{len(v['missing_recommended'])} recommended column(s) "
                      f"-- traceability / routing degraded: "
                      f"{', '.join(v['missing_recommended'])}", flush=True)

        results = df.copy()

        # ── Isolation Forest scoring 
        ces = extract_ces_features(df, source)
        X   = ces.values.astype(float)

        if self.iso_forest is not None:
            raw_scores   = self.iso_forest.decision_function(X)
            predictions  = self.iso_forest.predict(X)
            anomaly_score= 1.0 - np.clip((raw_scores + 0.5) / 0.5, 0.0, 1.0)
            results["anomaly_score"] = anomaly_score
            results["is_anomaly"]    = (predictions == -1).astype(int)
        else:
            results["anomaly_score"] = 0.0
            results["is_anomaly"]    = 0

        # ── Phase 2: Correlation + ATT&CK enrichment ──────────────────────────
        
        if self.correlation_engine is not None and self.attack_mapper is not None:
            try:
                phase2_df = self._prepare_phase2_input(df, source)
                phase2_df = self.correlation_engine.evaluate(phase2_df)
                phase2_df = self.attack_mapper.map(phase2_df)
                
                for col in ("cor_rules_fired", "cor_fire_count",
                            "attack_tactic", "attack_technique",
                            "attack_label", "attack_all"):
                    if col in phase2_df.columns:
                        results[col] = phase2_df[col].reindex(results.index).fillna(
                            "" if phase2_df[col].dtype == object else 0).values
               
                self.last_phase2["cor_total_fires"]   = int(
                    results["cor_fire_count"].sum())
                self.last_phase2["cor_events_w_fire"] = int(
                    (results["cor_fire_count"] > 0).sum())
                from collections import Counter as _Counter
                _per = _Counter()
                for row in results["cor_rules_fired"]:
                    if isinstance(row, (list, tuple)):
                        _per.update(row)
                self.last_phase2["cor_per_rule"] = dict(_per.most_common())
                self.last_phase2["attack_coverage"] = self.attack_mapper.coverage(results)
            except Exception as exc:
                results["cor_rules_fired"]  = [[] for _ in range(len(results))]
                results["cor_fire_count"]   = 0
                results["attack_tactic"]    = ""
                results["attack_technique"] = ""
                results["attack_label"]     = ""
                results["attack_all"]       = ""
                self.last_phase2["error"] = str(exc)
        else:
            results["cor_rules_fired"]  = [[] for _ in range(len(results))]
            results["cor_fire_count"]   = 0
            results["attack_tactic"]    = ""
            results["attack_technique"] = ""
            results["attack_label"]     = ""
            results["attack_all"]       = ""

       
        if self.model_b is not None:
            X_b = np.column_stack([X, results["anomaly_score"].values])
            try:
                preds_enc = self.model_b.predict(X_b)
                results["model_b_label"] = self.model_b_encoder.inverse_transform(preds_enc)
                if hasattr(self.model_b, "predict_proba"):
                    proba = self.model_b.predict_proba(X_b)
                    results["model_b_confidence"] = proba.max(axis=1)
                    
                    for idx, cls in enumerate(self.model_b_encoder.classes_):
                        results[f"model_b_p_{cls}"] = proba[:, idx]
            except Exception as exc:
                results["model_b_label"]      = f"error: {exc}"
                results["model_b_confidence"] = 0.0
        else:
            results["model_b_label"]      = "not_loaded"
            results["model_b_confidence"] = 0.0

   
        if self.threat_scorer is not None:
            ts_in = results.copy()
          
            if ("severity_score" not in ts_in.columns and
                    "severity_norm" not in ts_in.columns):
                if "severity_weight" in ts_in.columns:
                    ts_in["severity_norm"] = (
                        pd.to_numeric(ts_in["severity_weight"], errors="coerce")
                        .fillna(0).clip(0, 1))
                else:
                    ts_in["severity_norm"] = ts_in["anomaly_score"]
            
            if "is_after_hours" not in ts_in.columns:
                if "is_off_hours" in ts_in.columns:
                    ts_in["is_after_hours"] = pd.to_numeric(
                        ts_in["is_off_hours"], errors="coerce").fillna(0)
                elif "is_business_hours" in ts_in.columns:
                    ts_in["is_after_hours"] = 1 - pd.to_numeric(
                        ts_in["is_business_hours"], errors="coerce").fillna(1)
                elif "is_working_hours" in ts_in.columns:
                    ts_in["is_after_hours"] = 1 - pd.to_numeric(
                        ts_in["is_working_hours"], errors="coerce").fillna(1)
                else:
                    ts_in["is_after_hours"] = 0
            try:
                scored = self.threat_scorer.score(ts_in)
                for c in ("its_score", "its_severity", "its_action"):
                    results[c] = scored[c].values
                self.last_phase2["its_summary"] = ThreatScorer.summarise(scored)
            except Exception as exc:
                self.last_phase2["threat_scorer_error"] = str(exc)
               
                self.threat_scorer = None

        if self.threat_scorer is None:
           
            if "severity_score" in df.columns:
                sev_raw  = pd.to_numeric(df["severity_score"], errors="coerce").fillna(0)
                sev_norm = (sev_raw / sev_raw.max()).clip(0, 1) if sev_raw.max() > 0 else sev_raw
            elif "severity_weight" in df.columns:
                sev_raw  = pd.to_numeric(df["severity_weight"], errors="coerce").fillna(0)
                sev_norm = (sev_raw / sev_raw.max()).clip(0, 1) if sev_raw.max() > 0 else sev_raw
            elif "anomaly_score" in df.columns:
                sev_norm = pd.to_numeric(df["anomaly_score"], errors="coerce").fillna(0)
                sev_norm = (sev_norm / sev_norm.max()).clip(0, 1) if sev_norm.max() > 0 else sev_norm
            else:
                sev_norm = pd.Series(np.zeros(len(df)), index=df.index)
            if "is_after_hours" in df.columns:
                after_hrs = pd.to_numeric(df["is_after_hours"], errors="coerce").fillna(0)
            elif "is_off_hours" in df.columns:
                after_hrs = pd.to_numeric(df["is_off_hours"], errors="coerce").fillna(0)
            elif "is_working_hours" in df.columns:
                after_hrs = 1 - pd.to_numeric(df["is_working_hours"], errors="coerce").fillna(1)
            elif "is_business_hours" in df.columns:
                after_hrs = 1 - pd.to_numeric(df["is_business_hours"], errors="coerce").fillna(1)
            else:
                after_hrs = pd.Series(np.zeros(len(df)), index=df.index)
            cor_hits_norm = (pd.to_numeric(results.get("cor_fire_count", 0),
                              errors="coerce").fillna(0).clip(lower=0) / 5.0
                             ).clip(upper=1.0)
            its_scores    = [compute_its(sv, an, ah, ch)
                             for sv, an, ah, ch in zip(
                                 sev_norm, results["anomaly_score"], after_hrs, cor_hits_norm)]
            its_labels    = [classify_its(s) for s in its_scores]
            results["its_score"]    = its_scores
            results["its_severity"] = [l[0] for l in its_labels]
            results["its_action"]   = [l[1] for l in its_labels]

      
        if self.response_engine is not None and self.model_b is not None:
            # Attach CES temporal columns required by ResponseEngine.decide_batch
            results["ces_hour"]          = ces["ces_hour"].values
            results["ces_day_of_week"]   = ces["ces_day_of_week"].values
            results["ces_is_after_hours"]= ces["ces_is_after_hours"].values
            try:
                results = self.response_engine.decide_batch(results)
            except Exception as exc:
                results["response_actions"] = ""
                results["response_confirm_required"] = False
                results["response_downgraded"] = False
                results["response_rationale"] = f"engine error: {exc}"

     
        per_model_runs: list = []     # [(mid, mask, preds, conf_arr)]
        eligible_for_source = [(mid, m) for mid, m in self.supervised.items()
                               if m["info"]["source"] == source]

        for mid, m in eligible_for_source:
            pred_fn = MODEL_ELIGIBILITY.get(mid)
            try:
                mask = (pred_fn(df) if pred_fn is not None
                        else pd.Series(True, index=df.index))
            except Exception:
                mask = pd.Series(False, index=df.index)
            
            results[f"m{mid}_label"]      = ""
            results[f"m{mid}_confidence"] = 0.0
            if not bool(mask.any()):
                continue
            sub_df = df.loc[mask]
            try:
                meta = m.get("metadata")
                if meta is not None:
                    X_sup = _extract_features_for_model(sub_df, meta)
                else:
                    X_sup = extract_supervised_features(sub_df, source, mid)
                clf   = m["model"]
                preds = clf.predict(X_sup)
                enc   = m.get("encoder")
                if enc is not None:
                    preds = enc.inverse_transform(preds)
                if hasattr(clf, "predict_proba"):
                    conf = clf.predict_proba(X_sup).max(axis=1)
                else:
                    conf = np.zeros(len(sub_df), dtype=float)
            except Exception as exc:
                
                results.loc[mask, f"m{mid}_label"] = f"error: {exc}"
                continue
            results.loc[mask, f"m{mid}_label"]      = preds
            results.loc[mask, f"m{mid}_confidence"] = conf
            per_model_runs.append((mid, mask, preds, conf))

      
        results["supervised_label"]      = ""
        results["supervised_confidence"] = 0.0
        results["supervised_model_id"]   = 0
        if per_model_runs:
            best_conf  = pd.Series(-1.0, index=results.index)
            best_label = pd.Series("",   index=results.index, dtype=object)
            best_mid   = pd.Series(0,    index=results.index, dtype=int)
            for mid, mask, preds, conf in per_model_runs:
                conf_s  = pd.Series(conf,  index=results.index[mask])
                label_s = pd.Series(preds, index=results.index[mask])
                wins_mask = conf_s > best_conf.loc[mask]
                winners = conf_s.index[wins_mask]
                if len(winners):
                    best_conf.loc[winners]  = conf_s.loc[winners]
                    best_label.loc[winners] = label_s.loc[winners]
                    best_mid.loc[winners]   = mid
            results["supervised_label"]      = best_label
            results["supervised_confidence"] = best_conf.clip(lower=0.0)
            results["supervised_model_id"]   = best_mid
        elif not eligible_for_source:
            results["supervised_label"] = "model_not_trained"

        
        results = self._run_incident_lifecycle(results)

      
        if source == "evtx" and source_path:
            try:
                self._persist_evtx_episodes(source_path, source_name)
            except Exception as exc:
                print(f"  [WARN] episode promotion failed: {exc}", flush=True)

        return results



def build_report(df_scored: pd.DataFrame, source: str,
                 input_path: str, engine: EIRPInferenceEngine) -> dict:
   
    its      = df_scored["its_score"]
    severity = df_scored["its_severity"].value_counts().to_dict()
    anomalies= int(df_scored["is_anomaly"].sum())

    top_incidents = (df_scored[df_scored["its_severity"].isin(["CRITICAL","HIGH"])]
                     .sort_values("its_score", ascending=False)
                     .head(20))

    top_rows = []
    for _, row in top_incidents.iterrows():
        r = {
            "its_score":    round(float(row["its_score"]), 4),
            "its_severity": str(row["its_severity"]),
            "anomaly_score":round(float(row.get("anomaly_score", 0)), 4),
        }
        if "model_b_label" in row.index and pd.notna(row["model_b_label"]):
            r["model_b_label"]      = str(row["model_b_label"])
            r["model_b_confidence"] = round(float(row.get("model_b_confidence", 0)), 4)
        if "response_actions" in row.index and pd.notna(row["response_actions"]):
            r["response_actions"]      = str(row["response_actions"])
            r["response_downgraded"]   = bool(row.get("response_downgraded", False))
            r["response_confirm_required"] = bool(row.get("response_confirm_required", False))
        for col in ["timestamp", "label", "hour", "is_after_hours",
                    "severity", "severity_score", "rule_id",
                    "supervised_label", "event_category"]:
            if col in row.index and pd.notna(row[col]):
                r[col] = str(row[col])
        top_rows.append(r)

    
    model_b_dist = {}
    if "model_b_label" in df_scored.columns:
        valid = df_scored["model_b_label"].astype(str)
        valid = valid[~valid.isin(["not_loaded", "nan"]) & ~valid.str.startswith("error:")]
        if len(valid):
            model_b_dist = {k: int(v) for k, v in valid.value_counts().items()}

   
    response_dist = {}
    response_summary = {}
    if "response_actions" in df_scored.columns:
        all_actions = []
        for s in df_scored["response_actions"].astype(str):
            if s and s != "nan":
                all_actions.extend(a for a in s.split("|") if a)
        if all_actions:
            response_dist = {k: int(v) for k, v in Counter(all_actions).most_common()}
            response_summary = {
                "n_requires_confirm":  int(df_scored.get("response_confirm_required",
                                                          pd.Series(dtype=bool)).sum()),
                "n_downgraded":        int(df_scored.get("response_downgraded",
                                                         pd.Series(dtype=bool)).sum()),
                "total_action_emissions": len(all_actions),
                "mean_actions_per_event": round(len(all_actions) / max(len(df_scored), 1), 2),
            }

   
    incident_lifecycle = {}
    if "incident_type" in df_scored.columns:
        inc_types_all = df_scored["incident_type"].astype(str)
        inc_types_nz  = inc_types_all[inc_types_all != ""]
        inc_distribution = {k: int(v) for k, v in inc_types_nz.value_counts().items()}

        inc_ids = df_scored.get("incident_id", pd.Series([""] * len(df_scored))).astype(str)
        persisted_ids = inc_ids[(inc_ids != "") & (~inc_ids.str.startswith("error:"))]

        lc = engine.last_lifecycle
       
        inc_severity = {}
        if "its_severity" in df_scored.columns:
            sev_series = df_scored.loc[inc_types_all != "", "its_severity"].astype(str)
            inc_severity = {k: int(v) for k, v in sev_series.value_counts().items()}

        incident_lifecycle = {
            "classifier_loaded":            engine.incident_classifier is not None,
            "playbook_engine_loaded":       engine.playbook_engine is not None,
            "case_store_persisting":        engine.case_store is not None,
            "notifier_active":              engine.notifier is not None,
            "containment_advisor_loaded":   engine.containment_advisor is not None,
            "recovery_checklist_loaded":    engine.recovery_checklist is not None,
            "bcp_monitor_loaded":           engine.bcp_monitor is not None,
            "db_path":                      str(engine.db_path) if engine.case_store else None,
            "n_classified":                 int(len(inc_types_nz)),
            "n_persisted_incidents":        int(len(persisted_ids)),
            "n_incidents_net_new":          len(lc["incidents_created"]),
            "n_incidents_merged":           len(lc["incidents_merged"]),
            "incidents_by_type":            inc_distribution,
            "incidents_by_severity":        inc_severity,
            "playbook_executions_started":  len(lc["playbooks_started"]),
            "steps_auto_completed":         int(lc["steps_auto_completed"]),
            "notifications_dispatched":     int(lc["notifications_sent"]),
            "incidents_skipped_due_to_cap": int(lc["skipped_beyond_cap"]),
            "containment_advisories_issued":int(lc["containment_advisories_issued"]),
            "recovery_checklists_attached": int(lc["recovery_checklists_attached"]),
            "bcp_activations":              list(lc["bcp_activations"]),
            "n_bcp_activations":            len(lc["bcp_activations"]),
        }

   
    if "incident_type" in df_scored.columns:
        for r, (_, row) in zip(top_rows, top_incidents.iterrows()):
            inc_type = str(row.get("incident_type", ""))
            if inc_type:
                r["incident_type"]     = inc_type
                r["incident_name"]     = str(row.get("incident_name", ""))
                r["playbook_id"]       = str(row.get("playbook_id", ""))
                inc_id = str(row.get("incident_id", ""))
                if inc_id and not inc_id.startswith("error:"):
                    r["incident_id"] = inc_id

    report = {
        "report_metadata": {
            "generated_at":     datetime.now().isoformat(),
            "input_file":       str(input_path),
            "source_type":      source,
            "researcher":       "Alozie Obidinma Christian",
            "reg_number":       "EBSU/PG/PhD/2023/11861",
            "institution":      "Ebonyi State University",
            "supervisor":       "Dr. Ituma",
            "case_hospital":    "ESUTH / DUFUTH",
            "models_available": {
                "isolation_forest":     engine.iso_forest is not None,
                "model_b_unified":      engine.model_b is not None,
                "model_c_response":     engine.response_engine is not None,
                "incident_classifier":  engine.incident_classifier is not None,
                "playbook_engine":      engine.playbook_engine is not None,
                "case_store":           engine.case_store is not None,
                "notifier":             engine.notifier is not None,
                "containment_advisor":  engine.containment_advisor is not None,
                "recovery_checklist":   engine.recovery_checklist is not None,
                "bcp_monitor":          engine.bcp_monitor is not None,
                "supervised":           list(engine.supervised.keys()),
            },
        },
        "event_summary": {
            "total_events":       len(df_scored),
            "anomalies_flagged":  anomalies,
            "anomaly_rate_pct":   round(100 * anomalies / max(len(df_scored), 1), 2),
        },
        "its_distribution": {
            "mean":   round(float(its.mean()), 4),
            "max":    round(float(its.max()),  4),
            "min":    round(float(its.min()),  4),
            "std":    round(float(its.std()),  4),
        },
        "severity_breakdown":           severity,
        "model_b_class_distribution":   model_b_dist,
        "model_c_response_summary":     response_summary,
        "model_c_action_distribution":  response_dist,
        "incident_lifecycle_summary":   incident_lifecycle,
        "top_incidents":                top_rows,
    }
    return report


def print_console_report(report: dict, df_scored: pd.DataFrame) -> None:
    """Print a human-readable summary to the console."""
    W = 72
    print("\n" + "=" * W)
    print("  EIRP-EMR INFERENCE REPORT")
    print("=" * W)
    meta = report["report_metadata"]
    print(f"  Researcher  : {meta['researcher']}  ({meta['reg_number']})")
    print(f"  Institution : {meta['institution']}  |  Supervisor: {meta['supervisor']}")
    print(f"  Generated   : {meta['generated_at'][:19]}")
    print(f"  Input File  : {Path(meta['input_file']).name}")
    print(f"  Source Type : {meta['source_type'].upper()}")
    print(f"  Model A (IF): {'Loaded' if meta['models_available']['isolation_forest'] else 'NOT FOUND'}")
    print(f"  Model B (T2): {'Loaded' if meta['models_available']['model_b_unified'] else 'NOT FOUND'}")
    print(f"  Model C (T3): {'Loaded' if meta['models_available'].get('model_c_response') else 'NOT FOUND'}")
    inc_clf = meta['models_available'].get('incident_classifier')
    pb_eng  = meta['models_available'].get('playbook_engine')
    cs      = meta['models_available'].get('case_store')
    notif   = meta['models_available'].get('notifier')
    ca      = meta['models_available'].get('containment_advisor')
    rc      = meta['models_available'].get('recovery_checklist')
    bcp     = meta['models_available'].get('bcp_monitor')
    print(f"  Lifecycle   : classifier={'Y' if inc_clf else 'N'}  "
          f"playbook={'Y' if pb_eng else 'N'}  "
          f"case_store={'Y' if cs else 'N'}  "
          f"notifier={'Y' if notif else 'N'}")
    print(f"  Recovery    : containment={'Y' if ca else 'N'}  "
          f"checklist={'Y' if rc else 'N'}  "
          f"bcp_monitor={'Y' if bcp else 'N'}")
    sup = meta['models_available']['supervised']
    print(f"  Supervised  : Models {sup if sup else 'none (run training scripts first)'}")

    es = report["event_summary"]
    print(f"\n  {'='*30}")
    print(f"  EVENTS PROCESSED : {es['total_events']:>8,}")
    print(f"  ANOMALIES FLAGGED: {es['anomalies_flagged']:>8,}  ({es['anomaly_rate_pct']}%)")

    its = report["its_distribution"]
    print(f"\n  ITS STATISTICS:")
    print(f"    Mean : {its['mean']:.4f}   Max : {its['max']:.4f}")
    print(f"    Min  : {its['min']:.4f}   Std : {its['std']:.4f}")

    sev = report["severity_breakdown"]
    order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    print(f"\n  SEVERITY BREAKDOWN:")
    for level in order:
        n = sev.get(level, 0)
        bar = "#" * min(int(n / max(es['total_events'], 1) * 40), 40)
        print(f"    {level:<9} {n:>6,}  |{bar}")

    mb_dist = report.get("model_b_class_distribution", {})
    if mb_dist:
        print(f"\n  MODEL B UNIFIED INCIDENT CLASSES:")
        total = sum(mb_dist.values())
        for cls in sorted(mb_dist, key=mb_dist.get, reverse=True):
            n = mb_dist[cls]
            pct = 100 * n / max(total, 1)
            bar = "#" * min(int(pct * 0.4), 40)
            print(f"    {cls:<18} {n:>6,}  ({pct:5.1f}%)  |{bar}")

    mc_summary = report.get("model_c_response_summary", {})
    mc_actions = report.get("model_c_action_distribution", {})
    if mc_actions:
        print(f"\n  MODEL C RESPONSE ENGINE:")
        print(f"    Total action emissions   : {mc_summary.get('total_action_emissions', 0):>6,}")
        print(f"    Mean actions per event   : {mc_summary.get('mean_actions_per_event', 0):>6.2f}")
        print(f"    Events needing confirm   : {mc_summary.get('n_requires_confirm', 0):>6,}")
        print(f"    Events downgraded        : {mc_summary.get('n_downgraded', 0):>6,}")
        print(f"\n  TOP RESPONSE ACTIONS:")
        total_em = sum(mc_actions.values())
        for action in list(mc_actions.keys())[:8]:
            n = mc_actions[action]
            pct = 100 * n / max(total_em, 1)
            bar = "#" * min(int(pct * 0.4), 40)
            print(f"    {action:<28} {n:>6,}  ({pct:5.1f}%)  |{bar}")

    lc = report.get("incident_lifecycle_summary", {})
    if lc and lc.get("n_classified"):
        print(f"\n  INCIDENT LIFECYCLE (Tier 3+):")
        print(f"    Events classified into INC   : {lc['n_classified']:>6,}")
        print(f"    Incidents persisted          : {lc['n_persisted_incidents']:>6,}")
        print(f"      net-new                    : {lc.get('n_incidents_net_new', 0):>6,}")
        print(f"      merged into existing       : {lc.get('n_incidents_merged', 0):>6,}")
        print(f"    Playbook executions started  : {lc['playbook_executions_started']:>6,}")
        print(f"    Auto-completed steps         : {lc['steps_auto_completed']:>6,}")
        print(f"    Notifications dispatched     : {lc['notifications_dispatched']:>6,}")
        if lc.get("incidents_skipped_due_to_cap"):
            print(f"    Skipped (per-run cap)        : {lc['incidents_skipped_due_to_cap']:>6,}")
        if lc.get("db_path"):
            print(f"    Case store DB                : {Path(lc['db_path']).name}")
        ibt = lc.get("incidents_by_type", {})
        if ibt:
            print(f"\n  INCIDENT TYPE DISTRIBUTION:")
            for inc in sorted(ibt, key=ibt.get, reverse=True):
                n = ibt[inc]
                pct = 100 * n / max(lc['n_classified'], 1)
                bar = "#" * min(int(pct * 0.4), 40)
                print(f"    {inc:<10} {n:>6,}  ({pct:5.1f}%)  |{bar}")

        # Tier 4 recovery + continuity rollup
        if (lc.get("containment_advisor_loaded")
                or lc.get("recovery_checklist_loaded")
                or lc.get("bcp_monitor_loaded")):
            print(f"\n  RECOVERY + CONTINUITY (Tier 4):")
            print(f"    Containment advisories issued: "
                  f"{lc.get('containment_advisories_issued', 0):>6,}")
            print(f"    Recovery checklists attached : "
                  f"{lc.get('recovery_checklists_attached', 0):>6,}")
            n_bcp = lc.get("n_bcp_activations", 0)
            print(f"    BCP activations              : {n_bcp:>6,}")
            if n_bcp:
                for act_id in lc.get("bcp_activations", [])[:5]:
                    print(f"        -> {act_id}")
                if n_bcp > 5:
                    print(f"        -> ... and {n_bcp - 5} more")

    incidents = report["top_incidents"]
    if incidents:
        print(f"\n  TOP INCIDENTS (ITS >= 0.60):")
        print(f"    {'ITS':>6}  {'SEV':<10}  {'Anomaly':>7}  {'ModelB':<16} Details")
        print(f"    {'-'*6}  {'-'*10}  {'-'*7}  {'-'*16} {'-'*30}")
        for r in incidents[:10]:
            mb_label = r.get("model_b_label", "-")
            mb_conf  = r.get("model_b_confidence", 0)
            mb_str   = f"{mb_label[:14]}({mb_conf:.2f})" if mb_label != "-" else "-"
            details = []
            for key in ["incident_id","incident_type","timestamp","rule_id",
                        "label","event_category","supervised_label"]:
                if key in r:
                    details.append(f"{key}={r[key]}")
            detail_str = "  ".join(details)[:40]
            print(f"    {r['its_score']:>6.4f}  {r['its_severity']:<10}  "
                  f"{r['anomaly_score']:>7.4f}  {mb_str:<16} {detail_str}")

    print(f"\n{'='*W}\n")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "EIRP-EMR Remote Validation Engine — scores ESUTH/DUFUTH "
            "log CSV exports and produces ITS-based incident reports."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--csv", type=str, default=None,
        help="Path to a parser output CSV file (LIRA / Access / Error / EVTX)."
    )
    parser.add_argument(
        "--source", type=str,
        choices=["lira", "access", "error", "evtx"],
        default=None,
        help="Parser source type. Auto-detected if omitted."
    )
    parser.add_argument(
        "--out", type=str, default=None,
        help="Path for output JSON report. Default: eirp_report_TIMESTAMP.json"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run a built-in demonstration using saved ML_Datasets/ test data."
    )
    parser.add_argument(
        "--sample", type=int, default=None,
        help="Randomly sample N rows from the input CSV (useful for large files)."
    )
    parser.add_argument(
        "--no-persist", action="store_true",
        help="Disable case_store persistence (no SQLite writes)."
    )
    parser.add_argument(
        "--no-notify", action="store_true",
        help="Disable notifier dispatch (no email / SMS / dashboard logs)."
    )
    parser.add_argument(
        "--db", type=str, default=None,
        help="Path to case_store SQLite DB (default: eirp_cases.db)."
    )
    parser.add_argument(
        "--max-incidents", type=int, default=500,
        help="Cap on number of incidents persisted per run (default 500)."
    )
    parser.add_argument(
        "--no-recovery", action="store_true",
        help="Disable Tier-4 recovery modules (containment advisor, recovery "
             "checklist, BCP monitor)."
    )
    parser.add_argument(
        "--bcp-any-severity", action="store_true",
        help="Activate BCP on any severity (default: CRITICAL only) for "
             "INC-02 / INC-03 incidents."
    )
    parser.add_argument(
        "--report", action="store_true",
        help="After inference, generate Tier-5 PDF + Excel + signed-audit "
             "+ NDPR-compliance reports for the persisted incidents."
    )
    parser.add_argument(
        "--report-dir", type=str, default=None,
        help="Output directory for Tier-5 reports "
             "(default: results/tier5_reports/<timestamp>/)."
    )
    parser.add_argument(
        "--report-only", action="store_true",
        help="Skip inference; generate Tier-5 reports for every incident "
             "already in the case_store. Useful for re-rendering after a run."
    )
    args = parser.parse_args()

    print("\n" + "=" * 72)
    print("  EIRP-EMR Inference and Remote Validation Engine")
    print("  PhD Research — Alozie Obidinma Christian (EBSU/PG/PhD/2023/11861)")
    print("=" * 72)
    print(f"\n  Loading available models from: {MODELS_DIR.relative_to(BASE_DIR)}")

    engine = EIRPInferenceEngine(
        persist_incidents        = not args.no_persist,
        db_path                  = Path(args.db) if args.db else None,
        dispatch_notifications   = not args.no_notify,
        max_incidents_per_run    = args.max_incidents,
        recovery_modules_enabled = not args.no_recovery,
        bcp_critical_only        = not args.bcp_any_severity,
    )

   
    if args.report_only:
        print("\n  Generating Tier-5 reports from existing case_store...")
        result = engine.generate_reports(
            report_dir=Path(args.report_dir) if args.report_dir else None,
            incident_ids=None,  # all incidents in DB
        )
        _print_report_summary(result)
        return

    if args.demo:
        run_demo(engine)
        if args.report:
            print("\n  Generating Tier-5 reports for this run's incidents...")
            result = engine.generate_reports(
                report_dir=Path(args.report_dir) if args.report_dir else None,
            )
            _print_report_summary(result)
        return

    if args.csv is None:
        print("\n  No input specified. Use --csv <file.csv> or --demo")
        print("  Example: python ml_inference.py --csv LIRA_2026_Output/LIRA_2026_00_master_all_events.csv")
        parser.print_help()
        return

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"\n  [ERROR] File not found: {csv_path}")
        sys.exit(1)

    print(f"\n  Loading: {csv_path.name}")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"  Rows: {len(df):,}  |  Columns: {len(df.columns)}")

    if args.sample and args.sample < len(df):
        df = df.sample(args.sample, random_state=42)
        print(f"  Sampled: {len(df):,} rows")

    source = args.source or detect_source(df)
    print(f"  Source detected: {source.upper()}")

    print(f"\n  Scoring {len(df):,} events...")
    df_scored = engine.score(df, source,
                             source_path=str(csv_path),
                             source_csv_path=str(csv_path))

    report = build_report(df_scored, source, str(csv_path), engine)
    print_console_report(report, df_scored)

    out_path = Path(args.out) if args.out else \
               BASE_DIR / f"eirp_report_{source}_{datetime.now():%Y%m%d_%H%M%S}.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"  Report saved: {out_path.name}")
    print(f"  (Send this file to: chimenkagoodluck82@gmail.com for analysis)\n")

    if args.report:
        print("  Generating Tier-5 reports for this run's incidents...")
        result = engine.generate_reports(
            report_dir=Path(args.report_dir) if args.report_dir else None,
        )
        _print_report_summary(result)


def _print_report_summary(result: Optional[Dict[str, Any]]) -> None:
    if not result:
        print("  [--]  No Tier-5 reports produced.")
        return
    W = 72
    print("\n" + "=" * W)
    print("  TIER 5 REPORTING SUMMARY")
    print("=" * W)
    print(f"  Output directory   : {result['output_dir']}")
    print(f"  Incidents reported : {result['n_incidents']}")
    print(f"  PDFs generated     : {len(result.get('per_incident_pdfs', []))}")
    print(f"  TXT files          : {len(result.get('per_incident_text', []))}")
    if "aggregate_excel" in result:
        print(f"  Aggregate workbook : {Path(result['aggregate_excel']).name}")
    if "signed_audit" in result:
        rh = result.get("audit_root_hash") or "(empty chain)"
        print(f"  Signed audit chain : {Path(result['signed_audit']).name}")
        print(f"     root hash       : {rh}")
    dash = result.get("ndpr_dashboard", {}) or {}
    if dash.get("n_incidents", 0) > 0:
        mc = dash.get("mean_compliance", 0)
        print(f"  NDPR mean compliance: {mc:.1%}  "
              f"(PASS={dash.get('n_pass',0)} "
              f"PARTIAL={dash.get('n_partial',0)} "
              f"FAIL={dash.get('n_fail',0)})")
    print("=" * W + "\n")


if __name__ == "__main__":
    main()
