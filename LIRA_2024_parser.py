"""


USAGE:
    python LIRA_2024_parser.py --input "C:\\path\\to\\log_031214_2024.txt"
    python LIRA_2024_parser.py --input log_031214_2024.txt --output C:\\results\\

OUTPUT:
    LIRA_2024_00_master_all_events.csv
    LIRA_2024_01_incidents_only.csv
    LIRA_2024_02_model_downtime_events.csv
    LIRA_2024_03_model_downtime_sessions.csv
    LIRA_2024_04_model_data_corruption.csv
    LIRA_2024_05_model_unauthorized_access.csv
    LIRA_2024_06_model_suspicious_review.csv
    LIRA_2024_07_label_audit_trail.csv
    LIRA_2024_REPORT.txt
"""

import re
import csv
import os
import argparse
import hashlib
from datetime import datetime
from collections import Counter


# ═══════════════════════════════════════════════════════════════════════
# TOOL METADATA
# ═══════════════════════════════════════════════════════════════════════

TOOL_NAME    = "LIRA — 2024 Dedicated Log Parser"
TOOL_VERSION = "1.0"
YEAR         = "2024"
HOSPITAL     = "Enugu State University Teaching Hospital (ESUTH)"
PRIMARY_DB   = "bamed"

SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Working hours
WORK_START = 7
WORK_END   = 21


# ═══════════════════════════════════════════════════════════════════════
# 2024 CONFIRMED BASELINE
# Derived from complete scan of log_031214_2024.txt.
# Total connection events ~70,000. Threshold: >= 1% = >= 700 connections.
# ═══════════════════════════════════════════════════════════════════════

BASELINE_USERS_2024 = {"root3"}

SUSPICIOUS_USERS_2024 = {"basoft"}

# Hosts with >= 700 connections in 2024
BASELINE_HOSTS_2024 = {
    "Emergency-Phamarcy",   # 9,813
    "DESKTOP-VLAGG25",      # 5,355
    "A-E-BILLING",          # 3,107
    "DESKTOP-45HCUFT",      # 3,095
    "DESKTOP-20DMDI8",      # 3,034
    "DESKTOP-EE1TUR0",      # 2,091
    "DESKTOP-7GDKJ9T",      # 2,037
    "DESKTOP-DQNJURJ",      # 2,015
    "HOU-REVENUE-PC",       # 1,760
    "DESKTOP-H0VKHI9",      # 1,579
    "DESKTOP-7B1UJP6",      # 1,486
    "DESKTOP-17O6HNS",      # 1,479
    "Med-Records-1",        # 1,401
    "DESKTOP-V1SVAAI",      # 1,381
    "DESKTOP-56BL7RE",      # 1,338
    "DESKTOP-1OMGH9H",      # 1,318
    "DESKTOP-BEFTIQ9",      # 1,297
    "A-E-REVENUE",          # 1,267
    "DESKTOP-HG3HT3A",      # 1,244
    "DESKTOP-NL7R141",      # 1,197
    "GOPD-Revenue",         # 1,101
    "DESKTOP-7T7ELOQ",      # 1,066
    "DESKTOP-1CDJVE5",      # 996
    "HOD-PHARMACY",         # 991
    "DESKTOP-STLV8TP",      # 902
    "DESKTOP-GGTJUEO",      # 888
    "DESKTOP-T5C63R6",      # 779
    "DESKTOP-6K3CMI9",      # 708
}

# Non-baseline hospital hosts (below 700 threshold, but known devices)
NON_BASELINE_HOSTS_2024 = {
    "DESKTOP-F8293EV", "DESKTOP-HBNVSCK", "DESKTOP-S50VKNJ",
    "DESKTOP-1BM1MOJ", "DESKTOP-4KC70RJ", "DESKTOP-ILTBA5K",
    "DESKTOP-VBEUS4Q", "DESKTOP-LE7D64J", "DESKTOP-H9P6S16",
    "DESKTOP-D4NCA3G", "DESKTOP-VBC03FI", "DESKTOP-RRUQIDS",
    "DUFUTH-SERVER",    # special — anomalous behaviour tracked separately
    "DESKTOP-6NPIQOS", "DESKTOP-V81NVAT", "Fammylarge",
    "DESKTOP-CBLB6Q1", "DESKTOP-AGH6702", "DESKTOP-SI53C8B",
    "DESKTOP-F32GO0N", "CODE-S", "SIRVICK", "BookingEnergy",
    "DESKTOP-59DJKV9", "DESKTOP-IHKUT7J", "DESKTOP-UOEFDLJ",
    "DESKTOP-9O3E0BR", "DESKTOP-BP3714M", "DESKTOP-0SFCL2D",
    "DESKTOP-JAM9I17", "DESKTOP-PA7LLB3", "DESKTOP-A6E7VCB",
    "DESKTOP-IP59NG6", "DESKTOP-GARLJAI",
}

# IPv6 link-local addresses confirmed in 2024 file
IPV6_HOSTS_2024 = {
    "fe80::d82b:43c8:e023:b349%27",
    "fe80::4da7:981d:da2:8b7e%27",
    "fe80::cf9:59fd:54f3:8aa1%27",
    "fe80::b667:6246:3acb:3a82%27",
    "fe80::c823:2569:2b1c:3147%27",
    "fe80::c95:a3fa:df55:a891%27",
    "fe80::30b4:afa:23e8:9147%27",
    "fe80::c537:5b1c:88bb:1b1e%27",
    "fe80::b426:814f:e79:1aad%27",
    "fe80::cc52:f831:ab58:4704%27",
    "fe80::f95a:37ce:a603:bcd5%27",
    "fe80::97bc:97d5:91a5:27c4%27",
    "fe80::56c4:92d4:37ab:9daa%27",
    "fe80::356a:de9e:60b:45b3%27",
    "fe80::ed74:7f9c:d3e0:7b95%27",
    "fe80::5080:f23f:3ffb:d24b%27",
}

# Raw IPs confirmed in 2024 (appear in access denied @ field, host field)
RAW_IP_HOSTS_2024 = {
    "10.5.50.22", "10.5.50.30", "10.5.50.10", "10.5.50.25",
    "10.5.50.38", "10.5.50.34", "10.5.50.8",  "10.5.50.35",
    "10.5.50.9",  "10.5.50.47", "10.5.50.45", "10.5.50.16",
}


# ═══════════════════════════════════════════════════════════════════════
# REGEX PATTERNS
# ═══════════════════════════════════════════════════════════════════════

RE_MAIN = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{1,2}:\d{2}:\d{2})\s+'
    r'(?P<thread>\d+)\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<message>.+)$'
)
RE_ABORTED = re.compile(
    r"Aborted connection\s+(?P<conn_id>\d+)\s+to\s+db:\s*'(?P<db>[^']*)'\s+"
    r"user:\s*'(?P<user>[^']*)'\s+host:\s*'(?P<host>[^']*)'\s*"
    r"\((?P<reason>[^)]+)\)"
)
RE_ACCESS_DENIED = re.compile(
    r"Access denied for user\s+'(?P<user>[^']*)'\s*@\s*'(?P<host>[^']+)'"
    r"\s+\(using password:\s*(?P<pwd>YES|NO)\)"
)
RE_DNS   = re.compile(
    r"(?:IP address|Host(?:name)?)\s+'(?P<entity>[^']+)'\s+"
    r"(?:could not be resolved|does not resolve to\s+'(?P<target>[^']+)')"
)
RE_LSN   = re.compile(r"LSN=(\d+)")
RE_VER   = re.compile(r"^Version:\s+'")
RE_ARIA_P= re.compile(r"^recovered pages:")
RE_DASH  = re.compile(r"^\s*-\s+\S")
RE_IPV4  = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
RE_IPV6  = re.compile(r'^fe80::')


# ═══════════════════════════════════════════════════════════════════════
# RULE CATALOG — 2024 EDITION
# Includes all 2023 rules + 3 new rules from 2024-specific patterns
# ═══════════════════════════════════════════════════════════════════════

RULE_CATALOG = {
    # ── Downtime / Availability ──────────────────────────────────────
    "R01":  "InnoDB crash recovery initiated",
    "R02":  "Aria engine crash recovery initiated",
    "R03":  "Database service restarted — now online",
    "R04":  "Planned normal shutdown initiated",
    "R05":  "InnoDB clean shutdown completed",
    "R06":  "Shutdown sub-sequence event",
    "R26":  "Too many connections — DB connection limit exhausted",
    "R27":  "Table cache mutex contention — performance degradation",
    # ── Data Corruption (context-dependent) ─────────────────────────
    "R07":  "Temp tablespace recreated — crash context only",
    "R08":  "Stale temp file removed — crash context only",
    "R09":  "Rollback segments activated — crash context only",
    # ── Critical Infrastructure Failures ────────────────────────────
    "R28":  "InnoDB ibdata1 not writable — critical storage failure",
    "R29":  "InnoDB LSN mismatch — data integrity at risk",
    "R30":  "InnoDB/plugin storage engine failure — service unable to start",
    "R31":  "Database emergency abort — unrecoverable failure",
    # ── Unauthorized Access ──────────────────────────────────────────
    "R10":  "Unauthenticated connection from real host — auth never completed",
    "R11":  "Access denied — unknown user basoft [CRITICAL]",
    "R11B": "Access denied — root3 from DUFUTH-SERVER [ANOMALY]",
    "R11C": "Access denied — empty user, no password from DUFUTH [2024 NEW]",
    "R13":  "Aborted — closed without authentication",
    "R14":  "Connection from IPv6 link-local unregistered device",
    "R15":  "Connection from raw IP address (no hostname)",
    "R16":  "Aborted connection from non-baseline host",
    "R17":  "Aborted connection from baseline host — benign",
    "R18":  "After-hours aborted connection from baseline host",
    "R19":  "DNS resolution failure or hostname mismatch",
    # ── 2024 New Abort Reason Rules ──────────────────────────────────
    "R32":  "Aborted — Unknown error (anomalous connection termination)",
    "R33":  "Aborted — Query execution was interrupted",
    # ── Benign Operational ───────────────────────────────────────────
    "R21":  "InnoDB buffer pool management — benign",
    "R22":  "Plugin or extension status event — benign",
    "R23":  "Startup / replication / config event — benign",
    "R24":  "General informational Note — benign",
    "R25":  "Unclassified Warning — manual review needed",
}


# ═══════════════════════════════════════════════════════════════════════
# PASS 1b — STARTUP CONTEXT ASSIGNMENT
#
# 2024-specific addition: abort_startup context
#
# Three session types in 2024:
#   crash_startup  : started, had crash recovery, reached ready for connections
#   clean_startup  : started after clean shutdown, reached ready for connections
#   abort_startup  : started but hit ERROR/Aborting before ready for connections
#                   (2024-03-22 catastrophe is the only abort_startup in 2024)
#   running        : event occurred while DB was actively serving connections
#
# R07/R08/R09 only fire as DATA_CORRUPTION in crash_startup sessions.
# In clean_startup and abort_startup they are BENIGN (or not present).
# ═══════════════════════════════════════════════════════════════════════

def assign_startup_context(events: list) -> list:
    """Assign startup_context and startup_session_id to every event."""
    for e in events:
        e["startup_context"]    = "running"
        e["startup_session_id"] = 0

    session_id  = 0
    in_startup  = False
    buffer      = []
    had_crash   = False
    had_abort   = False

    for e in events:
        msg = e["message"].lower()

        if "starting mariadb" in msg:
            # Flush any open incomplete session
            if in_startup and buffer:
                if had_abort:
                    ctx = "abort_startup"
                elif had_crash:
                    ctx = "crash_startup"
                else:
                    ctx = "clean_startup"
                for be in buffer:
                    be["startup_context"]    = ctx
                    be["startup_session_id"] = session_id

            session_id += 1
            in_startup  = True
            had_crash   = False
            had_abort   = False
            buffer      = [e]
            e["startup_context"]    = "unknown"
            e["startup_session_id"] = session_id
            continue

        if in_startup:
            e["startup_session_id"] = session_id
            e["startup_context"]    = "unknown"
            buffer.append(e)

            # Detect crash recovery
            if ("innodb: starting crash recovery" in msg or
                    "aria engine: starting recovery" in msg):
                had_crash = True

            # Detect abort (Aborting = unrecoverable failure)
            if msg.strip() == "aborting":
                had_abort = True

            # Detect end of startup window
            if "ready for connections" in msg:
                ctx = "crash_startup" if had_crash else "clean_startup"
                for be in buffer:
                    be["startup_context"]    = ctx
                    be["startup_session_id"] = session_id
                in_startup = False
                buffer     = []
                had_crash  = False
                had_abort  = False
        else:
            e["startup_context"]    = "running"
            e["startup_session_id"] = session_id

    # Flush incomplete session at end of file
    if in_startup and buffer:
        if had_abort:
            ctx = "abort_startup"
        elif had_crash:
            ctx = "crash_startup"
        else:
            ctx = "clean_startup"
        for be in buffer:
            be["startup_context"]    = ctx
            be["startup_session_id"] = session_id

    return events


# ═══════════════════════════════════════════════════════════════════════
# PASS 1 — PARSER
# Reads every line and extracts all sub-fields.
# No whitespace-padded lines in 2024 (confirmed from file scan).
# ═══════════════════════════════════════════════════════════════════════

def parse_log(filepath: str) -> tuple:
    """
    Returns: (events, raw_line_count, skipped_lines, file_size_bytes)
    """
    events    = []
    raw_lines = 0
    skipped   = 0
    current   = None

    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        file_size = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw_lines += 1
            line = raw.strip()

            if not line:
                skipped += 1
                continue

            # Skip non-event continuation lines
            if RE_VER.match(line) or RE_ARIA_P.match(line) or RE_DASH.match(line):
                skipped += 1
                if current:
                    current["_cont"] += 1
                continue

            m = RE_MAIN.match(line)
            if m:
                if current:
                    events.append(current)

                date_str = m.group("date")
                time_str = m.group("time").strip()
                if len(time_str) == 7:
                    time_str = "0" + time_str
                ts_str  = f"{date_str} {time_str}"
                message = m.group("message").strip()
                level   = m.group("level")

                try:
                    ts   = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    hour = ts.hour
                    dow  = ts.strftime("%A")
                    mon  = ts.strftime("%B")
                    yr   = ts.year
                except ValueError:
                    ts = None
                    hour = -1
                    dow = mon = ""
                    yr = ""

                # ── Aborted connection sub-fields ─────────────────────
                user = db = host = conn_id = abort_reason = ""
                ab = RE_ABORTED.search(message)
                if ab:
                    conn_id      = ab.group("conn_id")
                    db           = ab.group("db")
                    user         = ab.group("user")
                    host         = ab.group("host")
                    abort_reason = ab.group("reason").strip()

                # ── Access denied sub-fields ──────────────────────────
                ad_user = ad_host = ad_pwd = ""
                ad = RE_ACCESS_DENIED.search(message)
                if ad:
                    ad_user = ad.group("user")   # may be empty string ""
                    ad_host = ad.group("host")
                    ad_pwd  = ad.group("pwd")
                    if not user:
                        user = ad_user if ad_user else "__empty__"
                    if not host:
                        host = ad_host

                # ── DNS failure ───────────────────────────────────────
                dns_m      = RE_DNS.search(message)
                dns_entity = dns_m.group("entity") if dns_m else ""

                # ── LSN ───────────────────────────────────────────────
                lsn_m = RE_LSN.search(message)
                lsn   = lsn_m.group(1) if lsn_m else ""

                # ── After-hours flag ──────────────────────────────────
                is_aft = (
                    "1" if (hour != -1 and
                           (hour < WORK_START or hour > WORK_END))
                    else "0"
                )

                # ── Fingerprint ───────────────────────────────────────
                fp = hashlib.sha256(
                    f"{ts_str}|{m.group('thread')}|{message[:100]}".encode()
                ).hexdigest()[:16]

                # ── Host classification ───────────────────────────────
                if not host or host == "__empty__":
                    hc = "no_host"
                elif RE_IPV6.match(host):
                    hc = "ipv6_unregistered"
                elif RE_IPV4.match(host):
                    hc = "raw_ip"
                elif host == "connecting host":
                    hc = "connecting_host_system"  # special: Too many conn
                elif host in BASELINE_HOSTS_2024:
                    hc = "baseline"
                elif host in NON_BASELINE_HOSTS_2024:
                    hc = "non_baseline_known"
                elif host in ("unknown", "unconnected"):
                    hc = "system"
                else:
                    hc = "non_baseline_unknown"

                # ── User classification ───────────────────────────────
                raw_user = ad_user if ad else user
                if not raw_user or raw_user == "__empty__":
                    uc = "anonymous"
                elif raw_user == "unauthenticated":
                    uc = "unauthenticated"
                elif raw_user == "unconnected":
                    uc = "system"
                elif raw_user in BASELINE_USERS_2024:
                    uc = "baseline"
                elif raw_user in SUSPICIOUS_USERS_2024:
                    uc = "suspicious_known"
                else:
                    uc = "non_baseline_unknown"

                current = {
                    # Identity
                    "event_id":             len(events) + 1,
                    "fingerprint":          fp,
                    "source_line":          raw_lines,
                    # Temporal
                    "timestamp":            ts_str,
                    "date":                 date_str,
                    "time":                 time_str,
                    "hour":                 hour,
                    "day_of_week":          dow,
                    "month":                mon,
                    "year":                 yr,
                    "is_after_hours":       is_aft,
                    # Core
                    "thread_id":            m.group("thread"),
                    "level":                level,
                    "message":              message,
                    # Connection
                    "user":                 user,
                    "host":                 host,
                    "database":             db,
                    "connection_id":        conn_id,
                    "abort_reason":         abort_reason,
                    # Access denied
                    "ad_user":              ad_user,
                    "ad_host":              ad_host,
                    "ad_pwd_used":          ad_pwd,
                    # DNS
                    "dns_failure":          "1" if dns_m else "0",
                    "dns_entity":           dns_entity,
                    # InnoDB
                    "lsn_checkpoint":       lsn,
                    # Feature flags
                    "is_aborted":           "1" if ab else "0",
                    "is_access_denied":     "1" if ad else "0",
                    "is_crash_recovery":    "1" if "crash recovery" in message.lower() else "0",
                    "is_aria_recovery":     "1" if "aria engine: starting recovery" in message.lower() else "0",
                    "is_startup":           "1" if "ready for connections" in message.lower() else "0",
                    "is_clean_shutdown":    "1" if "normal shutdown" in message.lower() else "0",
                    "is_error_level":       "1" if level == "ERROR" else "0",
                    "host_class":           hc,
                    "user_class":           uc,
                    # Startup context — Pass 1b
                    "startup_context":      "",
                    "startup_session_id":   0,
                    # Labels — Pass 2
                    "label":                "",
                    "sublabel":             "",
                    "severity":             "",
                    "severity_score":       "",
                    "rule_id":              "",
                    "rule_description":     "",
                    "model_flags":          "",
                    "confidence":           "HIGH",
                    "is_incident":          "",
                    "analyst_notes":        "",
                    "_cont":                0,
                }
            else:
                if current:
                    current["message"] += " || " + line
                    current["_cont"]   += 1
                else:
                    skipped += 1

    if current:
        events.append(current)

    return events, raw_lines, skipped, file_size


# ═══════════════════════════════════════════════════════════════════════
# PASS 2 — LABELING ENGINE
# All rules verified against actual 2024 log patterns.
# Rule ordering is critical — more specific rules come first.
# ═══════════════════════════════════════════════════════════════════════

def label_event(event: dict) -> dict:
    """Apply 2024 labeling rules. Every decision is traceable by Rule ID."""

    msg    = event["message"].lower()
    user   = event["user"]
    host   = event["host"]
    level  = event["level"]
    hour   = event["hour"]
    hc     = event["host_class"]
    uc     = event["user_class"]
    is_aft = event["is_after_hours"] == "1"
    ar     = event["abort_reason"].lower()
    ctx    = event["startup_context"]
    db     = event["database"]
    ad_u   = event["ad_user"]
    ad_h   = event["ad_host"]
    ad_pwd = event["ad_pwd_used"]

    label      = "BENIGN"
    sublabel   = "general_informational"
    severity   = "INFO"
    rule_id    = "R24"
    models     = []
    confidence = "HIGH"
    notes      = ""

    # ══════════════════════════════════════════════════════════════════
    # BLOCK 0 — CRITICAL INFRASTRUCTURE FAILURES (ERROR level)
    # Must be checked FIRST — ERROR level events only appear in
    # the 2024-03-22 catastrophe sequence. Handle before all other rules.
    # ══════════════════════════════════════════════════════════════════

    if level == "ERROR" and "innodb_system data file" in msg and "writable" in msg:
        label    = "DATA_CORRUPTION"
        sublabel = "innodb_ibdata1_not_writable_critical"
        severity = "CRITICAL"
        rule_id  = "R28"
        models   = ["data_corruption", "downtime_events"]
        notes = (
            "CRITICAL: InnoDB cannot write to its system tablespace file "
            "(ibdata1). This is the root cause of the 2024-03-22 database "
            "abort. All patient record writes are failing at this moment. "
            "Likely cause: disk full, permissions changed, or disk failure."
        )

    elif level == "ERROR" and "init function returned error" in msg:
        label    = "SYSTEM_DOWNTIME"
        sublabel = "innodb_plugin_init_function_error"
        severity = "CRITICAL"
        rule_id  = "R30"
        models   = ["downtime_events"]
        notes = (
            "InnoDB plugin initialization failed. Direct consequence of "
            "ibdata1 being non-writable (R28). InnoDB cannot start — "
            "the EMR database is completely unavailable."
        )

    elif level == "ERROR" and "registration as a storage engine failed" in msg:
        label    = "SYSTEM_DOWNTIME"
        sublabel = "innodb_storage_engine_registration_failed"
        severity = "CRITICAL"
        rule_id  = "R30"
        models   = ["downtime_events"]
        notes = (
            "InnoDB failed to register as a storage engine. ALL tables in "
            "the bamed EMR database are InnoDB tables. Without InnoDB, "
            "every patient record, billing entry, and appointment is "
            "inaccessible. Complete hospital EMR unavailability."
        )

    elif level == "ERROR" and ("unknown/unsupported storage engine" in msg or
                                "unsupported storage engine" in msg):
        label    = "SYSTEM_DOWNTIME"
        sublabel = "innodb_unknown_unsupported_storage_engine"
        severity = "CRITICAL"
        rule_id  = "R30"
        models   = ["downtime_events"]
        notes = (
            "MariaDB reports InnoDB as unknown/unsupported — InnoDB "
            "registration failed completely. The database cannot serve "
            "any requests. ESUTH EMR system fully offline."
        )

    elif level == "ERROR" and msg.strip() == "aborting":
        label    = "SYSTEM_DOWNTIME"
        sublabel = "database_emergency_abort_unrecoverable_failure"
        severity = "CRITICAL"
        rule_id  = "R31"
        models   = ["downtime_events"]
        notes = (
            "MariaDB performed an emergency abort — the sequence "
            "ibdata1 unwritable (R28) → InnoDB init failed (R30) → "
            "Storage engine unavailable (R30) → Aborting (R31) "
            "represents the most severe single incident in the 2024 log. "
            "Manual IT intervention was required to restore EMR access. "
            "Date: 2024-03-22 13:19:28."
        )

    # ══════════════════════════════════════════════════════════════════
    # BLOCK A — SYSTEM DOWNTIME
    # ══════════════════════════════════════════════════════════════════

    elif "innodb: starting crash recovery" in msg:
        label    = "SYSTEM_DOWNTIME"
        sublabel = "innodb_crash_recovery"
        severity = "CRITICAL"
        rule_id  = "R01"
        models   = ["downtime_events", "data_corruption"]
        lsn      = event.get("lsn_checkpoint", "")
        notes = (
            f"InnoDB detected unclean prior shutdown, recovering from "
            f"checkpoint LSN={lsn if lsn else 'unknown'}. EMR UNAVAILABLE "
            f"to all hospital workstations until recovery completes. "
            f"START of downtime session."
        )

    elif "aria engine: starting recovery" in msg:
        label    = "SYSTEM_DOWNTIME"
        sublabel = "aria_engine_crash_recovery"
        severity = "CRITICAL"
        rule_id  = "R02"
        models   = ["downtime_events", "data_corruption"]
        notes    = "Aria storage engine recovery — hard system failure. EMR UNAVAILABLE."

    elif "ready for connections" in msg:
        label    = "SYSTEM_DOWNTIME"
        sublabel = "service_restart_online"
        severity = "MEDIUM"
        rule_id  = "R03"
        models   = ["downtime_events"]
        notes    = "Database back online. END of downtime session when preceded by crash recovery."

    elif "normal shutdown" in msg:
        label    = "PLANNED_MAINTENANCE"
        sublabel = "authorized_normal_shutdown"
        severity = "INFO"
        rule_id  = "R04"
        models   = ["downtime_events"]
        notes    = "Authorized clean shutdown. NEGATIVE CLASS for downtime model."

    elif "innodb: shutdown completed" in msg or (
            "shutdown complete" in msg and "innodb" in msg):
        label    = "PLANNED_MAINTENANCE"
        sublabel = "innodb_clean_shutdown_complete"
        severity = "INFO"
        rule_id  = "R05"
        models   = ["downtime_events"]
        notes    = "Clean InnoDB shutdown. No crash recovery needed next startup."

    elif (any(k in msg for k in [
        "event scheduler: purging", "fts optimize thread exiting",
        "innodb: starting shutdown", "innodb: dumping buffer",
    ]) or ("initiated by:" in msg and "shutdown" in msg)):
        label    = "PLANNED_MAINTENANCE"
        sublabel = "shutdown_sub_sequence"
        severity = "INFO"
        rule_id  = "R06"
        models   = ["downtime_events"]
        notes    = "Part of authorized shutdown sub-sequence. Benign."

    # ── Too many connections — BEFORE general unauthenticated check ───
    elif (hc == "connecting_host_system" and
          "too many connections" in ar):
        # R26: host='connecting host', user='unauthenticated', db='unconnected'
        # MariaDB uses this sentinel hostname when it cannot resolve
        # the hostname before rejecting the connection due to limit.
        label    = "SYSTEM_DOWNTIME"
        sublabel = "connection_limit_exhausted_availability_incident"
        severity = "HIGH"
        rule_id  = "R26"
        models   = ["downtime_events"]
        notes = (
            "Database hit its max_connections limit — connection rejected "
            "before hostname resolution. With 70,000+ connections in 2024 "
            "across ~85 workstations, pool exhaustion is a recurring "
            "availability risk. All 3,864 such events in 2024 occurred "
            "primarily in Feb-Mar 2024. Partial EMR unavailability."
        )

    # ── Table cache mutex contention (NOTE level in 2024) ─────────────
    elif "table cache mutex contention" in msg:
        label    = "SYSTEM_DOWNTIME"
        sublabel = "table_cache_mutex_contention_performance_degradation"
        severity = "MEDIUM"
        rule_id  = "R27"
        models   = ["downtime_events"]
        notes = (
            "Table cache mutex contention detected — multiple EMR threads "
            "competing for the same internal lock, causing query slowdowns "
            "for all hospital workstations simultaneously. 6 events in "
            "April 2024. table_open_cache is undersized for 2024 load."
        )

    # ══════════════════════════════════════════════════════════════════
    # BLOCK B — DATA CORRUPTION (context-dependent)
    # ══════════════════════════════════════════════════════════════════

    elif "creating shared tablespace for temporary tables" in msg:
        if ctx == "crash_startup":
            label    = "DATA_CORRUPTION"
            sublabel = "temp_tablespace_recreated_post_crash"
            severity = "HIGH"
            rule_id  = "R07"
            models   = ["data_corruption"]
            notes = (
                "Temp tablespace recreated in crash_startup session. "
                "Any in-progress patient records or billing entries "
                "at crash time are permanently lost."
            )
        else:
            # clean_startup or abort_startup — normal operation
            label    = "BENIGN"
            sublabel = "innodb_temp_tablespace_init_normal_startup"
            severity = "INFO"
            rule_id  = "R23"
            notes    = "Normal InnoDB startup temp tablespace init. No data risk."

    elif "removed temporary tablespace data file" in msg:
        if ctx == "crash_startup":
            label    = "DATA_CORRUPTION"
            sublabel = "stale_temp_file_removed_after_crash"
            severity = "MEDIUM"
            rule_id  = "R08"
            models   = ["data_corruption"]
            notes = (
                "Stale ibtmp1 removed in crash_startup — prior session "
                "terminated abnormally. Temp table data is unrecoverable."
            )
        else:
            label    = "BENIGN"
            sublabel = "innodb_temp_file_cleanup_normal_startup"
            severity = "INFO"
            rule_id  = "R23"
            notes    = "Normal InnoDB startup temp file cleanup. Benign."

    elif "rollback segments are active" in msg:
        if ctx == "crash_startup":
            label    = "DATA_CORRUPTION"
            sublabel = "rollback_segments_activated_post_crash"
            severity = "MEDIUM"
            rule_id  = "R09"
            models   = ["data_corruption"]
            notes = (
                "Rollback segments active in crash_startup session. "
                "Uncommitted transactions at crash time rolled back. "
                "EMR data mid-write at crash time was NOT saved."
            )
        else:
            label    = "BENIGN"
            sublabel = "innodb_rollback_segments_normal_init"
            severity = "INFO"
            rule_id  = "R23"
            notes    = "Normal InnoDB startup. No data integrity risk."

    # ══════════════════════════════════════════════════════════════════
    # BLOCK C — UNAUTHORIZED ACCESS
    # Order matters: most specific checks first.
    # ══════════════════════════════════════════════════════════════════

    elif (event["is_access_denied"] == "1" and
          ad_pwd == "NO" and
          (not ad_u or ad_u == "__empty__") and
          ad_h == "DUFUTH-SERVER"):
        # R11C: Empty username, no password from DUFUTH-SERVER.
        # New in 2024. 9 events. This is an anonymous connection probe —
        # DUFUTH is attempting to connect with no credentials at all.
        # Distinct from root3 (wrong password) and basoft (unknown user).
        label    = "UNAUTHORIZED_ACCESS"
        sublabel = "anonymous_no_password_probe_dufuth_server"
        severity = "HIGH"
        rule_id  = "R11C"
        models   = ["unauthorized_access"]
        notes = (
            "DUFUTH-SERVER attempting anonymous database connection "
            "(empty username, no password). New pattern in 2024. "
            "Indicates DUFUTH is probing for open/passwordless access "
            "in addition to the root3 credential failures (R11B). "
            "Suggests the DUFUTH application is cycling through "
            "multiple authentication strategies."
        )

    elif event["is_access_denied"] == "1" and ad_u in SUSPICIOUS_USERS_2024:
        # R11: basoft — completely unknown user
        label    = "UNAUTHORIZED_ACCESS"
        sublabel = "access_denied_unknown_user_basoft"
        severity = "CRITICAL"
        rule_id  = "R11"
        models   = ["unauthorized_access"]
        notes = (
            f"Unknown user 'basoft' attempted login from '{ad_h}'. "
            "Not in any approved user registry. 8 events in 2024, "
            "all from CODE-S. Confirmed external credential attack."
        )

    elif (event["is_access_denied"] == "1" and
          ad_u in BASELINE_USERS_2024 and
          ad_h == "DUFUTH-SERVER"):
        # R11B: root3 from DUFUTH-SERVER — 6,924 events in 2024.
        # Pattern: heavy Jan-Mar 2024, stops by May 2024.
        label    = "UNAUTHORIZED_ACCESS"
        sublabel = "access_denied_dufuth_server_root3_credential_anomaly"
        severity = "CRITICAL"
        rule_id  = "R11B"
        models   = ["unauthorized_access"]
        notes = (
            f"root3 repeatedly failing authentication from DUFUTH-SERVER "
            f"— a registered baseline host. 6,924 events Jan-May 2024. "
            f"After May 2024 the access denied events cease but DUFUTH "
            f"continues making aborted connections. Root cause: database "
            f"password was changed and not updated in DUFUTH application "
            f"config, or DUFUTH-SERVER was compromised. The partial "
            f"resolution in May 2024 suggests IT made a corrective action "
            f"but did not fully address the underlying issue."
        )

    elif event["is_access_denied"] == "1":
        # Other access denied events not covered by specific rules above
        label    = "UNAUTHORIZED_ACCESS"
        sublabel = "access_denied_other"
        severity = "HIGH"
        rule_id  = "R11B"
        models   = ["unauthorized_access"]
        notes = (
            f"Access denied for user '{ad_u}' from '{ad_h}' "
            f"(password:{ad_pwd}). Not matching specific known patterns — "
            f"review against approved user and host registry."
        )

    elif (uc == "unauthenticated" and
          hc == "connecting_host_system"):
        # This should not reach here — R26 catches it first.
        # Safety net only.
        label    = "SYSTEM_DOWNTIME"
        sublabel = "connection_limit_exhausted_availability_incident"
        severity = "HIGH"
        rule_id  = "R26"
        models   = ["downtime_events"]
        notes    = "Connection limit hit — caught by fallback R26 rule."

    elif uc == "unauthenticated" and "closed normally without authentication" in ar:
        # R13: closed without auth — from real (non-connecting-host) hosts
        label    = "UNAUTHORIZED_ACCESS"
        sublabel = "connection_closed_without_authentication"
        severity = "HIGH"
        rule_id  = "R13"
        models   = ["unauthorized_access"]
        notes = (
            f"Connection from '{host}' closed before authentication "
            "completed (closed normally). Connection pool probe or "
            "misconfigured client testing the database port."
        )

    elif uc == "unauthenticated":
        # R10: unauthenticated from real identifiable hosts
        # (DESKTOP-DQNJURJ 24, DESKTOP-V1SVAAI 14, etc.)
        label    = "UNAUTHORIZED_ACCESS"
        sublabel = "unauthenticated_connection_dropped_real_host"
        severity = "CRITICAL"
        rule_id  = "R10"
        models   = ["unauthorized_access"]
        notes = (
            f"Connection from '{host}' dropped — authentication handshake "
            f"never completed. 86 such events from real hosts in 2024 "
            f"(DESKTOP-DQNJURJ 24, DESKTOP-V1SVAAI 14, DESKTOP-6NPIQOS 8, "
            f"DESKTOP-STLV8TP 6, and others). Possible causes: port "
            f"scanner, brute-force probe, or severely misconfigured client."
        )

    elif hc == "ipv6_unregistered":
        label    = "SUSPICIOUS"
        sublabel = "connection_from_ipv6_link_local_unregistered_device"
        severity = "HIGH"
        rule_id  = "R14"
        models   = ["unauthorized_access", "suspicious_review"]
        confidence = "MEDIUM"
        notes = (
            f"Connection from IPv6 link-local '{host}'. Not in any "
            "registered hostname registry. 16 unique IPv6 addresses "
            "in 2024. fe80::d82b:43c8:e023:b349%27 is most active "
            "with 2,326 connections."
        )

    elif hc == "raw_ip":
        label    = "SUSPICIOUS"
        sublabel = "connection_from_raw_ip_no_hostname"
        severity = "HIGH"
        rule_id  = "R15"
        models   = ["unauthorized_access", "suspicious_review"]
        confidence = "MEDIUM"
        notes = (
            f"Connection from raw IP '{host}'. Legitimate workstations "
            "use hostnames. Direct IP bypasses hostname-based controls."
        )

    elif event["is_aborted"] == "1" and "unknown error" in ar:
        # R32: Unknown error abort — new in 2024. 1 event from BookingEnergy/bamedstorage.
        label    = "SUSPICIOUS"
        sublabel = "aborted_unknown_error_anomalous_termination"
        severity = "HIGH"
        rule_id  = "R32"
        models   = ["suspicious_review", "unauthorized_access"]
        confidence = "MEDIUM"
        notes = (
            f"Connection from '{host}' to database '{db}' terminated with "
            f"'Unknown error' — an anomalous abort reason not seen in "
            f"normal EMR operation. "
            + (
                f"NOTABLE: This connection was to 'bamedstorage' — not the "
                f"primary 'bamed' EMR database. BookingEnergy accessing a "
                f"secondary database warrants investigation."
                if db == "bamedstorage" else
                "Verify the connection circumstances with IT admin."
            )
        )

    elif event["is_aborted"] == "1" and "query execution was interrupted" in ar:
        # R33: Query interrupted — 1 event in 2024.
        label    = "SUSPICIOUS"
        sublabel = "aborted_query_execution_interrupted"
        severity = "MEDIUM"
        rule_id  = "R33"
        models   = ["suspicious_review"]
        confidence = "LOW"
        notes = (
            f"Connection from '{host}' aborted because a query execution "
            "was interrupted. Could indicate a forced disconnect, a "
            "long-running query killed by admin, or abnormal client behavior."
        )

    elif event["is_aborted"] == "1" and hc in (
        "non_baseline_known", "non_baseline_unknown"
    ):
        if is_aft:
            label    = "SUSPICIOUS"
            sublabel = "after_hours_aborted_non_baseline_host"
            severity = "HIGH"
            rule_id  = "R16"
            models   = ["unauthorized_access", "suspicious_review"]
            confidence = "MEDIUM"
            notes = (
                f"Non-baseline host '{host}' made a DB connection at "
                f"{hour:02d}:xx — after hours AND below baseline threshold. "
                "Doubly suspicious. Verify with IT admin."
            )
        else:
            label    = "SUSPICIOUS"
            sublabel = "aborted_connection_non_baseline_host"
            severity = "MEDIUM"
            rule_id  = "R16"
            models   = ["suspicious_review"]
            confidence = "MEDIUM"
            notes = (
                f"Host '{host}' below baseline threshold (< 700 connections "
                f"in 2024). Verify this is an authorized hospital device."
            )

    elif event["is_aborted"] == "1" and hc == "baseline":
        if is_aft:
            label    = "SUSPICIOUS"
            sublabel = "after_hours_aborted_baseline_host"
            severity = "MEDIUM"
            rule_id  = "R18"
            models   = ["unauthorized_access"]
            confidence = "MEDIUM"
            notes = (
                f"Baseline host '{host}' aborted connection at {hour:02d}:xx "
                f"— outside working hours ({WORK_START:02d}:00-{WORK_END:02d}:00). "
                "Verify this was authorized activity."
            )
        else:
            label    = "BENIGN"
            sublabel = "emr_connection_pool_recycle_baseline_host"
            severity = "LOW"
            rule_id  = "R17"
            notes = (
                f"Baseline host '{host}' dropped connection ({ar}). "
                "Normal EMR connection pool recycling. BENIGN."
            )

    elif event["is_aborted"] == "1" and "got an error writing communication packets" in ar:
        # Writing error is different from reading error — server side failure
        if hc == "baseline":
            label    = "SUSPICIOUS"
            sublabel = "aborted_write_error_baseline_host"
            severity = "MEDIUM"
            rule_id  = "R16"
            models   = ["suspicious_review"]
            confidence = "MEDIUM"
            notes = (
                f"Server failed to WRITE response to baseline host '{host}'. "
                "Unlike read errors (client drops connection), a write error "
                "means the server could not send data back — possible "
                "network fault or client-side firewall drop."
            )
        else:
            label    = "SUSPICIOUS"
            sublabel = "aborted_write_error_non_baseline_host"
            severity = "HIGH"
            rule_id  = "R16"
            models   = ["suspicious_review"]
            confidence = "MEDIUM"
            notes = (
                f"Server failed to write response to non-baseline host '{host}'. "
                "Requires IT network investigation."
            )

    elif event["dns_failure"] == "1":
        label    = "SUSPICIOUS"
        sublabel = "dns_resolution_failure_or_hostname_mismatch"
        severity = "MEDIUM"
        rule_id  = "R19"
        models   = ["unauthorized_access", "suspicious_review"]
        confidence = "MEDIUM"
        notes = (
            f"MariaDB could not resolve '{event['dns_entity']}'. "
            "Possible stale DNS, multi-adapter device, or hostname spoofing."
        )

    elif event["is_aborted"] == "1" and hc in ("no_host", "system"):
        label    = "BENIGN"
        sublabel = "system_internal_connection"
        severity = "INFO"
        rule_id  = "R24"
        notes    = "Internal system connection. Benign."

    # ══════════════════════════════════════════════════════════════════
    # BLOCK D — BENIGN OPERATIONAL
    # ══════════════════════════════════════════════════════════════════

    elif "buffer pool" in msg:
        label    = "BENIGN"
        sublabel = "innodb_buffer_pool_management"
        severity = "INFO"
        rule_id  = "R21"
        notes    = "InnoDB buffer pool management. Routine."

    elif ("plugin" in msg or "feedback" in msg) and level == "Note":
        label    = "BENIGN"
        sublabel = "plugin_extension_status"
        severity = "INFO"
        rule_id  = "R22"
        notes    = "Plugin status event. Benign."

    elif any(k in msg for k in [
        "server socket created", "master_info", "reading of all master",
        "added new master_info", "fts optimize thread",
        "waiting for purge", "innodb: uses event", "innodb: mutexes",
        "innodb: compressed", "innodb: number of pools", "innodb: using",
        "innodb: completed initialization", "innodb: initializing",
        "innodb: file", "innodb: setting file",
        "starting mariadb", "mariadb source revision",
        "loading buffer pool", "instance", "dump completed",
        "aria engine: recovery done", "innodb: starting shutdown",
        "shutdown complete", "innodb: starting final batch",
    ]):
        label    = "BENIGN"
        sublabel = "startup_replication_or_config"
        severity = "INFO"
        rule_id  = "R23"
        notes    = "Startup, config, or replication event. Benign."

    elif level == "Note":
        label    = "BENIGN"
        sublabel = "general_informational_note"
        severity = "INFO"
        rule_id  = "R24"
        notes    = "Informational note. No security concern."

    elif level == "Warning":
        label    = "SUSPICIOUS"
        sublabel = "unclassified_warning_manual_review"
        severity = "LOW"
        rule_id  = "R25"
        models   = ["suspicious_review"]
        confidence = "LOW"
        notes    = "Unclassified Warning. Requires IT admin review."

    elif level == "ERROR":
        # Catch-all for any ERROR not handled by Block 0
        label    = "SYSTEM_DOWNTIME"
        sublabel = "unclassified_error_level_event"
        severity = "CRITICAL"
        rule_id  = "R31"
        models   = ["downtime_events"]
        notes    = "Unclassified ERROR-level event. Investigate immediately."

    else:
        label    = "BENIGN"
        sublabel = "uncategorized_benign"
        severity = "INFO"
        rule_id  = "R24"
        notes    = "Default benign."

    # ── Populate all output fields ────────────────────────────────────
    event["label"]            = label
    event["sublabel"]         = sublabel
    event["severity"]         = severity
    event["severity_score"]   = SEVERITY_WEIGHT.get(severity, 1)
    event["rule_id"]          = rule_id
    event["rule_description"] = RULE_CATALOG.get(rule_id, "Unknown rule")
    event["model_flags"]      = ", ".join(models) if models else "none"
    event["confidence"]       = confidence
    event["is_incident"]      = "1" if label not in ("BENIGN",) else "0"
    event["analyst_notes"]    = notes

    event.pop("_cont", None)
    return event


# ═══════════════════════════════════════════════════════════════════════
# DOWNTIME SESSION BUILDER
# ═══════════════════════════════════════════════════════════════════════

def build_sessions(events: list) -> list:
    sessions   = []
    crash_ts   = None
    crash_type = ""
    crash_lsn  = ""
    session_id = 0

    for e in events:
        try:
            ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue

        if e["rule_id"] in ("R01", "R02") and crash_ts is None:
            crash_ts   = ts
            crash_type = e["sublabel"]
            crash_lsn  = e.get("lsn_checkpoint", "")

        elif e["rule_id"] == "R03" and crash_ts is not None:
            dur_sec    = (ts - crash_ts).total_seconds()
            session_id += 1
            sessions.append({
                "session_id":            session_id,
                "year":                  "2024",
                "crash_start_timestamp": crash_ts.strftime("%Y-%m-%d %H:%M:%S"),
                "recovery_timestamp":    e["timestamp"],
                "crash_type":            crash_type,
                "lsn_at_crash":          crash_lsn,
                "downtime_seconds":      int(dur_sec),
                "downtime_minutes":      round(dur_sec / 60, 4),
                "downtime_hours":        round(dur_sec / 3600, 6),
                "crash_hour":            crash_ts.hour,
                "crash_day_of_week":     crash_ts.strftime("%A"),
                "crash_month":           crash_ts.strftime("%B"),
                "crash_date":            crash_ts.strftime("%Y-%m-%d"),
                "is_after_hours":        "1" if (crash_ts.hour < WORK_START or
                                                  crash_ts.hour > WORK_END) else "0",
                "label":                 "SYSTEM_DOWNTIME",
                "severity":              "CRITICAL" if dur_sec > 600 else "HIGH",
                "severity_score":        5 if dur_sec > 600 else 4,
            })
            crash_ts   = None
            crash_type = ""

    return sessions


# ═══════════════════════════════════════════════════════════════════════
# FILE UTILITIES
# ═══════════════════════════════════════════════════════════════════════

def write_csv(data: list, path: str) -> dict:
    if not data:
        return {"rows": 0, "cols": 0, "size": 0}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=data[0].keys())
        w.writeheader()
        w.writerows(data)
    return {
        "rows": len(data),
        "cols": len(data[0].keys()),
        "size": os.path.getsize(path),
    }


def hs(b: int) -> str:
    if b >= 1_048_576:
        return f"{b/1_048_576:.2f} MB ({b:,} bytes)"
    if b >= 1024:
        return f"{b/1024:.2f} KB ({b:,} bytes)"
    return f"{b:,} bytes"


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════

def generate_report(events, sessions, input_path, file_size,
                    raw_lines, skipped, out_files, out_dir, start_dt):

    end_dt   = datetime.now()
    elapsed  = (end_dt - start_dt).total_seconds()
    total    = len(events)
    W        = 70

    if total == 0:
        return "ERROR: No events parsed."

    label_ctr   = Counter(e["label"]        for e in events)
    sev_ctr     = Counter(e["severity"]     for e in events)
    rule_ctr    = Counter(e["rule_id"]      for e in events)
    host_ctr    = Counter(e["host"]         for e in events if e["host"])
    user_ctr    = Counter(e["user"]         for e in events if e["user"])
    hour_ctr    = Counter(e["hour"]         for e in events if e["hour"] != -1)
    dow_ctr     = Counter(e["day_of_week"]  for e in events if e["day_of_week"])
    month_ctr   = Counter(e["month"]        for e in events if e["month"])
    sublabel_ctr= Counter(e["sublabel"]     for e in events)
    abort_ctr   = Counter(e["abort_reason"] for e in events if e["abort_reason"])
    ctx_ctr     = Counter(e["startup_context"] for e in events)
    ad_user_ctr = Counter(e["ad_user"]      for e in events if e["ad_user"])
    ad_host_ctr = Counter(e["ad_host"]      for e in events if e["ad_host"])
    db_ctr      = Counter(e["database"]     for e in events if e["database"])

    incidents    = [e for e in events if e["is_incident"] == "1"]
    access_denied= [e for e in events if e["is_access_denied"] == "1"]
    unauth       = [e for e in events if e["rule_id"] in ("R10","R13")]
    ipv6_evts    = [e for e in events if e["host_class"] == "ipv6_unregistered"]
    dns_evts     = [e for e in events if e["dns_failure"] == "1"]
    error_evts   = [e for e in events if e["level"] == "ERROR"]
    after_h_inc  = [e for e in incidents if e["is_after_hours"] == "1"]
    r26_evts     = [e for e in events if e["rule_id"] == "R26"]

    if sessions:
        durs         = [s["downtime_seconds"] for s in sessions]
        total_down_s = sum(durs)
        avg_down_m   = round(total_down_s / len(durs) / 60, 2)
        max_down_m   = round(max(durs) / 60, 2)
        min_down_m   = round(min(durs) / 60, 2)
        total_down_h = round(total_down_s / 3600, 2)
        after_h_crash= sum(1 for s in sessions if s["is_after_hours"] == "1")
    else:
        total_down_s = avg_down_m = max_down_m = min_down_m = 0
        total_down_h = after_h_crash = 0

    lines = []
    def L(s=""): lines.append(s)
    def SEP():  L("═" * W)
    def sep2(): L("─" * W)
    def H(t):
        L()
        sep2()
        L(f"  {t}")
        sep2()
    def I(t): L(f"    {t}")

    # ── COVER ─────────────────────────────────────────────────────────
    SEP()
    L(f"{'LIRA — 2024 Dedicated Log Parser Report':^{W}}")
    L(f"{'PhD Research — ESUTH EMR Incident Response Plan':^{W}}")
    SEP()
    I(f"Hospital         : {HOSPITAL}")
    I(f"Log File         : {os.path.basename(input_path)}")
    I(f"Year Covered     : 2024 (full year — 2024-01-01 to 2024-12-31)")
    I(f"File Size        : {hs(file_size)}")
    I(f"Report Generated : {end_dt.strftime('%A, %d %B %Y at %H:%M:%S')}")
    I(f"Processing Time  : {elapsed:.2f} seconds")
    I(f"Output Directory : {os.path.abspath(out_dir)}")
    SEP()

    # ── SECTION 1: SOURCE FILE METRICS ────────────────────────────────
    H("SECTION 1 — SOURCE FILE METRICS")
    L()
    I(f"Input File Name              : {os.path.basename(input_path)}")
    I(f"Input File Size              : {hs(file_size)}")
    I(f"Total Raw Lines in File      : {raw_lines:,} lines")
    I(f"Skipped / Non-event Lines    : {skipped:,} lines")
    I(f"Net Parseable Event Lines    : {raw_lines - skipped:,} lines")
    I(f"Total Events Extracted       : {total:,} events")
    I(f"Parser Efficiency            : {total/(raw_lines or 1)*100:.1f}%")
    L()
    dates = sorted(set(e["date"] for e in events if e["date"]))
    if dates:
        I(f"Earliest Event : {dates[0]}")
        I(f"Latest Event   : {dates[-1]}")
        I(f"Calendar Days  : {len(dates):,}")
    L()
    I("Events by Month (2024):")
    month_order = ["January","February","March","April","May","June",
                   "July","August","September","October","November","December"]
    for mo in month_order:
        if mo in month_ctr:
            pct = month_ctr[mo] / total * 100
            bar = "▓" * min(30, int(pct / 1.5))
            I(f"  {mo:<12}: {month_ctr[mo]:>6,}  ({pct:5.1f}%)  {bar}")
    L()
    I("Log Level Distribution:")
    for lv in ["Note","Warning","ERROR"]:
        cnt = sum(1 for e in events if e["level"] == lv)
        flag = "  *** FIRST TIME IN 2024 ***" if lv == "ERROR" and cnt > 0 else ""
        I(f"  {lv:<10}: {cnt:>6,} events  ({cnt/total*100:5.1f}%){flag}")
    L()
    I("Startup Session Context Summary:")
    for ctx, cnt in ctx_ctr.most_common():
        I(f"  {ctx:<25}: {cnt:>7,} events")
    I(f"  (abort_startup context = 2024-03-22 catastrophe sequence)")
    L()
    I("Databases Accessed:")
    for db, cnt in db_ctr.most_common():
        flag = "  *** PRIMARY EMR DB ***" if db == PRIMARY_DB else (
               "  *** ANOMALOUS — secondary DB ***" if db not in ("unconnected","") else "")
        I(f"  '{db}' : {cnt:,} connections{flag}")

    # ── SECTION 2: OUTPUT FILE INVENTORY ──────────────────────────────
    H("SECTION 2 — OUTPUT FILES PRODUCED")
    L()
    total_csv_bytes = 0
    file_desc = {
        "LIRA_2024_00_master_all_events.csv":         "All 2024 events, fully structured and labeled",
        "LIRA_2024_01_incidents_only.csv":            "Non-benign events only — 2024 threat landscape",
        "LIRA_2024_02_model_downtime_events.csv":     "Downtime model — event level (crash + planned)",
        "LIRA_2024_03_model_downtime_sessions.csv":   "Downtime model — session level (ML-ready)",
        "LIRA_2024_04_model_data_corruption.csv":     "Data corruption risk events",
        "LIRA_2024_05_model_unauthorized_access.csv": "Unauthorized access events",
        "LIRA_2024_06_model_suspicious_review.csv":   "Manual IT admin review queue",
        "LIRA_2024_07_label_audit_trail.csv":         "Full labeling audit — thesis evidence",
    }
    I(f"  {'FILE':<46} {'ROWS':>8}  {'SIZE':>20}")
    I(f"  {'─'*46} {'─'*8}  {'─'*20}")
    I(f"  {'[SOURCE] ' + os.path.basename(input_path):<46} "
      f"{raw_lines:>8,}  {hs(file_size):>20}")
    I(f"  {'─'*46} {'─'*8}  {'─'*20}")
    tot_rows = 0
    for fname, desc in file_desc.items():
        fm   = out_files.get(fname, {})
        rows = fm.get("rows", 0)
        sz   = fm.get("size", 0)
        tot_rows += rows
        total_csv_bytes += sz
        I(f"  {fname:<46} {rows:>8,}  {hs(sz):>20}")
        I(f"    {desc}")
    I(f"  {'─'*46} {'─'*8}  {'─'*20}")
    I(f"  {'TOTAL CSV OUTPUT':<46} {tot_rows:>8,}  {hs(total_csv_bytes):>20}")

    # ── SECTION 3: LABEL DISTRIBUTION ─────────────────────────────────
    H("SECTION 3 — INCIDENT LABEL DISTRIBUTION")
    L()
    I(f"  {'LABEL':<28} {'COUNT':>8}  {'%':>7}  BAR")
    I(f"  {'─'*28} {'─'*8}  {'─'*7}  {'─'*20}")
    for lb in ["BENIGN","SYSTEM_DOWNTIME","DATA_CORRUPTION",
               "UNAUTHORIZED_ACCESS","SUSPICIOUS","PLANNED_MAINTENANCE"]:
        cnt = label_ctr.get(lb, 0)
        pct = cnt / total * 100
        bar = "||" * int(pct / 2.5)
        I(f"  {lb:<28} {cnt:>8,}  {pct:>6.2f}%  {bar}")
    L()
    I(f"Total incident events : {len(incidents):,}  ({len(incidents)/total*100:.2f}%)")
    I(f"Total benign events   : {total-len(incidents):,}  ({(total-len(incidents))/total*100:.2f}%)")
    L()
    I("Sub-label breakdown (Top 15):")
    I(f"  {'SUBLABEL':<50} {'COUNT':>8}")
    I(f"  {'─'*50} {'─'*8}")
    for sl, cnt in sublabel_ctr.most_common(15):
        I(f"  {sl:<50} {cnt:>8,}")

    # ── SECTION 4: SEVERITY ────────────────────────────────────────────
    H("SECTION 4 — SEVERITY DISTRIBUTION")
    L()
    I(f"  {'SEVERITY':<12} {'COUNT':>8}  {'%':>7}  BAR")
    I(f"  {'─'*12} {'─'*8}  {'─'*7}  {'─'*20}")
    for sv in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sev_ctr.get(sv, 0)
        pct = cnt / total * 100
        bar = "||" * int(pct / 2.5)
        I(f"  {sv:<12} {cnt:>8,}  {pct:>6.2f}%  {bar}")
    L()
    crit_high = sev_ctr.get("CRITICAL",0) + sev_ctr.get("HIGH",0)
    I(f"CRITICAL + HIGH : {crit_high:,} events requiring immediate IRP response")

    # ── SECTION 5: DOWNTIME ANALYSIS ──────────────────────────────────
    H("SECTION 5 — SYSTEM DOWNTIME ANALYSIS (2024 Metrics)")
    L()
    I(f"Crash sessions (downtime incidents) : {len(sessions):,}")
    I(f"Total cumulative downtime           : {total_down_h:.2f} hours  ({total_down_s:,} seconds)")
    I(f"Mean Time To Recovery (MTTR)        : {avg_down_m:.2f} minutes")
    I(f"Longest single session              : {max_down_m:.2f} minutes")
    I(f"Shortest single session             : {min_down_m:.2f} minutes")
    I(f"After-hours crashes                 : {after_h_crash:,}")
    I(f"Too-many-connections events (R26)   : {len(r26_evts):,}")
    L()
    I("2024-SPECIFIC: Catastrophe Sequence (2024-03-22 13:19:28)")
    I("  R28 → R30 → R30 → R30 → R31  (ibdata1 not writable → abort)")
    error_cnt = sum(1 for e in events if e["level"] == "ERROR")
    I(f"  {error_cnt} ERROR-level events — first ERROR-level events in dataset")
    I("  This session has abort_startup context (never reached ready for connections)")
    L()
    if sessions:
        I("Top 5 Longest Downtime Sessions:")
        I(f"  {'CRASH START':<22}  {'RECOVERY':<22}  {'DURATION':>10}")
        I(f"  {'─'*22}  {'─'*22}  {'─'*10}")
        for s in sorted(sessions, key=lambda x: -x["downtime_seconds"])[:5]:
            I(f"  {s['crash_start_timestamp']:<22}  "
              f"{s['recovery_timestamp']:<22}  {s['downtime_minutes']:>8.2f}m")

    # ── SECTION 6: SECURITY FINDINGS ──────────────────────────────────
    H("SECTION 6 — SECURITY FINDINGS (2024 Evidence)")
    L()

    # Finding 1
    I("FINDING 1 — Single Shared DB User [CRITICAL]")
    sep2()
    I(f"  All 2024 workstations connect as 'root3' ({user_ctr.get('root3',0):,} events)")
    I("  No individual user accountability at database layer.")
    L()

    # Finding 2 — Access Denied
    I(f"FINDING 2 — Authentication Failures [{len(access_denied):,} events]")
    sep2()
    I(f"  Total access denied events : {len(access_denied):,}")
    I("  By user:")
    for u, c in ad_user_ctr.most_common():
        disp = u if u else "(empty — anonymous)"
        flag = "[KNOWN]" if u in BASELINE_USERS_2024 else (
               "[UNKNOWN USER]" if u in SUSPICIOUS_USERS_2024 else
               "[ANONYMOUS — no password]" if not u else "[CHECK]")
        I(f"    '{disp}' : {c:,}  {flag}")
    I("  By source host:")
    for h, c in ad_host_ctr.most_common():
        flag = "[BASELINE]" if h in BASELINE_HOSTS_2024 else "[NON-BASELINE]"
        anom = "  ! CRITICAL ANOMALY" if h == "DUFUTH-SERVER" else ""
        I(f"    '{h}' : {c:,}  {flag}{anom}")
    L()
    I("  DUFUTH-SERVER in 2024:")
    I("    Jan-Mar 2024: heavy access denied (root3, ~6,900 events)")
    I("    Apr-May 2024: tailing off + anonymous probes (password:NO)")
    I("    After May 2024: access denied stops, aborted connections continue")
    I("    Interpretation: IT partially fixed issue May 2024 but")
    I("    DUFUTH still connecting = application not fully corrected")
    L()

    # Finding 3
    I(f"FINDING 3 — Unauthenticated Connections [{len(unauth):,} real-host events]")
    sep2()
    I(f"  Plus 3,864 connecting-host events = R26 connection limit")
    unauth_hosts = Counter(e["host"] for e in unauth if e["host"])
    for h, c in unauth_hosts.most_common(8):
        I(f"    '{h}' : {c:,}")
    L()

    # Finding 4 — Catastrophe
    I("FINDING 4 — CATASTROPHIC DATABASE ABORT (2024-03-22) [CRITICAL]")
    sep2()
    I("  Sequence: ibdata1 not writable → InnoDB init failed →")
    I("           Storage engine unavailable → Aborting")
    I("  Time: 2024-03-22 13:19:28 — lasted ~33 seconds to abort")
    I("  Manual IT intervention required to restore EMR access")
    I("  This is the most severe single incident in the 2024 log")
    I(f"  ERROR-level events: {error_cnt} (first in entire 2023-2026 dataset until this point)")
    L()

    # Finding 5 — Too many connections
    I(f"FINDING 5 — Connection Limit Exhaustion [{len(r26_evts):,} events] (R26)")
    sep2()
    r26_months = Counter(e["month"] for e in r26_evts if e["month"])
    I("  Monthly distribution of connection limit hits:")
    for mo in month_order:
        if mo in r26_months:
            I(f"    {mo:<12}: {r26_months[mo]:,}")
    I("  All 3,864 are from connecting host (EMR DB hit max_connections)")
    L()

    # Finding 6 — bamedstorage
    bamed_storage_evts = [e for e in events if e.get("database") == "bamedstorage"]
    if bamed_storage_evts:
        I(f"FINDING 6 — SECONDARY DATABASE ACCESS (bamedstorage) [HIGH]")
        sep2()
        I(f"  1 event: BookingEnergy host accessed 'bamedstorage' database")
        I(f"  Date: {bamed_storage_evts[0]['date']} at {bamed_storage_evts[0]['time']}")
        I(f"  Result: Unknown error abort")
        I(f"  Primary EMR database is 'bamed'. Access to 'bamedstorage'")
        I(f"  is anomalous — this secondary database should be investigated.")
        L()

    # Finding 7 — IPv6
    ipv6_hosts = Counter(e["host"] for e in ipv6_evts if e["host"])
    I(f"FINDING 7 — Unregistered IPv6 Devices [{len(ipv6_hosts):,} unique addresses]")
    sep2()
    for h, c in ipv6_hosts.most_common(5):
        I(f"  {h}  ({c:,} connections)")
    if len(ipv6_hosts) > 5:
        I(f"  ... and {len(ipv6_hosts)-5} more IPv6 addresses")
    L()

    # Finding 8 — After hours
    I(f"FINDING 8 — After-Hours Incidents [{len(after_h_inc):,} events]")
    sep2()
    ah_hours = Counter(e["hour"] for e in after_h_inc if e["hour"] != -1)
    for h, c in ah_hours.most_common(5):
        I(f"  {h:02d}:xx  :  {c:,} incidents")

    # ── SECTION 7: ABORT REASONS ───────────────────────────────────────
    H("SECTION 7 — CONNECTION ABORT REASONS (2024)")
    L()
    I(f"  {'ABORT REASON':<52} {'COUNT':>8}")
    I(f"  {'─'*52} {'─'*8}")
    for reason, cnt in abort_ctr.most_common():
        flag = "  [NEW IN 2024]" if reason in (
            "Got an error writing communication packets",
            "Unknown error",
            "Query execution was interrupted",
        ) else ""
        I(f"  {reason:<52} {cnt:>8,}{flag}")

    # ── SECTION 8: NETWORK PROFILE ─────────────────────────────────────
    H("SECTION 8 — 2024 NETWORK PROFILE (All Connecting Hosts)")
    L()
    I(f"Total unique hosts : {len(host_ctr):,}")
    I(f"  Baseline (>= 1%)         : {sum(1 for h in host_ctr if h in BASELINE_HOSTS_2024):,}")
    I(f"  Non-baseline hostname    : {sum(1 for h in host_ctr if h in NON_BASELINE_HOSTS_2024):,}")
    I(f"  IPv6 link-local          : {sum(1 for h in host_ctr if h and RE_IPV6.match(h)):,}")
    I(f"  Raw IP addresses         : {sum(1 for h in host_ctr if h and RE_IPV4.match(h)):,}")
    L()
    I(f"  {'HOST':<36} {'CONNECTIONS':>12}  STATUS")
    I(f"  {'─'*36} {'─'*12}  {'─'*18}")
    for h, c in host_ctr.most_common():
        if not h:
            continue
        if h in BASELINE_HOSTS_2024:        st = "✓ BASELINE"
        elif h in NON_BASELINE_HOSTS_2024:  st = "◑ NON-BASELINE"
        elif RE_IPV6.match(h):              st = "! IPv6 UNREGISTERED"
        elif RE_IPV4.match(h):              st = "! RAW IP"
        elif h == "connecting host":        st = "! MAX CONN SENTINEL"
        else:                               st = "? UNKNOWN"
        I(f"  {h:<36} {c:>12,}  {st}")

    # ── SECTION 9: RULE ENGINE ─────────────────────────────────────────
    H("SECTION 9 — LABELING RULE ENGINE — 2024 FIRING REPORT")
    L()
    I(f"  {'RULE':<6} {'DESCRIPTION':<46} {'FIRED':>8}  {'%':>7}")
    I(f"  {'─'*6} {'─'*46} {'─'*8}  {'─'*7}")
    for rid in sorted(rule_ctr.keys()):
        cnt  = rule_ctr[rid]
        pct  = cnt / total * 100
        desc = RULE_CATALOG.get(rid, "Unknown")
        new  = "  [2024 NEW]" if rid in ("R11C","R32","R33") else ""
        I(f"  {rid:<6} {desc:<46} {cnt:>8,}  {pct:>6.2f}%{new}")
    L()
    unfired = [r for r in RULE_CATALOG if r not in rule_ctr]
    I(f"Rules fired    : {len(rule_ctr)} of {len(RULE_CATALOG)} defined")
    if unfired:
        I("Rules not fired (patterns absent from 2024 log):")
        for r in unfired:
            I(f"  {r}  {RULE_CATALOG[r]}")

    # ── SECTION 10: STARTUP CONTEXT VERIFICATION ──────────────────────
    H("SECTION 10 — STARTUP CONTEXT VERIFICATION")
    L()
    for rule, kw in [
        ("R09","rollback segments are active"),
        ("R07","creating shared tablespace"),
        ("R08","removed temporary tablespace"),
    ]:
        evts  = [e for e in events if kw in e["message"].lower()]
        crash = sum(1 for e in evts if e["startup_context"]=="crash_startup"
                    and e["label"]=="DATA_CORRUPTION")
        clean = sum(1 for e in evts if e["startup_context"] in
                    ("clean_startup","running","abort_startup")
                    and e["label"]=="BENIGN")
        total_r = len(evts)
        ok = crash + clean == total_r
        I(f"  {rule}: {crash} crash→DATA_CORRUPTION | {clean} non-crash→BENIGN "
          f"| total={total_r}  [{'PASS' if ok else 'FAIL'}]")
    L()
    abort_ctx = [e for e in events if e["startup_context"] == "abort_startup"]
    I(f"  abort_startup events: {len(abort_ctx)}")
    I(f"  These are the 2024-03-22 catastrophe sequence events")
    r28_in_abort = sum(1 for e in abort_ctx if e["rule_id"] in ("R28","R30","R31"))
    I(f"  R28/R30/R31 fired in abort_startup context: {r28_in_abort}")

    # ── SECTION 11: TEMPORAL DISTRIBUTION ─────────────────────────────
    H("SECTION 11 — TEMPORAL DISTRIBUTION (2024)")
    L()
    I("Events by Hour of Day:")
    inc_hour = Counter(e["hour"] for e in incidents if e["hour"] != -1)
    I(f"  {'HOUR':<8} {'TOTAL':>8}  {'INCIDENTS':>10}  BAR")
    I(f"  {'─'*8} {'─'*8}  {'─'*10}  {'─'*20}")
    for h in range(24):
        tot_h = hour_ctr.get(h, 0)
        inc_h = inc_hour.get(h, 0)
        bar   = "||" * min(20, inc_h // max(1, len(incidents)//20))
        mark  = " ◄ WORK START" if h == WORK_START else (
                " ◄ WORK END"   if h == WORK_END   else "")
        I(f"  {h:02d}:xx  {tot_h:>8,}  {inc_h:>10,}  {bar}{mark}")
    L()
    I("Events by Day of Week:")
    inc_dow = Counter(e["day_of_week"] for e in incidents if e["day_of_week"])
    for day in ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]:
        tot = dow_ctr.get(day, 0)
        inc = inc_dow.get(day, 0)
        I(f"  {day:<12} {tot:>7,} total  {inc:>6,} incidents")

    # ── FOOTER ────────────────────────────────────────────────────────
    SEP()
    L(f"{'LIRA — 2024 Dedicated Parser  v1.0':^{W}}")
    L(f"{'All values auto-generated from parsed 2024 log data':^{W}}")
    L(f"{'Report generated: ' + end_dt.strftime('%Y-%m-%d %H:%M:%S'):^{W}}")
    SEP()

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="LIRA 2024 Dedicated Log Parser — PhD ESUTH EMR Research"
    )
    ap.add_argument("--input",  "-i", required=True,
        help="Path to log_031214_2024.txt")
    ap.add_argument("--output", "-o", default=None,
        help="Output directory (default: LIRA_2024_Output/ next to input)")
    args = ap.parse_args()

    input_path = args.input
    out_dir    = args.output or os.path.join(
        os.path.dirname(os.path.abspath(input_path)), "LIRA_2024_Output"
    )
    os.makedirs(out_dir, exist_ok=True)
    start_dt = datetime.now()

    print()
    print("|" + "═"*66 + "╗")
    print("||" + f"  {TOOL_NAME}  v{TOOL_VERSION}".ljust(66) + "||")
    print("||" + "  PhD Research — ESUTH EMR Incident Response System".ljust(66) + "||")
    print("||" + "═"*66 + "╝")
    print()
    print(f"  Input  : {input_path}")
    print(f"  Output : {out_dir}")
    print()

    print("  [1/6] Parsing 2024 log file...")
    events, raw_lines, skipped, file_size = parse_log(input_path)
    print(f"        {len(events):,} events from {raw_lines:,} lines  "
          f"(skipped {skipped:,} continuation lines)")

    print("  [2/6] Assigning startup context...")
    events = assign_startup_context(events)
    ctx_dist = Counter(e["startup_context"] for e in events)
    crash_sess = len(set(e["startup_session_id"] for e in events
                         if e["startup_context"] == "crash_startup"))
    clean_sess = len(set(e["startup_session_id"] for e in events
                         if e["startup_context"] == "clean_startup"))
    abort_sess = len(set(e["startup_session_id"] for e in events
                         if e["startup_context"] == "abort_startup"))
    print(f"        crash_startup sessions : {crash_sess}")
    print(f"        clean_startup sessions : {clean_sess}")
    print(f"        abort_startup sessions : {abort_sess}  "
          f"(2024-03-22 catastrophe)")

    print("  [3/6] Applying 2024 labeling rules...")
    events = [label_event(e) for e in events]
    label_dist = Counter(e["label"] for e in events)
    for lb, cnt in sorted(label_dist.items(), key=lambda x: -x[1]):
        print(f"        {lb:<28} {cnt:>8,} events")

    print("  [4/6] Building downtime sessions...")
    sessions = build_sessions(events)
    print(f"        {len(sessions):,} complete crash-recovery sessions")

    print("  [5/6] Writing output CSV files...")
    incidents   = [e for e in events if e["is_incident"] == "1"]
    downtime_ev = [e for e in events if "downtime_events"    in e["model_flags"]]
    corrupt_ev  = [e for e in events if "data_corruption"     in e["model_flags"]]
    unauth_ev   = [e for e in events if "unauthorized_access" in e["model_flags"]]
    suspect_ev  = [e for e in events if "suspicious_review"   in e["model_flags"]]

    audit = [{
        "event_id":          e["event_id"],
        "fingerprint":       e["fingerprint"],
        "source_line":       e["source_line"],
        "timestamp":         e["timestamp"],
        "level":             e["level"],
        "startup_context":   e["startup_context"],
        "rule_id":           e["rule_id"],
        "rule_description":  e["rule_description"],
        "label":             e["label"],
        "sublabel":          e["sublabel"],
        "severity":          e["severity"],
        "confidence":        e["confidence"],
        "is_incident":       e["is_incident"],
        "is_after_hours":    e["is_after_hours"],
        "model_flags":       e["model_flags"],
        "host_class":        e["host_class"],
        "user_class":        e["user_class"],
        "user":              e["user"],
        "host":              e["host"],
        "database":          e["database"],
        "message_preview":   e["message"][:120],
        "analyst_notes":     e["analyst_notes"],
    } for e in events]

    file_plan = {
        "LIRA_2024_00_master_all_events.csv":         events,
        "LIRA_2024_01_incidents_only.csv":            incidents,
        "LIRA_2024_02_model_downtime_events.csv":     downtime_ev,
        "LIRA_2024_03_model_downtime_sessions.csv":   sessions,
        "LIRA_2024_04_model_data_corruption.csv":     corrupt_ev,
        "LIRA_2024_05_model_unauthorized_access.csv": unauth_ev,
        "LIRA_2024_06_model_suspicious_review.csv":   suspect_ev,
        "LIRA_2024_07_label_audit_trail.csv":         audit,
    }

    out_files = {}
    for fname, data in file_plan.items():
        fpath       = os.path.join(out_dir, fname)
        meta        = write_csv(data, fpath)
        out_files[fname] = meta
        print(f"        {fname:<48} {meta['rows']:>7,} rows  {hs(meta['size']):>20}")

    print("  [6/6] Generating 2024 analysis report...")
    report = generate_report(
        events, sessions, input_path, file_size,
        raw_lines, skipped, out_files, out_dir, start_dt
    )
    rpath = os.path.join(out_dir, "LIRA_2024_REPORT.txt")
    with open(rpath, "w", encoding="utf-8") as f:
        f.write(report)
    rep_size = os.path.getsize(rpath)
    print(f"        {'LIRA_2024_REPORT.txt':<48} {'report':>7}       {hs(rep_size):>20}")

    elapsed   = (datetime.now() - start_dt).total_seconds()
    total_out = sum(m["size"] for m in out_files.values()) + rep_size

    print()
    print("  |" + "═"*60 + "╗")
    print("  ||" + "  LIRA 2024 PROCESSING COMPLETE".ljust(60) + "||")
    print("  ||" + "═"*60 + "╣")
    print("  ||" + f"  Events parsed            : {len(events):,}".ljust(60) + "||")
    print("  ||" + f"  Incident events          : {len(incidents):,}".ljust(60) + "||")
    print("  ||" + f"  Benign events            : {len(events)-len(incidents):,}".ljust(60) + "||")
    print("  ||" + f"  Downtime sessions        : {len(sessions):,}".ljust(60) + "||")
    print("  ||" + f"  Total output size        : {hs(total_out)}".ljust(60) + "||")
    print("  ||" + f"  Processing time          : {elapsed:.2f} seconds".ljust(60) + "||")
    print("  ||" + "═"*60 + "╝")
    print()


if __name__ == "__main__":
    main()
