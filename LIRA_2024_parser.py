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


TOOL_NAME    = "LIRA — 2024 Dedicated Log Parser"
TOOL_VERSION = "1.0"
YEAR         = "2024"
HOSPITAL     = "Enugu State University Teaching Hospital (ESUTH)"
PRIMARY_DB   = "bamed"

SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


WORK_START = 7
WORK_END   = 21



BASELINE_USERS_2024 = {"root3"}

SUSPICIOUS_USERS_2024 = {"basoft"}


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



RULE_CATALOG = {
   
    "R01":  "InnoDB crash recovery initiated",
    "R02":  "Aria engine crash recovery initiated",
    "R03":  "Database service restarted — now online",
    "R04":  "Planned normal shutdown initiated",
    "R05":  "InnoDB clean shutdown completed",
    "R06":  "Shutdown sub-sequence event",
    "R26":  "Too many connections — DB connection limit exhausted",
    "R27":  "Table cache mutex contention — performance degradation",
   
    "R07":  "Temp tablespace recreated — crash context only",
    "R08":  "Stale temp file removed — crash context only",
    "R09":  "Rollback segments activated — crash context only",
  
    "R28":  "InnoDB ibdata1 not writable — critical storage failure",
    "R29":  "InnoDB LSN mismatch — data integrity at risk",
    "R30":  "InnoDB/plugin storage engine failure — service unable to start",
    "R31":  "Database emergency abort — unrecoverable failure",
   
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
   
    "R32":  "Aborted — Unknown error (anomalous connection termination)",
    "R33":  "Aborted — Query execution was interrupted",
   
    "R21":  "InnoDB buffer pool management — benign",
    "R22":  "Plugin or extension status event — benign",
    "R23":  "Startup / replication / config event — benign",
    "R24":  "General informational Note — benign",
    "R25":  "Unclassified Warning — manual review needed",
}



def assign_startup_context(events: list) -> list:

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



def parse_log(filepath: str) -> tuple:
  
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

               
                user = db = host = conn_id = abort_reason = ""
                ab = RE_ABORTED.search(message)
                if ab:
                    conn_id      = ab.group("conn_id")
                    db           = ab.group("db")
                    user         = ab.group("user")
                    host         = ab.group("host")
                    abort_reason = ab.group("reason").strip()

                
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

                #
                dns_m      = RE_DNS.search(message)
                dns_entity = dns_m.group("entity") if dns_m else ""

                
                lsn_m = RE_LSN.search(message)
                lsn   = lsn_m.group(1) if lsn_m else ""

                
                is_aft = (
                    "1" if (hour != -1 and
                           (hour < WORK_START or hour > WORK_END))
                    else "0"
                )

                
                fp = hashlib.sha256(
                    f"{ts_str}|{m.group('thread')}|{message[:100]}".encode()
                ).hexdigest()[:16]

                
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


    elif (hc == "connecting_host_system" and
          "too many connections" in ar):
       
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



    elif (event["is_access_denied"] == "1" and
          ad_pwd == "NO" and
          (not ad_u or ad_u == "__empty__") and
          ad_h == "DUFUTH-SERVER"):
       
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



