"""


USAGE:
    python LIRA_2025_parser.py --input "C:\\path\\to\\log_031214_2025.txt"
"""

import re
import csv
import os
import argparse
import hashlib
from datetime import datetime
from collections import Counter


# ───────────────────────────────────────────────────────────────────────
TOOL_NAME    = "LIRA — 2025 Dedicated Log Parser"
TOOL_VERSION = "1.0"
HOSPITAL     = "Enugu State University Teaching Hospital (ESUTH)"
PRIMARY_DB   = "bamed"
WORK_START   = 7
WORK_END     = 21
SEVERITY_W   = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# ───────────────────────────────────────────────────────────────────────
# 2025 CONFIRMED BASELINE (>= 1,150 connections = 1% of ~115,000)
# ───────────────────────────────────────────────────────────────────────
BASELINE_USERS = {"root3"}

BASELINE_HOSTS = {
    "Emergency-Phamarcy","DESKTOP-EE1TUR0","A-E-BILLING",
    "DESKTOP-20DMDI8","DESKTOP-6UQ9AGN","DESKTOP-7T7ELOQ",
    "DESKTOP-VLAGG25","DESKTOP-45HCUFT","HOU-REVENUE-PC",
    "DESKTOP-H0VKHI9","HOD-PHARMACY","DESKTOP-17O6HNS",
    "DESKTOP-BEFTIQ9","DESKTOP-PUSFV0B","GOPD-Revenue",
    "DESKTOP-T5C63R6","DESKTOP-STLV8TP","DESKTOP-KBNO5SK",
    "A-E-REVENUE","DESKTOP-HG3HT3A","DESKTOP-VBC03FI",
    "DESKTOP-7B1UJP6","DESKTOP-S50VKNJ","DESKTOP-V1SVAAI",
    "DESKTOP-GF78FBP","DESKTOP-1CDJVE5",
}

NON_BASELINE_HOSTS = {
    "DESKTOP-4KC70RJ","DESKTOP-S9861HO","DESKTOP-96GG79H",
    "DESKTOP-057MUID","DESKTOP-0UKNV7K","DESKTOP-SL8VGLQ",
    "DESKTOP-NSBN0U7","Med-Records-1","DESKTOP-F8293EV",
    "DESKTOP-7GDKJ9T","DESKTOP-KSOTEUC","DESKTOP-18ACQQN",
    "DESKTOP-NE61ATE","DESKTOP-6K3CMI9","DESKTOP-DQNJURJ",
    "DUFUTH-SERVER","DESKTOP-COUTBAV","DESKTOP-FSTFVE6",
    "DESKTOP-SR7S8JA","DESKTOP-2DNRJGK","DESKTOP-UOEFDLJ",
    "DESKTOP-56BL7RE","DESKTOP-1BM1MOJ","DESKTOP-PICJ8ID",
    "DESKTOP-LUK4BSP","PAEDIATRIC-CLINIC","DESKTOP-AGH6702",
    "DESKTOP-NVOCDLO","DESKTOP-RH8L10S","DESKTOP-V81NVAT",
    "DESKTOP-623L5RF","Dera","DESKTOP-MHPR0F4","DESKTOP-7HNCJF7",
    "DESKTOP-0B7HROI","DESKTOP-CDSS996","localhost",
    "DESKTOP-HEJ82QI","DESKTOP-0SFCL2D","SMARTLINKS",
    "DESKTOP-LE7D64J","DESKTOP-9P7SE4L","BookingEnergy",
    "DESKTOP-B8QG4NE","DESKTOP-2AGHE6J","DESKTOP-MVCJG67",
    "DESKTOP-3JNEPMU","DESKTOP-R1MIGE4","DESKTOP-CBLB6Q1",
    "DESKTOP-IM2QM8E","DESKTOP-D4NCA3G","DESKTOP-25O5OPP",
    "DESKTOP-J8OM3AM","DESKTOP-26RB4AT",
}

# 28 IPv6 link-local addresses confirmed in 2025
IPV6_HOSTS = {
    "fe80::7483:f083:735:e9e7%27","fe80::b667:6246:3acb:3a82%27",
    "fe80::6063:7357:e409:6d46%27","fe80::2422:9959:1987:7801%27",
    "fe80::7a24:cc42:f3c2:c950%27","fe80::4da7:981d:da2:8b7e%27",
    "fe80::351b:917a:aa04:cb4e%27","fe80::d5a5:5399:5db9:8eab%27",
    "fe80::81c:f95e:c4ca:77ed%27","fe80::b875:c80c:61e2:4435%27",
    "fe80::8c01:73e9:180a:60cd%27","fe80::86ef:ce53:3ea8:2b69%27",
    "fe80::25e7:988:8e8d:5d78%27","fe80::ec03:48e9:d6ec:7d23%27",
    "fe80::5080:f23f:3ffb:d24b%27","fe80::af39:35bc:da85:aa6f%27",
    "fe80::6dac:ef7b:79df:c16e%27","fe80::f866:6e95:9e49:ef70%27",
    "fe80::a6b2:85d5:1010:63fd%27","fe80::ed74:7f9c:d3e0:7b95%27",
    "fe80::8b0:7817:e8e8:e04d%27","fe80::7f83:2299:97e4:4459%27",
    "fe80::6c34:3182:1fb6:4a48%27","fe80::d23a:6c26:4d3d:6905%27",
    "fe80::5961:57c4:aa77:45e0%27","fe80::c0d3:80e2:90b:fd23%27",
    "fe80::672c:77fe:a1e7:548b%27","fe80::56c4:92d4:37ab:9daa%27",
}

RAW_IP_HOSTS = {
    "10.5.50.20","10.5.50.22","10.5.50.17","10.5.50.21",
    "10.5.50.18","10.5.50.8","10.5.50.7","10.5.50.42",
    "10.5.50.23","10.5.50.13","10.5.50.37","10.5.50.35",
    "10.5.50.3","10.5.50.249","10.5.50.16","10.5.50.11","10.5.50.10",
}

RULE_CATALOG = {
    "R01":"InnoDB crash recovery initiated",
    "R02":"Aria engine crash recovery initiated",
    "R03":"Database service restarted — now online",
    "R04":"Planned normal shutdown initiated",
    "R05":"InnoDB clean shutdown completed",
    "R06":"Shutdown sub-sequence event",
    "R07":"Temp tablespace recreated — crash context only",
    "R08":"Stale temp file removed — crash context only",
    "R09":"Rollback segments activated — crash context only",
    "R10":"Unauthenticated connection from real host",
    "R13":"Aborted — closed without authentication",
    "R14":"Connection from IPv6 link-local unregistered device",
    "R15":"Connection from raw IP address (no hostname)",
    "R16":"Aborted connection from non-baseline host",
    "R17":"Aborted connection from baseline host — benign",
    "R18":"After-hours aborted connection from baseline host",
    "R19":"DNS resolution failure or hostname mismatch",
    "R21":"InnoDB buffer pool management — benign",
    "R22":"Plugin or extension status event — benign",
    "R23":"Startup / replication / config event — benign",
    "R24":"General informational Note — benign",
    "R25":"Unclassified Warning — manual review needed",
    "R27":"Table cache mutex contention — performance degradation",
    "R29":"InnoDB LSN mismatch — data integrity divergence detected",
    "R32":"Aborted — anomalous secondary database access",
}

RE_MAIN = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{1,2}:\d{2}:\d{2})\s+'
    r'(?P<thread>\d+)\s+\[(?P<level>\w+)\]\s+(?P<message>.+)$'
)
RE_ABORTED = re.compile(
    r"Aborted connection\s+(?P<conn_id>\d+)\s+to\s+db:\s*'(?P<db>[^']*)'\s+"
    r"user:\s*'(?P<user>[^']*)'\s+host:\s*'(?P<host>[^']*)'\s*\((?P<reason>[^)]+)\)"
)
RE_DNS = re.compile(
    r"(?:IP address|Host(?:name)?)\s+'(?P<entity>[^']+)'\s+"
    r"(?:could not be resolved|does not resolve to)"
)
RE_LSN     = re.compile(r"LSN=(\d+)")
RE_LSN_MM  = re.compile(
    r"log sequence number\s+(\d+)\s+in the system tablespace does not match"
    r"\s+the log sequence number\s+(\d+)\s+in the ib_logfiles"
)
RE_VER   = re.compile(r"^Version:\s+'")
RE_ARIA_P= re.compile(r"^recovered pages:")
RE_DASH  = re.compile(r"^\s*-\s+\S")
RE_IPV4  = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
RE_IPV6  = re.compile(r'^fe80::')


def assign_startup_context(events):
    for e in events:
        e["startup_context"] = "running"
        e["startup_session_id"] = 0
    session_id = 0
    in_startup = False
    buffer = []
    had_crash = False
    for e in events:
        msg = e["message"].lower()
        if "starting mariadb" in msg:
            if in_startup and buffer:
                ctx = "crash_startup" if had_crash else "clean_startup"
                for be in buffer:
                    be["startup_context"] = ctx
                    be["startup_session_id"] = session_id
            session_id += 1
            in_startup = True
            had_crash = False
            buffer = [e]
            e["startup_context"] = "unknown"
            e["startup_session_id"] = session_id
            continue
        if in_startup:
            e["startup_session_id"] = session_id
            e["startup_context"] = "unknown"
            buffer.append(e)
            if ("innodb: starting crash recovery" in msg or
                    "aria engine: starting recovery" in msg):
                had_crash = True
            if "ready for connections" in msg:
                ctx = "crash_startup" if had_crash else "clean_startup"
                for be in buffer:
                    be["startup_context"] = ctx
                    be["startup_session_id"] = session_id
                in_startup = False
                buffer = []
                had_crash = False
        else:
            e["startup_context"] = "running"
            e["startup_session_id"] = session_id
    if in_startup and buffer:
        ctx = "crash_startup" if had_crash else "clean_startup"
        for be in buffer:
            be["startup_context"] = ctx
            be["startup_session_id"] = session_id
    return events


def parse_log(filepath):
    events = []
    raw_lines = 0
    skipped = 0
    current = None
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
                    hour = -1
                    dow = mon = ""
                    yr = ""
                user = db = host = conn_id = abort_reason = ""
                ab = RE_ABORTED.search(message)
                if ab:
                    conn_id = ab.group("conn_id")
                    db = ab.group("db")
                    user = ab.group("user")
                    host = ab.group("host")
                    abort_reason = ab.group("reason").strip()
                dns_m = RE_DNS.search(message)
                dns_entity = dns_m.group("entity") if dns_m else ""
                lsn_m = RE_LSN.search(message)
                lsn = lsn_m.group(1) if lsn_m else ""
                lsn_mm = RE_LSN_MM.search(message)
                lsn_sys  = lsn_mm.group(1) if lsn_mm else ""
                lsn_logs = lsn_mm.group(2) if lsn_mm else ""
                is_aft = "1" if (hour != -1 and (hour < WORK_START or hour > WORK_END)) else "0"
                fp = hashlib.sha256(f"{ts_str}|{m.group('thread')}|{message[:100]}".encode()).hexdigest()[:16]
                if not host:
                    hc = "no_host"
                elif RE_IPV6.match(host):
                    hc = "ipv6_unregistered"
                elif RE_IPV4.match(host):
                    hc = "raw_ip"
                elif host in BASELINE_HOSTS:
                    hc = "baseline"
                elif host in NON_BASELINE_HOSTS:
                    hc = "non_baseline_known"
                elif host in ("unknown","unconnected"):
                    hc = "system"
                else:
                    hc = "non_baseline_unknown"
                if not user:
                    uc = "no_user"
                elif user == "unauthenticated":
                    uc = "unauthenticated"
                elif user == "unconnected":
                    uc = "system"
                elif user in BASELINE_USERS:
                    uc = "baseline"
                else:
                    uc = "non_baseline_unknown"
                current = {
                    "event_id":len(events)+1,"fingerprint":fp,"source_line":raw_lines,
                    "timestamp":ts_str,"date":date_str,"time":time_str,"hour":hour,
                    "day_of_week":dow,"month":mon,"year":yr,"is_after_hours":is_aft,
                    "thread_id":m.group("thread"),"level":level,"message":message,
                    "user":user,"host":host,"database":db,"connection_id":conn_id,
                    "abort_reason":abort_reason,"dns_failure":"1" if dns_m else "0",
                    "dns_entity":dns_entity,"lsn_checkpoint":lsn,
                    "lsn_mismatch_sys":lsn_sys,"lsn_mismatch_logs":lsn_logs,
                    "is_aborted":"1" if ab else "0",
                    "is_crash_recovery":"1" if "crash recovery" in message.lower() else "0",
                    "is_startup":"1" if "ready for connections" in message.lower() else "0",
                    "is_clean_shutdown":"1" if "normal shutdown" in message.lower() else "0",
                    "is_lsn_mismatch":"1" if lsn_mm else "0",
                    "host_class":hc,"user_class":uc,
                    "startup_context":"","startup_session_id":0,
                    "label":"","sublabel":"","severity":"","severity_score":"",
                    "rule_id":"","rule_description":"","model_flags":"",
                    "confidence":"HIGH","is_incident":"","analyst_notes":"","_cont":0,
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


def label_event(event):
    msg    = event["message"].lower()
    level  = event["level"]
    hour   = event["hour"]
    hc     = event["host_class"]
    uc     = event["user_class"]
    is_aft = event["is_after_hours"] == "1"
    ar     = event["abort_reason"].lower()
    ctx    = event["startup_context"]
    db     = event["database"]
    host   = event["host"]

    label = "BENIGN"; sublabel = "general_informational"; severity = "INFO"
    rule_id = "R24"; models = []; confidence = "HIGH"; notes = ""

    # BLOCK A — DOWNTIME
    if "innodb: starting crash recovery" in msg:
        label="SYSTEM_DOWNTIME"; sublabel="innodb_crash_recovery"; severity="CRITICAL"
        rule_id="R01"; models=["downtime_events","data_corruption"]
        notes=(f"InnoDB crash recovery. LSN={event.get('lsn_checkpoint','')}. "
               "EMR UNAVAILABLE. START of downtime session. "
               "258 crash recoveries in 2025 — only 1 clean shutdown all year.")
    elif "aria engine: starting recovery" in msg:
        label="SYSTEM_DOWNTIME"; sublabel="aria_engine_crash_recovery"; severity="CRITICAL"
        rule_id="R02"; models=["downtime_events","data_corruption"]
        notes="Aria engine crash recovery. Hard failure. EMR UNAVAILABLE."
    elif "ready for connections" in msg:
        label="SYSTEM_DOWNTIME"; sublabel="service_restart_online"; severity="MEDIUM"
        rule_id="R03"; models=["downtime_events"]
        notes="Database restarted. END of downtime session."
    elif "normal shutdown" in msg:
        label="PLANNED_MAINTENANCE"; sublabel="authorized_normal_shutdown"; severity="INFO"
        rule_id="R04"; models=["downtime_events"]
        notes="Authorized clean shutdown. Only 1 such event in all 2025."
    elif "innodb: shutdown completed" in msg or ("shutdown complete" in msg and "innodb" in msg):
        label="PLANNED_MAINTENANCE"; sublabel="innodb_clean_shutdown_complete"; severity="INFO"
        rule_id="R05"; models=["downtime_events"]
        notes="Clean InnoDB shutdown. Confirms authorized maintenance."
    elif (any(k in msg for k in ["event scheduler: purging","fts optimize thread exiting",
         "innodb: starting shutdown","innodb: dumping buffer"]) or
         ("initiated by:" in msg and "shutdown" in msg)):
        label="PLANNED_MAINTENANCE"; sublabel="shutdown_sub_sequence"; severity="INFO"
        rule_id="R06"; models=["downtime_events"]
        notes="Authorized shutdown sub-sequence. Benign."
    elif "table cache mutex contention" in msg:
        label="SYSTEM_DOWNTIME"; sublabel="table_cache_mutex_contention_performance_degradation"
        severity="MEDIUM"; rule_id="R27"; models=["downtime_events"]
        notes="Table cache mutex contention. 9 events July 2025. Query slowdowns for all workstations."

    # BLOCK B — DATA CORRUPTION (including LSN mismatch)
    elif event["is_lsn_mismatch"] == "1":
        label="DATA_CORRUPTION"; sublabel="innodb_lsn_mismatch_system_tablespace_out_of_sync"
        severity="HIGH"; rule_id="R29"; models=["data_corruption"]; confidence="HIGH"
        notes=(f"InnoDB LSN divergence: system tablespace LSN={event['lsn_mismatch_sys']} "
               f"vs ib_logfiles LSN={event['lsn_mismatch_logs']}. "
               "Note-level in 2025 (self-recovering). Still indicates data integrity risk — "
               "committed transactions may not be fully in system tablespace. "
               "2 events: Sep 27 and Oct 1 2025. Same stale sys LSN 1,617,670,912 both times.")
    elif "creating shared tablespace for temporary tables" in msg:
        if ctx == "crash_startup":
            label="DATA_CORRUPTION"; sublabel="temp_tablespace_recreated_post_crash"
            severity="HIGH"; rule_id="R07"; models=["data_corruption"]
            notes="Temp tablespace recreated post-crash. In-progress EMR data at crash time is lost."
        else:
            label="BENIGN"; sublabel="innodb_temp_tablespace_init_normal_startup"
            severity="INFO"; rule_id="R23"; notes="Normal InnoDB startup init. Benign."
    elif "removed temporary tablespace data file" in msg:
        if ctx == "crash_startup":
            label="DATA_CORRUPTION"; sublabel="stale_temp_file_removed_after_crash"
            severity="MEDIUM"; rule_id="R08"; models=["data_corruption"]
            notes="Stale ibtmp1 removed post-crash. Temp table data unrecoverable."
        else:
            label="BENIGN"; sublabel="innodb_temp_file_cleanup_normal_startup"
            severity="INFO"; rule_id="R23"; notes="Normal startup file cleanup. Benign."
    elif "rollback segments are active" in msg:
        if ctx == "crash_startup":
            label="DATA_CORRUPTION"; sublabel="rollback_segments_activated_post_crash"
            severity="MEDIUM"; rule_id="R09"; models=["data_corruption"]
            notes="Rollback segments active post-crash. Mid-write data at crash time not saved."
        else:
            label="BENIGN"; sublabel="innodb_rollback_segments_normal_init"
            severity="INFO"; rule_id="R23"; notes="Normal InnoDB startup. No data risk."

    # BLOCK C — UNAUTHORIZED ACCESS
    elif uc == "unauthenticated" and "closed normally without authentication" in ar:
        label="UNAUTHORIZED_ACCESS"; sublabel="connection_closed_without_authentication"
        severity="HIGH"; rule_id="R13"; models=["unauthorized_access"]
        notes=(f"Connection from '{host}' closed before auth. "
               "105 such events in 2025. Connection pool probe or misconfigured client.")
    elif uc == "unauthenticated":
        label="UNAUTHORIZED_ACCESS"; sublabel="unauthenticated_connection_real_host"
        severity="CRITICAL"; rule_id="R10"; models=["unauthorized_access"]
        notes=(f"Authentication never completed from '{host}'. "
               "210 real-host unauthenticated events in 2025. "
               "Top: DESKTOP-EE1TUR0 (92), DESKTOP-PUSFV0B (14), A-E-BILLING (12).")
    elif hc == "ipv6_unregistered":
        label="SUSPICIOUS"; sublabel="connection_from_ipv6_link_local_unregistered_device"
        severity="HIGH"; rule_id="R14"; models=["unauthorized_access","suspicious_review"]
        confidence="MEDIUM"
        notes=(f"IPv6 link-local '{host}' not in hostname registry. "
               "28 unique IPv6 addresses in 2025. "
               "fe80::7483:f083:735:e9e7%27 most active (1,721 connections).")
    elif hc == "raw_ip":
        label="SUSPICIOUS"; sublabel="connection_from_raw_ip_no_hostname"
        severity="HIGH"; rule_id="R15"; models=["unauthorized_access","suspicious_review"]
        confidence="MEDIUM"
        notes=(f"Raw IP '{host}' — legitimate workstations use hostnames. "
               "Direct IP bypasses hostname-based access controls.")
    elif event["is_aborted"] == "1" and db == "bamedstorage":
        label="SUSPICIOUS"; sublabel="aborted_connection_to_secondary_database_bamedstorage"
        severity="HIGH"; rule_id="R32"; models=["suspicious_review","unauthorized_access"]
        confidence="MEDIUM"
        notes=(f"Host '{host}' accessed 'bamedstorage' — secondary database. "
               "Primary EMR is 'bamed'. bamedstorage growing: 3 events in 2025 "
               "(DESKTOP-LE7D64J, A-E-REVENUE, DESKTOP-7T7ELOQ) vs 1 in 2024. "
               "IT admin must clarify purpose and access controls for this database.")
    elif event["is_aborted"] == "1" and hc in ("non_baseline_known","non_baseline_unknown"):
        if is_aft:
            label="SUSPICIOUS"; sublabel="after_hours_aborted_non_baseline_host"
            severity="HIGH"; rule_id="R16"; models=["unauthorized_access","suspicious_review"]
            confidence="MEDIUM"
            notes=(f"Non-baseline host '{host}' connected at {hour:02d}:xx — "
                   "after hours AND below baseline. Doubly suspicious.")
        else:
            label="SUSPICIOUS"; sublabel="aborted_connection_non_baseline_host"
            severity="MEDIUM"; rule_id="R16"; models=["suspicious_review"]
            confidence="MEDIUM"
            notes=f"Host '{host}' below 2025 baseline (< 1,150 connections). Verify authorization."
    elif event["is_aborted"] == "1" and hc == "baseline":
        if is_aft:
            label="SUSPICIOUS"; sublabel="after_hours_aborted_baseline_host"
            severity="MEDIUM"; rule_id="R18"; models=["unauthorized_access"]
            confidence="MEDIUM"
            notes=(f"Baseline host '{host}' aborted at {hour:02d}:xx — "
                   f"outside working hours ({WORK_START:02d}:00–{WORK_END:02d}:00).")
        else:
            label="BENIGN"; sublabel="emr_connection_pool_recycle_baseline_host"
            severity="LOW"; rule_id="R17"
            notes=f"Baseline host '{host}' dropped connection ({ar}). Normal EMR pool recycling."
    elif event["is_aborted"] == "1" and "got an error writing communication packets" in ar:
        if hc == "baseline":
            label="SUSPICIOUS"; sublabel="aborted_write_error_baseline_host"
            severity="MEDIUM"; rule_id="R16"; models=["suspicious_review"]
            confidence="MEDIUM"
            notes=f"Server write error to '{host}'. Network fault or client-side firewall drop. 45 in 2025."
        else:
            label="SUSPICIOUS"; sublabel="aborted_write_error_non_baseline"
            severity="HIGH"; rule_id="R16"; models=["suspicious_review"]
            notes=f"Server write error to non-baseline '{host}'. Network investigation needed."
    elif event["dns_failure"] == "1":
        label="SUSPICIOUS"; sublabel="dns_resolution_failure_or_hostname_mismatch"
        severity="MEDIUM"; rule_id="R19"; models=["unauthorized_access","suspicious_review"]
        confidence="MEDIUM"
        notes=(f"DNS could not resolve '{event['dns_entity']}'. "
               "Stale DNS, multi-adapter device, or spoofing. 356 events in 2025.")
    elif event["is_aborted"] == "1" and hc in ("no_host","system"):
        label="BENIGN"; sublabel="system_internal_connection"; severity="INFO"
        rule_id="R24"; notes="Internal system connection. Benign."

    # BLOCK D — BENIGN
    elif "buffer pool" in msg:
        label="BENIGN"; sublabel="innodb_buffer_pool_management"; severity="INFO"
        rule_id="R21"; notes="InnoDB buffer pool management. Routine."
    elif ("plugin" in msg or "feedback" in msg) and level == "Note":
        label="BENIGN"; sublabel="plugin_extension_status"; severity="INFO"
        rule_id="R22"; notes="Plugin status event. Benign."
    elif any(k in msg for k in [
        "server socket created","master_info","reading of all master",
        "added new master_info","fts optimize thread","waiting for purge",
        "innodb: uses event","innodb: mutexes","innodb: compressed",
        "innodb: number of pools","innodb: using","innodb: completed",
        "innodb: initializing","innodb: file","innodb: setting file",
        "starting mariadb","mariadb source revision","loading buffer pool",
        "instance","dump completed","aria engine: recovery done",
        "innodb: starting shutdown","shutdown complete","innodb: starting final",
    ]):
        label="BENIGN"; sublabel="startup_replication_or_config"; severity="INFO"
        rule_id="R23"; notes="Startup, config, or replication event. Benign."
    elif level == "Note":
        label="BENIGN"; sublabel="general_informational_note"; severity="INFO"
        rule_id="R24"; notes="Informational note. No security concern."
    elif level == "Warning":
        label="SUSPICIOUS"; sublabel="unclassified_warning_manual_review"; severity="LOW"
        rule_id="R25"; models=["suspicious_review"]; confidence="LOW"
        notes="Unclassified Warning. Requires IT admin review."
    else:
        label="BENIGN"; sublabel="uncategorized_benign"; severity="INFO"
        rule_id="R24"; notes="Default benign."

    event["label"] = label
    event["sublabel"] = sublabel
    event["severity"] = severity
    event["severity_score"] = SEVERITY_W.get(severity, 1)
    event["rule_id"] = rule_id
    event["rule_description"] = RULE_CATALOG.get(rule_id, "Unknown")
    event["model_flags"] = ", ".join(models) if models else "none"
    event["confidence"] = confidence
    event["is_incident"] = "1" if label not in ("BENIGN",) else "0"
    event["analyst_notes"] = notes
    event.pop("_cont", None)
    return event


def build_sessions(events):
    sessions = []
    crash_ts = None; crash_type = ""; crash_lsn = ""; session_id = 0
    for e in events:
        try:
            ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue
        if e["rule_id"] in ("R01","R02") and crash_ts is None:
            crash_ts = ts; crash_type = e["sublabel"]
            crash_lsn = e.get("lsn_checkpoint","")
        elif e["rule_id"] == "R03" and crash_ts is not None:
            dur = (ts - crash_ts).total_seconds()
            session_id += 1
            sessions.append({
                "session_id":session_id,"year":"2025",
                "crash_start_timestamp":crash_ts.strftime("%Y-%m-%d %H:%M:%S"),
                "recovery_timestamp":e["timestamp"],"crash_type":crash_type,
                "lsn_at_crash":crash_lsn,"downtime_seconds":int(dur),
                "downtime_minutes":round(dur/60,4),"downtime_hours":round(dur/3600,6),
                "crash_hour":crash_ts.hour,"crash_day_of_week":crash_ts.strftime("%A"),
                "crash_month":crash_ts.strftime("%B"),"crash_date":crash_ts.strftime("%Y-%m-%d"),
                "is_after_hours":"1" if (crash_ts.hour<WORK_START or crash_ts.hour>WORK_END) else "0",
                "label":"SYSTEM_DOWNTIME",
                "severity":"CRITICAL" if dur>600 else "HIGH",
                "severity_score":5 if dur>600 else 4,
            })
            crash_ts = None; crash_type = ""
    return sessions


def write_csv(data, path):
    if not data:
        return {"rows":0,"cols":0,"size":0}
    with open(path,"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=data[0].keys())
        w.writeheader(); w.writerows(data)
    return {"rows":len(data),"cols":len(data[0].keys()),"size":os.path.getsize(path)}


def hs(b):
    if b>=1_048_576: return f"{b/1_048_576:.2f} MB ({b:,} bytes)"
    if b>=1024: return f"{b/1024:.2f} KB ({b:,} bytes)"
    return f"{b:,} bytes"


def generate_report(events, sessions, input_path, file_size,
                    raw_lines, skipped, out_files, out_dir, start_dt):
    end_dt = datetime.now()
    elapsed = (end_dt - start_dt).total_seconds()
    total = len(events)
    W = 70
    if total == 0:
        return "ERROR: No events parsed."
    label_ctr  = Counter(e["label"]       for e in events)
    sev_ctr    = Counter(e["severity"]    for e in events)
    rule_ctr   = Counter(e["rule_id"]     for e in events)
    host_ctr   = Counter(e["host"]        for e in events if e["host"])
    hour_ctr   = Counter(e["hour"]        for e in events if e["hour"] != -1)
    dow_ctr    = Counter(e["day_of_week"] for e in events if e["day_of_week"])
    month_ctr  = Counter(e["month"]       for e in events if e["month"])
    sublb_ctr  = Counter(e["sublabel"]    for e in events)
    abort_ctr  = Counter(e["abort_reason"] for e in events if e["abort_reason"])
    db_ctr     = Counter(e["database"]    for e in events if e["database"])
    ctx_ctr    = Counter(e["startup_context"] for e in events)
    incidents  = [e for e in events if e["is_incident"]=="1"]
    unauth     = [e for e in events if e["rule_id"] in ("R10","R13")]
    ipv6_evts  = [e for e in events if e["host_class"]=="ipv6_unregistered"]
    dns_evts   = [e for e in events if e["dns_failure"]=="1"]
    lsn_evts   = [e for e in events if e["is_lsn_mismatch"]=="1"]
    bamed_s    = [e for e in events if e.get("database")=="bamedstorage"]
    after_h_i  = [e for e in incidents if e["is_after_hours"]=="1"]
    if sessions:
        durs = [s["downtime_seconds"] for s in sessions]
        total_down_s = sum(durs)
        avg_down_m   = round(total_down_s/len(durs)/60,2)
        max_down_m   = round(max(durs)/60,2)
        min_down_m   = round(min(durs)/60,2)
        total_down_h = round(total_down_s/3600,2)
        after_h_cr   = sum(1 for s in sessions if s["is_after_hours"]=="1")
    else:
        total_down_s=avg_down_m=max_down_m=min_down_m=total_down_h=after_h_cr=0

    lines = []
    def L(s=""): lines.append(s)
    def SEP():  L("═"*W)
    def sep2(): L("─"*W)
    def H(t):   L(); sep2(); L(f"  {t}"); sep2()
    def I(t):   L(f"    {t}")

    SEP()
    L(f"{'LIRA — 2025 Dedicated Log Parser Report':^{W}}")
    L(f"{'PhD Research — ESUTH EMR Incident Response Plan':^{W}}")
    SEP()
    I(f"Hospital         : {HOSPITAL}")
    I(f"Log File         : {os.path.basename(input_path)}")
    I(f"Year Covered     : 2025  (2025-01-02 to 2025-12-31)")
    I(f"File Size        : {hs(file_size)}")
    I(f"Report Generated : {end_dt.strftime('%A, %d %B %Y at %H:%M:%S')}")
    I(f"Processing Time  : {elapsed:.2f} seconds")
    SEP()

    H("SECTION 1 — SOURCE FILE METRICS")
    L()
    I(f"Raw Lines                    : {raw_lines:,}")
    I(f"Skipped Lines                : {skipped:,}")
    I(f"Events Extracted             : {total:,}")
    I(f"Parser Efficiency            : {total/(raw_lines or 1)*100:.1f}%")
    dates = sorted(set(e["date"] for e in events if e["date"]))
    if dates:
        I(f"Earliest / Latest            : {dates[0]}  →  {dates[-1]}")
        I(f"Calendar Days                : {len(dates):,}")
    L()
    I("Events by Month (2025):")
    mo_order = ["January","February","March","April","May","June",
                "July","August","September","October","November","December"]
    for mo in mo_order:
        if mo in month_ctr:
            pct = month_ctr[mo]/total*100
            I(f"  {mo:<12}: {month_ctr[mo]:>7,}  ({pct:5.1f}%)  {'||'*min(30,int(pct/1.5))}")
    L()
    I("Log Level Distribution:")
    for lv in ["Note","Warning","ERROR"]:
        cnt = sum(1 for e in events if e["level"]==lv)
        I(f"  {lv:<10}: {cnt:>7,} ({cnt/total*100:5.1f}%)")
    L()
    I("Startup Context Summary:")
    for ctx, cnt in ctx_ctr.most_common():
        I(f"  {ctx:<25}: {cnt:>7,}")
    L()
    I("Databases Accessed:")
    for db, cnt in db_ctr.most_common():
        flag = ("  *** PRIMARY EMR ***" if db==PRIMARY_DB else
                "  *** ANOMALOUS SECONDARY DB — GROWING ***" if db=="bamedstorage" else "")
        I(f"  '{db}' : {cnt:,}{flag}")

    H("SECTION 2 — OUTPUT FILE INVENTORY")
    L()
    total_csv = 0
    fdescs = {
        "LIRA_2025_00_master_all_events.csv":"All 2025 events, fully structured and labeled",
        "LIRA_2025_01_incidents_only.csv":"Non-benign events — 2025 threat landscape",
        "LIRA_2025_02_model_downtime_events.csv":"Downtime model — event level",
        "LIRA_2025_03_model_downtime_sessions.csv":"Downtime model — session level (ML-ready)",
        "LIRA_2025_04_model_data_corruption.csv":"Data corruption events (incl. LSN mismatch)",
        "LIRA_2025_05_model_unauthorized_access.csv":"Unauthorized access events",
        "LIRA_2025_06_model_suspicious_review.csv":"IT admin review queue",
        "LIRA_2025_07_label_audit_trail.csv":"Full labeling audit — thesis evidence",
    }
    I(f"  {'FILE':<46} {'ROWS':>8}  {'SIZE':>20}")
    I(f"  {'─'*46} {'─'*8}  {'─'*20}")
    I(f"  {'[SOURCE] '+os.path.basename(input_path):<46} {raw_lines:>8,}  {hs(file_size):>20}")
    I(f"  {'─'*46} {'─'*8}  {'─'*20}")
    tot_rows = 0
    for fname, desc in fdescs.items():
        fm = out_files.get(fname, {})
        rows = fm.get("rows",0); sz = fm.get("size",0)
        tot_rows += rows; total_csv += sz
        I(f"  {fname:<46} {rows:>8,}  {hs(sz):>20}")
        I(f"    {desc}")
    I(f"  {'─'*46} {'─'*8}  {'─'*20}")
    I(f"  {'TOTAL CSV OUTPUT':<46} {tot_rows:>8,}  {hs(total_csv):>20}")

    H("SECTION 3 — LABEL DISTRIBUTION")
    L()
    I(f"  {'LABEL':<28} {'COUNT':>8}  {'%':>7}  BAR")
    I(f"  {'─'*28} {'─'*8}  {'─'*7}  {'─'*20}")
    for lb in ["BENIGN","SYSTEM_DOWNTIME","DATA_CORRUPTION",
               "UNAUTHORIZED_ACCESS","SUSPICIOUS","PLANNED_MAINTENANCE"]:
        cnt = label_ctr.get(lb,0)
        pct = cnt/total*100
        I(f"  {lb:<28} {cnt:>8,}  {pct:>6.2f}%  {'||'*int(pct/2.5)}")
    L()
    I(f"Incident events : {len(incidents):,}  ({len(incidents)/total*100:.2f}%)")
    I(f"Benign events   : {total-len(incidents):,}  ({(total-len(incidents))/total*100:.2f}%)")
    L()
    I("Sub-label breakdown (Top 15):")
    I(f"  {'SUBLABEL':<50} {'COUNT':>8}")
    I(f"  {'─'*50} {'─'*8}")
    for sl, cnt in sublb_ctr.most_common(15):
        I(f"  {sl:<50} {cnt:>8,}")

    H("SECTION 4 — SEVERITY DISTRIBUTION")
    L()
    I(f"  {'SEVERITY':<12} {'COUNT':>8}  {'%':>7}")
    I(f"  {'─'*12} {'─'*8}  {'─'*7}")
    for sv in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sev_ctr.get(sv,0)
        I(f"  {sv:<12} {cnt:>8,}  {cnt/total*100:>6.2f}%")

    H("SECTION 5 — DOWNTIME ANALYSIS (2025 Metrics)")
    L()
    I(f"Crash sessions                       : {len(sessions):,}")
    I(f"Total cumulative downtime            : {total_down_h:.2f} hours  ({total_down_s:,} seconds)")
    I(f"Mean Time To Recovery (MTTR)         : {avg_down_m:.2f} minutes")
    I(f"Longest session                      : {max_down_m:.2f} minutes")
    I(f"Shortest session                     : {min_down_m:.2f} minutes")
    I(f"After-hours crashes                  : {after_h_cr:,}")
    I(f"Clean shutdowns entire year          : 1  (258/261 startups were crash recoveries)")
    L()
    I("PhD Note: 258/261 startups were crash recoveries in 2025.")
    I("Only 1 clean shutdown all year — persistent instability.")
    if sessions:
        L()
        I("Top 5 Longest Downtime Sessions:")
        I(f"  {'CRASH START':<22}  {'RECOVERY':<22}  {'DURATION':>10}")
        I(f"  {'─'*22}  {'─'*22}  {'─'*10}")
        for s in sorted(sessions, key=lambda x: -x["downtime_seconds"])[:5]:
            I(f"  {s['crash_start_timestamp']:<22}  {s['recovery_timestamp']:<22}  {s['downtime_minutes']:>8.2f}m")

    H("SECTION 6 — SECURITY FINDINGS (2025 Evidence)")
    L()
    I("FINDING 1 — Single Shared DB User [CRITICAL]")
    sep2()
    I("  root3: 99.8% of all 2025 connections. NDPR violation.")
    L()
    I("FINDING 2 — DUFUTH-SERVER: Access Denied RESOLVED [MEDIUM]")
    sep2()
    dufuth_cnt = host_ctr.get("DUFUTH-SERVER",0)
    I(f"  {dufuth_cnt:,} DUFUTH-SERVER connections in 2025 — ZERO access denied.")
    I("  Timeout (138) + read errors (82) = normal connection pool behavior.")
    I("  Password fix confirmed. But server still connecting — review app config.")
    L()
    I(f"FINDING 3 — Unauthenticated Connections [{len(unauth):,} events]")
    sep2()
    unauth_h = Counter(e["host"] for e in unauth)
    for h, c in unauth_h.most_common(5):
        I(f"  '{h}' : {c:,}")
    L()
    I(f"FINDING 4 — InnoDB LSN Mismatch [{len(lsn_evts):,} events] [HIGH]")
    sep2()
    I("  2025-09-27 and 2025-10-01 — Note level (self-recovering in 2025).")
    I("  System tablespace LSN: 1,617,670,912 (same both dates).")
    I("  ib_logfiles LSN:       1,748,357,644 / 1,759,100,940.")
    I("  Persistent stale sys tablespace — DBA investigation needed.")
    L()
    I(f"FINDING 5 — bamedstorage Secondary DB [{len(bamed_s):,} events] [HIGH]")
    sep2()
    for e in bamed_s:
        I(f"  {e['date']} {e['time']} — '{e['host']}'")
    I("  Growing trend: 1 event in 2024 → 3 in 2025 (different hosts each time).")
    L()
    ipv6_h = Counter(e["host"] for e in ipv6_evts)
    I(f"FINDING 6 — IPv6 Unregistered Devices [{len(ipv6_h):,} unique]")
    sep2()
    for h, c in ipv6_h.most_common(5):
        I(f"  {h}  ({c:,})")
    if len(ipv6_h) > 5:
        I(f"  ... and {len(ipv6_h)-5} more")

    H("SECTION 7 — ABORT REASONS (2025)")
    L()
    I(f"  {'ABORT REASON':<52} {'COUNT':>8}")
    I(f"  {'─'*52} {'─'*8}")
    for r, c in abort_ctr.most_common():
        I(f"  {r:<52} {c:>8,}")
    L()
    I("  NOTE: 'Too many connections' ABSENT — connection limit issue fixed from 2024.")

    H("SECTION 8 — NETWORK PROFILE (All Connecting Hosts)")
    L()
    I(f"  {'HOST':<36} {'CONNECTIONS':>12}  STATUS")
    I(f"  {'─'*36} {'─'*12}  {'─'*18}")
    for h, c in host_ctr.most_common():
        if not h:
            continue
        if h in BASELINE_HOSTS:      st="$ BASELINE"
        elif h in NON_BASELINE_HOSTS: st="◑ NON-BASELINE"
        elif RE_IPV6.match(h):        st="⚠ IPv6 UNREGISTERED"
        elif RE_IPV4.match(h):        st="⚠ RAW IP"
        else:                         st="? UNKNOWN"
        I(f"  {h:<36} {c:>12,}  {st}")

    H("SECTION 9 — RULE ENGINE FIRING REPORT")
    L()
    I(f"  {'RULE':<6} {'DESCRIPTION':<46} {'FIRED':>8}  {'%':>7}")
    I(f"  {'─'*6} {'─'*46} {'─'*8}  {'─'*7}")
    for rid in sorted(rule_ctr.keys()):
        cnt = rule_ctr[rid]; pct = cnt/total*100
        desc = RULE_CATALOG.get(rid,"Unknown")
        I(f"  {rid:<6} {desc:<46} {cnt:>8,}  {pct:>6.2f}%")
    L()
    unfired = [r for r in RULE_CATALOG if r not in rule_ctr]
    I(f"Rules fired : {len(rule_ctr)} of {len(RULE_CATALOG)}")
    if unfired:
        I("Absent from 2025 (patterns not in this file):")
        for r in unfired:
            I(f"  {r}  {RULE_CATALOG[r]}")

    H("SECTION 10 — STARTUP CONTEXT VERIFICATION")
    L()
    for rule, kw in [("R09","rollback segments are active"),
                     ("R07","creating shared tablespace"),
                     ("R08","removed temporary tablespace")]:
        evts = [e for e in events if kw in e["message"].lower()]
        crash = sum(1 for e in evts if e["startup_context"]=="crash_startup" and e["label"]=="DATA_CORRUPTION")
        other = sum(1 for e in evts if e["startup_context"] in ("clean_startup","running") and e["label"]=="BENIGN")
        ok = crash+other == len(evts)
        I(f"  {rule}: {crash} crash→DATA_CORRUPTION | {other} other→BENIGN  [{'PASS' if ok else 'FAIL'}]")
    L()
    I(f"  LSN mismatch (R29): {len(lsn_evts)} events")
    for e in lsn_evts:
        I(f"    {e['date']} {e['time']}  ctx={e['startup_context']}  label={e['label']}")

    H("SECTION 11 — TEMPORAL DISTRIBUTION")
    L()
    inc_hour = Counter(e["hour"] for e in incidents if e["hour"] != -1)
    I(f"  {'HOUR':<8} {'TOTAL':>8}  {'INCIDENTS':>10}  BAR")
    I(f"  {'─'*8} {'─'*8}  {'─'*10}  {'─'*20}")
    for h in range(24):
        tot_h = hour_ctr.get(h,0); inc_h = inc_hour.get(h,0)
        bar = "||"*min(20, inc_h//max(1,len(incidents)//20))
        mark = " ◄ WORK START" if h==WORK_START else (" ◄ WORK END" if h==WORK_END else "")
        I(f"  {h:02d}:xx  {tot_h:>8,}  {inc_h:>10,}  {bar}{mark}")
    L()
    inc_dow = Counter(e["day_of_week"] for e in incidents if e["day_of_week"])
    for day in ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]:
        I(f"  {day:<12} {dow_ctr.get(day,0):>7,} total  {inc_dow.get(day,0):>6,} incidents")

    H("SECTION 12 — 2025 vs 2024 TREND ANALYSIS")
    L()
    I("IMPROVEMENTS (better security posture in 2025 vs 2024):")
    I("  $ Access denied events       :    0   (was 6,932 in 2024)")
    I("  $ DUFUTH access denied       :    0   (was 6,933 in 2024)")
    I("  $ basoft unknown user        :    0   (was 8 in 2024)")
    I("  $ Too many connections       :    0   (was 3,864 in 2024)")
    I("  $ ERROR-level events         :    0   (was 6 in 2024)")
    I("  $ abort_startup sessions     :    0   (was 1 in 2024)")
    L()
    I("CONCERNS (worsening conditions in 2025 vs 2024):")
    I("  x Crash recoveries  : 258   (was 38 in 2024 — 6.8x increase!)")
    I("  x Clean shutdowns   :   1   (was 5 in 2024)")
    I("  x bamedstorage      :   3   (was 1 in 2024 — growing)")
    I("  x LSN mismatch      :   2   (same as 2024 — persisting)")
    I("  x IPv6 devices      :  28   (was 16 in 2024)")
    L()
    I("PhD Thesis: Security improved but infrastructure instability worsened.")
    I("The IRP must address both: proactive crash prevention and automated")
    I("recovery to reduce MTTR and protect EMR data integrity.")

    SEP()
    L(f"{'LIRA — 2025 Dedicated Parser  v1.0':^{W}}")
    L(f"{'Report generated: ' + end_dt.strftime('%Y-%m-%d %H:%M:%S'):^{W}}")
    SEP()

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="LIRA 2025 Dedicated Log Parser")
    ap.add_argument("--input",  "-i", required=True)
    ap.add_argument("--output", "-o", default=None)
    args = ap.parse_args()
    input_path = args.input
    out_dir = args.output or os.path.join(
        os.path.dirname(os.path.abspath(input_path)), "LIRA_2025_Output")
    os.makedirs(out_dir, exist_ok=True)
    start_dt = datetime.now()

    print()
    print("||"+"═"*66+"╗")
    print("||"+f"  {TOOL_NAME}  v{TOOL_VERSION}".ljust(66)+"||")
    print("||"+"  PhD Research — ESUTH EMR Incident Response System".ljust(66)+"||")
    print("||"+"═"*66+"╝")
    print(f"\n  Input  : {input_path}\n  Output : {out_dir}\n")

    print("  [1/6] Parsing 2025 log file...")
    events, raw_lines, skipped, file_size = parse_log(input_path)
    print(f"        {len(events):,} events from {raw_lines:,} lines  (skipped {skipped:,})")

    print("  [2/6] Assigning startup context...")
    events = assign_startup_context(events)
    crash_sess = len(set(e["startup_session_id"] for e in events if e["startup_context"]=="crash_startup"))
    clean_sess = len(set(e["startup_session_id"] for e in events if e["startup_context"]=="clean_startup"))
    print(f"        crash_startup: {crash_sess}  |  clean_startup: {clean_sess}  (only 1 clean shutdown!)")

    print("  [3/6] Applying 2025 labeling rules...")
    events = [label_event(e) for e in events]
    for lb, cnt in sorted(Counter(e["label"] for e in events).items(), key=lambda x: -x[1]):
        print(f"        {lb:<28} {cnt:>8,}")

    print("  [4/6] Building downtime sessions...")
    sessions = build_sessions(events)
    print(f"        {len(sessions):,} crash-recovery sessions")

    print("  [5/6] Writing CSVs...")
    incidents   = [e for e in events if e["is_incident"]=="1"]
    downtime_ev = [e for e in events if "downtime_events"    in e["model_flags"]]
    corrupt_ev  = [e for e in events if "data_corruption"     in e["model_flags"]]
    unauth_ev   = [e for e in events if "unauthorized_access" in e["model_flags"]]
    suspect_ev  = [e for e in events if "suspicious_review"   in e["model_flags"]]
    audit = [{
        "event_id":e["event_id"],"fingerprint":e["fingerprint"],
        "source_line":e["source_line"],"timestamp":e["timestamp"],
        "level":e["level"],"startup_context":e["startup_context"],
        "rule_id":e["rule_id"],"rule_description":e["rule_description"],
        "label":e["label"],"sublabel":e["sublabel"],"severity":e["severity"],
        "confidence":e["confidence"],"is_incident":e["is_incident"],
        "is_after_hours":e["is_after_hours"],"model_flags":e["model_flags"],
        "host_class":e["host_class"],"user_class":e["user_class"],
        "user":e["user"],"host":e["host"],"database":e["database"],
        "is_lsn_mismatch":e["is_lsn_mismatch"],
        "message_preview":e["message"][:120],
        "analyst_notes":e["analyst_notes"],
    } for e in events]
    file_plan = {
        "LIRA_2025_00_master_all_events.csv":events,
        "LIRA_2025_01_incidents_only.csv":incidents,
        "LIRA_2025_02_model_downtime_events.csv":downtime_ev,
        "LIRA_2025_03_model_downtime_sessions.csv":sessions,
        "LIRA_2025_04_model_data_corruption.csv":corrupt_ev,
        "LIRA_2025_05_model_unauthorized_access.csv":unauth_ev,
        "LIRA_2025_06_model_suspicious_review.csv":suspect_ev,
        "LIRA_2025_07_label_audit_trail.csv":audit,
    }
    out_files = {}
    for fname, data in file_plan.items():
        meta = write_csv(data, os.path.join(out_dir, fname))
        out_files[fname] = meta
        print(f"        {fname:<48} {meta['rows']:>7,} rows  {hs(meta['size']):>20}")

    print("  [6/6] Generating report...")
    report = generate_report(events, sessions, input_path, file_size,
                              raw_lines, skipped, out_files, out_dir, start_dt)
    rpath = os.path.join(out_dir, "LIRA_2025_REPORT.txt")
    with open(rpath,"w",encoding="utf-8") as f:
        f.write(report)
    rep_size = os.path.getsize(rpath)
    print(f"        {'LIRA_2025_REPORT.txt':<48} {'report':>7}       {hs(rep_size):>20}")

    elapsed = (datetime.now()-start_dt).total_seconds()
    total_out = sum(m["size"] for m in out_files.values()) + rep_size
    print()
    print("  ||"+"═"*58+"╗")
    print("  ||"+"  LIRA 2025 PROCESSING COMPLETE".ljust(58)+"||")
    print("  ||"+"═"*58+"╣")
    print("  ||"+f"  Events parsed          : {len(events):,}".ljust(58)+"||")
    print("  ||"+f"  Incident events        : {len(incidents):,}".ljust(58)+"||")
    print("  ||"+f"  Benign events          : {len(events)-len(incidents):,}".ljust(58)+"||")
    print("  ||"+f"  Downtime sessions      : {len(sessions):,}".ljust(58)+"||")
    print("  ||"+f"  Total output size      : {hs(total_out)}".ljust(58)+"||")
    print("  ||"+f"  Processing time        : {elapsed:.2f} seconds".ljust(58)+"||")
    print("  ||"+"═"*58+"╝")
    print()

if __name__ == "__main__":
    main()
