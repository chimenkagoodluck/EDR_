"""


USAGE:
    python evtx_parser.py
    python evtx_parser.py --logs-dir "C:\\path\\to\\Logs" --output-dir "EVTX_Output"
    python evtx_parser.py --work-start 7 --work-end 21
"""

import os
import sys
import csv
import json
import argparse
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, Counter

try:
    import Evtx.Evtx as evtx
    from lxml import etree
except ImportError:
    print("[ERROR] python-evtx or lxml not found.  Run: pip install python-evtx lxml")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════
# TOOL METADATA
# ═══════════════════════════════════════════════════════════════════════

TOOL_NAME      = "WELA — Windows Event Log Analyzer"
TOOL_VERSION   = "1.0"
RESEARCH_TITLE = (
    "An Enhanced Incident Response Plan for Electronic Medical "
    "Record Systems at Tertiary Health Facilities in Nigeria"
)
HOSPITAL_NAME  = "Enugu State University Teaching Hospital (ESUTH)"

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Logon type descriptions (Windows standard)
LOGON_TYPES = {
    "2":  "Interactive",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

# ═══════════════════════════════════════════════════════════════════════
# PRIORITY FILE REGISTRY
# ═══════════════════════════════════════════════════════════════════════

PRIORITY_FILES = [
    # (priority, filename, channel_key)
    ("CRITICAL", "Security.evtx",                                                              "security"),
    ("CRITICAL", "System.evtx",                                                                "system"),
    ("CRITICAL", "Microsoft-Windows-Windows Defender%4Operational.evtx",                      "defender"),
    ("CRITICAL", "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",  "firewall"),
    ("HIGH",     "Microsoft-Windows-PowerShell%4Operational.evtx",                            "powershell"),
    ("HIGH",     "Microsoft-Windows-WMI-Activity%4Operational.evtx",                          "wmi"),
    ("HIGH",     "Microsoft-Windows-TaskScheduler%4Maintenance.evtx",                         "taskscheduler"),
    ("HIGH",     "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",  "rdp"),
    ("HIGH",     "Microsoft-Windows-WinRM%4Operational.evtx",                                 "winrm"),
    ("HIGH",     "Microsoft-Windows-SMBServer%4Security.evtx",                                "smb_security"),
    ("HIGH",     "Microsoft-Windows-SMBServer%4Operational.evtx",                             "smb_operational"),
    ("MEDIUM",   "Application.evtx",                                                           "application"),
    ("MEDIUM",   "Microsoft-Windows-UAC%4Operational.evtx",                                   "uac"),
    ("MEDIUM",   "Microsoft-Windows-CodeIntegrity%4Operational.evtx",                         "codeintegrity"),
    ("MEDIUM",   "Microsoft-Windows-GroupPolicy%4Operational.evtx",                           "grouppolicy"),
    ("MEDIUM",   "Microsoft-Windows-Winlogon%4Operational.evtx",                              "winlogon"),
    ("MEDIUM",   "Windows PowerShell.evtx",                                                    "powershell_classic"),
]

# ═══════════════════════════════════════════════════════════════════════
# PASS 1: EVTX EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

def _text(elem):
    return (elem.text or "").strip() if elem is not None else ""


def extract_event_data(root):
    """Flatten all EventData/UserData Name=Value pairs into a dict."""
    data = {}
    for container_tag in (f"{NS}EventData", f"{NS}UserData"):
        container = root.find(f".//{container_tag}")
        if container is None:
            continue
        for child in container:
            name = child.get("Name")
            if name:
                data[name] = (child.text or "").strip()
            else:
                # Unnamed data element — use tag
                tag = child.tag.replace(NS, "")
                data[tag] = (child.text or "").strip()
    return data


def parse_record(record):
    """
    Parse a single EVTX record into a flat dict with core fields + EventData.
    Returns None on parse failure.
    """
    try:
        xml_str = record.xml()
        root = etree.fromstring(xml_str.encode("utf-8"))
    except Exception:
        return None

    # System fields
    sys_elem = root.find(f"{NS}System")
    if sys_elem is None:
        return None

    def sf(tag):
        e = sys_elem.find(f"{NS}{tag}")
        return _text(e)

    def sf_attr(tag, attr):
        e = sys_elem.find(f"{NS}{tag}")
        return e.get(attr, "") if e is not None else ""

    ts_raw = sf_attr("TimeCreated", "SystemTime")
    ts = None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",    "%Y-%m-%d %H:%M:%S"):
        try:
            ts = datetime.strptime(ts_raw.strip(), fmt).replace(tzinfo=None)
            break
        except ValueError:
            continue
    if ts is None and ts_raw:
        try:
            ts = datetime.fromisoformat(ts_raw.split(".")[0].replace("T", " "))
        except ValueError:
            pass

    event_id_full = sf("EventID")
    # Qualifiers may be embedded as attribute
    qualifiers = sys_elem.find(f"{NS}EventID")
    if qualifiers is not None:
        event_id_full = qualifiers.text or ""

    rec = {
        "event_id":       event_id_full.strip(),
        "timestamp":      ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "",
        "timestamp_dt":   ts,
        "level":          sf("Level"),
        "channel":        sf("Channel"),
        "computer":       sf("Computer"),
        "provider":       sf_attr("Provider", "Name"),
        "record_id":      sf("EventRecordID"),
        "process_id":     sf_attr("Execution", "ProcessID"),
        "thread_id":      sf_attr("Execution", "ThreadID"),
        "activity_id":    sf_attr("Correlation", "ActivityID"),
        "keywords":       sf("Keywords"),
    }

    # Merge EventData fields
    rec.update(extract_event_data(root))
    return rec


def load_evtx_file(filepath, channel_key):
    """Generator: yields parsed record dicts from an EVTX file."""
    try:
        log_handle = evtx.Evtx(filepath)
    except Exception as e:
        print(f"    [WARN] Could not open {filepath}: {e}")
        return

    with log_handle:
        for record in log_handle.records():
            try:
                parsed = parse_record(record)
            except Exception:
                continue
            if parsed:
                parsed["source_file"] = os.path.basename(filepath)
                parsed["channel_key"] = channel_key
                yield parsed


# ═══════════════════════════════════════════════════════════════════════
# PASS 2: LABELING ENGINE
# ═══════════════════════════════════════════════════════════════════════

# Rule registry: rule_id -> (label, severity, description)
RULES = {
    # ── Authentication (Security.evtx) ──────────────────────────────
    "W01": ("AUTH_LOGON_SUCCESS",        "INFO",     "Successful logon event"),
    "W02": ("AUTH_LOGON_FAILURE",        "HIGH",     "Failed logon attempt"),
    "W03": ("AUTH_LOGOFF",               "INFO",     "Normal logoff"),
    "W04": ("EXPLICIT_CREDENTIAL_USE",   "HIGH",     "Logon with explicitly supplied credentials (pass-the-hash indicator)"),
    "W05": ("PRIVILEGE_ASSIGNED",        "MEDIUM",   "Special privileges assigned at logon"),
    "W06": ("ACCOUNT_CREATED",           "HIGH",     "New user account created"),
    "W07": ("ACCOUNT_DELETED",           "HIGH",     "User account deleted"),
    "W08": ("ACCOUNT_MODIFIED",          "MEDIUM",   "User account properties changed"),
    "W09": ("GROUP_MEMBERSHIP_CHANGE",   "HIGH",     "User added/removed from security group"),
    "W10": ("AUDIT_LOG_CLEARED",         "CRITICAL", "Security audit log was cleared — anti-forensic indicator"),
    "W11": ("KERBEROS_FAILURE",          "HIGH",     "Kerberos pre-authentication failed"),
    "W12": ("NTLM_AUTH",                 "MEDIUM",   "NTLM credential validation attempt"),
    "W13": ("OFF_HOURS_LOGON",           "HIGH",     "Successful logon outside working hours"),
    "W14": ("NETWORK_LOGON",             "MEDIUM",   "Network logon (Type 3) — lateral movement vector"),
    "W15": ("REMOTE_INTERACTIVE_LOGON",  "HIGH",     "Remote interactive logon (Type 10) — direct remote access"),
    # ── System ──────────────────────────────────────────────────────
    "W16": ("SERVICE_INSTALLED",         "HIGH",     "New service installed — persistence/privilege escalation vector"),
    "W17": ("SERVICE_STATE_CHANGE",      "INFO",     "Service started or stopped"),
    "W18": ("SYSTEM_STARTUP",            "INFO",     "System/EventLog started"),
    "W19": ("SYSTEM_SHUTDOWN",           "MEDIUM",   "System/EventLog stopped — possible unexpected shutdown"),
    "W20": ("DCOM_PERMISSION_ERROR",     "LOW",      "DCOM access permission error"),
    # ── Malware / Defender ──────────────────────────────────────────
    "W21": ("MALWARE_DETECTED",          "CRITICAL", "Windows Defender detected malware"),
    "W22": ("MALWARE_ACTION_TAKEN",      "CRITICAL", "Windows Defender took action on malware"),
    "W23": ("DEFENDER_CONFIG_CHANGED",   "HIGH",     "Windows Defender configuration changed"),
    "W24": ("REALTIME_PROTECTION_EVENT", "HIGH",     "Real-time protection scan event"),
    # ── Firewall ────────────────────────────────────────────────────
    "W25": ("FIREWALL_RULE_ADDED",       "HIGH",     "Firewall rule added"),
    "W26": ("FIREWALL_RULE_DELETED",     "HIGH",     "Firewall rule deleted"),
    "W27": ("FIREWALL_RULE_MODIFIED",    "MEDIUM",   "Firewall rule modified"),
    # ── Script Execution ────────────────────────────────────────────
    "W28": ("POWERSHELL_SCRIPT_EXEC",    "HIGH",     "PowerShell script block logged"),
    "W29": ("POWERSHELL_PROVIDER_START", "INFO",     "PowerShell provider/session started"),
    # ── WMI ─────────────────────────────────────────────────────────
    "W30": ("WMI_PROVIDER_LOAD",         "INFO",     "WMI provider loaded"),
    "W31": ("WMI_SUBSCRIPTION",          "HIGH",     "WMI event subscription — common persistence mechanism"),
    "W32": ("WMI_QUERY",                 "LOW",      "WMI activity query/operation"),
    # ── Scheduled Tasks ─────────────────────────────────────────────
    "W33": ("TASK_REGISTERED",           "HIGH",     "Scheduled task registered — persistence indicator"),
    "W34": ("TASK_TRIGGERED",            "INFO",     "Scheduled task triggered/launched"),
    "W35": ("TASK_DELETED",              "MEDIUM",   "Scheduled task deleted"),
    # ── Remote Access ────────────────────────────────────────────────
    "W36": ("RDP_LOGON",                 "MEDIUM",   "RDP session logon"),
    "W37": ("RDP_LOGOFF",                "INFO",     "RDP session logoff/disconnect"),
    "W38": ("WINRM_ERROR",               "MEDIUM",   "WinRM connection error — possible failed remote access"),
    # ── SMB ─────────────────────────────────────────────────────────
    "W39": ("SMB_ACCESS_DENIED",         "HIGH",     "SMB file/share access denied — lateral movement or ransomware recon"),
    "W40": ("SMB_AUTH_FAILURE",          "HIGH",     "SMB authentication failure"),
    "W41": ("SMB_FILE_OPERATION",        "INFO",     "SMB normal file operation"),
    # ── Application ─────────────────────────────────────────────────
    "W42": ("APPLICATION_CRASH",         "MEDIUM",   "Application crash event"),
    "W43": ("APPLICATION_CRASH_REPORT",  "MEDIUM",   "Windows Error Reporting crash report"),
    # ── Code Integrity ───────────────────────────────────────────────
    "W44": ("UNSIGNED_CODE_DETECTED",    "HIGH",     "Code integrity: unsigned/policy-violating code detected"),
    # ── Group Policy ─────────────────────────────────────────────────
    "W45": ("GROUP_POLICY_APPLIED",      "INFO",     "Group policy applied successfully"),
    "W46": ("GROUP_POLICY_ERROR",        "MEDIUM",   "Group policy application error"),
    # ── UAC ──────────────────────────────────────────────────────────
    "W47": ("UAC_ELEVATION",             "HIGH",     "UAC elevation event"),
    # ── Episode labels (applied in Pass 3) ───────────────────────────
    "W48": ("BRUTE_FORCE_EPISODE",       "CRITICAL", "Brute-force episode: >=5 auth failures within 60 seconds from same source"),
    "W49": ("SMB_ACCESS_STORM",          "CRITICAL", "SMB access-denied storm: >=50 denials within 60 seconds — ransomware indicator"),
    "W50": ("CREDENTIAL_STUFFING",       "CRITICAL", "Credential stuffing: >=5 different accounts failed from same IP within 300s"),
    # ── Newly mapped previously-unknown EIDs ─────────────────────────
    "W51": ("DRIVER_LOAD_EVENT",         "LOW",      "Kernel driver loaded or failed to load"),
    "W52": ("TIME_SYNC_EVENT",           "INFO",     "NTP/time-service synchronisation event"),
    "W53": ("KERNEL_POWER_EVENT",        "LOW",      "Kernel power / firmware power settings change"),
    "W54": ("KERNEL_TRACING_EVENT",      "INFO",     "Kernel EventTracing session event"),
    "W55": ("NTFS_OPERATIONAL",          "INFO",     "NTFS file-system operational event"),
    "W56": ("CREDENTIAL_MANAGER_READ",   "MEDIUM",   "Credential Manager credentials read — enumerate creds indicator"),
    "W57": ("GROUP_ENUM",                "LOW",      "Local group membership enumerated"),
    "W58": ("APP_INFO_EVENT",            "INFO",     "Application-specific informational event"),
    "WUNK": ("UNKNOWN_EVENT",            "INFO",     "Event not matched by any rule"),
}

# EventID -> rule_id mapping
EID_RULES = {
    # Security
    "4624":  "W01",
    "4625":  "W02",
    "4634":  "W03",
    "4647":  "W03",
    "4648":  "W04",
    "4672":  "W05",
    "4720":  "W06",
    "4726":  "W07",
    "4738":  "W08",
    "4722":  "W08",
    "4723":  "W08",
    "4724":  "W08",
    "4725":  "W08",
    "4728":  "W09",
    "4732":  "W09",
    "4733":  "W09",
    "4756":  "W09",
    "1102":  "W10",
    "517":   "W10",
    "4771":  "W11",
    "4776":  "W12",
    # System
    "7045":  "W16",
    "7036":  "W17",
    "6005":  "W18",
    "6006":  "W19",
    "6008":  "W19",
    "10016": "W20",
    # Defender
    "1116":  "W21",
    "1006":  "W21",
    "1117":  "W22",
    "1007":  "W22",
    "5007":  "W23",
    "2001":  "W24",
    "1000":  "W21",
    "1001":  "W22",
    # Firewall
    "2002":  "W25",
    "2004":  "W25",
    "2006":  "W26",
    "2033":  "W26",
    "2010":  "W27",
    # PowerShell
    "4104":  "W28",
    "4103":  "W28",
    "53504": "W29",
    "40961": "W29",
    "40962": "W29",
    "4100":  "W28",
    "400":   "W29",
    "600":   "W29",   # provider-started, not script-block
    "403":   "W29",
    # WMI
    "5857":  "W30",
    "5858":  "W32",
    "5860":  "W31",
    "5861":  "W31",
    "5859":  "W32",
    # TaskScheduler
    "106":   "W33",
    "4698":  "W33",
    "4699":  "W35",
    "141":   "W35",
    "200":   "W34",
    "800":   "W34",
    # RDP
    "21":    "W36",
    "25":    "W36",
    "22":    "W36",
    "23":    "W37",
    "24":    "W37",
    "41":    "W36",
    "42":    "W37",
    # WinRM
    "161":   "W38",
    "142":   "W38",
    "145":   "W38",
    "254":   "W38",
    # SMB
    "551":   "W39",
    "1009":  "W40",
    "1010":  "W41",
    "1011":  "W41",
    "1017":  "W41",
    "1016":  "W41",
    "1905":  "W41",
    # Application
    "1000":  "W42",
    "1001":  "W43",
    "1003":  "W42",
    # Code Integrity
    "3033":  "W44",
    "3034":  "W44",
    "3085":  "W44",
    "3089":  "W44",
    # Group Policy
    "5320":  "W45",
    "5351":  "W45",
    "4117":  "W45",
    "5117":  "W45",
    "5324":  "W45",
    "5312":  "W46",
    "1085":  "W46",
    # UAC
    "1":     "W47",
    # Winlogon
    "811":   "W36",
    "812":   "W37",
    # System — previously UNKNOWN
    "6":     "W51",   # Driver loaded/failed
    "134":   "W52",   # Time-sync (NTP)
    "16":    "W53",   # Kernel power / firmware power settings
    "140":   "W54",   # Kernel EventTracing
    "55":    "W55",   # NTFS operational
    # Security — previously UNKNOWN
    "5379":  "W56",   # Credential Manager read
    "4799":  "W57",   # Local group membership enumerated
    # Application — previously UNKNOWN
    "100":   "W58",   # Application-specific informational
}


def label_event(rec, work_start, work_end):
    """Apply labeling rules. Returns (rule_id, label, severity, notes)."""
    eid   = rec.get("event_id", "")
    ch    = rec.get("channel_key", "")
    ts_dt = rec.get("timestamp_dt")

    rule_id = EID_RULES.get(eid, "WUNK")

    # Refine W01 logon type sub-labels
    if rule_id == "W01":
        logon_type = rec.get("LogonType", rec.get("logon_type", ""))
        if logon_type == "3":
            rule_id = "W14"
        elif logon_type == "10":
            rule_id = "W15"
        # Off-hours logon check
        if ts_dt:
            hour = ts_dt.hour
            if not (work_start <= hour < work_end):
                rule_id = "W13"

    label, severity, desc = RULES.get(rule_id, RULES["WUNK"])
    notes = desc

    # Extra notes for specific events
    if eid == "4625":
        user = rec.get("TargetUserName", rec.get("SubjectUserName", ""))
        ip   = rec.get("IpAddress", "")
        if user:
            notes += f" | User: {user}"
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            notes += f" | Source IP: {ip}"

    if eid == "4672":
        user = rec.get("SubjectUserName", "")
        privs = rec.get("PrivilegeList", "")
        if user:
            notes += f" | Account: {user}"
        if privs:
            notes += f" | Privileges: {privs[:80]}"

    if ch == "defender" and eid in ("1116", "1006", "1000", "1117", "1007", "2001", "5007"):
        # EID 1116/1006 use "Threat Name"; EID 2001 uses "Name"; try all variants
        threat = (rec.get("Threat Name") or rec.get("ThreatName")
                  or rec.get("Name") or rec.get("threat_name") or "")
        path   = (rec.get("Path") or rec.get("File Name") or rec.get("FileName") or "")
        sev    = (rec.get("Severity") or rec.get("Severity Name") or "")
        if threat:
            notes += f" | Threat: {threat}"
        if sev:
            notes += f" | Severity: {sev}"
        if path:
            notes += f" | Path: {path[:80]}"

    if eid == "7045":
        svc   = rec.get("ServiceName", "")
        stype = rec.get("ServiceType", "")
        sfile = rec.get("ImagePath", "")
        notes += f" | Service: {svc} | Type: {stype} | Path: {sfile[:60]}"

    if eid == "4104":
        script = rec.get("ScriptBlockText", "")
        if script:
            notes += f" | Script[100]: {script[:100].replace(chr(10),' ')}"

    if eid in ("551", "1009") and ch == "smb_security":
        client = (rec.get("ClientName") or rec.get("ClientIpAddress")
                  or rec.get("IpAddress") or rec.get("WorkstationName") or "")
        user   = (rec.get("UserName") or rec.get("AccountName")
                  or rec.get("SubjectUserName") or "")
        share  = (rec.get("ShareName") or rec.get("ObjectName") or "")
        if client:
            notes += f" | Client: {client}"
        if user:
            notes += f" | User: {user}"
        if share:
            notes += f" | Share: {share}"

    return rule_id, label, severity, notes


# ═══════════════════════════════════════════════════════════════════════
# PASS 3: EPISODE DETECTION + FEATURE ENGINEERING
# ═══════════════════════════════════════════════════════════════════════

def detect_episodes(labeled_events, brute_window=60, brute_threshold=5,
                    smb_window=60, smb_threshold=50, stuffing_window=300):
    """
    Scan labeled events for temporal attack episodes.
    Returns list of episode dicts.
    """
    episodes = []

    # Index failure events by (source_ip, timestamp_dt)
    auth_failures = [
        e for e in labeled_events
        if e.get("label") == "AUTH_LOGON_FAILURE" and e.get("timestamp_dt")
    ]
    auth_failures.sort(key=lambda e: e["timestamp_dt"])

    smb_denials = [
        e for e in labeled_events
        if e.get("label") == "SMB_ACCESS_DENIED" and e.get("timestamp_dt")
    ]
    smb_denials.sort(key=lambda e: e["timestamp_dt"])

    # Brute-force detection: >=N failures from same IP within window seconds
    def sliding_window_episodes(events, window_sec, threshold, ep_label, rule_id):
        seen = set()
        for i, ev in enumerate(events):
            t0 = ev["timestamp_dt"]
            ip = ev.get("IpAddress", ev.get("WorkstationName", "unknown"))
            window_end = t0 + timedelta(seconds=window_sec)
            bucket = [
                e for e in events[i:]
                if e["timestamp_dt"] <= window_end
                and e.get("IpAddress", e.get("WorkstationName", "unknown")) == ip
            ]
            if len(bucket) >= threshold:
                ep_key = (ip, t0.strftime("%Y-%m-%d %H:%M:%S"))
                if ep_key not in seen:
                    seen.add(ep_key)
                    affected_users = list({
                        e.get("TargetUserName", e.get("SubjectUserName", "?"))
                        for e in bucket
                    })
                    label, severity, _ = RULES[rule_id]
                    episodes.append({
                        "episode_type":     ep_label,
                        "rule_id":          rule_id,
                        "severity":         severity,
                        "start_time":       t0.strftime("%Y-%m-%d %H:%M:%S"),
                        "end_time":         bucket[-1]["timestamp_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                        "source":           ip,
                        "event_count":      len(bucket),
                        "affected_accounts": ", ".join(affected_users[:10]),
                        "channel":          ev.get("channel_key", ""),
                    })

    sliding_window_episodes(auth_failures, brute_window, brute_threshold,
                            "BRUTE_FORCE_EPISODE", "W48")
    sliding_window_episodes(smb_denials, smb_window, smb_threshold,
                            "SMB_ACCESS_STORM", "W49")

    # Credential stuffing: >=N DIFFERENT accounts failed from same IP within window
    ip_buckets = defaultdict(list)
    for ev in auth_failures:
        ip = ev.get("IpAddress", ev.get("WorkstationName", "unknown"))
        ip_buckets[ip].append(ev)

    seen_stuffing = set()
    for ip, evs in ip_buckets.items():
        evs.sort(key=lambda e: e["timestamp_dt"])
        for i, ev in enumerate(evs):
            t0 = ev["timestamp_dt"]
            window_end = t0 + timedelta(seconds=stuffing_window)
            bucket = [e for e in evs[i:] if e["timestamp_dt"] <= window_end]
            unique_users = {
                e.get("TargetUserName", e.get("SubjectUserName", ""))
                for e in bucket
                if e.get("TargetUserName", e.get("SubjectUserName", "")) not in ("", "-")
            }
            if len(unique_users) >= 5:
                ep_key = (ip, t0.strftime("%Y-%m-%d %H:%M:%S"))
                if ep_key not in seen_stuffing:
                    seen_stuffing.add(ep_key)
                    label, severity, _ = RULES["W50"]
                    episodes.append({
                        "episode_type":     "CREDENTIAL_STUFFING",
                        "rule_id":          "W50",
                        "severity":         severity,
                        "start_time":       t0.strftime("%Y-%m-%d %H:%M:%S"),
                        "end_time":         bucket[-1]["timestamp_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                        "source":           ip,
                        "event_count":      len(bucket),
                        "affected_accounts": ", ".join(list(unique_users)[:10]),
                        "channel":          "security",
                    })

    return episodes


def build_features(labeled_events, work_start, work_end):
    """
    Engineer a feature row per event for ML training.
    Keeps only fields needed for a classifier; drops raw text blobs.
    """
    rows = []
    for e in labeled_events:
        ts_dt = e.get("timestamp_dt")
        if ts_dt is None:
            continue

        hour      = ts_dt.hour
        dow       = ts_dt.weekday()          # 0=Mon … 6=Sun
        is_wh     = int(work_start <= hour < work_end)
        is_wknd   = int(dow >= 5)
        eid       = e.get("event_id", "")
        logon_t   = e.get("LogonType", "")
        severity  = e.get("severity", "INFO")

        rows.append({
            "timestamp":          e.get("timestamp", ""),
            "event_id":           eid,
            "channel_key":        e.get("channel_key", ""),
            "label":              e.get("label", ""),
            "rule_id":            e.get("rule_id", ""),
            "severity":           severity,
            "severity_weight":    SEVERITY_WEIGHT.get(severity, 1),
            "hour_of_day":        hour,
            "day_of_week":        dow,
            "is_working_hours":   is_wh,
            "is_weekend":         is_wknd,
            "logon_type":         logon_t,
            "logon_type_desc":    LOGON_TYPES.get(logon_t, ""),
            "source_ip":          e.get("IpAddress", e.get("WorkstationName", "")),
            "target_user":        e.get("TargetUserName", e.get("SubjectUserName", "")),
            "computer":           e.get("computer", ""),
            "process_name":       e.get("ProcessName", e.get("NewProcessName", "")),
        })
    return rows


# ═══════════════════════════════════════════════════════════════════════
# OUTPUT WRITERS
# ═══════════════════════════════════════════════════════════════════════

def write_csv(rows, filepath, fieldnames=None):
    if not rows:
        return
    if fieldnames is None:
        # Collect all keys, put standard ones first
        standard = [
            "timestamp", "event_id", "channel_key", "source_file",
            "label", "rule_id", "severity", "notes",
            "computer", "provider",
        ]
        extra = sorted({k for r in rows for k in r if k not in standard
                        and k != "timestamp_dt"})
        fieldnames = standard + extra

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_episodes_csv(episodes, filepath):
    if not episodes:
        return
    fields = [
        "episode_type", "rule_id", "severity", "start_time", "end_time",
        "source", "event_count", "affected_accounts", "channel",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(episodes)


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════

def generate_report(labeled_events, episodes, stats, output_dir, work_start, work_end):
    path = os.path.join(output_dir, "WELA_report.txt")
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    label_counts    = Counter(e.get("label") for e in labeled_events)
    severity_counts = Counter(e.get("severity") for e in labeled_events)
    channel_counts  = Counter(e.get("channel_key") for e in labeled_events)
    eid_counts      = Counter(e.get("event_id") for e in labeled_events)

    # Top offenders by source IP (failures only)
    ip_fail_counts = Counter(
        e.get("IpAddress", e.get("WorkstationName", "unknown"))
        for e in labeled_events
        if e.get("severity") in ("HIGH", "CRITICAL")
        and e.get("IpAddress", e.get("WorkstationName", "")) not in ("", "-", "::1", "127.0.0.1")
    )

    lines = []
    W = 78

    def hr(char="="):
        lines.append(char * W)

    def section(title):
        hr()
        lines.append(f"  {title}")
        hr()

    hr()
    lines.append(f"  {TOOL_NAME}  v1.0")
    lines.append(f"  {HOSPITAL_NAME}")
    lines.append(f"  Research: {RESEARCH_TITLE}")
    lines.append(f"  Report generated: {now}")
    hr()

    # ── Overview
    section("1. OVERVIEW")
    lines.append(f"  Total events parsed    : {stats['total_events']:,}")
    lines.append(f"  Total labeled          : {len(labeled_events):,}")
    lines.append(f"  Episodes detected      : {len(episodes)}")
    lines.append(f"  Working hours config   : {work_start:02d}:00 - {work_end:02d}:00")
    lines.append(f"  Output directory       : {output_dir}")
    lines.append("")
    lines.append("  Events by severity:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = severity_counts.get(sev, 0)
        bar = "#" * min(40, cnt // max(1, len(labeled_events) // 40))
        lines.append(f"    {sev:<10} {cnt:>8,}  {bar}")

    # ── Per-source summary
    section("2. EVENTS BY SOURCE CHANNEL")
    lines.append(f"  {'Channel':<30} {'Events':>8}  {'CRITICAL':>8}  {'HIGH':>8}")
    hr("-")
    for ch, cnt in sorted(channel_counts.items(), key=lambda x: -x[1]):
        crit = sum(1 for e in labeled_events if e.get("channel_key") == ch and e.get("severity") == "CRITICAL")
        high = sum(1 for e in labeled_events if e.get("channel_key") == ch and e.get("severity") == "HIGH")
        lines.append(f"  {ch:<30} {cnt:>8,}  {crit:>8,}  {high:>8,}")

    # ── Top labels
    section("3. TOP EVENT LABELS")
    for label, cnt in label_counts.most_common(20):
        rule_match = next((rid for rid, (lbl, _, _) in RULES.items() if lbl == label), "?")
        _, sev, desc = RULES.get(rule_match, ("", "INFO", ""))
        lines.append(f"  [{sev:<8}] {label:<35} {cnt:>8,}  ({desc[:40]})")

    # ── Episodes
    section("4. DETECTED EPISODES / ATTACK PATTERNS")
    if not episodes:
        lines.append("  No episodes detected.")
    else:
        ep_type_counts = Counter(e["episode_type"] for e in episodes)
        for ep_type, cnt in ep_type_counts.most_common():
            lines.append(f"  {ep_type:<35} {cnt:>6} episodes")
        lines.append("")
        lines.append(f"  {'Type':<30} {'Start':<20} {'Source':<20} {'Count':>6}  {'Accounts'}")
        hr("-")
        for ep in sorted(episodes, key=lambda x: x["start_time"])[:50]:
            lines.append(
                f"  {ep['episode_type']:<30} {ep['start_time']:<20} "
                f"{ep['source'][:20]:<20} {ep['event_count']:>6}  {ep['affected_accounts'][:40]}"
            )

    # ── Top offending source IPs
    section("5. TOP SOURCE IPs IN HIGH/CRITICAL EVENTS")
    if not ip_fail_counts:
        lines.append("  No source IP data available.")
    else:
        for ip, cnt in ip_fail_counts.most_common(15):
            lines.append(f"  {ip:<40} {cnt:>8,} high/critical events")

    # ── Top Event IDs
    section("6. TOP EVENT IDs")
    for eid, cnt in eid_counts.most_common(20):
        rule_id = EID_RULES.get(eid, "WUNK")
        label, sev, desc = RULES.get(rule_id, ("UNKNOWN", "INFO", ""))
        lines.append(f"  EID {eid:<6} {cnt:>8,}  [{sev:<8}] {label:<30} {desc[:35]}")

    # ── Defender-specific
    defender_events = [e for e in labeled_events if e.get("channel_key") == "defender"]
    if defender_events:
        section("7. WINDOWS DEFENDER DETAIL")
        detections = [e for e in defender_events if e.get("severity") in ("CRITICAL", "HIGH")]
        lines.append(f"  Total Defender events : {len(defender_events):,}")
        lines.append(f"  High/Critical         : {len(detections):,}")
        threat_counts = Counter(
            e.get("Threat Name", e.get("ThreatName", "Unknown"))
            for e in detections
        )
        if threat_counts:
            lines.append("  Top threats detected:")
            for threat, cnt in threat_counts.most_common(10):
                lines.append(f"    {threat:<50} {cnt:>6} events")

    # ── SMB-specific
    smb_sec = [e for e in labeled_events if e.get("channel_key") == "smb_security"]
    if smb_sec:
        section("8. SMB SECURITY DETAIL")
        lines.append(f"  Total SMB security events : {len(smb_sec):,}")
        denied = [e for e in smb_sec if e.get("label") == "SMB_ACCESS_DENIED"]
        auth_fail = [e for e in smb_sec if e.get("label") == "SMB_AUTH_FAILURE"]
        lines.append(f"  Access denied (EID 551)   : {len(denied):,}")
        lines.append(f"  Auth failures (EID 1009)  : {len(auth_fail):,}")
        client_counts = Counter(
            e.get("ClientName", e.get("ClientIpAddress", "unknown"))
            for e in denied
        )
        if client_counts:
            lines.append("  Top denied clients:")
            for client, cnt in client_counts.most_common(10):
                lines.append(f"    {client:<40} {cnt:>8,} denials")

    # ── Dataset alignment note
    section("9. DATASET ALIGNMENT NOTE (LIRA vs WELA)")
    ts_list = [
        e["timestamp_dt"].replace(tzinfo=None) if e["timestamp_dt"].tzinfo else e["timestamp_dt"]
        for e in labeled_events if e.get("timestamp_dt")
    ]
    if ts_list:
        global_min = min(ts_list)
        global_max = max(ts_list)
        lines.append(f"  WELA event range : {global_min.strftime('%Y-%m-%d')} to {global_max.strftime('%Y-%m-%d')}")
        lines.append(f"  LIRA log years   : 2023, 2024, 2025, 2026")
        lira_years = {2023, 2024, 2025, 2026}
        covered = {t.year for t in ts_list}
        overlap = lira_years & covered
        lines.append(f"  Overlapping years: {sorted(overlap)}")
        if overlap:
            lines.append("  Cross-source join: POSSIBLE on timestamp + computer field")
            lines.append("  Recommended join key: FLOOR(timestamp, 1-minute) + computer name")
        else:
            lines.append("  WARNING: No year overlap — direct correlation not possible with current logs")

    # ── Output files
    section("10. OUTPUT FILES")
    output_csvs = [
        ("security_events.csv",       "Security.evtx labeled events (auth, privileges, account changes)"),
        ("system_events.csv",         "System.evtx labeled events (services, startups, DCOM)"),
        ("defender_events.csv",       "Windows Defender events (detections, actions, config changes)"),
        ("firewall_events.csv",       "Firewall rule changes"),
        ("powershell_events.csv",     "PowerShell script block + classic log events"),
        ("wmi_events.csv",            "WMI provider loads, queries, subscriptions"),
        ("rdp_events.csv",            "RDP / TerminalServices + Winlogon events"),
        ("smb_events.csv",            "SMB security + operational events"),
        ("application_events.csv",    "Application crashes and WER reports"),
        ("other_events.csv",          "UAC, CodeIntegrity, GroupPolicy, WinRM events"),
        ("all_labeled_events.csv",    "All events from all channels combined with labels"),
        ("episodes.csv",              "Detected attack episodes (brute force, SMB storms, stuffing)"),
        ("training_features.csv",     "Engineered feature matrix — ready for ML training"),
        ("WELA_report.txt",           "This report"),
    ]
    for fname, desc in output_csvs:
        lines.append(f"  {fname:<35} {desc}")

    hr()
    lines.append(f"  End of report  |  {TOOL_NAME}")
    hr()

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return path


# ═══════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════

CHANNEL_GROUP = {
    "security":          "security_events.csv",
    "system":            "system_events.csv",
    "defender":          "defender_events.csv",
    "firewall":          "firewall_events.csv",
    "powershell":        "powershell_events.csv",
    "powershell_classic":"powershell_events.csv",
    "wmi":               "wmi_events.csv",
    "rdp":               "rdp_events.csv",
    "winlogon":          "rdp_events.csv",
    "smb_security":      "smb_events.csv",
    "smb_operational":   "smb_events.csv",
    "application":       "application_events.csv",
    "uac":               "other_events.csv",
    "codeintegrity":     "other_events.csv",
    "grouppolicy":       "other_events.csv",
    "winrm":             "other_events.csv",
    "taskscheduler":     "other_events.csv",
}


def main():
    parser = argparse.ArgumentParser(description=TOOL_NAME)
    parser.add_argument("--logs-dir",   default=os.path.join(os.path.dirname(__file__), "Logs", "Logs"))
    parser.add_argument("--output-dir", default=os.path.join(os.path.dirname(__file__), "EVTX_Output"))
    parser.add_argument("--work-start", type=int, default=7,  help="Start of working hours (24h)")
    parser.add_argument("--work-end",   type=int, default=21, help="End of working hours (24h)")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("=" * 78)
    print(f"  {TOOL_NAME}  v{TOOL_VERSION}")
    print(f"  {HOSPITAL_NAME}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 78)

    # ── PASS 1 + 2: Extract and label ────────────────────────────────
    all_labeled    = []
    per_channel    = defaultdict(list)
    stats          = {"total_events": 0, "total_files": 0, "skipped": 0}

    for priority, filename, channel_key in PRIORITY_FILES:
        filepath = os.path.join(args.logs_dir, filename)
        if not os.path.exists(filepath):
            print(f"  [SKIP] {filename}")
            stats["skipped"] += 1
            continue

        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"\n  [PASS 1+2] {filename}  ({size_mb:.1f} MB)", flush=True)

        file_count = 0
        for rec in load_evtx_file(filepath, channel_key):
            rule_id, label, severity, notes = label_event(rec, args.work_start, args.work_end)
            rec["rule_id"]  = rule_id
            rec["label"]    = label
            rec["severity"] = severity
            rec["notes"]    = notes

            all_labeled.append(rec)
            per_channel[channel_key].append(rec)
            file_count += 1

        print(f"           Extracted: {file_count:,} events  |  Labels applied", flush=True)
        stats["total_events"] += file_count
        stats["total_files"]  += 1

    print(f"\n  Total events labeled: {stats['total_events']:,}")

    # ── PASS 3: Episode detection ─────────────────────────────────────
    print("\n  [PASS 3] Detecting attack episodes...", flush=True)
    episodes = detect_episodes(all_labeled)
    print(f"           Episodes found: {len(episodes)}")

    # ── Feature engineering ───────────────────────────────────────────
    print("  [PASS 3] Engineering features...", flush=True)
    features = build_features(all_labeled, args.work_start, args.work_end)
    print(f"           Feature rows: {len(features):,}")

    # ── Write per-channel CSVs ────────────────────────────────────────
    print("\n  [OUTPUT] Writing per-channel CSVs...")
    bucket_rows = defaultdict(list)
    for ch, rows in per_channel.items():
        out_file = CHANNEL_GROUP.get(ch, "other_events.csv")
        bucket_rows[out_file].extend(rows)

    for out_file, rows in bucket_rows.items():
        path = os.path.join(args.output_dir, out_file)
        write_csv(rows, path)
        print(f"    {out_file:<35} {len(rows):>8,} rows")

    # ── Write combined CSV ────────────────────────────────────────────
    combined_path = os.path.join(args.output_dir, "all_labeled_events.csv")
    write_csv(all_labeled, combined_path)
    print(f"    {'all_labeled_events.csv':<35} {len(all_labeled):>8,} rows")

    # ── Write episodes CSV ────────────────────────────────────────────
    ep_path = os.path.join(args.output_dir, "episodes.csv")
    write_episodes_csv(episodes, ep_path)
    print(f"    {'episodes.csv':<35} {len(episodes):>8,} rows")

    # ── Write features CSV ────────────────────────────────────────────
    feat_fields = [
        "timestamp", "event_id", "channel_key", "label", "rule_id",
        "severity", "severity_weight", "hour_of_day", "day_of_week",
        "is_working_hours", "is_weekend", "logon_type", "logon_type_desc",
        "source_ip", "target_user", "computer", "process_name",
    ]
    feat_path = os.path.join(args.output_dir, "training_features.csv")
    write_csv(features, feat_path, fieldnames=feat_fields)
    print(f"    {'training_features.csv':<35} {len(features):>8,} rows")

    # ── Generate report ───────────────────────────────────────────────
    print("\n  [REPORT] Generating WELA_report.txt...")
    report_path = generate_report(
        all_labeled, episodes, stats, args.output_dir,
        args.work_start, args.work_end
    )
    print(f"    Saved: {report_path}")

    print("\n" + "=" * 78)
    print(f"  WELA complete.  Output: {args.output_dir}")
    print("=" * 78)


if __name__ == "__main__":
    main()
