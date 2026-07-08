

import re, csv, os, argparse, hashlib, textwrap
from datetime import datetime
from collections import Counter

TOOL_NAME    = "LIRA 2023:  Log Intelligence & Response Analyzer"
TOOL_VERSION = "1.0"
LOG_YEAR     = "2023"
HOSPITAL     = "David Umahi Teaching Hospital (DAFUTH)"

SEVERITY_WEIGHT = {"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}
WORK_HOUR_START = 7
WORK_HOUR_END   = 21

RE_MAIN = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{1,2}:\d{2}:\d{2})\s+'
    r'(?P<thread>\d+)\s+\[(?P<level>\w+)\]\s+(?P<message>.+)$')
RE_ABORTED = re.compile(
    r"Aborted connection\s+(?P<conn_id>\d+)\s+to\s+db:\s*'(?P<db>[^']*)'\s+"
    r"user:\s*'(?P<user>[^']*)'\s+host:\s*'(?P<host>[^']*)'\s*\((?P<reason>[^)]+)\)")
RE_AD = re.compile(
    r"Access denied for user\s+'(?P<user>[^']+)'@'(?P<host>[^']+)'\s+"
    r"\(using password:\s*(?P<pwd>YES|NO)\)")
RE_DNS  = re.compile(
    r"(?:IP address|Host(?:name)?)\s+'(?P<entity>[^']+)'\s+"
    r"(?:could not be resolved|does not resolve to\s+'[^']+')")
RE_LSN  = re.compile(r"LSN=(\d+)")
RE_VER  = re.compile(r"^Version:\s+'")
RE_ARIA = re.compile(r"^recovered pages:")
RE_DASH = re.compile(r"^\s*-\s+\S")
RE_IP4  = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
RE_IP6  = re.compile(r'^fe80::')

RULE_CATALOG = {
    "R01":"InnoDB crash recovery initiated",
    "R02":"Aria engine crash recovery initiated",
    "R03":"Database service restarted — now online",
    "R04":"Planned normal shutdown initiated",
    "R05":"InnoDB clean shutdown completed",
    "R06":"Shutdown sub-sequence event",
    "R07":"Temp tablespace recreated after crash [context-dependent]",
    "R08":"Stale temp file removed after crash [context-dependent]",
    "R09":"InnoDB rollback segments activated post-recovery [context-dependent]",
    "R10":"Unauthenticated connection — authentication never completed",
    "R11":"Access denied — wrong credentials or unknown user",
    "R12":"Connection from user NOT in statistical baseline",
    "R13":"Aborted connection — closed without authentication",
    "R14":"Connection from unregistered IPv6 link-local device",
    "R15":"Connection from raw IP address — no registered hostname",
    "R16":"Aborted connection from non-baseline host",
    "R17":"Aborted connection from baseline host — benign connection pool",
    "R18":"After-hours aborted connection from baseline host",
    "R19":"DNS resolution failure or hostname/IP mismatch",
    "R20":"After-hours general database activity",
    "R21":"InnoDB buffer pool operation — benign",
    "R22":"Plugin or extension status event — benign",
    "R23":"Startup / replication / config event — benign",
    "R24":"General informational Note — benign",
    "R25":"Unclassified Warning — manual review needed",
    "R27":"Table cache mutex contention — performance degradation",
}

# PASS 1: DISCOVERY

def discover(filepath):
    raw_events=[];raw_lines=0;skipped=0;current=None
    users=Counter();hosts=Counter();dbs=Counter();levels=Counter()
    abort_reasons=Counter();db_names=set();ver_strings=Counter()
    msg_templates=Counter();all_dates=[]

    try:    fsize = os.path.getsize(filepath)
    except: fsize = 0

    def anon(t):
        t=re.sub(r"'[^']*'","'X'",t);t=re.sub(r'"[^"]*"','"X"',t)
        t=re.sub(r'\b\d+\b','N',t)
        t=re.sub(r'fe80::[a-f0-9:%]+','IPv6',t,flags=re.I)
        t=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','IPv4',t)
        return t.strip()

    with open(filepath,"r",encoding="utf-8",errors="replace") as fh:
        for raw in fh:
            raw_lines+=1
            line=raw.rstrip("\r\n").strip()
            if not line:skipped+=1;continue
            if RE_VER.match(line):
                ver_strings[line.split("'")[1]]+=1;skipped+=1
                if current:current["_cont"]+=1
                continue
            if RE_ARIA.match(line) or RE_DASH.match(line):
                skipped+=1
                if current:current["_extra"]=current.get("_extra","")+"|"+line
                continue
            m=RE_MAIN.match(line)
            if m:
                if current:raw_events.append(current)
                date_str=m.group("date")
                time_str=m.group("time").strip()
                if len(time_str)==7:time_str="0"+time_str
                ts_str=f"{date_str} {time_str}"
                try:
                    ts=datetime.strptime(ts_str,"%Y-%m-%d %H:%M:%S")
                    hour=ts.hour;dow=ts.strftime("%A");mon=ts.strftime("%B");yr=ts.year
                    all_dates.append(date_str)
                except:ts=None;hour=-1;dow=mon=yr=""
                level=m.group("level");msg=m.group("message").strip()
                levels[level]+=1
                user=db=host=conn_id=abort_reason=""
                ab=RE_ABORTED.search(msg)
                if ab:
                    conn_id=ab.group("conn_id");db=ab.group("db")
                    user=ab.group("user");host=ab.group("host")
                    abort_reason=ab.group("reason").strip()
                    users[user]+=1;hosts[host]+=1;dbs[db]+=1
                    abort_reasons[abort_reason]+=1
                    if db:db_names.add(db)
                ad_user=ad_host=ad_pwd=""
                ad=RE_AD.search(msg)
                if ad:
                    ad_user=ad.group("user");ad_host=ad.group("host");ad_pwd=ad.group("pwd")
                    users[ad_user]+=1;hosts[ad_host]+=1
                dns_m=RE_DNS.search(msg)
                dns_entity=dns_m.group("entity") if dns_m else ""
                lsn_m=RE_LSN.search(msg)
                lsn=lsn_m.group(1) if lsn_m else ""
                fp=hashlib.sha256(f"{ts_str}|{m.group('thread')}|{msg[:120]}".encode()).hexdigest()[:16]
                msg_templates[anon(msg)]+=1
                current={
                    "event_id":len(raw_events)+1,"fingerprint":fp,
                    "source_line_number":raw_lines,
                    "timestamp":ts_str,"date":date_str,"time":time_str,
                    "hour":hour,"day_of_week":dow,"month":mon,"year":yr,
                    "thread_id":m.group("thread"),"level":level,"message":msg,
                    "user":user,"host":host,"database":db,
                    "connection_id":conn_id,"abort_reason":abort_reason,
                    "access_denied_user":ad_user,"access_denied_host":ad_host,
                    "access_denied_pwd_used":ad_pwd,
                    "is_dns_failure":"1" if dns_m else "0","dns_entity":dns_entity,
                    "lsn_checkpoint":lsn,
                    "is_aborted_connection":"1" if ab else "0",
                    "is_access_denied":"1" if ad else "0",
                    "is_crash_recovery":"1" if "crash recovery" in msg.lower() else "0",
                    "is_aria_recovery":"1" if "aria engine: starting recovery" in msg.lower() else "0",
                    "is_service_startup":"1" if "ready for connections" in msg.lower() else "0",
                    "is_clean_shutdown":"1" if "normal shutdown" in msg.lower() else "0",
                    "startup_context":"","startup_session_id":0,
                    "label":"","sublabel":"","severity":"","severity_score":"",
                    "rule_id":"","rule_description":"","model_flags":"",
                    "confidence":"HIGH","is_incident":"","is_after_hours":"",
                    "host_status":"","user_status":"","analyst_notes":"",
                    "_cont":0,"_extra":"",
                }
            else:
                if current:current["message"]+=" || "+line;current["_cont"]+=1
                else:skipped+=1
    if current:raw_events.append(current)
    dates_s=sorted(set(all_dates))
    dr=(dates_s[0],dates_s[-1]) if dates_s else ("unknown","unknown")
    return {"raw_events":raw_events,"file_size_bytes":fsize,
            "raw_line_count":raw_lines,"skipped_lines":skipped,
            "all_users":users,"all_hosts":hosts,"all_databases":dbs,
            "all_levels":levels,"all_abort_reasons":abort_reasons,
            "all_db_names":db_names,"date_range":dr,"all_dates":dates_s,
            "version_strings":ver_strings,"message_templates":msg_templates}

#  BASELINE 

def compute_baseline(disc, user_pct, host_pct):
    tc=sum(disc["all_users"].values()) or 1
    th=sum(disc["all_hosts"].values()) or 1
    bu={u for u,c in disc["all_users"].items() if c/tc*100>=user_pct}
    bh={h for h,c in disc["all_hosts"].items()
        if c/th*100>=host_pct and not RE_IP6.match(h) and not RE_IP4.match(h)
        and h not in ("","unknown","unconnected")}
    pu=disc["all_users"].most_common(1)[0][0] if disc["all_users"] else ""
    pd=disc["all_databases"].most_common(1)[0][0] if disc["all_databases"] else ""
    return {"baseline_users":bu,"baseline_hosts":bh,"primary_user":pu,"primary_db":pd,
            "ipv6_hosts":{h for h in disc["all_hosts"] if h and RE_IP6.match(h)},
            "ip_hosts":{h for h in disc["all_hosts"] if h and RE_IP4.match(h)},
            "unknown_hosts":{h for h in disc["all_hosts"] if h and h not in bh
                             and not RE_IP6.match(h) and not RE_IP4.match(h)
                             and h not in ("","unknown","unconnected")},
            "total_conn_events":tc,"total_host_events":th,
            "user_pct_threshold":user_pct,"host_pct_threshold":host_pct}



def assign_startup_context(events):
    for e in events:e["startup_context"]="running";e["startup_session_id"]=0
    sid=0;in_s=False;buf=[];had_crash=False
    for e in events:
        msg=e["message"].lower()
        if "starting mariadb" in msg:
            if in_s and buf:
                ctx="crash_startup" if had_crash else "clean_startup"
                for be in buf:be["startup_context"]=ctx;be["startup_session_id"]=sid
            sid+=1;in_s=True;had_crash=False;buf=[e]
            e["startup_context"]="unknown";e["startup_session_id"]=sid;continue
        if in_s:
            e["startup_session_id"]=sid;e["startup_context"]="unknown";buf.append(e)
            if "innodb: starting crash recovery" in msg or "aria engine: starting recovery" in msg:
                had_crash=True
            if "ready for connections" in msg:
                ctx="crash_startup" if had_crash else "clean_startup"
                for be in buf:be["startup_context"]=ctx;be["startup_session_id"]=sid
                in_s=False;buf=[];had_crash=False
        else:
            e["startup_context"]="running";e["startup_session_id"]=sid
    if in_s and buf:
        ctx="crash_startup" if had_crash else "clean_startup"
        for be in buf:be["startup_context"]=ctx;be["startup_session_id"]=sid
    return events

#labelling events

def label_event(event, bl):
    msg=event["message"].lower();user=event["user"];host=event["host"]
    level=event["level"];hour=event["hour"]
    ad_u=event["access_denied_user"];dns=event["is_dns_failure"]
    abort_r=event["abort_reason"].lower()
    sc=event.get("startup_context","running")
    is_aft=(hour!=-1 and (hour<WORK_HOUR_START or hour>WORK_HOUR_END))

    if not host:hs="no_host"
    elif RE_IP6.match(host):hs="ipv6_unregistered"
    elif RE_IP4.match(host):hs="raw_ip"
    elif host in bl["baseline_hosts"]:hs="baseline"
    elif host in ("unknown","unconnected"):hs="system"
    else:hs="non_baseline"

    if not user:us="no_user"
    elif user=="unauthenticated":us="unauthenticated"
    elif user=="unconnected":us="unconnected_system"
    elif user in bl["baseline_users"]:us="baseline"
    else:us="non_baseline"

    event["host_status"]=hs;event["user_status"]=us

    label="BENIGN";sublabel="general_informational";severity="INFO"
    rule_id="R24";models=[];confidence="HIGH";notes=""

    
    if "innodb: starting crash recovery" in msg:
        label="SYSTEM_DOWNTIME";sublabel="innodb_crash_recovery";severity="CRITICAL"
        rule_id="R01";models=["downtime_events","data_corruption"]
        lsn=event.get("lsn_checkpoint","")
        notes=(f"InnoDB detected unclean prior shutdown. Replaying redo log from "
               f"LSN={lsn if lsn else 'unknown'}. EMR system UNAVAILABLE. "
               "Marks START of downtime session.")

    elif "aria engine: starting recovery" in msg:
        label="SYSTEM_DOWNTIME";sublabel="aria_engine_crash_recovery";severity="CRITICAL"
        rule_id="R02";models=["downtime_events","data_corruption"]
        notes="Aria engine crash recovery alongside InnoDB — hard system failure. EMR UNAVAILABLE."

    elif "ready for connections" in msg:
        label="SYSTEM_DOWNTIME";sublabel="service_restart_online";severity="MEDIUM"
        rule_id="R03";models=["downtime_events"]
        notes="Service restarted. When preceded by crash recovery, marks END of downtime session (MTTR endpoint)."

    elif "normal shutdown" in msg:
        label="PLANNED_MAINTENANCE";sublabel="authorized_normal_shutdown";severity="INFO"
        rule_id="R04";models=["downtime_events"]
        notes="Authorized clean shutdown. NEGATIVE CLASS for downtime model. 6 of these in 2023 vs 95 crashes."

    elif "innodb: shutdown completed" in msg or ("shutdown complete" in msg and "innodb" in msg):
        label="PLANNED_MAINTENANCE";sublabel="innodb_clean_shutdown_complete"
        severity="INFO";rule_id="R05";models=["downtime_events"]
        notes="InnoDB flushed all dirty pages cleanly. No crash recovery needed on next startup."

    elif "event scheduler: purging" in msg or "fts optimize thread exiting" in msg or (
            "initiated by:" in msg and "shutdown" in msg):
        label="PLANNED_MAINTENANCE";sublabel="shutdown_sub_sequence"
        severity="INFO";rule_id="R06";models=["downtime_events"]
        notes="Part of the authorized shutdown sub-sequence. Benign."

    #  BLOCK B: DATA CORRUPTION 
    elif "creating shared tablespace for temporary tables" in msg:
        if sc=="crash_startup":
            label="DATA_CORRUPTION";sublabel="temp_tablespace_recreated_post_crash"
            severity="HIGH";rule_id="R07";models=["data_corruption"]
            notes=("InnoDB recreating ibtmp1 after crash (confirmed: crash_startup context). "
                   "In-progress EMR saves at crash time are permanently lost.")
        else:
            label="BENIGN";sublabel="innodb_temp_tablespace_init_clean_startup"
            severity="INFO";rule_id="R23"
            notes="Normal InnoDB temp tablespace init during clean startup. No data risk."

    elif "removed temporary tablespace data file" in msg:
        if sc=="crash_startup":
            label="DATA_CORRUPTION";sublabel="stale_temp_file_removed_after_crash"
            severity="MEDIUM";rule_id="R08";models=["data_corruption"]
            notes=("Leftover ibtmp1 from crashed session removed (crash_startup confirmed). "
                   "Any temp table data at crash time is unrecoverable.")
        else:
            label="BENIGN";sublabel="innodb_temp_file_cleanup_clean_startup"
            severity="INFO";rule_id="R23"
            notes="Normal InnoDB temp file cleanup during clean startup. No risk."

    elif "rollback segments are active" in msg:
        if sc=="crash_startup":
            label="DATA_CORRUPTION";sublabel="rollback_segments_activated_post_crash"
            severity="MEDIUM";rule_id="R09";models=["data_corruption"]
            notes=("InnoDB rollback segments active in crash_startup session (confirmed). "
                   "Uncommitted transactions at crash time rolled back. "
                   "Any patient record mid-write when system crashed was NOT saved.")
        else:
            label="BENIGN";sublabel="innodb_rollback_segments_normal_init"
            severity="INFO";rule_id="R23"
            notes="Standard rollback segment activation on clean startup. No crash, no data risk."

    # BLOCK C: UNAUTHORIZED ACCESS 
    elif us=="unauthenticated" and "closed normally without authentication" in abort_r:
        # 4 events in 2023
        label="UNAUTHORIZED_ACCESS";sublabel="connection_closed_without_authentication"
        severity="HIGH";rule_id="R13";models=["unauthorized_access"]
        notes=(f"Connection from '{host}' closed before auth completed (normal close). "
               "Client connected to port 3306 but did not submit credentials.")

    elif us=="unauthenticated":
        
        label="UNAUTHORIZED_ACCESS";sublabel="unauthenticated_connection_dropped"
        severity="CRITICAL";rule_id="R10";models=["unauthorized_access"]
        notes=(f"Connection from '{host}' dropped before auth completed. "
               "Port 3306 reached but no credentials submitted. Possible scanner or brute-force tool.")

    elif event["is_access_denied"]=="1":
       
        ad_host=event.get("access_denied_host",host)
        is_unknown_u=ad_u not in bl["baseline_users"] and ad_u not in ("","unauthenticated","unconnected")
        is_dominant=ad_host in bl["baseline_hosts"] and not is_unknown_u
        label="UNAUTHORIZED_ACCESS"
        sublabel=("access_denied_unknown_user" if is_unknown_u else
                  "access_denied_baseline_host_anomaly" if is_dominant else
                  "access_denied_wrong_credentials")
        severity="CRITICAL" if (is_unknown_u or is_dominant) else "HIGH"
        rule_id="R11";models=["unauthorized_access"]
        notes=(f"Access denied: user='{ad_u}' host='{ad_host}'. "+
               ("CRITICAL: unknown user not in baseline. Confirm unauthorized access." if is_unknown_u else
                f"CRITICAL ANOMALY: '{ad_host}' is a REGISTERED BASELINE HOST generating repeated "
                "access denied events. Starts November 2023. Investigate immediately — "
                "misconfigured app or compromised server." if is_dominant else
                "Known user with wrong credentials. Possible password change not propagated."))

    elif us=="non_baseline" and user not in ("","unconnected"):
        label="UNAUTHORIZED_ACCESS";sublabel="connection_from_non_baseline_user"
        severity="HIGH";rule_id="R12";models=["unauthorized_access"]
        notes=f"User '{user}' below baseline threshold. Verify with IT admin."

    elif hs=="ipv6_unregistered":
       
        label="SUSPICIOUS";sublabel="connection_from_ipv6_link_local_device"
        severity="HIGH";rule_id="R14";models=["unauthorized_access","suspicious_review"]
        confidence="MEDIUM"
        notes=(f"IPv6 link-local address '{host}' not registered in hospital DNS. "
               "Possible personal device or unregistered workstation.")

    elif hs=="raw_ip":
       
        label="SUSPICIOUS";sublabel="connection_from_raw_ip_no_hostname"
        severity="HIGH";rule_id="R15";models=["unauthorized_access","suspicious_review"]
        confidence="MEDIUM"
        notes=(f"Raw IP '{host}' — no registered hostname. "
               "Legitimate EMR workstations connect by hostname.")

    elif event["is_aborted_connection"]=="1" and hs=="non_baseline":
        label="SUSPICIOUS";sublabel="aborted_connection_non_baseline_host"
        severity="HIGH";rule_id="R16";models=["unauthorized_access","suspicious_review"]
        confidence="MEDIUM"
        notes=f"Host '{host}' below baseline threshold. Verify with IT admin."

    elif event["is_aborted_connection"]=="1" and hs=="baseline":
        if is_aft:
            label="SUSPICIOUS";sublabel="after_hours_aborted_connection_baseline_host"
            severity="MEDIUM";rule_id="R18";models=["unauthorized_access"]
            confidence="MEDIUM"
            notes=(f"Registered host '{host}' aborted connection at {hour:02d}:xx "
                   f"outside working hours. Confirm authorized with IT.")
        else:
            label="BENIGN";sublabel="emr_connection_pool_recycle"
            severity="LOW";rule_id="R17"
            notes=(f"Registered host '{host}' dropped connection ({abort_r}). "
                   "Normal EMR connection pool recycle. BENIGN negative class.")

    elif dns=="1":
       
        label="SUSPICIOUS";sublabel="dns_resolution_failure_or_hostname_mismatch"
        severity="MEDIUM";rule_id="R19";models=["unauthorized_access","suspicious_review"]
        confidence="MEDIUM"
        notes=(f"Cannot resolve '{event['dns_entity']}'. "
               "Stale DNS, multiple adapters, or hostname spoofing. Verify with IT.")

    elif event["is_aborted_connection"]=="1" and hs in ("no_host","system"):
        label="BENIGN";sublabel="system_internal_connection"
        severity="INFO";rule_id="R24"
        notes="Internal system connection event. Benign."

   
    elif "table cache mutex contention" in msg:
        
        label="SYSTEM_DOWNTIME";sublabel="table_cache_mutex_contention_performance_degradation"
        severity="MEDIUM";rule_id="R27";models=["downtime_events"]
        notes=("Table cache mutex contention — multiple threads competing for same lock. "
               "Causes query slowdowns for all hospital workstations. "
               "table_open_cache too small for concurrent load.")

    
    elif is_aft and level=="Warning" and event["is_aborted_connection"]!="1":
        label="SUSPICIOUS";sublabel="after_hours_warning_event"
        severity="LOW";rule_id="R20";models=["suspicious_review"];confidence="LOW"
        notes=f"Warning at {hour:02d}:xx outside working hours. Verify if scheduled maintenance."

   
    elif "buffer pool" in msg:
        label="BENIGN";sublabel="innodb_buffer_pool_management"
        severity="INFO";rule_id="R21"
        notes="InnoDB buffer pool management. Routine startup/shutdown activity."

    elif any(k in msg for k in ["plugin","feedback"]) and level=="Note":
        label="BENIGN";sublabel="plugin_extension_status"
        severity="INFO";rule_id="R22"
        notes="Plugin/extension status event. Benign."

    elif any(k in msg for k in [
        "server socket created","master_info","reading of all master",
        "added new master_info","fts optimize thread","waiting for purge",
        "innodb: uses event","innodb: mutexes","innodb: compressed",
        "innodb: number of pools","innodb: using","innodb: completed init",
        "innodb: initializing","innodb: file","innodb: setting file",
        "starting mariadb","mariadb source revision","loading buffer pool",
        "instance","dump completed","aria engine: recovery done",
    ]):
        label="BENIGN";sublabel="startup_replication_or_config"
        severity="INFO";rule_id="R23"
        notes="Startup, configuration, or replication event. Benign."

    elif level=="Note":
        label="BENIGN";sublabel="general_informational_note"
        severity="INFO";rule_id="R24"
        notes="Informational note. No security concern."

    elif level=="Warning":
        label="SUSPICIOUS";sublabel="unclassified_warning_manual_review"
        severity="LOW";rule_id="R25";models=["suspicious_review"];confidence="LOW"
        notes="Warning not matched by any rule. Queued for IT admin review."

    elif level=="Error":
        label="SYSTEM_DOWNTIME";sublabel="explicit_database_error"
        severity="HIGH";rule_id="R01";models=["downtime_events"]
        notes="Explicit Error-level event."

    else:
        label="BENIGN";sublabel="uncategorized_benign";severity="INFO";rule_id="R24"
        notes="Default benign classification."

    event["label"]=label;event["sublabel"]=sublabel;event["severity"]=severity
    event["severity_score"]=SEVERITY_WEIGHT.get(severity,1)
    event["rule_id"]=rule_id;event["rule_description"]=RULE_CATALOG.get(rule_id,"Unknown")
    event["model_flags"]=", ".join(models) if models else "none"
    event["confidence"]=confidence;event["is_incident"]="1" if label!="BENIGN" else "0"
    event["is_after_hours"]="1" if is_aft else "0";event["analyst_notes"]=notes
    event.pop("_cont",None);event.pop("_extra",None)
    return event

# DOWNTIME SESSIONS 

def build_sessions(events):
    sessions=[];crash_ts=None;crash_type="";crash_lsn="";sid=0
    for e in events:
        try:ts=datetime.strptime(e["timestamp"],"%Y-%m-%d %H:%M:%S")
        except:continue
        if e["rule_id"] in ("R01","R02") and crash_ts is None:
            crash_ts=ts;crash_type=e["sublabel"];crash_lsn=e.get("lsn_checkpoint","")
        elif e["rule_id"]=="R03" and crash_ts is not None:
            dur=( ts-crash_ts).total_seconds();sid+=1
            sessions.append({
                "session_id":sid,
                "crash_start_timestamp":crash_ts.strftime("%Y-%m-%d %H:%M:%S"),
                "recovery_timestamp":e["timestamp"],"crash_type":crash_type,
                "lsn_at_crash":crash_lsn,"downtime_seconds":int(dur),
                "downtime_minutes":round(dur/60,4),"downtime_hours":round(dur/3600,6),
                "crash_hour":crash_ts.hour,"crash_day_of_week":crash_ts.strftime("%A"),
                "crash_month":crash_ts.strftime("%B"),"crash_year":crash_ts.year,
                "crash_date":crash_ts.strftime("%Y-%m-%d"),
                "is_after_hours":"1" if (crash_ts.hour<WORK_HOUR_START or crash_ts.hour>WORK_HOUR_END) else "0",
                "is_long_outage":"1" if dur>3600 else "0","label":"SYSTEM_DOWNTIME",
                "severity":"CRITICAL" if dur>600 else "HIGH",
                "severity_score":5 if dur>600 else 4,
            })
            crash_ts=None;crash_type=""
    return sessions

# FILE UTILITIES 

def write_csv(data,path):
    if not data:return {"rows":0,"cols":0,"size":0,"path":path}
    with open(path,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=data[0].keys())
        w.writeheader();w.writerows(data)
    sz=os.path.getsize(path)
    return {"rows":len(data),"cols":len(data[0].keys()),"size":sz,"path":path}

def hs(b):
    if b>=1048576:return f"{b/1048576:.2f} MB ({b:,} bytes)"
    if b>=1024:return f"{b/1024:.2f} KB ({b:,} bytes)"
    return f"{b:,} bytes"





#Main function

def main():
    ap=argparse.ArgumentParser(description="LIRA 2023 Log Parser")
    ap.add_argument("--input","-i",required=True)
    ap.add_argument("--output","-o",default=None)
    ap.add_argument("--work-start",type=int,default=7)
    ap.add_argument("--work-end",type=int,default=21)
    ap.add_argument("--top-user-pct",type=float,default=5.0)
    ap.add_argument("--top-host-pct",type=float,default=1.0)
    args=ap.parse_args()

    global WORK_HOUR_START,WORK_HOUR_END
    WORK_HOUR_START=args.work_start;WORK_HOUR_END=args.work_end

    input_path=args.input
    out_dir=args.output or os.path.join(
        os.path.dirname(os.path.abspath(input_path)),"LIRA_2023_Output")
    os.makedirs(out_dir,exist_ok=True)
    start_dt=datetime.now()

   

if __name__=="__main__":
    main()
