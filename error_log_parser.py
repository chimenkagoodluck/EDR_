

import re
import csv
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict


AH_DESCRIPTIONS = {
    'AH00094': 'Command line used to start Apache',
    'AH00098': 'PID file overwritten — unclean previous shutdown',
    'AH00354': 'Child process started worker threads',
    'AH00364': 'Child: all worker threads have exited',
    'AH00418': 'Parent created a child process',
    'AH00422': 'Parent received shutdown signal',
    'AH00430': 'Parent confirmed child process exited',
    'AH00455': 'Apache server configured and starting',
    'AH00456': 'Apache server build information',
    'AH01909': 'SSL certificate CN does not match server name',
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}
DOW_MAP = {'Mon': 0, 'Tue': 1, 'Wed': 2, 'Thu': 3, 'Fri': 4, 'Sat': 5, 'Sun': 6}

# Main log line
LOG_RE = re.compile(
    r'\[(?P<dow>\w+)\s+(?P<mon>\w+)\s+(?P<day>\d+)\s+'
    r'(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)\.(?P<micro>\d+)\s+'
    r'(?P<year>\d{4})\]'
    r'\s+\[(?P<module>[\w.]+):(?P<level>\w+)\]'
    r'\s+\[pid\s+(?P<pid>\d+):tid\s+(?P<tid>\d+)\]'
    r'(?:\s+\[client\s+(?P<client>[^\]]+)\])?'
    r'\s+(?P<message>.+)',
    re.DOTALL
)

# Client: IPv6 link-local with port  fe80::xxxx:port  or IPv4:port
CLIENT_RE = re.compile(r'^(?P<ip>.+):(?P<port>\d+)$')

# AH code in message
AH_RE = re.compile(r'\b(AH\d{5})\b')

# PHP error type
PHP_TYPE_RE = re.compile(r'^PHP\s+(Fatal error|Warning|Notice|Deprecated):\s+(.+)')

# Uncaught exception
UNCAUGHT_RE = re.compile(r'Uncaught\s+(\w+(?:_\w+)*):\s+(.+?)(?:\s+in\s+C:|$)', re.DOTALL)

# PHP "in file on line N"
LOCATION_RE = re.compile(r'in\s+C:[^\s]*[/\\](\w+\.php)(?::(\d+))?')
LINE_RE = re.compile(r'on\s+line\s+(\d+)')

# DB auth failure: "Access denied for user 'USER'@'HOST'"
AUTH_FAIL_RE = re.compile(r"Access denied for user '([^']+)'@'([^']+)'")

# DNS failure: "getaddrinfo for HOST failed"
DNS_FAIL_RE = re.compile(r"getaddrinfo for ([\w.\-]+) failed")

# ---------------------------------------------------------------------------
# Event categorisation
# ---------------------------------------------------------------------------

AH_TO_CATEGORY = {
    'AH00455': 'server_start',
    'AH00456': 'server_info',
    'AH00094': 'server_info',
    'AH00418': 'process_spawn',
    'AH00354': 'workers_started',
    'AH00422': 'shutdown_signal',
    'AH00364': 'workers_stopped',
    'AH00430': 'process_exited',
    'AH00098': 'unclean_shutdown',
    'AH01909': 'ssl_cert_mismatch',
}

INTERNAL_HOSTS = {'localhost', 'dufuth-server', 'dufuth-server.local', '127.0.0.1', '::1'}

KNOWN_EXTERNAL_HOSTS = {'www.bookingafrica.org', '197.211.52.107'}


def classify_event(module: str, level: str, ah_code: str,
                   php_type: str, php_msg: str) -> str:
    if ah_code and ah_code in AH_TO_CATEGORY:
        return AH_TO_CATEGORY[ah_code]
    if module == 'ssl':
        return 'ssl_cert_mismatch'
    if module == 'core' and level == 'warn':
        return 'unclean_shutdown'
    if module == 'core' and level == 'notice':
        return 'server_info'
    if module in ('mpm_winnt',):
        return 'server_lifecycle'
    if module == 'php':
        if 'getaddrinfo' in php_msg or 'No such host' in php_msg:
            return 'php_dns_fail'
        if 'Access denied' in php_msg:
            return 'php_db_auth_fail'
        if 'Too many connections' in php_msg:
            return 'php_too_many_conn'
        if 'Maximum execution time' in php_msg:
            return 'php_timeout'
        if php_type == 'Warning':
            return 'php_warning_other'
        if php_type == 'Fatal error':
            return 'php_fatal_other'
        return 'php_other'
    return 'unknown'


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

CATEGORY_BASE_SCORE = {
    'server_start':     0,
    'server_info':      0,
    'process_spawn':    0,
    'workers_started':  0,
    'server_lifecycle': 0,
    'shutdown_signal':  1,
    'workers_stopped':  1,
    'process_exited':   1,
    'ssl_cert_mismatch': 2,
    'unclean_shutdown': 3,
    'php_warning_other': 2,
    'php_dns_fail':     4,
    'php_db_auth_fail': 6,
    'php_too_many_conn': 5,
    'php_timeout':      5,
    'php_fatal_other':  7,
    'php_other':        3,
    'unknown':          1,
}


def score_event(category: str, is_external: int, is_off_hours: int,
                is_weekend: int, level: str) -> tuple:
    score = CATEGORY_BASE_SCORE.get(category, 1)
    flags = []

    if category == 'ssl_cert_mismatch':
        flags.append('SSL_CERT_MISMATCH')
    elif category == 'unclean_shutdown':
        flags.append('UNCLEAN_SHUTDOWN')
    elif category == 'php_db_auth_fail':
        flags.append('DB_AUTH_FAIL')
    elif category == 'php_dns_fail':
        flags.append('DNS_FAIL')
    elif category == 'php_too_many_conn':
        flags.append('TOO_MANY_CONN')
    elif category == 'php_timeout':
        flags.append('EXEC_TIMEOUT')

    if is_external:
        score += 2
        flags.append('EXTERNAL_HOST')

    if is_off_hours:
        score += 1
        flags.append('OFF_HOURS')

    if is_weekend:
        score += 1
        flags.append('WEEKEND')

    if score == 0:
        label = 'normal'
    elif score <= 2:
        label = 'low'
    elif score <= 4:
        label = 'medium'
    elif score <= 6:
        label = 'high'
    else:
        label = 'critical'

    return score, label, '|'.join(flags) if flags else 'none'


# ---------------------------------------------------------------------------
# Output columns
# ---------------------------------------------------------------------------

COLUMNS = [
    # --- Temporal ---
    'line_number',
    'timestamp_raw',
    'timestamp_iso',
    'timestamp_epoch',
    'year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond',
    'day_of_week',        # 0=Mon … 6=Sun
    'weekday_name',
    'is_weekend',
    'is_business_hours',  # 08:00-18:00
    'is_off_hours',       # <06:00 or >=22:00
    # --- Module / process ---
    'module',             # php | mpm_winnt | ssl | core
    'level',              # error | warn | notice
    'module_level',       # php:error | ssl:warn | …
    'pid',
    'tid',
    # --- Client (PHP entries only) ---
    'has_client',
    'client_ip',
    'client_port',
    # --- AH error code ---
    'ah_code',
    'ah_description',
    # --- Event classification ---
    'event_category',
    # --- PHP-specific fields ---
    'php_error_type',     # Fatal error | Warning | (empty for non-PHP)
    'php_exception_class',# mysqli_sql_exception | (empty)
    'php_message_short',  # condensed error message (no stack trace)
    'source_script',      # backup.php | restore.php | index.php | (empty)
    'source_line',        # PHP file line number
    # --- DB/network context ---
    'target_db_user',     # DB user in error (e.g., root3)
    'target_db_host',     # DB/connection host (e.g., DUFUTH-SERVER, www.bookingafrica.org)
    'target_db_name',     # DB name if parseable
    'is_external_host',   # 1 if target is internet-routable
    # --- BASoft context ---
    'is_basoft',
    'is_backup_op',
    'is_restore_op',
    # --- Raw message ---
    'message_raw',
    # --- Severity ---
    'severity_score',
    'severity_label',
    'event_flags',
]


# ---------------------------------------------------------------------------
# Timestamp parser
# ---------------------------------------------------------------------------

def parse_ts(dow: str, mon: str, day: str, hour: str, minute: str,
             second: str, micro: str, year: str):
    try:
        mo = MONTH_MAP.get(mon, 0)
        dt = datetime(int(year), mo, int(day),
                      int(hour), int(minute), int(second),
                      int(micro[:6].ljust(6, '0')),
                      tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_log(input_path: str, output_path: str):
    total = skipped = 0

    with open(input_path, 'r', encoding='utf-8', errors='replace') as fin, \
         open(output_path, 'w', newline='', encoding='utf-8') as fout:

        writer = csv.DictWriter(fout, fieldnames=COLUMNS)
        writer.writeheader()

        for line_no, raw_line in enumerate(fin, start=1):
            line = raw_line.rstrip('\n').rstrip('\r')
            if not line.strip():
                skipped += 1
                continue

            m = LOG_RE.match(line)
            if not m:
                skipped += 1
                continue

            total += 1
            g = m.groupdict()

            # ---- Timestamp ----
            dt = parse_ts(g['dow'], g['mon'], g['day'],
                          g['hour'], g['minute'], g['second'],
                          g['micro'], g['year'])
            ts_epoch = dt.timestamp() if dt else 0.0
            ts_iso = dt.isoformat() if dt else ''
            ts_raw = (f"[{g['dow']} {g['mon']} {g['day'].zfill(2)} "
                      f"{g['hour']}:{g['minute']}:{g['second']}.{g['micro']} {g['year']}]")

            year_i = int(g['year'])
            month_i = MONTH_MAP.get(g['mon'], 0)
            day_i = int(g['day'])
            hour_i = int(g['hour'])
            minute_i = int(g['minute'])
            second_i = int(g['second'])
            micro_i = int(g['micro'])
            dow_i = DOW_MAP.get(g['dow'], -1)
            is_weekend = 1 if dow_i >= 5 else 0
            is_biz = 1 if 8 <= hour_i < 18 else 0
            is_off = 1 if hour_i < 6 or hour_i >= 22 else 0

            # ---- Module / level ----
            module = g['module']
            level = g['level']
            module_level = f"{module}:{level}"
            pid = int(g['pid'])
            tid = int(g['tid'])

            # ---- Client ----
            client_raw = g.get('client') or ''
            has_client = 0
            client_ip = ''
            client_port = ''
            if client_raw:
                cm = CLIENT_RE.match(client_raw)
                if cm:
                    client_ip = cm.group('ip')
                    client_port = cm.group('port')
                    has_client = 1
                else:
                    client_ip = client_raw
                    has_client = 1

            # ---- AH code ----
            message = g.get('message', '').strip()
            ah_m = AH_RE.search(message)
            ah_code = ah_m.group(1) if ah_m else ''
            ah_desc = AH_DESCRIPTIONS.get(ah_code, '')

            # ---- PHP fields ----
            php_error_type = ''
            php_exception_class = ''
            php_message_short = ''
            source_script = ''
            source_line = ''
            target_db_user = ''
            target_db_host = ''
            target_db_name = ''

            if module == 'php':
                pt_m = PHP_TYPE_RE.match(message)
                if pt_m:
                    php_error_type = pt_m.group(1)
                    remainder = pt_m.group(2)

                    # Exception class
                    uc_m = UNCAUGHT_RE.match(remainder)
                    if uc_m:
                        php_exception_class = uc_m.group(1)
                        err_body = uc_m.group(2)
                    else:
                        err_body = remainder

                    # Shorten: strip stack trace
                    short = err_body.split(r'\nStack trace')[0].split('\\nStack trace')[0]
                    php_message_short = short[:300].strip()

                    # Source file & line
                    loc_m = LOCATION_RE.search(message)
                    if loc_m:
                        source_script = loc_m.group(1)
                        source_line = loc_m.group(2) or ''
                    if not source_line:
                        ln_m = LINE_RE.search(message)
                        if ln_m:
                            source_line = ln_m.group(1)

                    # DB auth failure
                    af_m = AUTH_FAIL_RE.search(message)
                    if af_m:
                        target_db_user = af_m.group(1)
                        target_db_host = af_m.group(2)

                    # DNS failure host
                    dns_m = DNS_FAIL_RE.search(message)
                    if dns_m:
                        target_db_host = dns_m.group(1)

            # ---- BASoft context ----
            is_basoft = 1 if source_script in ('backup.php', 'restore.php') else 0
            is_backup = 1 if source_script == 'backup.php' else 0
            is_restore = 1 if source_script == 'restore.php' else 0

            # ---- External host ----
            host_lower = target_db_host.lower()
            is_external = 0
            if target_db_host and host_lower not in INTERNAL_HOSTS:
                is_external = 1

            # ---- Event category ----
            category = classify_event(module, level, ah_code,
                                      php_error_type, message)

            # ---- Severity ----
            sev_score, sev_label, flags = score_event(
                category, is_external, is_off, is_weekend, level)

            # ---- Build row ----
            row = {
                'line_number':         line_no,
                'timestamp_raw':       ts_raw,
                'timestamp_iso':       ts_iso,
                'timestamp_epoch':     round(ts_epoch, 6),
                'year':                year_i,
                'month':               month_i,
                'day':                 day_i,
                'hour':                hour_i,
                'minute':              minute_i,
                'second':              second_i,
                'microsecond':         micro_i,
                'day_of_week':         dow_i,
                'weekday_name':        g['dow'],
                'is_weekend':          is_weekend,
                'is_business_hours':   is_biz,
                'is_off_hours':        is_off,
                'module':              module,
                'level':               level,
                'module_level':        module_level,
                'pid':                 pid,
                'tid':                 tid,
                'has_client':          has_client,
                'client_ip':           client_ip,
                'client_port':         client_port,
                'ah_code':             ah_code,
                'ah_description':      ah_desc,
                'event_category':      category,
                'php_error_type':      php_error_type,
                'php_exception_class': php_exception_class,
                'php_message_short':   php_message_short,
                'source_script':       source_script,
                'source_line':         source_line,
                'target_db_user':      target_db_user,
                'target_db_host':      target_db_host,
                'target_db_name':      target_db_name,
                'is_external_host':    is_external,
                'is_basoft':           is_basoft,
                'is_backup_op':        is_backup,
                'is_restore_op':       is_restore,
                'message_raw':         message[:500],
                'severity_score':      sev_score,
                'severity_label':      sev_label,
                'event_flags':         flags,
            }

            writer.writerow(row)

    return total, skipped


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import collections

    base = Path(__file__).parent
    input_file = base / 'Error Log.txt'
    output_file = base / 'error_log_dataset.csv'

    if not input_file.exists():
        print(f"[ERROR] Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing : {input_file}")
    print(f"Output  : {output_file}")

    total, skipped = parse_log(str(input_file), str(output_file))

    print(f"\nDone.")
    print(f"  Parsed lines : {total:,}")
    print(f"  Skipped lines: {skipped:,}")
    print(f"  Columns      : {len(COLUMNS)}")

    # Quick stats
    cats = collections.Counter()
    sevs = collections.Counter()
    ext_count = 0
    with open(output_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cats[row['event_category']] += 1
            sevs[row['severity_label']] += 1
            if row['is_external_host'] == '1':
                ext_count += 1

    print("\n--- Event Categories ---")
    for k, v in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {k:<30} {v:>8,}")

    print("\n--- Severity Distribution ---")
    for k in ['normal', 'low', 'medium', 'high', 'critical']:
        print(f"  {k:<10} {sevs.get(k, 0):>8,}")

    print(f"\n  External host events : {ext_count:,}")
    print(f"\nDataset saved to: {output_file}")
