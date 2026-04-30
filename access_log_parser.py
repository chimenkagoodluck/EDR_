#Writing access_log_parser.py
import re
import csv
import sys
import ipaddress
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

LOG_RE = re.compile(
    r'(?P<ip>\S+)'          # client IP
    r' \S+ \S+ '            # ident, auth (always -)
    r'\[(?P<time>[^\]]+)\]' # timestamp
    r' "(?P<request>[^"]*)"'# request line
    r' (?P<status>\d{3})'   # status code
    r' (?P<bytes>\S+)'      # bytes sent (or -)
    r' "(?P<referer>[^"]*)"'# referer
    r' "(?P<ua>[^"]*)"'     # user agent
)

# Request line: METHOD /path HTTP/1.x
REQUEST_RE = re.compile(r'(?P<method>\S+)\s+(?P<uri>\S+)(?:\s+(?P<proto>HTTP/[\d.]+))?')

BACKUP_RE = re.compile(
    r'backup\.php\?.*?onlineDB=(?P<db>[^&]+).*?offlineDBnameToUpload=(?P<fname>[^&]+).*?host=(?P<host>[^&\s]+)',
    re.IGNORECASE
)
RESTORE_RE = re.compile(
    r'restore\.php\?.*?offlineDBnameToUpload=(?P<fname>[^&]+).*?onlineHost=(?P<host>[^&]+).*?onlineUser=(?P<user>[^&]+).*?onlinePassword=(?P<pwd>[^&]+).*?onlineDB=(?P<db>[^&\s]+)',
    re.IGNORECASE
)

# Credential patterns in URL (any key=value that looks like auth material)
CRED_PARAM_RE = re.compile(
    r'(?:password|passwd|pwd|pass|secret|token|auth|key|apikey)=([^&\s]+)',
    re.IGNORECASE
)

# Suspicious path patterns
SUSPICIOUS_PATHS = re.compile(
    r'(?:\.\./|\.\.\\|%2e%2e|etc/passwd|/etc/shadow|/proc/|'
    r'cmd=|eval\(|base64|select.*from|union.*select|<script|'
    r'/wp-admin|/wp-login|/xmlrpc|\.git/|\.env|/admin/|/shell|'
    r'\.php\?.*=http|%00|null\x00)',
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

def parse_timestamp(ts_str: str):
    """Parse Apache timestamp like '27/Aug/2023:16:00:22 -0700'."""
    try:
        dt_part, tz_part = ts_str.rsplit(' ', 1)
        dt = datetime.strptime(dt_part, '%d/%b/%Y:%H:%M:%S')
        sign = 1 if tz_part[0] == '+' else -1
        tz_hours = int(tz_part[1:3])
        tz_mins = int(tz_part[3:5])
        offset = timedelta(hours=tz_hours, minutes=tz_mins) * sign
        tz = timezone(offset)
        dt = dt.replace(tzinfo=tz)
        return dt
    except Exception:
        return None


def classify_ip(ip_str: str):
    """Return (ip_version, ip_type) for an IP address string."""
    try:
        addr = ipaddress.ip_address(ip_str)
        version = addr.version
        if addr.is_loopback:
            ip_type = 'loopback'
        elif addr.is_link_local:
            ip_type = 'link_local'
        elif addr.is_private:
            ip_type = 'private'
        else:
            ip_type = 'public'
        return version, ip_type
    except ValueError:
        return 0, 'unknown'


def classify_resource(path: str, method: str):
    """Classify the resource type from the URI path."""
    ext = Path(path).suffix.lower().lstrip('.')
    static_css = {'css'}
    static_js = {'js'}
    static_img = {'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'webp', 'bmp'}
    static_font = {'woff', 'woff2', 'ttf', 'eot'}
    static_doc = {'pdf', 'txt', 'xml', 'json'}
    if ext in static_css:
        return ext, 'static_css'
    if ext in static_js:
        return ext, 'static_js'
    if ext in static_img:
        return ext, 'static_image'
    if ext in static_font:
        return ext, 'static_font'
    if ext in static_doc:
        return ext, 'static_doc'
    if ext == 'php':
        return ext, 'php_page'
    if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return ext or 'none', 'api_call'
    return ext or 'none', 'page'


def get_app_section(path: str):
    """Identify which application section is being accessed."""
    path_lower = path.lower()
    if path_lower.startswith('/basoft'):
        return 'BASoft'
    if path_lower.startswith('/phpmyadmin'):
        return 'phpMyAdmin'
    if path_lower.startswith('/dashboard'):
        return 'dashboard'
    if path_lower in ('/', ''):
        return 'root'
    return 'other'


def parse_user_agent(ua: str):
    """Extract browser family, OS family, and bot flag from UA string."""
    ua_lower = ua.lower()
    # Bot detection
    bot_keywords = ('bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
                    'python', 'httpclient', 'libwww', 'go-http', 'java/')
    is_bot = any(k in ua_lower for k in bot_keywords)

    # Browser family (order matters — most specific first)
    if 'msie' in ua_lower or 'trident' in ua_lower:
        browser = 'IE'
    elif 'edg/' in ua_lower or 'edge/' in ua_lower:
        browser = 'Edge'
    elif 'chrome' in ua_lower and 'safari' in ua_lower:
        browser = 'Chrome'
    elif 'firefox' in ua_lower:
        browser = 'Firefox'
    elif 'safari' in ua_lower:
        browser = 'Safari'
    elif 'opera' in ua_lower or 'opr/' in ua_lower:
        browser = 'Opera'
    elif ua == '-' or ua == '':
        browser = 'unknown'
    else:
        browser = 'other'

    # OS family
    if 'windows nt' in ua_lower:
        os_fam = 'Windows'
    elif 'macintosh' in ua_lower or 'mac os x' in ua_lower:
        os_fam = 'macOS'
    elif 'linux' in ua_lower or 'android' in ua_lower:
        os_fam = 'Linux/Android'
    elif 'iphone' in ua_lower or 'ipad' in ua_lower:
        os_fam = 'iOS'
    elif ua == '-' or ua == '':
        os_fam = 'unknown'
    else:
        os_fam = 'other'

    return browser, os_fam, is_bot


def parse_basoft_operation(uri: str):
    """Extract BASoft backup/restore metadata from the URI."""
    m = BACKUP_RE.search(uri)
    if m:
        fname = m.group('fname')
        # Extract date from filename like bamed2023-11-25
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', fname)
        backup_date = date_match.group(1) if date_match else ''
        return 'backup', m.group('db'), m.group('host'), '', backup_date

    m = RESTORE_RE.search(uri)
    if m:
        fname = m.group('fname')
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', fname)
        backup_date = date_match.group(1) if date_match else ''
        return 'restore', m.group('db'), m.group('host'), m.group('user'), backup_date

    return 'none', '', '', '', ''


# ---------------------------------------------------------------------------
# Anomaly scoring (rule-based labels for ML supervision)
# ---------------------------------------------------------------------------

def score_anomalies(row: dict) -> tuple[int, str]:
    """
    Apply rule-based anomaly detection.
    Returns (anomaly_score, pipe-separated list of triggered rules).
    Score: 0=normal, 1-2=low, 3-4=medium, 5+=high
    """
    score = 0
    flags = []

    # Credential exposure in URL
    if row['credentials_in_url']:
        score += 3
        flags.append('CRED_IN_URL')

    # Client error (404, 405)
    if row['status_category'] == '4xx':
        score += 1
        flags.append('CLIENT_ERROR')

    # Many 404s signal scanning — handled at session level via flag
    if row['status_code'] == 404:
        score += 1
        flags.append('NOT_FOUND')

    # Method not allowed
    if row['status_code'] == 405:
        score += 2
        flags.append('METHOD_NOT_ALLOWED')

    # Timeout / request abandoned
    if row['status_code'] == 408:
        score += 1
        flags.append('REQUEST_TIMEOUT')

    # Server error
    if row['status_category'] == '5xx':
        score += 3
        flags.append('SERVER_ERROR')

    # Suspicious path patterns
    if row['suspicious_path']:
        score += 4
        flags.append('SUSPICIOUS_PATH')

    # Off-hours access (outside 06:00–22:00)
    hour = int(row['hour'])
    if hour < 6 or hour >= 22:
        score += 1
        flags.append('OFF_HOURS')

    # Weekend access
    if row['is_weekend']:
        score += 1
        flags.append('WEEKEND')

    # High request rate (>60 req/min from same IP)
    if int(row['req_per_ip_last_60s']) > 60:
        score += 2
        flags.append('HIGH_RATE_60S')

    # Burst (>200 req/5min)
    if int(row['req_per_ip_last_5min']) > 200:
        score += 2
        flags.append('HIGH_RATE_5MIN')

    # Exact duplicate request within 5 seconds
    if row['is_duplicate']:
        score += 1
        flags.append('DUPLICATE_REQ')

    # BASoft restore with wrong date (date in URL != request date)
    if row['basoft_operation'] == 'restore' and row['basoft_date_mismatch']:
        score += 2
        flags.append('BASOFT_DATE_MISMATCH')

    # OPTIONS from non-browser (potential CORS probe)
    if row['method'] == 'OPTIONS' and row['browser_family'] == 'unknown':
        score += 1
        flags.append('CORS_PROBE')

    # No user-agent
    if row['user_agent'] in ('-', '', 'none'):
        score += 1
        flags.append('NO_UA')

    return score, '|'.join(flags) if flags else 'none'


# ---------------------------------------------------------------------------
# Session / behavioral state  (per-IP sliding windows)
# ---------------------------------------------------------------------------

class SessionTracker:
    """Tracks per-IP behavioral features using sliding time windows."""

    def __init__(self):
        # ip -> deque of timestamps (epoch seconds)
        self._windows: dict[str, deque] = defaultdict(deque)
        # ip -> last seen timestamp
        self._last_seen: dict[str, float] = {}
        # (ip, uri) -> last seen timestamp (duplicate detection)
        self._last_uri: dict[tuple, float] = {}

    def record(self, ip: str, uri: str, ts_epoch: float):
        dq = self._windows[ip]
        dq.append(ts_epoch)

        # Prune entries older than 5 min
        cutoff = ts_epoch - 300
        while dq and dq[0] < cutoff:
            dq.popleft()

        # Inter-request time
        inter_sec = round(ts_epoch - self._last_seen[ip], 2) if ip in self._last_seen else -1
        self._last_seen[ip] = ts_epoch

        # Request rate: last 60 s and last 5 min
        cutoff60 = ts_epoch - 60
        count60 = sum(1 for t in dq if t >= cutoff60)
        count5m = len(dq)

        # Duplicate detection: same IP + URI within 30 s
        key = (ip, uri)
        is_dup = (key in self._last_uri) and (ts_epoch - self._last_uri[key] <= 30)
        self._last_uri[key] = ts_epoch

        return inter_sec, count60, count5m, is_dup


# ---------------------------------------------------------------------------
# Output columns (ordered)
# ---------------------------------------------------------------------------

COLUMNS = [
    # --- Core fields ---
    'line_number', 'ip_address', 'timestamp_iso', 'timestamp_epoch',
    'year', 'month', 'day', 'hour', 'minute', 'second',
    'day_of_week',          # 0=Mon … 6=Sun
    'timezone_offset',      # e.g. +0100
    'method', 'uri', 'uri_path', 'uri_query', 'protocol',
    'status_code', 'response_bytes',
    'referer', 'has_referer',
    'user_agent',
    # --- Temporal derived ---
    'is_weekend',           # 1/0
    'is_business_hours',    # 1/0  (08:00–18:00)
    # --- IP / network ---
    'ip_version',           # 4 or 6
    'ip_type',              # loopback | link_local | private | public | unknown
    'is_internal',          # 1 if loopback or link_local or private
    # --- Request features ---
    'uri_depth',            # path segment count
    'uri_length',
    'file_extension',
    'resource_type',        # static_css | static_js | static_image | php_page | api_call | page …
    'app_section',          # BASoft | phpMyAdmin | dashboard | root | other
    'query_param_count',
    # --- Status features ---
    'status_category',      # 2xx | 3xx | 4xx | 5xx
    'is_redirect',
    'is_error',             # 1 if 4xx or 5xx
    'is_server_error',
    # --- User-agent features ---
    'browser_family',
    'os_family',
    'is_bot',
    'ua_length',
    # --- Security signals ---
    'credentials_in_url',
    'suspicious_path',
    # --- Behavioral / session features ---
    'inter_request_seconds',    # time since this IP's last request (-1 = first)
    'req_per_ip_last_60s',
    'req_per_ip_last_5min',
    'is_duplicate',             # 1 if same IP+URI seen within 30 s
    # --- BASoft application features ---
    'basoft_operation',         # backup | restore | none
    'basoft_target_db',
    'basoft_host',
    'basoft_user',              # restore only
    'basoft_date',              # date embedded in filename
    'basoft_date_mismatch',     # 1 if backup date != request date
    # --- Anomaly labels ---
    'anomaly_score',
    'anomaly_flags',
]


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_log(input_path: str, output_path: str):
    tracker = SessionTracker()
    total = skipped = 0

    with open(input_path, 'r', encoding='utf-8', errors='replace') as fin, \
         open(output_path, 'w', newline='', encoding='utf-8') as fout:

        writer = csv.DictWriter(fout, fieldnames=COLUMNS)
        writer.writeheader()

        for line_no, raw_line in enumerate(fin, start=1):
            line = raw_line.strip()
            if not line:
                skipped += 1
                continue

            m = LOG_RE.match(line)
            if not m:
                skipped += 1
                continue

            total += 1
            g = m.groupdict()

            # ---- Timestamp ----
            dt = parse_timestamp(g['time'])
            ts_epoch = dt.timestamp() if dt else 0.0
            ts_iso = dt.isoformat() if dt else ''
            tz_offset = g['time'].rsplit(' ', 1)[-1] if ' ' in g['time'] else ''

            # ---- Request line ----
            req_m = REQUEST_RE.match(g['request'])
            if req_m:
                method = req_m.group('method').upper()
                uri = req_m.group('uri')
                protocol = req_m.group('proto') or ''
            else:
                method = g['request'] or '-'
                uri = ''
                protocol = ''

            parsed_uri = urlparse(uri)
            uri_path = parsed_uri.path
            uri_query = parsed_uri.query
            query_params = parse_qs(uri_query, keep_blank_values=True)
            query_param_count = len(query_params)
            uri_depth = len([p for p in uri_path.split('/') if p])
            uri_length = len(uri)

            # ---- Status / bytes ----
            status_code = int(g['status'])
            raw_bytes = g['bytes']
            response_bytes = int(raw_bytes) if raw_bytes.isdigit() else 0

            status_cat = f"{status_code // 100}xx"
            is_redirect = 1 if 300 <= status_code < 400 else 0
            is_error = 1 if status_code >= 400 else 0
            is_server_error = 1 if status_code >= 500 else 0

            # ---- Referer ----
            referer = g['referer']
            has_referer = 0 if referer in ('-', '', 'none') else 1

            # ---- User agent ----
            ua = g['ua']
            browser, os_fam, is_bot = parse_user_agent(ua)

            # ---- IP classification ----
            ip = g['ip']
            ip_version, ip_type = classify_ip(ip)
            is_internal = 1 if ip_type in ('loopback', 'link_local', 'private') else 0

            # ---- Resource classification ----
            file_ext, resource_type = classify_resource(uri_path, method)
            app_section = get_app_section(uri_path)

            # ---- Temporal features ----
            if dt:
                year, month, day = dt.year, dt.month, dt.day
                hour, minute, second = dt.hour, dt.minute, dt.second
                dow = dt.weekday()  # 0=Mon
                is_weekend = 1 if dow >= 5 else 0
                is_biz = 1 if 8 <= hour < 18 else 0
            else:
                year = month = day = hour = minute = second = 0
                dow = is_weekend = is_biz = 0

            # ---- Security signals ----
            cred_in_url = 1 if CRED_PARAM_RE.search(uri) else 0
            susp_path = 1 if SUSPICIOUS_PATHS.search(uri) else 0

            # ---- Behavioral / session ----
            inter_sec, count60, count5m, is_dup = tracker.record(ip, uri, ts_epoch)

            # ---- BASoft features ----
            op, db, host, user, b_date = parse_basoft_operation(uri)
            if b_date and dt:
                # Compare embedded date with request date
                try:
                    emb_date = datetime.strptime(b_date, '%Y-%m-%d').date()
                    req_date = dt.date()
                    date_mismatch = 1 if emb_date != req_date else 0
                except ValueError:
                    date_mismatch = 0
            else:
                date_mismatch = 0

            # ---- Build row ----
            row = {
                'line_number': line_no,
                'ip_address': ip,
                'timestamp_iso': ts_iso,
                'timestamp_epoch': round(ts_epoch, 3),
                'year': year,
                'month': month,
                'day': day,
                'hour': hour,
                'minute': minute,
                'second': second,
                'day_of_week': dow,
                'timezone_offset': tz_offset,
                'method': method,
                'uri': uri,
                'uri_path': uri_path,
                'uri_query': uri_query,
                'protocol': protocol,
                'status_code': status_code,
                'response_bytes': response_bytes,
                'referer': referer,
                'has_referer': has_referer,
                'user_agent': ua,
                'is_weekend': is_weekend,
                'is_business_hours': is_biz,
                'ip_version': ip_version,
                'ip_type': ip_type,
                'is_internal': is_internal,
                'uri_depth': uri_depth,
                'uri_length': uri_length,
                'file_extension': file_ext,
                'resource_type': resource_type,
                'app_section': app_section,
                'query_param_count': query_param_count,
                'status_category': status_cat,
                'is_redirect': is_redirect,
                'is_error': is_error,
                'is_server_error': is_server_error,
                'browser_family': browser,
                'os_family': os_fam,
                'is_bot': 1 if is_bot else 0,
                'ua_length': len(ua),
                'credentials_in_url': cred_in_url,
                'suspicious_path': susp_path,
                'inter_request_seconds': inter_sec,
                'req_per_ip_last_60s': count60,
                'req_per_ip_last_5min': count5m,
                'is_duplicate': 1 if is_dup else 0,
                'basoft_operation': op,
                'basoft_target_db': db,
                'basoft_host': host,
                'basoft_user': user,
                'basoft_date': b_date,
                'basoft_date_mismatch': date_mismatch,
                'anomaly_score': 0,     # filled below
                'anomaly_flags': '',    # filled below
            }

            score, flags = score_anomalies(row)
            row['anomaly_score'] = score
            row['anomaly_flags'] = flags

            writer.writerow(row)

    return total, skipped


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    base = Path(__file__).parent
    input_file = base / 'access log.txt'
    output_file = base / 'access_log_dataset.csv'

    if not input_file.exists():
        print(f"[ERROR] Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing: {input_file}")
    print(f"Output:  {output_file}")

    total, skipped = parse_log(str(input_file), str(output_file))

    print(f"\nDone.")
    print(f"  Parsed lines : {total:,}")
    print(f"  Skipped lines: {skipped:,}")
    print(f"  Output rows  : {total:,}")
    print(f"  Columns      : {len(COLUMNS)}")
    print(f"\nDataset saved to: {output_file}")

    # Quick stats summary
    import collections
    with open(output_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        scores = collections.Counter()
        ops = collections.Counter()
        status_cats = collections.Counter()
        cred_count = 0
        for row in reader:
            scores[int(row['anomaly_score'])] += 1
            ops[row['basoft_operation']] += 1
            status_cats[row['status_category']] += 1
            if row['credentials_in_url'] == '1':
                cred_count += 1

    print("\n--- Dataset Summary ---")
    print(f"  Status categories  : {dict(status_cats)}")
    print(f"  BASoft operations  : {dict(ops)}")
    print(f"  Credentials in URL : {cred_count:,} rows")
    print("\n  Anomaly score distribution:")
    for s in sorted(scores):
        label = 'normal' if s == 0 else ('low' if s <= 2 else ('medium' if s <= 4 else 'high'))
        print(f"    Score {s:2d} ({label:6s}): {scores[s]:>7,} rows")
