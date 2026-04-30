

import os
import sys
from datetime import datetime, timezone
from collections import defaultdict

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    from lxml import etree
except ImportError:
    print("[ERROR] python-evtx or lxml not found. Run: pip install python-evtx lxml")
    sys.exit(1)

# ── Priority files in security-relevance order ─────────────────────────────
PRIORITY_FILES = [
    ("CRITICAL", "Security.evtx"),
    ("CRITICAL", "System.evtx"),
    ("CRITICAL", "Microsoft-Windows-Windows Defender%4Operational.evtx"),
    ("CRITICAL", "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"),
    ("HIGH",     "Microsoft-Windows-PowerShell%4Operational.evtx"),
    ("HIGH",     "Microsoft-Windows-WMI-Activity%4Operational.evtx"),
    ("HIGH",     "Microsoft-Windows-TaskScheduler%4Maintenance.evtx"),
    ("HIGH",     "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"),
    ("HIGH",     "Microsoft-Windows-WinRM%4Operational.evtx"),
    ("HIGH",     "Microsoft-Windows-SMBServer%4Security.evtx"),
    ("HIGH",     "Microsoft-Windows-SMBServer%4Audit.evtx"),
    ("HIGH",     "Microsoft-Windows-SMBServer%4Operational.evtx"),
    ("MEDIUM",   "Application.evtx"),
    ("MEDIUM",   "Microsoft-Windows-UAC%4Operational.evtx"),
    ("MEDIUM",   "Microsoft-Windows-CodeIntegrity%4Operational.evtx"),
    ("MEDIUM",   "Microsoft-Windows-GroupPolicy%4Operational.evtx"),
    ("MEDIUM",   "Microsoft-Windows-Winlogon%4Operational.evtx"),
    ("MEDIUM",   "Microsoft-Windows-Crypto-DPAPI%4Operational.evtx"),
    ("MEDIUM",   "Windows PowerShell.evtx"),
]

LOGS_DIR = os.path.join(os.path.dirname(__file__), "Logs", "Logs")

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_evtx_file(filepath):
    """Return (min_ts, max_ts, total_count, event_id_counts, errors)."""
    min_ts = None
    max_ts = None
    total = 0
    event_id_counts = defaultdict(int)
    errors = 0

    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = etree.fromstring(xml_str.encode("utf-8"))

                    # Timestamp
                    ts_elem = root.find(f".//{NS}TimeCreated")
                    if ts_elem is not None:
                        ts_raw = ts_elem.get("SystemTime", "")
                        # Strip trailing zeros / Z for fromisoformat compat
                        ts_raw = ts_raw.rstrip("Z").split(".")[0]
                        try:
                            ts = datetime.fromisoformat(ts_raw)
                            if min_ts is None or ts < min_ts:
                                min_ts = ts
                            if max_ts is None or ts > max_ts:
                                max_ts = ts
                        except ValueError:
                            pass

                    # Event ID
                    eid_elem = root.find(f".//{NS}EventID")
                    if eid_elem is not None and eid_elem.text:
                        event_id_counts[int(eid_elem.text)] += 1

                    total += 1

                except Exception:
                    errors += 1
                    continue

    except Exception as e:
        return None, None, 0, {}, str(e)

    return min_ts, max_ts, total, dict(event_id_counts), errors


def format_ts(ts):
    if ts is None:
        return "N/A"
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def top_event_ids(counts, n=5):
    if not counts:
        return "none"
    sorted_ids = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
    return ", ".join(f"EID {eid}({cnt})" for eid, cnt in sorted_ids)


def main():
    print("=" * 78)
    print("  EVTX DIAGNOSTIC SCANNER  —  ESUTH EDR Research")
    print(f"  Logs directory : {LOGS_DIR}")
    print(f"  Scan started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 78)

    results = []
    total_events_all = 0
    global_min = None
    global_max = None

    for priority, filename in PRIORITY_FILES:
        filepath = os.path.join(LOGS_DIR, filename)

        if not os.path.exists(filepath):
            print(f"\n[{priority:<8}] {filename}")
            print(f"           STATUS  : FILE NOT FOUND — skipping")
            results.append((priority, filename, None, None, 0, {}, "not found"))
            continue

        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"\n[{priority:<8}] {filename}")
        print(f"           Size    : {size_mb:.2f} MB", end="", flush=True)

        min_ts, max_ts, total, eid_counts, err = parse_evtx_file(filepath)

        if isinstance(err, str) and total == 0:
            print(f"\n           STATUS  : PARSE ERROR — {err}")
            results.append((priority, filename, None, None, 0, {}, err))
            continue

        print(f"  |  Events: {total:,}  |  Parse errors: {err}")
        print(f"           Range   : {format_ts(min_ts)}  to  {format_ts(max_ts)}")
        print(f"           Top IDs : {top_event_ids(eid_counts)}")

        total_events_all += total
        if min_ts and (global_min is None or min_ts < global_min):
            global_min = min_ts
        if max_ts and (global_max is None or max_ts > global_max):
            global_max = max_ts

        results.append((priority, filename, min_ts, max_ts, total, eid_counts, err))

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("  SUMMARY")
    print("=" * 78)
    print(f"  Files scanned        : {len(PRIORITY_FILES)}")
    found = sum(1 for r in results if r[4] > 0)
    print(f"  Files with events    : {found}")
    print(f"  Total events across  : {total_events_all:,}")
    print(f"  Global date range    : {format_ts(global_min)}  to  {format_ts(global_max)}")

    # Alignment check against LIRA years
    lira_years = {2023, 2024, 2025, 2026}
    covered_years = set()
    for r in results:
        min_ts, max_ts = r[2], r[3]
        if min_ts and max_ts:
            for y in range(min_ts.year, max_ts.year + 1):
                covered_years.add(y)

    overlap = lira_years & covered_years
    print(f"\n  LIRA dataset years   : {sorted(lira_years)}")
    print(f"  EVTX covered years   : {sorted(covered_years)}")
    if overlap:
        print(f"  Overlap (alignable)  : {sorted(overlap)}  [YES]  Cross-source correlation POSSIBLE")
    else:
        print(f"  Overlap              : NONE  [NO]  No direct timestamp alignment with LIRA data")

    # ── Per-file table ──────────────────────────────────────────────────────
    print("\n" + "-" * 78)
    print(f"  {'PRIORITY':<10} {'EVENTS':>8}  {'EARLIEST':<20} {'LATEST':<20}  FILE")
    print("-" * 78)
    for r in results:
        priority, filename, min_ts, max_ts, total, _, _ = r
        short = filename.replace("Microsoft-Windows-", "MW-").replace("%4", "@")
        print(f"  {priority:<10} {total:>8,}  {format_ts(min_ts):<20} {format_ts(max_ts):<20}  {short}")
    print("=" * 78)

    # ── Save results to text file ───────────────────────────────────────────
    out_path = os.path.join(os.path.dirname(__file__), "evtx_diagnostic_report.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("EVTX DIAGNOSTIC REPORT — ESUTH EDR Research\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Global date range : {format_ts(global_min)} to {format_ts(global_max)}\n")
        f.write(f"Total events      : {total_events_all:,}\n\n")
        f.write(f"{'PRIORITY':<10} {'EVENTS':>8}  {'EARLIEST':<20} {'LATEST':<20}  FILE\n")
        f.write("-" * 78 + "\n")
        for r in results:
            priority, filename, min_ts, max_ts, total, eid_counts, _ = r
            short = filename.replace("Microsoft-Windows-", "MW-").replace("%4", "@")
            f.write(f"{priority:<10} {total:>8,}  {format_ts(min_ts):<20} {format_ts(max_ts):<20}  {short}\n")
            if eid_counts:
                f.write(f"{'':10}   Top IDs: {top_event_ids(eid_counts, n=10)}\n")
        f.write("\n" + "=" * 78 + "\n")

    print(f"\n  Full report saved: {out_path}")


if __name__ == "__main__":
    main()
