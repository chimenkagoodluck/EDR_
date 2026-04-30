

import csv
import os
import sys
from datetime import datetime
from pathlib import Path

LIFECYCLE_CATS = {
    'server_start', 'server_info', 'process_spawn',
    'workers_started', 'shutdown_signal', 'workers_stopped',
    'process_exited', 'server_lifecycle',
}

SPLITS = [
    ("error_00_master_all_events",
     lambda r: True),

    ("error_01_server_lifecycle",
     lambda r: r["event_category"] in LIFECYCLE_CATS),

    ("error_02_ssl_cert_warnings",
     lambda r: r["event_category"] == "ssl_cert_mismatch"),

    ("error_03_unclean_shutdowns",
     lambda r: r["event_category"] == "unclean_shutdown"),

    ("error_04_php_dns_failures",
     lambda r: r["event_category"] == "php_dns_fail"),

    ("error_05_php_db_auth_failures",
     lambda r: r["event_category"] == "php_db_auth_fail"),

    ("error_06_basoft_backup_errors",
     lambda r: r["is_backup_op"] == "1"),

    ("error_07_basoft_restore_errors",
     lambda r: r["is_restore_op"] == "1"),

    ("error_08_external_host_events",
     lambda r: r["is_external_host"] == "1"),

    ("error_09_high_critical_events",
     lambda r: r["severity_label"] in ("high", "critical")),
]

SPLIT_DESCRIPTIONS = {
    "error_00_master_all_events":    "All parsed error log events (full dataset)",
    "error_01_server_lifecycle":     "Apache server start, stop, process spawn, worker events",
    "error_02_ssl_cert_warnings":    "SSL certificate CN-mismatch warnings (AH01909)",
    "error_03_unclean_shutdowns":    "Unclean/forced Apache shutdown detections (AH00098)",
    "error_04_php_dns_failures":     "PHP DNS resolution failures connecting to www.bookingafrica.org",
    "error_05_php_db_auth_failures": "PHP database authentication failures (wrong credentials)",
    "error_06_basoft_backup_errors": "All PHP errors from BASoft backup.php",
    "error_07_basoft_restore_errors":"All PHP errors from BASoft restore.php",
    "error_08_external_host_events": "Events involving an external internet-routable host",
    "error_09_high_critical_events": "All events with severity score high or critical",
}


def human_size(b: int) -> str:
    if b >= 1_048_576:
        return f"{b / 1_048_576:.2f} MB ({b:,} bytes)"
    if b >= 1024:
        return f"{b / 1024:.2f} KB ({b:,} bytes)"
    return f"{b:,} bytes"


def write_report(summary: dict, output_dir: str) -> str:
    W = 72
    lines = []

    def L(s=""): lines.append(s)
    def SEP():    L("=" * W)
    def sep2():   L("-" * W)

    SEP()
    L(f"{'Apache Error Log -- Dataset Split Report':^{W}}")
    L(f"{'ESUTH EMR PhD Research':^{W}}")
    SEP()
    L()
    L(f"  Input File   : {os.path.basename(summary['input_path'])}")
    L(f"  Input Rows   : {summary['total_rows']:,}")
    L(f"  Output Folder: {os.path.basename(summary['output_dir'])}")
    L(f"  Generated    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L()
    sep2()
    L(f"  {'OUTPUT FILE':<45} {'ROWS':>7}  {'PCT':>6}  {'SIZE':>18}")
    sep2()

    for entry in summary["splits"]:
        pct = entry["rows"] / summary["total_rows"] * 100 if summary["total_rows"] else 0
        L(f"  {entry['filename']:<45} {entry['rows']:>7,}  {pct:>5.1f}%  {human_size(entry['bytes']):>18}")

    sep2()
    L()
    L("  Split descriptions:")
    sep2()
    for entry in summary["splits"]:
        L(f"  {entry['filename']}")
        L(f"    -> {entry['description']}")
    L()
    SEP()

    report_path = os.path.join(output_dir, "error_log_split_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report_path


def split_dataset(input_path: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n  Reading: {input_path}")
    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    total = len(rows)
    print(f"  Loaded {total:,} rows  |  {len(fieldnames)} columns")
    print()

    summary_splits = []

    for name, filter_fn in SPLITS:
        out_path = os.path.join(output_dir, f"{name}.csv")
        subset = [r for r in rows if filter_fn(r)]

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in subset:
                writer.writerow(r)

        pct = len(subset) / total * 100 if total else 0
        print(f"  [{name}]  {len(subset):>7,} rows  ({pct:.1f}%)")

        summary_splits.append({
            "filename":    f"{name}.csv",
            "rows":        len(subset),
            "bytes":       os.path.getsize(out_path),
            "description": SPLIT_DESCRIPTIONS.get(name, ""),
        })

    summary = {
        "input_path": input_path,
        "output_dir": output_dir,
        "total_rows": total,
        "splits":     summary_splits,
    }

    report_path = write_report(summary, output_dir)
    print(f"\n  Report saved: {os.path.basename(report_path)}")
    return summary


if __name__ == "__main__":
    base = Path(__file__).parent
    input_csv = base / "error_log_dataset.csv"
    output_dir = base / "Error_Log_Output"

    if not input_csv.exists():
        print(f"[ERROR] Dataset not found: {input_csv}", file=sys.stderr)
        sys.exit(1)

    print("+" + "=" * 60 + "+")
    print("|" + "  Apache Error Log -- Dataset Splitter".ljust(60) + "|")
    print("+" + "=" * 60 + "+")

    split_dataset(str(input_csv), str(output_dir))

    print()
    print("  Done.  Split files are in:", output_dir)
    print()
