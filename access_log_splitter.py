

import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from collections import Counter


# ---------------------------------------------------------------------------
# Split definitions  (name, filter_fn)
# ---------------------------------------------------------------------------

SPLITS = [
    ("access_00_master_all_events",
     lambda r: True),

    ("access_01_normal_traffic",
     lambda r: int(r["anomaly_score"]) == 0),

    ("access_02_low_anomaly",
     lambda r: 1 <= int(r["anomaly_score"]) <= 2),

    ("access_03_medium_anomaly",
     lambda r: 3 <= int(r["anomaly_score"]) <= 4),

    ("access_04_high_anomaly",
     lambda r: int(r["anomaly_score"]) >= 5),

    ("access_05_credential_exposure",
     lambda r: r["credentials_in_url"] == "1"),

    ("access_06_basoft_backup_ops",
     lambda r: r["basoft_operation"] == "backup"),

    ("access_07_basoft_restore_ops",
     lambda r: r["basoft_operation"] == "restore"),

    ("access_08_http_errors_4xx",
     lambda r: r["status_category"] == "4xx"),

    ("access_09_phpmyadmin_access",
     lambda r: r["app_section"] == "phpMyAdmin"),
]

SPLIT_DESCRIPTIONS = {
    "access_00_master_all_events":   "All parsed access log events (full dataset)",
    "access_01_normal_traffic":      "Requests with zero anomaly signals",
    "access_02_low_anomaly":         "Requests with anomaly score 1-2 (minor flags)",
    "access_03_medium_anomaly":      "Requests with anomaly score 3-4 (moderate risk)",
    "access_04_high_anomaly":        "Requests with anomaly score >= 5 (high-risk events)",
    "access_05_credential_exposure": "Requests with credentials (password/token) in URL",
    "access_06_basoft_backup_ops":   "BASoft database backup operations",
    "access_07_basoft_restore_ops":  "BASoft database restore operations",
    "access_08_http_errors_4xx":     "Client-error HTTP responses (4xx status codes)",
    "access_09_phpmyadmin_access":   "Requests to the phpMyAdmin administration panel",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    L(f"{'Apache Access Log — Dataset Split Report':^{W}}")
    L(f"{'ESUTH EMR PhD Research':^{W}}")
    SEP()
    L()
    L(f"  Input File   : {os.path.basename(summary['input_path'])}")
    L(f"  Input Rows   : {summary['total_rows']:,}")
    L(f"  Output Folder: {os.path.basename(summary['output_dir'])}")
    L(f"  Generated    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L()
    sep2()
    L(f"  {'OUTPUT FILE':<42} {'ROWS':>8}  {'PCT':>6}  {'SIZE':>20}")
    sep2()

    for entry in summary["splits"]:
        pct = entry["rows"] / summary["total_rows"] * 100 if summary["total_rows"] else 0
        L(f"  {entry['filename']:<42} {entry['rows']:>8,}  {pct:>5.1f}%  {human_size(entry['bytes']):>20}")

    sep2()
    L()
    L("  Split descriptions:")
    sep2()
    for entry in summary["splits"]:
        L(f"  {entry['filename']}")
        L(f"    → {entry['description']}")
    L()
    SEP()

    report_path = os.path.join(output_dir, "access_log_split_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def split_dataset(input_path: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n  Reading: {input_path}")

    # Load all rows once
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
        byte_size = 0

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in subset:
                writer.writerow(r)
                byte_size += sum(len(v) for v in r.values()) + len(fieldnames)

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
    input_csv = base / "access_log_dataset.csv"
    output_dir = base / "Access_Log_Output"

    if not input_csv.exists():
        print(f"[ERROR] Dataset not found: {input_csv}", file=sys.stderr)
        sys.exit(1)

    print("+" + "=" * 60 + "+")
    print("|" + "  Apache Access Log -- Dataset Splitter".ljust(60) + "|")
    print("+" + "=" * 60 + "+")

    split_dataset(str(input_csv), str(output_dir))

    print()
    print("  Done.  Split files are in:", output_dir)
    print()
