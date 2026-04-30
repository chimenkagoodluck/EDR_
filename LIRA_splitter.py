import re
import os
import argparse
from datetime import datetime
from collections import Counter


# Matches lines that start with a valid timestamp
RE_TIMESTAMP = re.compile(r'^(\d{4})-\d{2}-\d{2}\s+\d{1,2}:\d{2}:\d{2}\s+')


def split_log(input_path: str, output_dir: str) -> dict:
    """
    Stream through the log file line by line.
    Each timestamped line is assigned to its year bucket.
    Continuation lines (non-timestamped) are assigned to whatever
    year the most recent timestamped line belonged to.

    Returns a summary dict with stats per year.
    """

    # ── File setup ────────────────────────────────────────────────────
    base_name   = os.path.splitext(os.path.basename(input_path))[0]
    file_size   = os.path.getsize(input_path)

    # Discover years in one quick pre-scan (avoids opening 4 files blindly)
    print("  [1/3] Pre-scanning to discover years in log file...")
    years_found = set()
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = RE_TIMESTAMP.match(line)
            if m:
                years_found.add(m.group(1))
    years_found = sorted(years_found)
    print(f"        Years discovered: {', '.join(years_found)}")

    # ── Open one output file per year ─────────────────────────────────
    output_files = {}
    output_paths = {}
    for yr in years_found:
        path = os.path.join(output_dir, f"{base_name}_{yr}.txt")
        output_paths[yr] = path
        output_files[yr] = open(path, "w", encoding="utf-8")

    # ── Stats ─────────────────────────────────────────────────────────
    year_line_counts  = Counter()
    year_event_counts = Counter()
    year_bytes        = Counter()
    total_lines       = 0
    skipped_lines     = 0   # lines before first timestamped event
    current_year      = None

    # ── Main split pass ───────────────────────────────────────────────
    print("  [2/3] Splitting log file by year...")
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            total_lines += 1
            m = RE_TIMESTAMP.match(raw_line)

            if m:
                # Timestamped line — assign to its year
                current_year = m.group(1)
                if current_year in output_files:
                    output_files[current_year].write(raw_line)
                    year_line_counts[current_year]  += 1
                    year_event_counts[current_year] += 1
                    year_bytes[current_year]        += len(raw_line.encode("utf-8"))
            else:
                # Continuation line or blank — goes to current year
                if current_year and current_year in output_files:
                    output_files[current_year].write(raw_line)
                    year_line_counts[current_year] += 1
                    year_bytes[current_year]       += len(raw_line.encode("utf-8"))
                else:
                    skipped_lines += 1

    # ── Close all output files ────────────────────────────────────────
    for fh in output_files.values():
        fh.close()

    # ── Build summary ─────────────────────────────────────────────────
    summary = {
        "input_path":   input_path,
        "input_size":   file_size,
        "total_lines":  total_lines,
        "skipped":      skipped_lines,
        "years":        years_found,
        "by_year": {
            yr: {
                "path":   output_paths[yr],
                "lines":  year_line_counts[yr],
                "events": year_event_counts[yr],
                "bytes":  year_bytes[yr],
            }
            for yr in years_found
        },
    }
    return summary


def human_size(b: int) -> str:
    if b >= 1_048_576:
        return f"{b/1_048_576:.2f} MB ({b:,} bytes)"
    if b >= 1024:
        return f"{b/1024:.2f} KB ({b:,} bytes)"
    return f"{b:,} bytes"


def write_report(summary: dict, output_dir: str) -> str:
    """Write a plain-text split report and return its path."""

    W = 68
    lines = []
    def L(s=""): lines.append(s)
    def SEP():   L("═" * W)
    def sep2():  L("─" * W)

    SEP()
    L(f"{'LIRA — Log Splitter Report':^{W}}")
    L(f"{'ESUTH EMR PhD Research':^{W}}")
    SEP()
    L()
    L(f"  Input File   : {os.path.basename(summary['input_path'])}")
    L(f"  Input Size   : {human_size(summary['input_size'])}")
    L(f"  Total Lines  : {summary['total_lines']:,}")
    L(f"  Years Found  : {', '.join(summary['years'])}")
    L(f"  Generated    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L()
    sep2()
    L(f"  {'OUTPUT FILE':<35} {'EVENTS':>8}  {'LINES':>8}  {'SIZE':>20}")
    sep2()

    total_events      = 0
    total_split_lines = 0
    total_bytes       = 0
    for yr in sorted(summary["by_year"].keys()):
        d = summary["by_year"][yr]
        fname = os.path.basename(d["path"])
        pct   = d["lines"] / summary["total_lines"] * 100
        L(f"  {fname:<35} {d['events']:>8,}  {d['lines']:>8,}  {human_size(d['bytes']):>20}  ({pct:.1f}%)")
        total_events      += d["events"]
        total_split_lines += d["lines"]
        total_bytes       += d["bytes"]

    sep2()
    L(f"  {'TOTAL':<35} {total_events:>8,}  {total_split_lines:>8,}  {human_size(total_bytes):>20}")
    L()
    match = total_split_lines == summary["total_lines"]
    L(f"  Line count check:")
    L(f"    Original file total lines  : {summary['total_lines']:,}")
    L(f"    Sum of all split files     : {total_split_lines:,}")
    L(f"    Lines match                : {'✓ YES — zero lines lost' if match else '✗ NO — ' + str(abs(total_split_lines - summary['total_lines'])) + ' lines missing'}")
    L()
    sep2()
    L("  NEXT STEP — Run LIRA parser on each year file:")
    sep2()
    for yr in sorted(summary["by_year"].keys()):
        fname = os.path.basename(summary["by_year"][yr]["path"])
        L(f"  python LIRA_parser.py --input \"{fname}\"")
    L()
    SEP()

    report_path = os.path.join(output_dir, "LIRA_split_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report_path


def main():
    ap = argparse.ArgumentParser(
        description="LIRA Log Splitter — splits MariaDB log by calendar year"
    )
    ap.add_argument("--input", "-i", required=True,
        help='Path to the MariaDB error log file')
    ap.add_argument("--output", "-o", default=None,
        help="Output directory (default: same folder as input file)")
    args = ap.parse_args()

    input_path = args.input
    output_dir = args.output or os.path.dirname(os.path.abspath(input_path))
    os.makedirs(output_dir, exist_ok=True)

    print()
    print("╔" + "═"*60 + "╗")
    print("||" + "  LIRA — Log Splitter by Year".ljust(60) + "||")
    print("||" + f"  Input: {os.path.basename(input_path)}".ljust(60) + "||")
    print("||" + "═"*60 + "||")
    print()

    summary = split_log(input_path, output_dir)

    print("  [3/3] Writing split report...")
    report_path = write_report(summary, output_dir)

    # ── Console summary ───────────────────────────────────────────────
    total_split_lines = sum(d["lines"] for d in summary["by_year"].values())

    print()
    print("  ╔" + "═"*64 + "╗")
    print("  ||" + "  SPLIT COMPLETE — LINE COUNT SUMMARY".ljust(64) + "||")
    print("  ||" + "═"*64 + "||")
    print("  ||" + (
        f"  ORIGINAL FILE  :  {summary['total_lines']:,} total lines"
        f"  ({human_size(summary['input_size'])})"
    ).ljust(64) + "||")
    print("  ||" + "═"*64 + "||")
    print("  ||" + f"  {'YEAR FILE':<36} {'LINES':>10}  {'SIZE':>14}".ljust(64) + "||")
    print("  ||" + f"  {'─'*36} {'─'*10}  {'─'*14}".ljust(64) + "||")
    for yr in sorted(summary["by_year"].keys()):
        d  = summary["by_year"][yr]
        fn = os.path.basename(d["path"])
        pct = d["lines"] / summary["total_lines"] * 100
        print("  ||" + (
            f"  {fn:<36} {d['lines']:>10,}  {human_size(d['bytes']):>14}  ({pct:.1f}%)"
        ).ljust(64) + "||")
    print("  ||" + f"  {'─'*36} {'─'*10}  {'─'*14}".ljust(64) + "||")
    print("  ||" + (
        f"  {'TOTAL LINES IN ALL SPLIT FILES':<36} {total_split_lines:>10,}"
    ).ljust(64) + "||")
    print("  ||" + (
        f"  {'LINES MATCH ORIGINAL?':<36} "
        + ("✓  YES — zero lines lost" if total_split_lines == summary['total_lines']
           else f"✗  NO — {abs(total_split_lines - summary['total_lines'])} lines missing")
    ).ljust(64) + "||")
    print("  ||" + "═"*64 + "||")
    print("  ||" + f"  Report saved: {os.path.basename(report_path)}".ljust(64) + "||")
    print("  ||" + "═"*64 + "||")
    print()
    print("  Run LIRA_parser.py on each output file separately.")
    print()


if __name__ == "__main__":
    main()