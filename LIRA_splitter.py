import re
import os
import argparse
from datetime import datetime
from collections import Counter

from access_log_splitter import write_report


# Matches lines that start with a valid timestamp
RE_TIMESTAMP = re.compile(r'^(\d{4})-\d{2}-\d{2}\s+\d{1,2}:\d{2}:\d{2}\s+')


def split_log(input_path: str, output_dir: str) -> dict:
    """Split a MariaDB log file into one file per year."""
    # ── File setup 
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

  
    output_files = {}
    output_paths = {}
    for yr in years_found:
        path = os.path.join(output_dir, f"{base_name}_{yr}.txt")
        output_paths[yr] = path
        output_files[yr] = open(path, "w", encoding="utf-8")

   
    year_line_counts  = Counter()
    year_event_counts = Counter()
    year_bytes        = Counter()
    total_lines       = 0
    skipped_lines     = 0  
    current_year      = None

  
    print("  [2/3] Splitting log file by year...")
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            total_lines += 1
            m = RE_TIMESTAMP.match(raw_line)

            if m:
                
                current_year = m.group(1)
                if current_year in output_files:
                    output_files[current_year].write(raw_line)
                    year_line_counts[current_year]  += 1
                    year_event_counts[current_year] += 1
                    year_bytes[current_year]        += len(raw_line.encode("utf-8"))
            else:
              
                if current_year and current_year in output_files:
                    output_files[current_year].write(raw_line)
                    year_line_counts[current_year] += 1
                    year_bytes[current_year]       += len(raw_line.encode("utf-8"))
                else:
                    skipped_lines += 1

   
    for fh in output_files.values():
        fh.close()

   
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
    write_report(summary, output_dir)

   
    total_split_lines = sum(d["lines"] for d in summary["by_year"].values())

    
if __name__ == "__main__":
    main()