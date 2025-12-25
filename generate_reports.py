#!/usr/bin/env python3
"""
Generate reports from existing sample data.
"""

import json
from pathlib import Path
import report
import log_list

DATA_DIR = Path(__file__).parent / "data"


def get_qualified_log_ids() -> set:
    """
    Get the set of log IDs that are currently qualified.

    Returns:
        Set of log_id strings for all qualified logs
    """
    log_list_data = log_list.fetch_log_list()
    static_logs = log_list.get_static_logs(log_list_data)
    rfc6962_logs = log_list.get_rfc6962_logs(log_list_data)

    qualified_ids = set()
    for log in static_logs + rfc6962_logs:
        log_id = log.get("log_id")
        if log_id:
            qualified_ids.add(log_id)

    return qualified_ids


def cleanup_stale_samples(samples_dir: Path, qualified_ids: set) -> int:
    """
    Delete sample files for logs that are no longer qualified.

    Args:
        samples_dir: Path to the samples directory
        qualified_ids: Set of currently qualified log IDs

    Returns:
        Number of stale sample files deleted
    """
    deleted_count = 0

    for sample_file in samples_dir.glob("*.json"):
        try:
            with open(sample_file, 'r') as f:
                sample_data = json.load(f)
                log_id = sample_data.get("log_id")
                log_name = sample_data.get("log_name", "Unknown")

                if log_id and log_id not in qualified_ids:
                    sample_file.unlink()
                    print(f"Deleted stale sample: {log_name} (no longer qualified)")
                    deleted_count += 1
        except Exception as e:
            print(f"Error processing {sample_file}: {e}")

    return deleted_count


# Get current qualified logs and cleanup stale samples
print("Checking for stale log samples...")
qualified_ids = get_qualified_log_ids()
samples_dir = DATA_DIR / "samples"

if samples_dir.exists():
    deleted = cleanup_stale_samples(samples_dir, qualified_ids)
    if deleted > 0:
        print(f"Cleaned up {deleted} stale sample(s)\n")
    else:
        print("No stale samples found\n")

# Load all sample files
log_samples = []

for sample_file in samples_dir.glob("*.json"):
    with open(sample_file, 'r') as f:
        sample_data = json.load(f)
        log_samples.append(sample_data)

print(f"Loaded {len(log_samples)} log samples\n")

# Generate CA breakdown report
print("=" * 80)
print("CA BREAKDOWN BY LOG")
print("=" * 80)
report_text = report.generate_report(log_samples)
print(report_text)

# Generate reverse report (CAs to logs)
print("\n" + "=" * 80)
print("TOP 10 CAs - CT LOG USAGE")
print("=" * 80)
reverse_report_text = report.generate_reverse_report(log_samples)
print(reverse_report_text)

# Save reports
report_file = DATA_DIR / "report.md"
with open(report_file, 'w') as f:
    f.write(report_text)
print(f"\nSaved report to {report_file}")

reverse_report_file = DATA_DIR / "reverse_report.md"
with open(reverse_report_file, 'w') as f:
    f.write(reverse_report_text)
print(f"Saved reverse report to {reverse_report_file}")

# Generate and save split report
print("\n" + "=" * 80)
print("STATIC VS RFC 6962 SPLIT")
print("=" * 80)
split_report_text = report.generate_split_report(log_samples)
print(split_report_text)

split_report_file = DATA_DIR / "split_report.md"
with open(split_report_file, 'w') as f:
    f.write(split_report_text)
print(f"\nSaved split report to {split_report_file}")

# Save JSON data
report.save_report_data(log_samples)
