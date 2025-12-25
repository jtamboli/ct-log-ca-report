#!/usr/bin/env python3
"""
Generate reports from existing sample data.
"""

import json
from pathlib import Path
import report

DATA_DIR = Path(__file__).parent / "data"

# Load all sample files
log_samples = []
samples_dir = DATA_DIR / "samples"

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
