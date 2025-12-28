"""
Generate reports from collected certificate data.
"""

import json
from pathlib import Path
from typing import Dict, List
from collections import Counter, defaultdict


DATA_DIR = Path(__file__).parent / "data"


def generate_report(log_samples: List[Dict]) -> str:
    """
    Generate a markdown report from log samples.

    Args:
        log_samples: List of log sample data dicts

    Returns:
        Markdown report string
    """
    report_lines = ["# Certificate Transparency Log CA Report\n"]

    for sample in log_samples:
        log_name = sample.get("log_name", "Unknown")
        operator = sample.get("operator", "Unknown")
        sample_count = sample.get("sample_count", 0)
        ca_counts = sample.get("ca_counts", {})
        log_type = sample.get("log_type", "static")
        log_type_label = "Static" if log_type == "static" else "RFC 6962"

        # Skip static logs with no certificates
        if log_type == "static" and sample_count == 0:
            continue

        report_lines.append(f"\n## {log_name} ({operator}) [{log_type_label}]\n")
        report_lines.append(f"Total certificates sampled: {sample_count:,}\n")

        if not ca_counts:
            report_lines.append("No certificates analyzed.\n")
            continue

        # Sort by count descending
        sorted_cas = sorted(ca_counts.items(), key=lambda x: x[1], reverse=True)

        report_lines.append("\n| Certificate Authority | Count | Percentage |")
        report_lines.append("|----------------------|-------|------------|")

        for ca_name, count in sorted_cas:
            percentage = (count / sample_count * 100) if sample_count > 0 else 0
            report_lines.append(f"| {ca_name} | {count:,} | {percentage:.1f}% |")

        report_lines.append("")

    return "\n".join(report_lines)


def save_report_data(log_samples: List[Dict]) -> None:
    """
    Save report data as JSON for later augmentation.

    Args:
        log_samples: List of log sample data dicts
    """
    report_file = DATA_DIR / "report.json"
    with open(report_file, 'w') as f:
        json.dump(log_samples, f, indent=2)
    print(f"\nSaved report data to {report_file}")


def aggregate_ca_counts(certificates: List[Dict]) -> Dict[str, int]:
    """
    Aggregate CA counts from a list of certificate info dicts.

    Args:
        certificates: List of certificate info dicts with 'ca' field

    Returns:
        Dict mapping CA name to count
    """
    ca_names = [cert.get("ca", "Unknown") for cert in certificates]
    return dict(Counter(ca_names))


def get_log_type_label(log_name: str, log_samples: List[Dict]) -> str:
    """
    Get the log type label for a given log name.

    Args:
        log_name: Name of the log
        log_samples: List of log sample data dicts

    Returns:
        Log type label ("Static" or "RFC 6962")
    """
    for sample in log_samples:
        if sample.get("log_name") == log_name:
            log_type = sample.get("log_type", "static")
            return "Static" if log_type == "static" else "RFC 6962"
    return "Unknown"


def generate_reverse_report(log_samples: List[Dict]) -> str:
    """
    Generate a reverse report showing which CT logs each CA uses.
    Focuses on the top 10 CAs by certificate count.

    Args:
        log_samples: List of log sample data dicts

    Returns:
        Markdown report string
    """
    # Aggregate CA counts across all logs
    ca_to_logs = defaultdict(lambda: {"total_count": 0, "logs": defaultdict(int)})

    for sample in log_samples:
        log_name = sample.get("log_name", "Unknown")
        ca_counts = sample.get("ca_counts", {})

        for ca_name, count in ca_counts.items():
            ca_to_logs[ca_name]["total_count"] += count
            ca_to_logs[ca_name]["logs"][log_name] += count

    # Sort CAs by total count and take top 10
    sorted_cas = sorted(ca_to_logs.items(), key=lambda x: x[1]["total_count"], reverse=True)[:10]

    # Generate report
    report_lines = ["# Top 10 Certificate Authorities by CT Log Usage\n"]
    report_lines.append(f"_Note: Time frames may not match across CT logs, so this analysis may have bias._\n")

    for rank, (ca_name, data) in enumerate(sorted_cas, 1):
        total_count = data["total_count"]
        logs = data["logs"]

        report_lines.append(f"\n## {rank}. {ca_name}\n")
        report_lines.append(f"**Total certificates**: {total_count:,}\n")
        report_lines.append(f"**Appears in {len(logs)} log(s)**\n")

        # Sort logs by count
        sorted_logs = sorted(logs.items(), key=lambda x: x[1], reverse=True)

        report_lines.append("\n| CT Log | Certificates | Percentage |")
        report_lines.append("|--------|-------------|------------|")

        for log_name, count in sorted_logs:
            percentage = (count / total_count * 100) if total_count > 0 else 0
            log_type_label = get_log_type_label(log_name, log_samples)
            report_lines.append(f"| {log_name} [{log_type_label}] | {count:,} | {percentage:.1f}% |")

        report_lines.append("")

    return "\n".join(report_lines)


def generate_split_report(log_samples: List[Dict]) -> str:
    """
    Generate a report showing static vs RFC 6962 split for top 10 CAs.

    Args:
        log_samples: List of log sample data dicts

    Returns:
        Markdown report string
    """
    # Aggregate CA counts by log type
    ca_to_log_types = defaultdict(lambda: {
        "total_count": 0,
        "static": {"count": 0, "logs": set()},
        "rfc6962": {"count": 0, "logs": set()}
    })

    for sample in log_samples:
        log_name = sample.get("log_name", "Unknown")
        log_type = sample.get("log_type", "static")
        ca_counts = sample.get("ca_counts", {})

        for ca_name, count in ca_counts.items():
            ca_to_log_types[ca_name]["total_count"] += count
            ca_to_log_types[ca_name][log_type]["count"] += count
            ca_to_log_types[ca_name][log_type]["logs"].add(log_name)

    # Sort CAs by total count and take top 10
    sorted_cas = sorted(ca_to_log_types.items(), key=lambda x: x[1]["total_count"], reverse=True)[:10]

    # Generate report
    report_lines = ["# Top 10 CAs: Static vs RFC 6962 Distribution\n"]
    report_lines.append(f"_This report shows how the top certificate authorities split their submissions between static (tiled) and RFC 6962 CT logs._\n")

    for rank, (ca_name, data) in enumerate(sorted_cas, 1):
        total_count = data["total_count"]
        static_count = data["static"]["count"]
        static_logs = len(data["static"]["logs"])
        rfc6962_count = data["rfc6962"]["count"]
        rfc6962_logs = len(data["rfc6962"]["logs"])

        report_lines.append(f"\n## {rank}. {ca_name}\n")
        report_lines.append(f"**Total certificates**: {total_count:,}\n")

        report_lines.append("\n| Log Type | Certificates | Percentage | Logs |")
        report_lines.append("|----------|-------------|------------|------|")

        if static_count > 0:
            static_percentage = (static_count / total_count * 100) if total_count > 0 else 0
            report_lines.append(f"| Static   | {static_count:,} | {static_percentage:.1f}% | {static_logs} |")

        if rfc6962_count > 0:
            rfc6962_percentage = (rfc6962_count / total_count * 100) if total_count > 0 else 0
            report_lines.append(f"| RFC 6962 | {rfc6962_count:,} | {rfc6962_percentage:.1f}% | {rfc6962_logs} |")

        report_lines.append("")

    return "\n".join(report_lines)
