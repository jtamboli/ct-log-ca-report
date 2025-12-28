"""
Generate reports from collected certificate data.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple
from collections import Counter, defaultdict
from datetime import datetime


DATA_DIR = Path(__file__).parent / "data"


def _calc_lifetime_days(not_before: str, not_after: str) -> int | None:
    """Calculate certificate lifetime in days from validity period strings."""
    try:
        nb = datetime.fromisoformat(not_before.replace('+00:00', ''))
        na = datetime.fromisoformat(not_after.replace('+00:00', ''))
        return (na - nb).days
    except (ValueError, TypeError):
        return None


def _analyze_extra_submissions() -> Dict[str, Dict[str, int]]:
    """
    Analyze which CAs submit certificates to more logs than required.

    Chrome's CT policy requires:
    - 2 SCTs for certificates with lifetime <= 180 days
    - 3 SCTs for certificates with lifetime > 180 days

    By correlating certificates across logs (using composite key of issuer CN,
    subject CN, not_before, not_after), we can determine when a CA submits
    to more logs than required.

    Returns:
        Dict mapping CA name to stats dict with keys:
        - total: total certs appearing in 2+ logs
        - required_only: certs with exactly the required number of logs
        - with_extras: certs with more logs than required
    """
    samples_dir = DATA_DIR / "samples"
    if not samples_dir.exists():
        return {}

    # Load all certificates from all logs, tracking which logs each cert appears in
    cert_info: Dict[Tuple, Dict] = {}

    for sample_file in samples_dir.glob("*.json"):
        try:
            with open(sample_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            continue

        log_id = data.get("log_id", "")
        log_type = data.get("log_type", "static")

        for cert in data.get("certificates", []):
            issuer_cn = cert.get("issuer", {}).get("cn", "")
            subject_cn = cert.get("subject", {}).get("cn", "")
            not_before = cert.get("not_before", "")
            not_after = cert.get("not_after", "")
            ca = cert.get("ca", "")

            key = (issuer_cn, subject_cn, not_before, not_after)

            if key not in cert_info:
                cert_info[key] = {
                    "ca": ca,
                    "not_before": not_before,
                    "not_after": not_after,
                    "static_logs": set(),
                    "rfc6962_logs": set()
                }

            if log_type == "static":
                cert_info[key]["static_logs"].add(log_id)
            else:
                cert_info[key]["rfc6962_logs"].add(log_id)

    # Analyze each CA's submission patterns
    ca_stats: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"total": 0, "required_only": 0, "with_extras": 0}
    )

    for key, info in cert_info.items():
        n_static = len(info["static_logs"])
        n_rfc = len(info["rfc6962_logs"])
        total_logs = n_static + n_rfc

        # Only analyze certs appearing in 2+ logs (where we can observe correlation)
        if total_logs < 2:
            continue

        lifetime = _calc_lifetime_days(info["not_before"], info["not_after"])
        if lifetime is None:
            continue

        ca = info["ca"]
        required = 3 if lifetime > 180 else 2

        ca_stats[ca]["total"] += 1
        if total_logs > required:
            ca_stats[ca]["with_extras"] += 1
        else:
            ca_stats[ca]["required_only"] += 1

    return dict(ca_stats)


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
    Generate a report showing static vs RFC 6962 split for top 10 CAs,
    including analysis of extra log submissions.

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

    # Get extra submission analysis
    extra_stats = _analyze_extra_submissions()

    # Generate report
    report_lines = ["# Top 10 CAs: Static vs RFC 6962 Distribution\n"]
    report_lines.append("_This report shows how the top certificate authorities split their submissions between static (tiled) and RFC 6962 CT logs._\n")

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

    # Add extra submissions section
    report_lines.append("\n---\n")
    report_lines.append("# Extra Log Submissions Analysis\n")
    report_lines.append("_Chrome requires 2 SCTs for certs ≤180 days, 3 SCTs for >180 days. ")
    report_lines.append("This analysis identifies CAs that submit to more logs than required._\n")
    report_lines.append("\n_Based on certificates appearing in 2+ logs in our sample (cross-log correlation)._\n")

    if extra_stats:
        # Sort by total correlated certs
        sorted_extras = sorted(
            extra_stats.items(),
            key=lambda x: x[1]["total"],
            reverse=True
        )[:15]  # Top 15 CAs with enough data

        report_lines.append("\n| CA | Correlated Certs | Required Only | With Extras | Extra % |")
        report_lines.append("|---|---|---|---|---|")

        for ca_name, stats in sorted_extras:
            if stats["total"] < 10:  # Skip CAs with too few samples
                continue
            total = stats["total"]
            required_only = stats["required_only"]
            with_extras = stats["with_extras"]
            extra_pct = (with_extras / total * 100) if total > 0 else 0
            report_lines.append(
                f"| {ca_name} | {total:,} | {required_only:,} | {with_extras:,} | {extra_pct:.1f}% |"
            )

        report_lines.append("")
    else:
        report_lines.append("\n_No cross-log correlation data available._\n")

    return "\n".join(report_lines)
