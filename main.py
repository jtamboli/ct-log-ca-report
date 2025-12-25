#!/usr/bin/env python3
"""
Main entry point for CT Log CA Report tool.
"""

import argparse
import json
import time
from pathlib import Path
from typing import List, Dict, Set

import log_list
import static_log
import rfc6962_log
import cert_parser
import report


DATA_DIR = Path(__file__).parent / "data"


def get_processed_log_ids() -> Set[str]:
    """
    Get set of log IDs that already have sample data.

    Returns:
        Set of log_id strings
    """
    processed = set()
    samples_dir = DATA_DIR / "samples"

    if not samples_dir.exists():
        return processed

    for sample_file in samples_dir.glob("*.json"):
        try:
            with open(sample_file, 'r') as f:
                data = json.load(f)
                log_id = data.get("log_id")
                if log_id:
                    processed.add(log_id)
        except Exception:
            continue

    return processed


def process_log(log_info: Dict, target_certs: int = 1000) -> Dict:
    """
    Process a single CT log to extract CA information.

    Args:
        log_info: Dict with log metadata (operator, description, url/monitoring_url, etc.)
        target_certs: Target number of certificates to fetch (default: 1000)

    Returns:
        Dict with log sample data including CA counts
    """
    log_name = log_info.get("description", "Unknown")
    operator = log_info.get("operator", "Unknown")
    log_id = log_info.get("log_id", "unknown")
    log_type = log_info.get("log_type", "static")
    temporal_interval = log_info.get("temporal_interval")

    print(f"\n{'='*80}")
    print(f"Processing: {log_name} ({operator}) [{log_type.upper()}]")
    print(f"{'='*80}")

    # Check if log can have any certificates based on temporal interval
    can_have_certs, reason = log_list.log_can_have_certificates(temporal_interval)
    if not can_have_certs:
        print(f"Skipping: {reason}")
        return {
            "log_name": log_name,
            "operator": operator,
            "log_id": log_id,
            "log_type": log_type,
            "sample_count": 0,
            "ca_counts": {},
            "certificates": [],
            "skipped": True,
            "skip_reason": reason
        }

    try:
        # Fetch certificates from the log until reaching target
        # Route to appropriate client based on log type
        if log_type == "rfc6962" or "url" in log_info:
            log_url = log_info.get("url")
            cert_bytes_list = rfc6962_log.fetch_certificates(log_url, target_count=target_certs)
        else:  # static
            monitoring_url = log_info.get("monitoring_url")
            cert_bytes_list = static_log.fetch_certificates(monitoring_url, target_count=target_certs)

        if not cert_bytes_list:
            print(f"No certificates fetched from {log_name}")
            return {
                "log_name": log_name,
                "operator": operator,
                "log_id": log_id,
                "log_type": log_type,
                "sample_count": 0,
                "ca_counts": {},
                "certificates": []
            }

        # Parse certificates and extract CA info
        certificates_info = []
        for cert_bytes in cert_bytes_list:
            cert = cert_parser.parse_certificate(cert_bytes)
            if cert:
                ca_info = cert_parser.get_ca_info(cert)
                ca_name = cert_parser.get_root_ca(cert)

                certificates_info.append({
                    "ca": ca_name,
                    "issuer": ca_info["issuer"],
                    "subject": ca_info["subject"],
                    "not_before": ca_info["not_before"],
                    "not_after": ca_info["not_after"]
                })

        # Aggregate CA counts
        ca_counts = report.aggregate_ca_counts(certificates_info)

        print(f"\nProcessed {len(certificates_info)} certificates")
        print(f"Found {len(ca_counts)} unique CAs")

        # Save per-log sample data
        sample_data = {
            "log_name": log_name,
            "operator": operator,
            "log_id": log_id,
            "log_type": log_type,
            "sample_count": len(certificates_info),
            "ca_counts": ca_counts,
            "certificates": certificates_info
        }

        # Save to file
        sample_file = DATA_DIR / "samples" / f"{log_id.replace('/', '_')}.json"
        sample_file.parent.mkdir(parents=True, exist_ok=True)
        with open(sample_file, 'w') as f:
            json.dump(sample_data, f, indent=2)
        print(f"Saved sample data to {sample_file}")

        return sample_data

    except Exception as e:
        print(f"Error processing {log_name}: {e}")
        import traceback
        traceback.print_exc()
        return {
            "log_name": log_name,
            "operator": operator,
            "log_id": log_id,
            "log_type": log_type,
            "sample_count": 0,
            "ca_counts": {},
            "certificates": [],
            "error": str(e)
        }


def main():
    """
    Main function to orchestrate the CT log analysis.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Analyze Certificate Transparency logs to determine CA distribution"
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="Retry only logs that don't have sample data yet (skip already processed logs)"
    )
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Retry only logs with 0 certificates (failed attempts)"
    )
    parser.add_argument(
        "--max-logs",
        type=int,
        default=None,
        help="Maximum number of logs to process (for testing)"
    )
    parser.add_argument(
        "--target-certs",
        type=int,
        default=1000,
        help="Target number of certificates per log (default: 1000)"
    )
    args = parser.parse_args()

    print("CT Log CA Report Tool")
    print("=" * 80)

    # Fetch and parse log list
    print("\nFetching CT log list...")
    log_list_data = log_list.fetch_log_list()

    print("\nExtracting static logs...")
    static_logs = log_list.get_static_logs(log_list_data)

    print("\nExtracting RFC 6962 logs...")
    rfc6962_logs = log_list.get_rfc6962_logs(log_list_data)

    # Combine both log types
    all_logs = static_logs + rfc6962_logs
    print(f"\nTotal logs: {len(all_logs)} ({len(static_logs)} static + {len(rfc6962_logs)} RFC 6962)")

    if not all_logs:
        print("No logs found!")
        return

    # Filter logs based on retry options
    if args.retry or args.retry_failed:
        processed_ids = get_processed_log_ids()
        print(f"Found {len(processed_ids)} already processed logs")

        if args.retry:
            # Skip logs we already have data for
            all_logs = [log for log in all_logs if log.get("log_id") not in processed_ids]
            print(f"Retrying {len(all_logs)} unprocessed logs")
        elif args.retry_failed:
            # Only retry logs with 0 certificates
            failed_ids = set()
            samples_dir = DATA_DIR / "samples"
            for sample_file in samples_dir.glob("*.json"):
                try:
                    with open(sample_file, 'r') as f:
                        data = json.load(f)
                        if data.get("sample_count", 0) == 0:
                            failed_ids.add(data.get("log_id"))
                except Exception:
                    continue

            all_logs = [log for log in all_logs if log.get("log_id") in failed_ids]
            print(f"Retrying {len(all_logs)} failed logs (0 certificates)")

    # Limit number of logs if requested
    if args.max_logs:
        all_logs = all_logs[:args.max_logs]
        print(f"Limited to {len(all_logs)} logs (--max-logs={args.max_logs})")

    if not all_logs:
        print("No logs to process!")
        return

    # Process each log
    log_samples = []
    for i, log_info in enumerate(all_logs, 1):
        print(f"\n[{i}/{len(all_logs)}]")
        sample_data = process_log(log_info, target_certs=args.target_certs)
        log_samples.append(sample_data)
        # Rate limiting between logs to avoid 429 errors
        time.sleep(2)

    # Generate and display report
    print("\n" + "=" * 80)
    print("GENERATING REPORT")
    print("=" * 80)

    report_text = report.generate_report(log_samples)
    print("\n" + report_text)

    # Generate reverse report (CAs to logs)
    print("\n" + "=" * 80)
    print("GENERATING REVERSE REPORT (Top 10 CAs)")
    print("=" * 80)

    reverse_report_text = report.generate_reverse_report(log_samples)
    print("\n" + reverse_report_text)

    # Generate split report (Static vs RFC 6962)
    print("\n" + "=" * 80)
    print("GENERATING SPLIT REPORT (Static vs RFC 6962)")
    print("=" * 80)

    split_report_text = report.generate_split_report(log_samples)
    print("\n" + split_report_text)

    # Save report data
    report.save_report_data(log_samples)

    # Save report as markdown file
    report_file = DATA_DIR / "report.md"
    with open(report_file, 'w') as f:
        f.write(report_text)
    print(f"\nSaved markdown report to {report_file}")

    # Save reverse report
    reverse_report_file = DATA_DIR / "reverse_report.md"
    with open(reverse_report_file, 'w') as f:
        f.write(reverse_report_text)
    print(f"Saved reverse report to {reverse_report_file}")

    # Save split report
    split_report_file = DATA_DIR / "split_report.md"
    with open(split_report_file, 'w') as f:
        f.write(split_report_text)
    print(f"Saved split report to {split_report_file}")


if __name__ == "__main__":
    main()
