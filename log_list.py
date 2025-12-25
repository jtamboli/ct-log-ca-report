"""
Fetch and parse the Certificate Transparency log list from Google.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
import httpx


# CA/Browser Forum certificate lifetime schedule (per April 2025 ballot)
# https://www.digicert.com/blog/tls-certificate-lifetimes-will-officially-reduce-to-47-days
CERT_LIFETIME_SCHEDULE = [
    # (effective_date, max_lifetime_days)
    (datetime(2029, 3, 15, tzinfo=timezone.utc), 47),
    (datetime(2027, 3, 15, tzinfo=timezone.utc), 100),
    (datetime(2026, 3, 15, tzinfo=timezone.utc), 200),
    (datetime(1970, 1, 1, tzinfo=timezone.utc), 398),  # Default/current
]


def get_max_cert_lifetime_days(as_of: Optional[datetime] = None) -> int:
    """
    Get the maximum certificate lifetime in days based on the current date.

    The CA/Browser Forum voted to progressively reduce certificate lifetimes:
    - Until March 15, 2026: 398 days
    - March 15, 2026: 200 days
    - March 15, 2027: 100 days
    - March 15, 2029: 47 days

    Args:
        as_of: Date to check (defaults to now)

    Returns:
        Maximum certificate lifetime in days
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)

    for effective_date, max_days in CERT_LIFETIME_SCHEDULE:
        if as_of >= effective_date:
            return max_days

    return 398  # Fallback


def log_can_have_certificates(temporal_interval: Optional[Dict], as_of: Optional[datetime] = None) -> tuple[bool, Optional[str]]:
    """
    Check if a log could have any certificates based on its temporal interval.

    A log accepts certificates with notAfter dates within its temporal_interval.
    If today + max_cert_lifetime < temporal_interval.start_inclusive, no
    certificates issued today (or earlier) could be in that log.

    Args:
        temporal_interval: Dict with start_inclusive and end_exclusive dates
        as_of: Date to check (defaults to now)

    Returns:
        Tuple of (can_have_certs, reason_if_not)
    """
    if temporal_interval is None:
        return True, None

    start_inclusive = temporal_interval.get("start_inclusive")
    if not start_inclusive:
        return True, None

    if as_of is None:
        as_of = datetime.now(timezone.utc)

    # Parse the start date
    start_date = datetime.fromisoformat(start_inclusive.replace("Z", "+00:00"))

    # Calculate the latest possible notAfter for certificates issued today
    max_lifetime = get_max_cert_lifetime_days(as_of)
    latest_not_after = as_of + timedelta(days=max_lifetime)

    if latest_not_after < start_date:
        return False, f"log accepts certs with notAfter >= {start_inclusive[:10]}, but max notAfter today is {latest_not_after.strftime('%Y-%m-%d')} ({max_lifetime} day lifetime)"

    return True, None


LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
DATA_DIR = Path(__file__).parent / "data"


def fetch_log_list() -> Dict:
    """
    Fetch the CT log list from Google and cache it locally.

    Returns:
        Dict containing the log list data
    """
    cache_file = DATA_DIR / "log_list.json"

    # Check if cached file exists and is recent
    if cache_file.exists():
        print(f"Loading cached log list from {cache_file}")
        with open(cache_file, 'r') as f:
            return json.load(f)

    print(f"Fetching log list from {LOG_LIST_URL}")

    # Retry logic for transient failures
    max_retries = 3
    delay = 1.0

    for attempt in range(max_retries + 1):
        try:
            response = httpx.get(LOG_LIST_URL, timeout=30.0, follow_redirects=True)
            response.raise_for_status()
            log_list = response.json()
            break

        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            if attempt < max_retries:
                status = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
                if status in (429, 503) or isinstance(e, httpx.RequestError):
                    print(f"  Error fetching log list, retrying in {delay:.1f}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    delay *= 2
                    continue
            raise
    else:
        raise Exception(f"Failed to fetch log list after {max_retries} retries")

    # Cache the result
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(cache_file, 'w') as f:
        json.dump(log_list, f, indent=2)

    print(f"Cached log list to {cache_file}")
    return log_list


def get_static_logs(log_list: Dict) -> List[Dict]:
    """
    Extract static (tiled) logs from the log list.
    Filters for usable, readonly, and qualified logs.

    Args:
        log_list: The full log list data

    Returns:
        List of static log entries with monitoring URLs
    """
    static_logs = []
    valid_states = {"usable", "readonly", "qualified"}

    for operator in log_list.get("operators", []):
        operator_name = operator.get("name", "Unknown")

        for log in operator.get("tiled_logs", []):
            state = log.get("state", {}).get("usable") or log.get("state", {}).get("readonly") or log.get("state", {}).get("qualified")

            # Check if log is in a valid state
            log_state = None
            if "usable" in log.get("state", {}):
                log_state = "usable"
            elif "readonly" in log.get("state", {}):
                log_state = "readonly"
            elif "qualified" in log.get("state", {}):
                log_state = "qualified"

            if log_state:
                static_logs.append({
                    "operator": operator_name,
                    "description": log.get("description", "Unknown"),
                    "log_id": log.get("log_id"),
                    "monitoring_url": log.get("monitoring_url"),
                    "state": log_state,
                    "log_type": "static",
                    "temporal_interval": log.get("temporal_interval")
                })

    print(f"Found {len(static_logs)} static logs")
    return static_logs


def get_rfc6962_logs(log_list: Dict) -> List[Dict]:
    """
    Extract RFC 6962 (non-static) logs from the log list.
    Filters for usable, readonly, and qualified logs.

    Args:
        log_list: The full log list data

    Returns:
        List of RFC 6962 log entries with URLs
    """
    rfc6962_logs = []
    valid_states = {"usable", "readonly", "qualified"}

    for operator in log_list.get("operators", []):
        operator_name = operator.get("name", "Unknown")

        for log in operator.get("logs", []):
            # Check if log is in a valid state
            log_state = None
            if "usable" in log.get("state", {}):
                log_state = "usable"
            elif "readonly" in log.get("state", {}):
                log_state = "readonly"
            elif "qualified" in log.get("state", {}):
                log_state = "qualified"

            if log_state:
                rfc6962_logs.append({
                    "operator": operator_name,
                    "description": log.get("description", "Unknown"),
                    "log_id": log.get("log_id"),
                    "url": log.get("url"),
                    "state": log_state,
                    "log_type": "rfc6962",
                    "temporal_interval": log.get("temporal_interval")
                })

    print(f"Found {len(rfc6962_logs)} RFC 6962 logs")
    return rfc6962_logs
