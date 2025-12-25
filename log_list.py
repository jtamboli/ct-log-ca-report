"""
Fetch and parse the Certificate Transparency log list from Google.
"""

import json
import time
from pathlib import Path
from typing import Dict, List
import httpx


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
                    "log_type": "static"
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
                    "log_type": "rfc6962"
                })

    print(f"Found {len(rfc6962_logs)} RFC 6962 logs")
    return rfc6962_logs
