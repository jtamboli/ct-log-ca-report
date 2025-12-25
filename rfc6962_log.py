"""
RFC 6962 Certificate Transparency API client for fetching log entries.
"""

import base64
import struct
import time
import httpx
from typing import List, Dict, Optional


def fetch_with_retry(url: str, max_retries: int = 3, initial_delay: float = 1.0, quiet: bool = False) -> httpx.Response:
    """
    Fetch a URL with retry logic for transient failures.

    Args:
        url: The URL to fetch
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds (doubles with each retry)
        quiet: If True, suppress output

    Returns:
        Response object

    Raises:
        httpx.HTTPStatusError: If all retries fail
    """
    delay = initial_delay

    for attempt in range(max_retries + 1):
        try:
            response = httpx.get(url, timeout=30.0, follow_redirects=True)
            response.raise_for_status()
            return response

        except httpx.HTTPStatusError as e:
            # Retry on 429 (Too Many Requests) and 503 (Service Unavailable)
            if e.response.status_code in (429, 503):
                if attempt < max_retries:
                    if not quiet:
                        print(f"  {e.response.status_code} error, retrying in {delay:.1f}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff
                    continue
            # For other errors or final retry, raise
            raise

        except httpx.RequestError as e:
            # Retry on network errors
            if attempt < max_retries:
                if not quiet:
                    print(f"  Network error, retrying in {delay:.1f}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                delay *= 2
                continue
            raise

    # Should not reach here, but just in case
    raise Exception(f"Failed to fetch {url} after {max_retries} retries")


def fetch_sth(log_url: str) -> Dict:
    """
    Fetch the Signed Tree Head (STH) from an RFC 6962 CT log.

    Args:
        log_url: The base URL for the log

    Returns:
        Dict with tree_size, timestamp, and other STH fields
    """
    # Remove trailing slash from log_url if present
    log_url = log_url.rstrip('/')
    sth_url = f"{log_url}/ct/v1/get-sth"
    response = fetch_with_retry(sth_url)

    # Parse JSON response
    sth_data = response.json()

    return {
        "tree_size": sth_data.get("tree_size", 0),
        "timestamp": sth_data.get("timestamp", 0),
        "sha256_root_hash": sth_data.get("sha256_root_hash", ""),
        "tree_head_signature": sth_data.get("tree_head_signature", "")
    }


def parse_merkle_tree_leaf(leaf_input_b64: str, quiet: bool = False) -> Optional[bytes]:
    """
    Parse a MerkleTreeLeaf structure to extract the certificate.

    Per RFC 6962 Section 3.4, the structure is:
    - Version (1 byte): 0x00
    - MerkleLeafType (1 byte): 0x00 (timestamped_entry)
    - Timestamp (8 bytes, big-endian milliseconds)
    - LogEntryType (2 bytes): 0x0000 (x509_entry) or 0x0001 (precert_entry)
    - For x509_entry:
        - certificate_length (3 bytes, 24-bit big-endian)
        - certificate_data (DER-encoded)
    - For precert_entry:
        - issuer_key_hash (32 bytes)
        - tbs_certificate_length (3 bytes, 24-bit big-endian)
        - tbs_certificate_data (DER-encoded TBS certificate)

    Args:
        leaf_input_b64: Base64-encoded MerkleTreeLeaf
        quiet: If True, suppress output

    Returns:
        Certificate bytes (DER-encoded), or None if parsing fails
    """
    try:
        # Decode base64
        data = base64.b64decode(leaf_input_b64)
        offset = 0

        # Parse version (1 byte)
        version = struct.unpack_from('!B', data, offset)[0]
        offset += 1
        if version != 0:
            if not quiet:
                print(f"  Warning: Unexpected version {version}, expected 0")
            return None

        # Parse MerkleLeafType (1 byte)
        leaf_type = struct.unpack_from('!B', data, offset)[0]
        offset += 1
        if leaf_type != 0:
            if not quiet:
                print(f"  Warning: Unexpected leaf type {leaf_type}, expected 0 (timestamped_entry)")
            return None

        # Parse timestamp (8 bytes, big-endian)
        timestamp = struct.unpack_from('!Q', data, offset)[0]
        offset += 8

        # Parse LogEntryType (2 bytes)
        entry_type = struct.unpack_from('!H', data, offset)[0]
        offset += 2

        if entry_type == 0:  # x509_entry
            # Parse certificate length (3 bytes, 24-bit big-endian)
            cert_len = struct.unpack_from('!I', b'\x00' + data[offset:offset+3])[0]
            offset += 3

            # Extract certificate
            certificate = data[offset:offset + cert_len]
            return certificate

        elif entry_type == 1:  # precert_entry
            # Skip issuer_key_hash (32 bytes)
            offset += 32

            # Parse TBS certificate length (3 bytes, 24-bit big-endian)
            tbs_len = struct.unpack_from('!I', b'\x00' + data[offset:offset+3])[0]
            offset += 3

            # Extract TBS certificate
            # Note: For precert, we need the actual precertificate from extra_data
            # This TBS certificate is not what we want to parse
            # Return None here and handle in parse_extra_data
            return None

        else:
            if not quiet:
                print(f"  Warning: Unknown entry type {entry_type}")
            return None

    except Exception as e:
        if not quiet:
            print(f"  Error parsing MerkleTreeLeaf: {e}")
        return None


def parse_extra_data(extra_data_b64: str, entry_type: int, quiet: bool = False) -> Optional[bytes]:
    """
    Parse extra_data to extract certificate for precert entries.

    For x509_entry: extra_data contains certificate chain (optional)
    For precert_entry: extra_data contains the precertificate and chain

    Args:
        extra_data_b64: Base64-encoded extra_data
        entry_type: 0 for x509_entry, 1 for precert_entry
        quiet: If True, suppress output

    Returns:
        Certificate bytes for precert, or None for x509
    """
    if entry_type == 0:  # x509_entry
        # For x509, the certificate is in leaf_input, not extra_data
        return None

    # For precert_entry, parse the precertificate from extra_data
    try:
        data = base64.b64decode(extra_data_b64)
        offset = 0

        # Parse precertificate length (3 bytes, 24-bit big-endian)
        if len(data) < 3:
            return None

        precert_len = struct.unpack_from('!I', b'\x00' + data[offset:offset+3])[0]
        offset += 3

        # Extract precertificate
        if len(data) < offset + precert_len:
            return None

        precertificate = data[offset:offset + precert_len]
        return precertificate

    except Exception as e:
        if not quiet:
            print(f"  Error parsing extra_data: {e}")
        return None


def fetch_entries(log_url: str, start: int, end: int, quiet: bool = False) -> List[bytes]:
    """
    Fetch entries from an RFC 6962 CT log.

    Args:
        log_url: The base URL for the log
        start: Starting index (inclusive)
        end: Ending index (inclusive)
        quiet: If True, suppress output

    Returns:
        List of certificate bytes (DER-encoded)
    """
    # Remove trailing slash from log_url if present
    log_url = log_url.rstrip('/')
    entries_url = f"{log_url}/ct/v1/get-entries?start={start}&end={end}"

    try:
        response = fetch_with_retry(entries_url, quiet=quiet)
        entries_data = response.json()

        certificates = []
        entries = entries_data.get("entries", [])

        for entry in entries:
            leaf_input = entry.get("leaf_input", "")
            extra_data = entry.get("extra_data", "")

            # First, try to parse from leaf_input (works for x509_entry)
            cert_bytes = parse_merkle_tree_leaf(leaf_input, quiet=quiet)

            # If that didn't work, try extra_data (for precert_entry)
            if cert_bytes is None and extra_data:
                # Determine entry type by trying to parse the leaf_input
                try:
                    data = base64.b64decode(leaf_input)
                    # Skip version (1), leaf_type (1), timestamp (8)
                    entry_type = struct.unpack_from('!H', data, 10)[0]
                    cert_bytes = parse_extra_data(extra_data, entry_type, quiet=quiet)
                except Exception:
                    pass

            if cert_bytes:
                certificates.append(cert_bytes)

        return certificates

    except httpx.HTTPStatusError as e:
        # Handle 404 (no entries) and other HTTP errors
        if e.response.status_code == 404:
            if not quiet:
                print(f"  No entries found in range {start}-{end}")
        else:
            if not quiet:
                print(f"  HTTP error {e.response.status_code} fetching entries {start}-{end}")
        return []
    except Exception as e:
        if not quiet:
            print(f"  Error fetching entries {start}-{end}: {e}")
        return []


def fetch_certificates(log_url: str, target_count: int = 1000, max_consecutive_errors: int = 5, quiet: bool = False) -> List[bytes]:
    """
    Fetch certificates from an RFC 6962 CT log.

    Fetches the most recent certificates up to target_count.

    Args:
        log_url: The base URL for the log
        target_count: Target number of certificates to fetch
        max_consecutive_errors: Stop after this many consecutive fetch errors
        quiet: If True, suppress output

    Returns:
        List of certificate bytes (DER-encoded)
    """
    if not quiet:
        print(f"Fetching STH from {log_url}...")

    try:
        sth = fetch_sth(log_url)
        tree_size = sth["tree_size"]
        if not quiet:
            print(f"Tree size: {tree_size:,}")

        if tree_size == 0:
            if not quiet:
                print("Log is empty (tree_size = 0)")
            return []

        # Calculate starting index (fetch most recent entries)
        start_index = max(0, tree_size - target_count)
        end_index = tree_size - 1

        if not quiet:
            print(f"Fetching entries {start_index:,} to {end_index:,}...")

        all_certificates = []
        consecutive_errors = 0
        current_start = start_index

        # Fetch in chunks of 1000 (RFC 6962 limit)
        while current_start <= end_index and consecutive_errors < max_consecutive_errors:
            # Calculate chunk end (max 1000 entries per request)
            chunk_end = min(current_start + 999, end_index)

            if not quiet:
                print(f"  Fetching entries {current_start:,} to {chunk_end:,}...")

            certificates = fetch_entries(log_url, current_start, chunk_end, quiet=quiet)

            if certificates:
                all_certificates.extend(certificates)
                consecutive_errors = 0
                if not quiet:
                    print(f"  Fetched {len(certificates)} certificates (total: {len(all_certificates)})")
            else:
                consecutive_errors += 1
                if not quiet:
                    print(f"  No certificates in this chunk (consecutive errors: {consecutive_errors})")

            # Move to next chunk
            current_start = chunk_end + 1

            # Small delay to avoid rate limiting
            if current_start <= end_index:
                time.sleep(0.5)

        if consecutive_errors >= max_consecutive_errors:
            if not quiet:
                print(f"Stopped after {max_consecutive_errors} consecutive errors")

        if not quiet:
            print(f"Total certificates fetched: {len(all_certificates)}")
        return all_certificates

    except Exception as e:
        if not quiet:
            print(f"Error fetching certificates: {e}")
            import traceback
            traceback.print_exc()
        return []
