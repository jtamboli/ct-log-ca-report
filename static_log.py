"""
Static Certificate Transparency API client for fetching log entries.
"""

import struct
import time
import httpx
from typing import List, Dict, Tuple, Optional
from pathlib import Path


def fetch_with_retry(url: str, max_retries: int = 3, initial_delay: float = 1.0) -> httpx.Response:
    """
    Fetch a URL with retry logic for transient failures.

    Args:
        url: The URL to fetch
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds (doubles with each retry)

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
                    print(f"  {e.response.status_code} error, retrying in {delay:.1f}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff
                    continue
            # For other errors or final retry, raise
            raise

        except httpx.RequestError as e:
            # Retry on network errors
            if attempt < max_retries:
                print(f"  Network error, retrying in {delay:.1f}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                delay *= 2
                continue
            raise

    # Should not reach here, but just in case
    raise Exception(f"Failed to fetch {url} after {max_retries} retries")


def fetch_checkpoint(monitoring_url: str) -> Dict:
    """
    Fetch the checkpoint (signed tree head) from a static CT log.

    Args:
        monitoring_url: The monitoring URL prefix for the log

    Returns:
        Dict with tree_size and root_hash
    """
    # Remove trailing slash from monitoring_url if present
    monitoring_url = monitoring_url.rstrip('/')
    checkpoint_url = f"{monitoring_url}/checkpoint"
    response = fetch_with_retry(checkpoint_url)

    # Parse checkpoint text format
    # Format is:
    # <origin>
    # <tree_size>
    # <root_hash>
    # [signature lines...]
    lines = response.text.strip().split('\n')
    if len(lines) < 3:
        raise ValueError(f"Invalid checkpoint format: {response.text}")

    origin = lines[0]
    tree_size = int(lines[1])
    root_hash = lines[2]

    return {
        "origin": origin,
        "tree_size": tree_size,
        "root_hash": root_hash
    }


def encode_tile_path(index: int) -> str:
    """
    Encode a tile index into the 3-digit path format.
    E.g., index 1234067 -> "x001/x234/067"

    Args:
        index: The tile index

    Returns:
        Encoded path string
    """
    if index < 0:
        raise ValueError(f"Tile index must be non-negative: {index}")

    # Convert to string and pad with zeros
    index_str = str(index).zfill(9)  # Pad to at least 9 digits

    # Split into 3-digit segments
    segments = []
    for i in range(0, len(index_str), 3):
        segment = index_str[i:i+3]
        # All but the last segment get 'x' prefix
        if i + 3 < len(index_str):
            segments.append(f"x{segment}")
        else:
            segments.append(segment)

    return "/".join(segments)


def fetch_data_tile(monitoring_url: str, tile_index: int) -> bytes:
    """
    Fetch a data tile from a static CT log.

    Args:
        monitoring_url: The monitoring URL prefix for the log
        tile_index: The tile index to fetch

    Returns:
        Raw bytes of the data tile
    """
    # Remove trailing slash from monitoring_url if present
    monitoring_url = monitoring_url.rstrip('/')
    tile_path = encode_tile_path(tile_index)
    tile_url = f"{monitoring_url}/tile/data/{tile_path}"

    # Use custom fetch for retry logic, but need to handle headers
    delay = 1.0
    max_retries = 3

    for attempt in range(max_retries + 1):
        try:
            headers = {"Accept-Encoding": "gzip, identity"}
            response = httpx.get(tile_url, headers=headers, timeout=60.0, follow_redirects=True)
            response.raise_for_status()
            return response.content

        except httpx.HTTPStatusError as e:
            # Retry on 429 (Too Many Requests) and 503 (Service Unavailable)
            if e.response.status_code in (429, 503):
                if attempt < max_retries:
                    print(f"  {e.response.status_code} error on tile {tile_index}, retrying in {delay:.1f}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    delay *= 2
                    continue
            # For other errors or final retry, raise
            raise

        except httpx.RequestError as e:
            if attempt < max_retries:
                print(f"  Network error on tile {tile_index}, retrying in {delay:.1f}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                delay *= 2
                continue
            raise

    raise Exception(f"Failed to fetch tile {tile_index} after {max_retries} retries")


def parse_tileleaf(data: bytes, offset: int = 0) -> Tuple[Optional[bytes], int]:
    """
    Parse a single TileLeaf entry from data tile bytes.

    Sunlight/Static CT API format (different from RFC 6962):
    - timestamp: 8 bytes (big-endian uint64, milliseconds)
    - entry_type: 2 bytes (big-endian uint16, 0=x509, 1=precert)

    For x509_entry (type 0):
      - certificate_length: 3 bytes
      - certificate: certificate_length bytes
      - extensions_length: 2 bytes
      - extensions: extensions_length bytes
      - chain_length: 2 bytes
      - chain: chain_length bytes (32-byte fingerprints)

    For precert_entry (type 1):
      - issuer_key_hash: 32 bytes
      - tbs_length: 3 bytes
      - tbs_certificate: tbs_length bytes
      - extensions_length: 2 bytes
      - extensions: extensions_length bytes
      - precert_length: 3 bytes
      - precertificate: precert_length bytes (this is the actual cert)
      - chain_length: 2 bytes
      - chain: chain_length bytes

    Args:
        data: Raw tile data bytes
        offset: Starting offset in the data

    Returns:
        Tuple of (certificate_bytes, new_offset) or (None, offset) if no more entries
    """
    if offset >= len(data):
        return None, offset

    try:
        start_offset = offset

        # Read timestamp (8 bytes)
        if offset + 8 > len(data):
            return None, start_offset
        timestamp = struct.unpack('>Q', data[offset:offset+8])[0]
        offset += 8

        # Read entry type (2 bytes, not 1!)
        if offset + 2 > len(data):
            return None, start_offset
        entry_type = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2

        cert_data = None

        if entry_type == 0:
            # x509_entry: certificate is directly after entry_type
            # Read certificate length (3 bytes)
            if offset + 3 > len(data):
                return None, start_offset
            cert_length = struct.unpack('>I', b'\x00' + data[offset:offset+3])[0]
            offset += 3

            # Read certificate
            if offset + cert_length > len(data):
                return None, start_offset
            cert_data = data[offset:offset+cert_length]
            offset += cert_length

            # Read extensions length (2 bytes)
            if offset + 2 > len(data):
                return None, start_offset
            ext_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            # Skip extensions
            if offset + ext_length > len(data):
                return None, start_offset
            offset += ext_length

            # Read chain length (2 bytes)
            if offset + 2 > len(data):
                return None, start_offset
            chain_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            # Skip chain
            if offset + chain_length > len(data):
                return None, start_offset
            offset += chain_length

        elif entry_type == 1:
            # precert_entry: has issuer_key_hash and TBS before the actual certificate

            # Read issuer_key_hash (32 bytes)
            if offset + 32 > len(data):
                return None, start_offset
            offset += 32  # Skip issuer_key_hash

            # Read TBS certificate length (3 bytes)
            if offset + 3 > len(data):
                return None, start_offset
            tbs_length = struct.unpack('>I', b'\x00' + data[offset:offset+3])[0]
            offset += 3

            # Skip TBS certificate (we want the precertificate, not TBS)
            if offset + tbs_length > len(data):
                return None, start_offset
            offset += tbs_length

            # Read extensions length (2 bytes)
            if offset + 2 > len(data):
                return None, start_offset
            ext_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            # Skip extensions
            if offset + ext_length > len(data):
                return None, start_offset
            offset += ext_length

            # Read precertificate length (3 bytes)
            if offset + 3 > len(data):
                return None, start_offset
            precert_length = struct.unpack('>I', b'\x00' + data[offset:offset+3])[0]
            offset += 3

            # Read precertificate (this is the actual certificate we want)
            if offset + precert_length > len(data):
                return None, start_offset
            cert_data = data[offset:offset+precert_length]
            offset += precert_length

            # Read chain length (2 bytes)
            if offset + 2 > len(data):
                return None, start_offset
            chain_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            # Skip chain
            if offset + chain_length > len(data):
                return None, start_offset
            offset += chain_length

        else:
            # Unknown entry type
            print(f"  Unknown entry type {entry_type} at offset {start_offset}")
            return None, start_offset

        return cert_data, offset

    except Exception as e:
        print(f"Error parsing TileLeaf at offset {offset}: {e}")
        return None, offset


def fetch_certificates(monitoring_url: str, target_count: int = 1000, max_consecutive_errors: int = 5) -> List[bytes]:
    """
    Fetch certificates from a static CT log until reaching target count.

    Args:
        monitoring_url: The monitoring URL prefix for the log
        target_count: Target number of certificates to fetch (default: 1000)
        max_consecutive_errors: Stop after this many consecutive tile fetch errors

    Returns:
        List of certificate bytes
    """
    print(f"Fetching checkpoint from {monitoring_url}")
    checkpoint = fetch_checkpoint(monitoring_url)
    tree_size = checkpoint["tree_size"]
    print(f"  Tree size: {tree_size:,}")
    print(f"  Target: {target_count:,} certificates")

    # Calculate the last tile index (256 entries per tile)
    last_tile_index = (tree_size - 1) // 256

    certificates = []
    consecutive_errors = 0
    tiles_fetched = 0

    # Fetch tiles from most recent backwards until we have enough certificates
    current_tile = last_tile_index

    while len(certificates) < target_count and current_tile >= 0:
        try:
            print(f"  Fetching tile {current_tile} (path: {encode_tile_path(current_tile)}) [{len(certificates):,}/{target_count:,} certs]")
            tile_data = fetch_data_tile(monitoring_url, current_tile)
            tiles_fetched += 1
            consecutive_errors = 0  # Reset on success

            # Parse all TileLeaf entries from this tile
            offset = 0
            tile_certs = 0
            while offset < len(tile_data):
                cert_data, new_offset = parse_tileleaf(tile_data, offset)
                if cert_data is None or new_offset == offset:
                    break
                certificates.append(cert_data)
                tile_certs += 1
                offset = new_offset

            print(f"    Parsed {tile_certs} certificates (total: {len(certificates):,})")

            # Check if we've reached the target
            if len(certificates) >= target_count:
                print(f"  Reached target of {target_count:,} certificates!")
                break

        except Exception as e:
            error_msg = str(e)
            consecutive_errors += 1

            # Check for rate limiting (429) - already handled by fetch_data_tile retry
            # but if it still fails after retries, wait longer and try again
            if "429" in error_msg:
                print(f"  Rate limited on tile {current_tile}, waiting 10s before continuing...")
                time.sleep(10)
                consecutive_errors = 0  # Don't count rate limits as consecutive errors
                continue  # Retry same tile

            # For 403/404 errors, move to next tile
            if "403" in error_msg or "404" in error_msg:
                # These are expected for some tiles, just skip
                pass
            else:
                print(f"  Error fetching tile {current_tile}: {e}")

            # Stop if too many consecutive errors (likely no more accessible tiles)
            if consecutive_errors >= max_consecutive_errors:
                print(f"  Stopping after {consecutive_errors} consecutive errors")
                break

        current_tile -= 1

        # Small delay between tiles to be respectful
        time.sleep(0.2)

    print(f"  Total certificates fetched: {len(certificates):,} (from {tiles_fetched} tiles)")
    return certificates
