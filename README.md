# CT Log CA Report Tool

Analyzes Certificate Transparency logs to determine which Certificate Authorities are submitting certificates to each CT log.

## Features

- Fetches certificates from static (tiled) CT logs using the Static CT API
- **Robust retry logic**: Automatically retries on 429 (Too Many Requests) and 503 (Service Unavailable) errors with exponential backoff
- Parses X.509 certificates to extract issuer (CA) information
- Generates two types of reports:
  1. **CA Breakdown by Log**: Shows which CAs submit to each CT log (with percentages)
  2. **Top 10 CAs Report**: Shows which CT logs each of the top 10 CAs uses (reverse view)
- Saves all data as JSON for later augmentation or analysis
- Caches log list and sample data to avoid redundant fetches
- Rate limiting between log fetches to avoid overwhelming servers

## Requirements

- Python 3.10+
- Dependencies: `httpx`, `cryptography`

## Installation

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -r requirements.txt
```

## Usage

### Run Full Analysis

Analyze all static CT logs and generate reports:

```bash
uv run python main.py
# or
python main.py
```

### Options

**Target certificates per log** (default: 1000):

The script automatically fetches tiles until reaching the target certificate count per log:

```bash
python main.py --target-certs 1000   # Default
python main.py --target-certs 5000   # More certificates
```

**Skip already-processed logs** (useful if previous run was interrupted):

```bash
python main.py --retry
```

This will only process logs that don't have sample data yet.

**Retry only failed logs** (logs with 0 certificates):

```bash
python main.py --retry-failed
```

**Limit number of logs** (for testing):

```bash
python main.py --max-logs 5
```

**Combine options**:

```bash
python main.py --retry --target-certs 2000 --max-logs 10
```

### Generate Reports from Existing Data

If you already have sample data and want to regenerate reports:

```bash
uv run python generate_reports.py
# or
python generate_reports.py
```

## Output Files

All outputs are saved in the `data/` directory:

- `data/log_list.json` - Cached CT log list from Google
- `data/samples/<log_id>.json` - Per-log certificate samples with CA information
- `data/report.md` - CA breakdown by log (markdown)
- `data/reverse_report.md` - Top 10 CAs and which logs they use (markdown)
- `data/report.json` - Aggregated data for all logs (JSON)

## Sample Output

### CA Breakdown Report

```markdown
## IPng Networks 'Halloumi2026h1'

Total certificates sampled: 86

| Certificate Authority | Count | Percentage |
|----------------------|-------|------------|
| Let's Encrypt (US)   | 72    | 83.7%      |
| Google Trust Services| 8     | 9.3%       |
| GoDaddy.com, Inc.    | 4     | 4.7%       |
```

### Reverse Report (Top CAs)

```markdown
## 1. Let's Encrypt (US)

**Total certificates**: 84
**Appears in 3 log(s)**

| CT Log | Certificates | Percentage |
|--------|-------------|------------|
| IPng Networks 'Halloumi2026h1' | 72 | 85.7% |
| IPng Networks 'Gouda2026h1'    | 8  | 9.5%  |
| Geomys 'Tuscolo2025h2'         | 4  | 4.8%  |
```

## Architecture

The tool is organized into modular components:

- `main.py` - Entry point, orchestrates the workflow
- `log_list.py` - Fetches and parses the CT log list
- `static_log.py` - Static CT API client for fetching data tiles
- `cert_parser.py` - X.509 certificate parsing and CA extraction
- `report.py` - Report generation (both normal and reverse)
- `generate_reports.py` - Standalone report generator from existing data

## Extensibility

The tool is designed to be extended with RFC 6962 CT log support in the future. The modular architecture allows easy addition of new log types by:

1. Implementing a new client module (similar to `static_log.py`)
2. Adding a `fetch_certificates()` method with the same interface
3. Updating `main.py` to call the appropriate client based on log type

## Error Handling

The tool includes robust error handling:

- **429 Too Many Requests**: Automatically retries with exponential backoff (1s, 2s, 4s delays), plus additional 10s wait if rate limiting persists
- **503 Service Unavailable**: Same retry logic as 429
- **Network errors**: Retries transient network failures
- **403 Forbidden / 404 Not Found**: Skipped and moves to next tile (common for restricted or not-yet-generated tiles)
- **Consecutive error limit**: Stops fetching from a log after 5 consecutive tile errors (indicates no more accessible tiles)
- **Max retries**: 3 attempts per request before giving up

## Limitations

- Currently only supports static (tiled) CT logs
- Many logs return 403 Forbidden or 404 Not Found for recent tiles (access restrictions or tiles not yet generated)
- Samples a limited number of tiles per log (configurable, default is 4 tiles ≈ 1,000 certificates)
- Uses immediate issuer as CA (does not currently walk the full certificate chain to root CA)
- Time frames may not match across different CT logs, introducing potential bias in cross-log comparisons

## Technical Notes

### Static CT API Format

The tool parses data tiles using the Static CT API format. Key findings during implementation:

- **Length fields are 4 bytes**, not 3 bytes as specified in RFC 6962
  - This appears to be a difference in the Static CT API implementation
  - Certificate length: 4-byte big-endian integer
  - Extensions length: 2-byte big-endian integer
  - Chain length: 2-byte big-endian integer

- **Data tiles contain variable numbers of entries**
  - Not always 256 entries per tile
  - Depends on certificate sizes
  - Parsing continues until end of tile data

- **TileLeaf structure**:
  ```
  timestamp (8 bytes)
  entry_type (1 byte) - 0=x509, 1=precert
  signed_entry_length (4 bytes)
  signed_entry_data (variable)
  extensions_length (2 bytes)
  extensions_data (variable)
  [for precert: pre_certificate_length (4 bytes) + pre_certificate_data]
  chain_length (2 bytes)
  chain_data (variable)
  ```

## License

See LICENSE file for details.
