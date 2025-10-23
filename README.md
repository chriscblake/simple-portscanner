# simple-portscanner

Simple, lightweight TCP port scanner (concurrent). This repository provides a small scanner script that performs TCP connect-style scans using configurable concurrency and timeout.

Features
- CLI via argparse
- Concurrent scans with ThreadPoolExecutor
- Optional progress bar if `tqdm` is installed
- JSON/CSV output and file writing

Usage

Scan a range:

```bash
python3 simple-portscanner --host 127.0.0.1 --range 20-1024 --threads 50
```

Scan specific ports and write JSON output:

```bash
python3 simple-portscanner --host example.com --ports 22,80,443 --format json --output-file results.json
```

Legal / safety

Only scan systems you own or have explicit permission to test. Unauthorized scanning can be considered malicious and may violate law or terms of service.

Development

Install dev dependencies (recommended):

```bash
python3 -m pip install -r requirements.txt
pytest -q
```

Notes
- IPv6 support: the scanner resolves the host and attempts to connect with the resolved address family.
- For long scans, install `tqdm` to get a progress bar.

