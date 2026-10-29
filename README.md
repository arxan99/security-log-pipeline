# Security Log Pipeline

A Python data pipeline that ingests raw security logs from several sources, normalises them into one event schema, stores them in SQL, and runs **detection rules mapped to MITRE ATT&CK** to raise alerts — a small version of what a SIEM does.

No third-party dependencies: Python standard library and SQLite.

## What it does

```
auth.log ──┐                                                  ┌──► alerts table
access.log ├─► parse ─► normalise ─► SQLite (events) ─► detect ┤
proxy.jsonl┘   (per source)  (one schema)   de-duplicated      └──► HTML / JSON report
```

**Sources**

| Source | Format | Example events |
| --- | --- | --- |
| `auth` | Linux `sshd` lines from `/var/log/auth.log` | failed / accepted logins, invalid users |
| `web` | Apache / Nginx combined access log | HTTP requests, status codes |
| `proxy` | JSON Lines from [zerotrust-proxy](https://github.com/arxan99/zerotrust-proxy) | allowed / blocked web access with policy rule and category |

The format is auto-detected from the first line, timestamps are converted to UTC, and every event gets a SHA-256 ID so re-ingesting the same file never creates duplicates.

**Detections**

| Rule | Logic | MITRE ATT&CK | Severity |
| --- | --- | --- | --- |
| `ssh_bruteforce` | ≥ 5 failed SSH logins from one IP within 5 min | T1110.001 Password Guessing | high |
| `password_spray` | one IP failing against ≥ 5 different accounts within 10 min | T1110.003 Password Spraying | high |
| `success_after_failures` | successful login from an IP right after ≥ 3 failures | T1078 Valid Accounts | critical |
| `web_attack` | SQL injection, path traversal or XSS patterns (URL-decoded twice to beat encoding tricks) | T1190 Exploit Public-Facing Application | high |
| `web_scanning` | ≥ 20 HTTP 4xx responses to one IP within 5 min | T1595.003 Wordlist Scanning | medium |
| `malware_access` | proxy requests blocked as the `malware` category, per user | T1071.001 Web Protocols (C2) | high |

Window-based rules group events by entity and find bursts with a sliding time window; all thresholds live in `detections.Config`.

## Quick start

```bash
pip install -e ".[dev]"
python samples/generate.py samples          # realistic logs with planted attacks

slp ingest --year 2026 samples/auth.log samples/access.log samples/proxy.jsonl
slp detect
slp report -o report.html                   # or: slp report --format json
```

Output of `slp detect` on the sample data:

```
[HIGH    ] ssh_bruteforce           203.0.113.45     12 failed SSH logins from 203.0.113.45 against root
[CRITICAL] success_after_failures   203.0.113.45     203.0.113.45 logged in as 'root' after 12 failed attempts
[MEDIUM  ] web_scanning             45.33.32.156     22 requests from 45.33.32.156 returned 4xx in a short burst
[HIGH    ] password_spray           198.51.100.23    198.51.100.23 tried 7 different accounts
[HIGH    ] web_attack               185.220.101.7    4 malicious requests (path_traversal, sql_injection, xss)
[HIGH    ] malware_access           dave             user dave attempted 8 connections to malware hosts
```

The sample data also contains normal traffic and ordinary password typos from office IPs, and a test checks that these do **not** raise alerts.

`slp detect --fail-on-alert` exits with code 1 when anything fires, so it can gate a scheduled job or CI step.

### Docker

```bash
docker build -t slp .
docker run --rm -v "$PWD:/data" slp ingest /data/samples/auth.log
```

## Project layout

```
slp/parsers.py      per-source parsers -> Event dataclass (normalised schema)
slp/store.py        SQLite schema, indexes, batched de-duplicated inserts
slp/detections.py   sliding-window detection rules with MITRE mapping
slp/report.py       HTML and JSON reports
slp/cli.py          ingest / detect / report / stats commands
samples/generate.py seeded generator for logs with planted attacks
tests/              parser unit tests and end-to-end detection tests
```

## Tests

```bash
pytest -q
```

CI runs lint, tests on Python 3.10 and 3.12, a full demo run, and uploads the HTML report as a build artifact.

## Limitations and next steps

- Batch processing of files; a streaming version would tail logs or read from Kafka.
- SQLite suits a single machine; the schema is plain SQL and could move to PostgreSQL for larger volumes.
- Signature-based web detection can be evaded; it is a first filter, not a WAF.
- Ideas: GeoIP enrichment, threat-intel IP reputation lookups, Sigma rule import, alert de-duplication across runs.
