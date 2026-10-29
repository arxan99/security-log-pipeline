"""Generate realistic sample logs with embedded attacks for demos and tests.

    python samples/generate.py samples/

Writes auth.log, access.log (web) and proxy.jsonl. Seeded, so output is repeatable.
"""

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

rng = random.Random(42)
BASE = datetime(2026, 10, 28, 9, 0, 0, tzinfo=timezone.utc)
STAFF = ["alice", "bob", "carol", "dave"]
OFFICE_IPS = [f"10.0.0.{i}" for i in range(10, 20)]


def auth_log() -> list[str]:
    lines = []

    def add(t, msg):
        lines.append((t, f"{t:%b} {t.day:2d} {t:%H:%M:%S} bastion sshd[{rng.randint(1000, 9999)}]: {msg}"))

    # normal logins through the day
    for _ in range(40):
        t = BASE + timedelta(minutes=rng.randint(0, 600))
        add(t, f"Accepted publickey for {rng.choice(STAFF)} from {rng.choice(OFFICE_IPS)} port 22 ssh2")
    # occasional typo
    for _ in range(6):
        t = BASE + timedelta(minutes=rng.randint(0, 600))
        add(t, f"Failed password for {rng.choice(STAFF)} from {rng.choice(OFFICE_IPS)} port 22 ssh2")
    # brute force against root, then a successful login (compromise)
    t = BASE + timedelta(hours=2)
    for i in range(12):
        add(t + timedelta(seconds=10 * i), "Failed password for root from 203.0.113.45 port 51122 ssh2")
    add(t + timedelta(seconds=130), "Accepted password for root from 203.0.113.45 port 51130 ssh2")
    # password spraying across many accounts
    t = BASE + timedelta(hours=4)
    for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "deploy", "git", "postgres"]):
        add(t + timedelta(seconds=40 * i), f"Invalid user {u} from 198.51.100.23 port 40{i}22")
    return [line for _, line in sorted(lines)]


def access_log() -> list[str]:
    lines = []

    def add(t, ip, method, path, status, size):
        lines.append((t, f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S %z}] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"'))

    pages = ["/", "/products", "/about", "/login", "/static/app.js", "/api/items?page=2"]
    for _ in range(200):
        t = BASE + timedelta(seconds=rng.randint(0, 36000))
        add(t, f"192.0.2.{rng.randint(1, 200)}", "GET", rng.choice(pages), 200, rng.randint(500, 20000))
    # content discovery scan
    t = BASE + timedelta(hours=3)
    for i, p in enumerate(["/admin", "/.env", "/wp-login.php", "/backup.zip", "/.git/config", "/phpmyadmin",
                           "/config.php", "/server-status", "/old", "/test", "/db.sql", "/api/v1/debug",
                           "/console", "/actuator", "/.aws/credentials", "/cgi-bin/", "/shell.php",
                           "/upload", "/install", "/setup", "/xmlrpc.php", "/.DS_Store"]):
        add(t + timedelta(seconds=3 * i), "45.33.32.156", "GET", p, 404, 162)
    # injection attempts
    t = BASE + timedelta(hours=5)
    for i, p in enumerate(["/api/items?id=1'%20OR%20'1'='1", "/api/items?id=1%20UNION%20SELECT%20password%20FROM%20users",
                           "/download?file=../../../../etc/passwd", "/search?q=<script>alert(1)</script>"]):
        add(t + timedelta(seconds=20 * i), "185.220.101.7", "GET", p, 400, 0)
    return [line for _, line in sorted(lines)]


def proxy_log() -> list[str]:
    lines = []

    def add(t, user, host, path, action, rule, status, category=""):
        e = {"ts": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "client_ip": rng.choice(OFFICE_IPS), "user": user,
             "group": "engineering", "method": "GET", "host": host, "path": path, "action": action,
             "rule": rule, "status": status, "bytes_out": rng.randint(0, 50000) if action == "allow" else 0,
             "duration_ms": rng.randint(5, 300)}
        if category:
            e["category"] = category
        lines.append((t, json.dumps(e)))

    for _ in range(150):
        t = BASE + timedelta(seconds=rng.randint(0, 36000))
        add(t, rng.choice(STAFF), rng.choice(["github.com", "pypi.org", "en.wikipedia.org"]), "/",
            "allow", "allow-dev-tools", 200, "dev-tools")
    # infected workstation beaconing to a C2 host
    t = BASE + timedelta(hours=6)
    for i in range(8):
        add(t + timedelta(minutes=5 * i), "dave", "beacon.malware-c2.test", "/gate.php", "block",
            "block-malware", 403, "malware")
    return [line for _, line in sorted(lines)]


def main(out_dir: str = "samples") -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "auth.log").write_text("\n".join(auth_log()) + "\n")
    (out / "access.log").write_text("\n".join(access_log()) + "\n")
    (out / "proxy.jsonl").write_text("\n".join(proxy_log()) + "\n")
    print(f"wrote sample logs to {out}/")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
