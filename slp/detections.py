"""Detection rules mapped to MITRE ATT&CK.

Each rule reads normalised events from the store and returns Alerts. Rules use
sliding time windows over events grouped by an entity (an IP or a user).
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

from .store import Store


@dataclass
class Alert:
    rule: str
    severity: str        # low | medium | high | critical
    technique: str       # MITRE ATT&CK technique ID and name
    entity: str          # the IP or user the alert is about
    first_seen: str
    last_seen: str
    summary: str
    evidence: list = field(default_factory=list)  # event_ids

    @property
    def alert_id(self) -> str:
        return hashlib.sha256(f"{self.rule}|{self.entity}|{self.first_seen}".encode()).hexdigest()[:16]


@dataclass
class Config:
    bruteforce_threshold: int = 5
    bruteforce_window_min: int = 5
    spray_distinct_users: int = 5
    spray_window_min: int = 10
    success_after_failures: int = 3
    scan_threshold: int = 20
    scan_window_min: int = 5


def _dt(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def _windows(rows, window: timedelta, trigger: Callable[[list], bool]):
    """Yield non-overlapping bursts: the first window in which `trigger` fires,
    extended while events keep arriving within `window` of the last one."""
    rows = list(rows)
    i = 0
    while i < len(rows):
        j = i
        while j < len(rows) and _dt(rows[j]["ts"]) - _dt(rows[i]["ts"]) <= window:
            j += 1
        if trigger(rows[i:j]):
            # extend the burst while activity continues
            while j < len(rows) and _dt(rows[j]["ts"]) - _dt(rows[j - 1]["ts"]) <= window:
                j += 1
            yield rows[i:j]
            i = j
        else:
            i += 1


def _group(rows, key: str) -> dict:
    out = defaultdict(list)
    for r in rows:
        if r[key]:
            out[r[key]].append(r)
    return out


# --------------------------------------------------------------------------- rules

def ssh_bruteforce(store: Store, cfg: Config) -> list[Alert]:
    rows = store.events("source='auth' AND action='failure'")
    alerts = []
    for ip, evs in _group(rows, "src_ip").items():
        for burst in _windows(evs, timedelta(minutes=cfg.bruteforce_window_min),
                              lambda w: len(w) >= cfg.bruteforce_threshold):
            users = sorted({e["user"] for e in burst})
            alerts.append(Alert(
                rule="ssh_bruteforce", severity="high",
                technique="T1110.001 Brute Force: Password Guessing", entity=ip,
                first_seen=burst[0]["ts"], last_seen=burst[-1]["ts"],
                summary=f"{len(burst)} failed SSH logins from {ip} against {', '.join(users[:5])}",
                evidence=[e["event_id"] for e in burst]))
    return alerts


def password_spray(store: Store, cfg: Config) -> list[Alert]:
    rows = store.events("source='auth' AND action='failure'")
    alerts = []
    for ip, evs in _group(rows, "src_ip").items():
        for burst in _windows(evs, timedelta(minutes=cfg.spray_window_min),
                              lambda w: len({e["user"] for e in w}) >= cfg.spray_distinct_users):
            users = {e["user"] for e in burst}
            alerts.append(Alert(
                rule="password_spray", severity="high",
                technique="T1110.003 Brute Force: Password Spraying", entity=ip,
                first_seen=burst[0]["ts"], last_seen=burst[-1]["ts"],
                summary=f"{ip} tried {len(users)} different accounts",
                evidence=[e["event_id"] for e in burst]))
    return alerts


def success_after_failures(store: Store, cfg: Config) -> list[Alert]:
    rows = store.events("source='auth' AND event_type IN ('login_failed','invalid_user','login_success')")
    alerts = []
    for ip, evs in _group(rows, "src_ip").items():
        failures: list = []
        for e in evs:
            if e["action"] == "failure":
                failures.append(e)
                continue
            recent = [f for f in failures if _dt(e["ts"]) - _dt(f["ts"]) <= timedelta(minutes=10)]
            if len(recent) >= cfg.success_after_failures:
                alerts.append(Alert(
                    rule="success_after_failures", severity="critical",
                    technique="T1078 Valid Accounts", entity=ip,
                    first_seen=recent[0]["ts"], last_seen=e["ts"],
                    summary=f"{ip} logged in as '{e['user']}' after {len(recent)} failed attempts",
                    evidence=[f["event_id"] for f in recent] + [e["event_id"]]))
            failures = []
    return alerts


def malware_access(store: Store, cfg: Config) -> list[Alert]:
    rows = store.events("source='proxy' AND detail LIKE '%category=malware%'")
    alerts = []
    for user, evs in _group(rows, "user").items():
        hosts = sorted({e["host"] for e in evs})
        alerts.append(Alert(
            rule="malware_access", severity="high",
            technique="T1071.001 Application Layer Protocol: Web Protocols", entity=user,
            first_seen=evs[0]["ts"], last_seen=evs[-1]["ts"],
            summary=f"user {user} attempted {len(evs)} connections to malware hosts: {', '.join(hosts)}",
            evidence=[e["event_id"] for e in evs]))
    return alerts


WEB_ATTACK_PATTERNS = {
    "sql_injection": re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bsleep\s*\(|;\s*drop\s+table)", re.I),
    "path_traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|c:\\windows)", re.I),
    "xss": re.compile(r"(<script|javascript:|onerror\s*=)", re.I),
}


def web_attack(store: Store, cfg: Config) -> list[Alert]:
    rows = store.events("source='web'")
    hits = defaultdict(list)
    for r in rows:
        # Decode twice: attackers often double-URL-encode payloads to dodge filters.
        target = unquote_plus(unquote_plus(r["detail"] or ""))
        for name, pat in WEB_ATTACK_PATTERNS.items():
            if pat.search(target):
                hits[r["src_ip"]].append((name, r))
                break
    alerts = []
    for ip, items in hits.items():
        kinds = sorted({k for k, _ in items})
        evs = [r for _, r in items]
        alerts.append(Alert(
            rule="web_attack", severity="high",
            technique="T1190 Exploit Public-Facing Application", entity=ip,
            first_seen=evs[0]["ts"], last_seen=evs[-1]["ts"],
            summary=f"{len(evs)} malicious requests from {ip} ({', '.join(kinds)})",
            evidence=[e["event_id"] for e in evs]))
    return alerts


def web_scanning(store: Store, cfg: Config) -> list[Alert]:
    rows = store.events("source='web' AND status BETWEEN 400 AND 499")
    alerts = []
    for ip, evs in _group(rows, "src_ip").items():
        for burst in _windows(evs, timedelta(minutes=cfg.scan_window_min),
                              lambda w: len(w) >= cfg.scan_threshold):
            alerts.append(Alert(
                rule="web_scanning", severity="medium",
                technique="T1595.003 Active Scanning: Wordlist Scanning", entity=ip,
                first_seen=burst[0]["ts"], last_seen=burst[-1]["ts"],
                summary=f"{len(burst)} requests from {ip} returned 4xx in a short burst (content discovery)",
                evidence=[e["event_id"] for e in burst]))
    return alerts


RULES = [ssh_bruteforce, password_spray, success_after_failures, malware_access, web_attack, web_scanning]


def run_all(store: Store, cfg: Config | None = None) -> list[Alert]:
    cfg = cfg or Config()
    alerts: list[Alert] = []
    for rule in RULES:
        alerts.extend(rule(store, cfg))
    return alerts
