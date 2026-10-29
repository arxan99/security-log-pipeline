"""Parsers that turn raw log lines into one normalised event schema.

Supported sources:
  * ``proxy``  - JSON Lines access logs from zerotrust-proxy
  * ``auth``   - Linux sshd lines from /var/log/auth.log
  * ``web``    - Apache/Nginx "combined" access logs
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class Event:
    """Normalised security event. Every parser emits this shape."""

    ts: str                      # ISO-8601 UTC
    source: str                  # proxy | auth | web
    event_type: str              # e.g. web_request, login_failed, login_success
    src_ip: str = ""
    user: str = ""
    host: str = ""               # destination host / server
    action: str = ""             # allow | block | success | failure
    status: int = 0
    bytes_out: int = 0
    detail: str = ""             # path, rule, category, ...
    raw: str = field(default="", repr=False)

    @property
    def event_id(self) -> str:
        """Stable hash of the raw line, used to de-duplicate re-ingested logs."""
        return hashlib.sha256(f"{self.source}|{self.raw}".encode()).hexdigest()

    def to_row(self) -> dict:
        row = asdict(self)
        row["event_id"] = self.event_id
        return row


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- proxy

def parse_proxy(line: str) -> Event | None:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    if "ts" not in d:
        return None
    detail = d.get("path", "")
    if d.get("rule"):
        detail = f"{detail} rule={d['rule']}"
    if d.get("category"):
        detail = f"{detail} category={d['category']}"
    return Event(
        ts=d["ts"],
        source="proxy",
        event_type="web_request",
        src_ip=d.get("client_ip", ""),
        user=d.get("user", ""),
        host=d.get("host", ""),
        action=d.get("action", ""),
        status=int(d.get("status", 0)),
        bytes_out=int(d.get("bytes_out", 0)),
        detail=detail.strip(),
        raw=line,
    )


# --------------------------------------------------------------------------- auth.log

_AUTH_PREFIX = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[\d+\]: (?P<msg>.*)$")
_FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")


def parse_auth(line: str, year: int) -> Event | None:
    """auth.log has no year, so the caller supplies one."""
    m = _AUTH_PREFIX.match(line)
    if not m:
        return None
    ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    msg = m["msg"]
    for pattern, etype, action in (
        (_FAILED, "login_failed", "failure"),
        (_ACCEPTED, "login_success", "success"),
        (_INVALID, "invalid_user", "failure"),
    ):
        mm = pattern.search(msg)
        if mm:
            return Event(ts=_iso(ts), source="auth", event_type=etype, src_ip=mm["ip"],
                         user=mm["user"], host=m["host"], action=action, detail=msg, raw=line)
    return None


# --------------------------------------------------------------------------- web access log

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
)


def parse_web(line: str, host: str = "web") -> Event | None:
    m = _COMBINED.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    status = int(m["status"])
    return Event(
        ts=_iso(ts),
        source="web",
        event_type="http_request",
        src_ip=m["ip"],
        user="" if m["user"] == "-" else m["user"],
        host=host,
        action="failure" if status >= 400 else "success",
        status=status,
        bytes_out=0 if m["bytes"] == "-" else int(m["bytes"]),
        detail=f"{m['method']} {m['path']}",
        raw=line,
    )


# --------------------------------------------------------------------------- dispatch

def parse_lines(lines: Iterable[str], source: str, year: int | None = None) -> Iterator[Event]:
    """Parse lines from one source, silently skipping lines that do not match."""
    year = year or datetime.now(timezone.utc).year
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if source == "proxy":
            ev = parse_proxy(line)
        elif source == "auth":
            ev = parse_auth(line, year)
        elif source == "web":
            ev = parse_web(line)
        else:
            raise ValueError(f"unknown source {source!r}")
        if ev:
            yield ev


def detect_source(first_line: str) -> str:
    """Guess the source type from the first non-empty line of a file."""
    s = first_line.strip()
    if s.startswith("{"):
        return "proxy"
    if " sshd[" in s:
        return "auth"
    if _COMBINED.match(s):
        return "web"
    raise ValueError("could not detect log format; pass --source")
