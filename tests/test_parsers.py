import json

import pytest

from slp.parsers import detect_source, parse_auth, parse_lines, parse_proxy, parse_web


def test_parse_proxy():
    line = json.dumps({"ts": "2026-10-29T11:56:45Z", "client_ip": "10.0.0.7", "user": "alice",
                       "host": "evil.test", "path": "/x", "action": "block", "rule": "block-malware",
                       "category": "malware", "status": 403, "bytes_out": 0})
    ev = parse_proxy(line)
    assert ev.user == "alice" and ev.action == "block" and ev.status == 403
    assert "category=malware" in ev.detail


def test_parse_proxy_rejects_garbage():
    assert parse_proxy("not json") is None
    assert parse_proxy('{"no_ts": 1}') is None


@pytest.mark.parametrize("line,etype,user,ip", [
    ("Oct 28 11:00:00 bastion sshd[123]: Failed password for root from 203.0.113.45 port 22 ssh2",
     "login_failed", "root", "203.0.113.45"),
    ("Oct 28 11:00:00 bastion sshd[123]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2",
     "login_failed", "bob", "1.2.3.4"),
    ("Oct  8 11:00:00 bastion sshd[123]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2",
     "login_success", "alice", "10.0.0.5"),
    ("Oct 28 11:00:00 bastion sshd[123]: Invalid user admin from 198.51.100.23 port 4022",
     "invalid_user", "admin", "198.51.100.23"),
])
def test_parse_auth(line, etype, user, ip):
    ev = parse_auth(line, 2026)
    assert (ev.event_type, ev.user, ev.src_ip) == (etype, user, ip)
    assert ev.ts.startswith("2026-10-")


def test_parse_auth_ignores_other_lines():
    assert parse_auth("Oct 28 11:00:00 bastion sshd[1]: Connection closed by 1.2.3.4", 2026) is None
    assert parse_auth("Oct 28 11:00:00 bastion cron[1]: job ran", 2026) is None


def test_parse_web_converts_timezone_to_utc():
    line = '1.2.3.4 - - [28/Oct/2026:14:30:00 +0530] "GET /login HTTP/1.1" 404 162 "-" "curl"'
    ev = parse_web(line)
    assert ev.ts == "2026-10-28T09:00:00Z"
    assert ev.status == 404 and ev.action == "failure" and ev.detail == "GET /login"


def test_detect_source():
    assert detect_source('{"ts": "x"}') == "proxy"
    assert detect_source("Oct 28 11:00:00 h sshd[1]: x") == "auth"
    assert detect_source('1.2.3.4 - - [28/Oct/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1') == "web"
    with pytest.raises(ValueError):
        detect_source("random text")


def test_parse_lines_skips_blank_and_unmatched():
    lines = ["", "garbage", '1.2.3.4 - - [28/Oct/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1']
    assert len(list(parse_lines(lines, "web"))) == 1


def test_event_id_is_stable():
    line = '1.2.3.4 - - [28/Oct/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1'
    assert parse_web(line).event_id == parse_web(line).event_id
