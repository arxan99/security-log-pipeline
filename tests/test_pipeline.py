import json
import sys
from pathlib import Path

import pytest

from slp import cli, detections
from slp.parsers import parse_lines
from slp.store import Store

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "samples"))
import generate  # noqa: E402


@pytest.fixture
def store(tmp_path):
    generate.main(str(tmp_path))
    s = Store(str(tmp_path / "test.db"))
    s.insert_events(parse_lines((tmp_path / "auth.log").read_text().splitlines(), "auth", 2026))
    s.insert_events(parse_lines((tmp_path / "access.log").read_text().splitlines(), "web"))
    s.insert_events(parse_lines((tmp_path / "proxy.jsonl").read_text().splitlines(), "proxy"))
    yield s
    s.close()


def rules_fired(alerts):
    return {(a.rule, a.entity) for a in alerts}


def test_reingest_is_deduplicated(store, tmp_path):
    lines = (tmp_path / "access.log").read_text().splitlines()
    inserted, dupes = store.insert_events(parse_lines(lines, "web"))
    assert inserted == 0 and dupes == len([ln for ln in lines if ln.strip()])


def test_detects_every_planted_attack(store):
    fired = rules_fired(detections.run_all(store))
    assert ("ssh_bruteforce", "203.0.113.45") in fired
    assert ("success_after_failures", "203.0.113.45") in fired
    assert ("password_spray", "198.51.100.23") in fired
    assert ("web_scanning", "45.33.32.156") in fired
    assert ("web_attack", "185.220.101.7") in fired
    assert ("malware_access", "dave") in fired


def test_no_alerts_for_normal_staff(store):
    alerts = detections.run_all(store)
    entities = {a.entity for a in alerts}
    office = {f"10.0.0.{i}" for i in range(10, 20)}
    assert not entities & office, "ordinary typos from office IPs must not alert"
    assert not entities & {"alice", "bob", "carol"}


def test_web_attack_classifies_kinds(store):
    alert = next(a for a in detections.web_attack(store, detections.Config()))
    assert "sql_injection" in alert.summary and "path_traversal" in alert.summary and "xss" in alert.summary


def test_thresholds_are_configurable(store):
    strict = detections.Config(bruteforce_threshold=100)
    assert detections.ssh_bruteforce(store, strict) == []


def test_cli_end_to_end(tmp_path, capsys):
    generate.main(str(tmp_path))
    db = str(tmp_path / "cli.db")
    for name in ("auth.log", "access.log", "proxy.jsonl"):
        assert cli.main(["--db", db, "ingest", "--year", "2026", str(tmp_path / name)]) == 0
    assert cli.main(["--db", db, "detect", "--fail-on-alert"]) == 1
    out = tmp_path / "report.html"
    assert cli.main(["--db", db, "report", "-o", str(out)]) == 0
    assert "T1110.001" in out.read_text()
    assert cli.main(["--db", db, "report", "--format", "json", "-o", str(tmp_path / "r.json")]) == 0
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["stats"]["alerts"] >= 6
