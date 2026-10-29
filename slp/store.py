"""SQLite storage for events and alerts."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable

from .parsers import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    source     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip     TEXT,
    user       TEXT,
    host       TEXT,
    action     TEXT,
    status     INTEGER,
    bytes_out  INTEGER,
    detail     TEXT,
    raw        TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip_type ON events(src_ip, event_type);
CREATE INDEX IF NOT EXISTS idx_events_user    ON events(user);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    technique   TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    entity      TEXT NOT NULL,
    summary     TEXT NOT NULL,
    evidence    TEXT NOT NULL
);
"""

COLUMNS = ["event_id", "ts", "source", "event_type", "src_ip", "user", "host",
           "action", "status", "bytes_out", "detail", "raw"]


class Store:
    def __init__(self, path: str = "slp.db"):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def insert_events(self, events: Iterable[Event], batch_size: int = 1000) -> tuple[int, int]:
        """Insert events in batches. Returns (inserted, duplicates_skipped)."""
        sql = (f"INSERT OR IGNORE INTO events ({', '.join(COLUMNS)}) "
               f"VALUES ({', '.join('?' * len(COLUMNS))})")
        inserted = seen = 0
        batch: list[tuple] = []

        def flush():
            nonlocal inserted
            before = self.conn.total_changes
            self.conn.executemany(sql, batch)
            inserted += self.conn.total_changes - before
            batch.clear()

        for ev in events:
            row = ev.to_row()
            batch.append(tuple(row[c] for c in COLUMNS))
            seen += 1
            if len(batch) >= batch_size:
                flush()
        if batch:
            flush()
        self.conn.commit()
        return inserted, seen - inserted

    def events(self, where: str = "1=1", params: tuple = ()) -> list[sqlite3.Row]:
        return self.conn.execute(f"SELECT * FROM events WHERE {where} ORDER BY ts", params).fetchall()

    def save_alerts(self, alerts) -> int:
        before = self.conn.total_changes
        self.conn.executemany(
            "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
            [(a.alert_id, a.rule, a.severity, a.technique, a.first_seen, a.last_seen,
              a.entity, a.summary, json.dumps(a.evidence)) for a in alerts],
        )
        self.conn.commit()
        return self.conn.total_changes - before

    def alerts(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM alerts ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, first_seen").fetchall()

    def stats(self) -> dict:
        q = self.conn.execute
        return {
            "events": q("SELECT COUNT(*) FROM events").fetchone()[0],
            "by_source": {r[0]: r[1] for r in q("SELECT source, COUNT(*) FROM events GROUP BY source")},
            "alerts": q("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "by_severity": {r[0]: r[1] for r in q("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")},
        }

    def close(self):
        self.conn.close()
