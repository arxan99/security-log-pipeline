"""Command-line interface: ingest, detect, report, stats."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import detections, report
from .parsers import detect_source, parse_lines
from .store import Store


def cmd_ingest(args) -> int:
    store = Store(args.db)
    for path in args.files:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        first = next((ln for ln in lines if ln.strip()), "")
        source = args.source or detect_source(first)
        inserted, dupes = store.insert_events(parse_lines(lines, source, args.year))
        print(f"{path}: source={source} inserted={inserted} duplicates={dupes}")
    store.close()
    return 0


def cmd_detect(args) -> int:
    store = Store(args.db)
    alerts = detections.run_all(store)
    store.save_alerts(alerts)
    for a in sorted(alerts, key=lambda a: a.first_seen):
        print(f"[{a.severity.upper():8}] {a.rule:24} {a.entity:16} {a.summary}")
    print(f"{len(alerts)} alerts")
    store.close()
    return 1 if args.fail_on_alert and alerts else 0


def cmd_report(args) -> int:
    store = Store(args.db)
    out = report.to_html(store) if args.format == "html" else report.to_json(store)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(out + "\n")
    store.close()
    return 0


def cmd_stats(args) -> int:
    store = Store(args.db)
    print(store.stats())
    store.close()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="slp", description="Security log pipeline")
    p.add_argument("--db", default="slp.db", help="SQLite database path")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("ingest", help="parse and store log files")
    i.add_argument("files", nargs="+")
    i.add_argument("--source", choices=["proxy", "auth", "web"], help="force log format")
    i.add_argument("--year", type=int, help="year for auth.log timestamps (no year in format)")
    i.set_defaults(func=cmd_ingest)

    d = sub.add_parser("detect", help="run detection rules and store alerts")
    d.add_argument("--fail-on-alert", action="store_true", help="exit 1 if any alert fires")
    d.set_defaults(func=cmd_detect)

    r = sub.add_parser("report", help="export alerts")
    r.add_argument("--format", choices=["html", "json"], default="html")
    r.add_argument("-o", "--output")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("stats", help="show counts")
    s.set_defaults(func=cmd_stats)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
