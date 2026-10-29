"""Render alerts as JSON or a self-contained HTML report."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .store import Store

SEVERITY_COLOURS = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467"}


def to_json(store: Store) -> str:
    rows = []
    for a in store.alerts():
        d = dict(a)
        d["evidence"] = json.loads(d["evidence"])
        rows.append(d)
    return json.dumps({"stats": store.stats(), "alerts": rows}, indent=2)


def to_html(store: Store) -> str:
    stats = store.stats()
    rows = []
    for a in store.alerts():
        colour = SEVERITY_COLOURS.get(a["severity"], "#475467")
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{colour}'>{html.escape(a['severity'])}</span></td>"
            f"<td>{html.escape(a['rule'])}</td>"
            f"<td>{html.escape(a['technique'])}</td>"
            f"<td><code>{html.escape(a['entity'])}</code></td>"
            f"<td>{html.escape(a['first_seen'])}</td>"
            f"<td>{html.escape(a['summary'])}</td>"
            f"<td>{len(json.loads(a['evidence']))}</td>"
            "</tr>")
    sources = ", ".join(f"{k}: {v}" for k, v in stats["by_source"].items()) or "none"
    sev = " · ".join(f"{k}: {v}" for k, v in stats["by_severity"].items()) or "none"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Security Alert Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:32px;color:#101828}}
h1{{margin:0 0 4px}} .muted{{color:#667085}}
.cards{{display:flex;gap:16px;margin:20px 0}}
.card{{border:1px solid #eaecf0;border-radius:8px;padding:12px 16px;min-width:160px}}
.card b{{font-size:24px;display:block}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border-bottom:1px solid #eaecf0;padding:8px;text-align:left;vertical-align:top}}
th{{background:#f9fafb}}
.sev{{color:#fff;border-radius:4px;padding:2px 6px;font-size:12px;text-transform:uppercase}}
</style></head><body>
<h1>Security Alert Report</h1>
<div class="muted">Generated {generated}</div>
<div class="cards">
  <div class="card"><b>{stats['events']}</b>events ingested<br><span class="muted">{html.escape(sources)}</span></div>
  <div class="card"><b>{stats['alerts']}</b>alerts<br><span class="muted">{html.escape(sev)}</span></div>
</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>MITRE ATT&amp;CK</th><th>Entity</th>
<th>First seen</th><th>Summary</th><th>Events</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="7">No alerts</td></tr>'}</tbody></table>
</body></html>"""
