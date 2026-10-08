"""Self-contained HTML report — one file, no external assets.

Grouped by severity rather than by protocol, because the first question a
reader has is "what is on fire", not "what did IPsec say".
"""

from __future__ import annotations

import html
from typing import Any, Dict, List

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": "#b00020", "high": "#d9480f", "medium": "#b8860b",
    "low": "#2b6cb0", "info": "#4a5568",
}
STATUS_COLOR = {
    "fail": "#b00020", "warn": "#b8860b", "pass": "#1e7e34",
    "n/a": "#6c757d", "skip": "#6c757d", "error": "#6f42c1",
}


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ""))


def render(report: Dict[str, Any]) -> str:
    s = report["summary"]
    findings = report["findings"]
    problems = [f for f in findings if f["status"] in ("fail", "warn")]
    problems.sort(key=lambda f: (SEV_ORDER.index(f["severity"]), f["check_id"]))
    others = [f for f in findings if f["status"] not in ("fail", "warn")]
    others.sort(key=lambda f: f["check_id"])

    def row(f):
        return f"""
        <tr>
          <td><code>{_esc(f['check_id'])}</code></td>
          <td><span class="pill" style="background:{STATUS_COLOR.get(f['status'],'#666')}">
              {_esc(f['status'])}</span></td>
          <td><span style="color:{SEV_COLOR.get(f['severity'],'#444')};font-weight:600">
              {_esc(f['severity'])}</span></td>
          <td>{_esc(f['target'])}</td>
          <td>
            <div class="title">{_esc(f.get('title'))}</div>
            <div class="summary">{_esc(f['summary'])}</div>
            {"<div class='rem'><b>Remediation:</b> " + _esc(f['remediation']) + "</div>" if f.get('remediation') and f['status'] in ('fail','warn') else ""}
            {"<div class='base'>" + _esc(', '.join(f.get('baselines') or [])) + "</div>" if f.get('baselines') else ""}
            {"<div class='ev'>evidence: " + _esc(', '.join(f['evidence'])) + "</div>" if f.get('evidence') else ""}
          </td>
        </tr>"""

    counts = s.get("by_status", {})
    chips = " ".join(
        f'<span class="chip" style="background:{STATUS_COLOR.get(k,"#666")}">{_esc(k)}: {v}</span>'
        for k, v in sorted(counts.items())
    )

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>VPN security report — {_esc(report['scope']['name'])}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         margin: 0; padding: 2rem; background: #fafafa; color: #1a1a1a; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #15181c; color: #e6e6e6; }}
    table {{ background: #1d2127 !important; }}
    th {{ background: #252a31 !important; }}
    td {{ border-color: #2c323a !important; }}
    .meta, .card {{ background: #1d2127 !important; border-color: #2c323a !important; }}
  }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .meta {{ background:#fff; border:1px solid #e3e3e3; border-radius:8px;
           padding:1rem; margin:1rem 0; }}
  .meta div {{ margin:.15rem 0; }}
  table {{ border-collapse: collapse; width:100%; background:#fff;
           border-radius:8px; overflow:hidden; margin-bottom:2rem; }}
  th {{ text-align:left; background:#f0f1f3; padding:.6rem .7rem; font-size:.8rem;
        text-transform:uppercase; letter-spacing:.04em; }}
  td {{ padding:.6rem .7rem; border-top:1px solid #ececec; vertical-align:top; }}
  .pill, .chip {{ color:#fff; border-radius:999px; padding:.1rem .55rem;
                  font-size:.75rem; font-weight:600; display:inline-block; }}
  .chip {{ margin-right:.35rem; }}
  .title {{ font-weight:600; }}
  .summary {{ margin-top:.15rem; }}
  .rem {{ margin-top:.35rem; font-size:.85rem; opacity:.85; }}
  .base {{ margin-top:.25rem; font-size:.75rem; opacity:.65; }}
  .ev {{ margin-top:.25rem; font-size:.75rem; font-family:ui-monospace,monospace; opacity:.6; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  h2 {{ font-size:1.05rem; margin:1.5rem 0 .5rem; }}
</style></head><body>
<h1>VPN security report</h1>
<div>{chips}</div>
<div class="meta">
  <div><b>Scope:</b> {_esc(report['scope']['name'])}</div>
  <div><b>Authorized by:</b> {_esc(report['scope']['authorized_by'])}</div>
  <div><b>Targets:</b> {_esc(', '.join(report['scope']['targets']))}</div>
  <div><b>Generated:</b> {_esc(report['generated_at'])}</div>
  <div><b>Evidence:</b> <code>{_esc(report['evidence']['directory'])}</code>
       ({len(report['evidence']['files'])} file(s), SHA-256 in MANIFEST.json)</div>
  <div><b>Disruptive enabled:</b> {_esc(report['scope']['allow_disruptive'] or 'none')}</div>
</div>

<h2>Findings requiring attention ({len(problems)})</h2>
<table>
  <tr><th>Control</th><th>Status</th><th>Severity</th><th>Target</th><th>Detail</th></tr>
  {''.join(row(f) for f in problems) if problems else
   '<tr><td colspan="5">Nothing failed or warned.</td></tr>'}
</table>

<h2>Everything else ({len(others)})</h2>
<table>
  <tr><th>Control</th><th>Status</th><th>Severity</th><th>Target</th><th>Detail</th></tr>
  {''.join(row(f) for f in others)}
</table>

<p style="font-size:.8rem;opacity:.7;max-width:60ch">
These checks cover the testable controls of the named baselines. They are not
proof of security: implementation bugs, certification, and design review stay
outside any automated tool.
</p>
</body></html>"""


def write(report: Dict[str, Any], path: str) -> str:
    with open(path, "w") as fh:
        fh.write(render(report))
    return path
