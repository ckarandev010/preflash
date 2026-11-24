"""Text, JSON and HTML output."""
import html
import json
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .rules import RANK, SEVERITIES


def summary(findings):
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


def to_text(findings, meta):
    out = [f"preflash {__version__}  |  {meta['project']}  |  config: {meta['config'] or 'none found'}  |  profile: {meta['profile']}"]
    if meta.get("partial"):
        out.append("  note: only sdkconfig.defaults found; unset options were evaluated at their Kconfig defaults. Build the project for exact results.")
    if not findings:
        out.append("\nNo findings.")
        return "\n".join(out)
    for f in sorted(findings, key=lambda f: (RANK[f.severity], f.file, f.line or 0)):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out.append(f"\n[{f.severity.upper():8}] {f.rule}  {f.title}\n           {loc}\n           {f.evidence}\n           fix: {f.fix}")
    s = summary(findings)
    out.append("\n" + "  ".join(f"{k}: {v}" for k, v in s.items()))
    return "\n".join(out)


def to_json(findings, meta):
    return json.dumps({
        "tool": "preflash", "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **meta, "summary": summary(findings),
        "findings": [f.__dict__ for f in sorted(findings, key=lambda f: (RANK[f.severity], f.file, f.line or 0))],
    }, indent=2)


_CSS = """
:root{--bg:#f4f6f8;--panel:#fff;--ink:#17202a;--ink2:#4b5866;--line:#d8dee5;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#2f5bd3;--info:#6b7785}
@media (prefers-color-scheme:dark){:root{--bg:#12171d;--panel:#1a222b;--ink:#e7ecf1;--ink2:#a9b4c0;--line:#2d3945;--crit:#ff7b72;--high:#fb923c;--med:#facc15;--low:#8fb0ff;--info:#94a3b8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px 16px 48px}h1{margin:0;font-size:24px}.meta{color:var(--ink2);margin:4px 0 16px}
.sum{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}.pill{padding:4px 10px;border-radius:999px;border:1px solid var(--line);background:var(--panel);font-weight:600}
.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;padding:12px 14px;margin:10px 0}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.sev{font:600 11px/1 ui-monospace,Consolas,monospace;text-transform:uppercase;letter-spacing:.05em}.critical .sev{color:var(--crit)}.high .sev{color:var(--high)}.medium .sev{color:var(--med)}.low .sev{color:var(--low)}.info .sev{color:var(--info)}
h3{margin:4px 0 6px;font-size:16px}code{font:12px ui-monospace,Consolas,monospace;background:var(--bg);padding:2px 6px;border-radius:4px;word-break:break-all}
.loc{color:var(--ink2);font-size:13px}.std{color:var(--ink2);font-size:12px;margin-top:6px}p{margin:6px 0}
"""


def to_html(findings, meta):
    s = summary(findings)
    e = html.escape
    rows = []
    for f in sorted(findings, key=lambda f: (RANK[f.severity], f.file, f.line or 0)):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        std = " · ".join(x for v in f.standards.values() for x in v)
        rows.append(f"""<div class="f {f.severity}"><div class="sev">{e(f.severity)} · {e(f.rule)}</div><h3>{e(f.title)}</h3>
<div class="loc">{e(loc)}</div><p><code>{e(f.evidence)}</code></p><p>{e(f.why)}</p><p><b>Fix:</b> {e(f.fix)}</p><div class="std">{e(std)}</div></div>""")
    note = "<p class='meta'>Only sdkconfig.defaults was found; unset options were evaluated at their Kconfig defaults.</p>" if meta.get("partial") else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>preflash report</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>preflash report</h1><div class="meta">{e(meta['project'])} · config {e(str(meta['config']))} · profile {e(meta['profile'])} · preflash {__version__}</div>{note}
<div class="sum">{''.join(f'<span class="pill">{k}: {v}</span>' for k, v in s.items())}</div>
{''.join(rows) or '<p>No findings.</p>'}
<p class="meta">Findings map to ETSI EN 303 645 provisions, the OWASP IoT Top 10 (2018) and NISTIR 8259A capabilities. This is a static check of configuration and source, not a certification or a penetration test.</p>
</div></body></html>"""
