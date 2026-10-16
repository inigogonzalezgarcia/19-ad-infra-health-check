"""Outputs: report.html, findings.csv and health_check.md (the note for the weekly ops or change meeting)."""
from __future__ import annotations

import csv
import html
from collections import Counter
from pathlib import Path

from .checks import AREAS, CRITICAL, INFO, WARNING, Finding, area_status
from .model import Snapshot

e = html.escape


def key(f: Finding) -> tuple[str, str]:
    return (f.code, f.target)


def write_findings(findings: list[Finding], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "area", "code", "target", "detail", "first_step"])
        for f in findings:
            w.writerow([f.severity, f.area, f.code, f.target, f.detail, f.fix])


def read_previous(path: Path | None) -> set[tuple[str, str]] | None:
    if not path or not path.exists():
        return None
    with open(path, newline="", encoding="utf-8") as fh:
        return {(r["code"], r["target"]) for r in csv.DictReader(fh)}


def changes(findings: list[Finding], previous: set[tuple[str, str]] | None) -> dict:
    if previous is None:
        return {"new": [], "resolved": [], "compared": False}
    now = {key(f) for f in findings}
    return {"new": [f for f in findings if key(f) not in previous], "resolved": sorted(previous - now),
            "compared": True}


def summary(s: Snapshot, findings: list[Finding]) -> dict:
    sev = Counter(f.severity for f in findings)
    failing = {(r.source, r.destination) for r in s.replication if r.failures or r.last_error not in ("", "0")}
    return {"dcs": len(s.dcs), "dcs_up": sum(1 for d in s.dcs if d.reachable),
            "links": len({(r.source, r.destination) for r in s.replication}), "links_failing": len(failing),
            "critical": sev.get(CRITICAL, 0), "warning": sev.get(WARNING, 0), "info": sev.get(INFO, 0)}


def health_md(s: Snapshot, findings: list[Finding], ch: dict) -> str:
    sm = summary(s, findings)
    st = area_status(findings)
    lines = [f"# AD health check · {s.domain.dns_root} · {s.collected_at:%Y-%m-%d}", "",
             f"{sm['dcs_up']}/{sm['dcs']} domain controllers answering · {sm['links_failing']} of {sm['links']} "
             f"replication links failing · {sm['critical']} critical, {sm['warning']} warnings, {sm['info']} to tidy up.",
             "", "| Area | Status |", "|---|---|"]
    lines += [f"| {a} | {st[a].upper() if st[a] != 'ok' else 'OK'} |" for a in AREAS]
    if ch["compared"]:
        lines += ["", f"Since the last run: {len(ch['new'])} new, {len(ch['resolved'])} resolved."]
    for sev, title in ((CRITICAL, "Fix today"), (WARNING, "Plan this week")):
        items = [f for f in findings if f.severity == sev]
        if not items:
            continue
        lines += ["", f"## {title}", ""]
        for f in items:
            new = " **(new)**" if ch["compared"] and f in ch["new"] else ""
            lines.append(f"- **{f.target}**: {f.detail}{new}  \n  First step: {f.fix}")
    infos = [f for f in findings if f.severity == INFO]
    if infos:
        lines += ["", "## Housekeeping", ""] + [f"- {f.target}: {f.detail}" for f in infos]
    lines += ["", "Full list: `findings.csv`. Read-only export; nothing was changed in the directory.", ""]
    return "\n".join(lines)


CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;--bad:#f2685c;--info:#5aa9f0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:28px}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.area{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:10px 14px}
.area.critical{border-left-color:var(--bad)}.area.warning{border-left-color:var(--warn)}.area.info{border-left-color:var(--info)}
.area span{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--bad)}.warning{color:var(--warn)}.info{color:var(--info)}.ok{color:var(--ok)}
.area.critical,.area.warning,.area.info,.area.ok{color:inherit}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;min-width:120px}.bar i{display:block;height:100%;background:var(--ok)}
.bar i.warning{background:var(--warn)}.bar i.critical{background:var(--bad)}
td.fix{font-size:13px;color:var(--muted);max-width:380px}footer{margin-top:40px;font-size:13px}
"""


def _dc_rows(s: Snapshot, findings: list[Finding]) -> str:
    worst = {}
    for f in findings:
        if f.area == AREAS[0] and f.severity in (CRITICAL, WARNING) and f.target not in worst:
            worst[f.target] = f.severity
    roles = Counter()
    holders: dict[str, list[str]] = {}
    for role, h in s.domain.fsmo.items():
        holders.setdefault(h, []).append(role.replace("Master", "").replace("Emulator", ""))
        roles[h] += 1
    rows = []
    for d in sorted(s.dcs, key=lambda d: (d.site, d.name)):
        st = worst.get(d.name, "ok")
        down = [k for k, v in d.services.items() if v.lower() != "running"]
        rows.append(
            f"<tr><td><b>{e(d.name)}</b><br><span class='muted'>{e(', '.join(holders.get(d.name, [])) or '—')}</span></td>"
            f"<td>{e(d.site)}</td><td>{e(d.os.replace('Windows Server ', 'WS '))}</td><td>{'GC' if d.is_gc else '—'}</td>"
            f"<td>{'unreachable' if not d.reachable else (', '.join(down) + ' down' if down else 'all running')}</td>"
            f"<td class='num'>{'' if d.time_offset_s is None else f'{d.time_offset_s:+.0f} s'}</td>"
            f"<td class='num'>{'' if d.ntds_free_pct is None else f'{d.ntds_free_pct:.0f}%'}</td>"
            f"<td><span class='pill {st}'>{st.upper() if st != 'ok' else 'OK'}</span></td></tr>")
    return "".join(rows)


def render_html(s: Snapshot, findings: list[Finding], ch: dict, title: str) -> str:
    sm = summary(s, findings)
    st = area_status(findings)
    tiles = (f"<div class='tile'><span class='muted'>DCs answering</span><b>{sm['dcs_up']}/{sm['dcs']}</b></div>"
             f"<div class='tile'><span class='muted'>Replication links failing</span><b>{sm['links_failing']}/{sm['links']}</b></div>"
             f"<div class='tile'><span class='muted'>Critical</span><b class='critical'>{sm['critical']}</b></div>"
             f"<div class='tile'><span class='muted'>Warnings</span><b class='warning'>{sm['warning']}</b></div>"
             f"<div class='tile'><span class='muted'>Housekeeping</span><b class='info'>{sm['info']}</b></div>")
    areas = "".join(f"<div class='area {st[a]}'><span>{e(a)}</span><b class='{st[a]}'>"
                    f"{'OK' if st[a] == 'ok' else st[a].capitalize()}</b></div>" for a in AREAS)
    new_keys = {key(f) for f in ch["new"]}
    frows = "".join(
        f"<tr><td><span class='pill {f.severity}'>{f.severity.upper()}</span>"
        f"{'<br><span class=muted>new</span>' if key(f) in new_keys else ''}</td><td>{e(f.area)}</td>"
        f"<td><b>{e(f.target)}</b><br>{e(f.detail)}</td><td class='fix'>{e(f.fix)}</td></tr>" for f in findings)
    t = 85
    drows = "".join(
        f"<tr><td>{e(sc.name)}<br><span class='muted'>{e(sc.server)} · {e(sc.scope_id)}</span></td>"
        f"<td>{sc.used_pct}%<div class='bar'><i class='{'critical' if sc.used_pct >= 95 else 'warning' if sc.used_pct >= t else ''}'"
        f" style='width:{min(sc.used_pct, 100)}%'></i></div></td><td class='num'>{sc.free}</td>"
        f"<td>{e(sc.failover or 'none')}</td></tr>" for sc in sorted(s.dhcp, key=lambda x: -x.used_pct))
    change_line = (f"<p>Since the last run: <b>{len(ch['new'])}</b> new, <b>{len(ch['resolved'])}</b> resolved.</p>"
                   if ch["compared"] else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head><body><main>
<h1>{e(title)}</h1><p class="muted">{e(s.domain.dns_root)} · domain {e(s.domain.domain_mode)} · forest {e(s.domain.forest_mode)} ·
collected {s.collected_at:%Y-%m-%d %H:%M} UTC</p>
<div class="tiles">{tiles}</div>
<h2>Areas</h2><div class="areas">{areas}</div>{change_line}
<h2>Domain controllers</h2><div class="wrap"><table><thead><tr><th>DC · FSMO</th><th>Site</th><th>OS</th><th>GC</th>
<th>Services</th><th>Clock</th><th>NTDS free</th><th>Status</th></tr></thead><tbody>{_dc_rows(s, findings)}</tbody></table></div>
<h2>Findings</h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Area</th><th>What</th><th>First step</th></tr></thead>
<tbody>{frows or "<tr><td colspan=4>Nothing to report.</td></tr>"}</tbody></table></div>
<h2>DHCP scopes</h2><div class="wrap"><table><thead><tr><th>Scope</th><th>Used</th><th class="num">Free</th><th>Failover</th></tr></thead>
<tbody>{drows}</tbody></table></div>
<footer class="muted">Read-only check. Thresholds and the meaning of each finding: README.md.</footer>
</main></body></html>"""
