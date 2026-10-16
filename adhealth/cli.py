"""Command line: `demo` builds everything from a fictional domain, `report` runs on your own export."""
from __future__ import annotations

import argparse
from pathlib import Path

from . import report, simulate
from .checks import Thresholds, run_all
from .model import load


def run(export: Path, out: Path, title: str, previous: Path | None, t: Thresholds) -> dict:
    snap = load(export)
    findings = run_all(snap, t)
    prev = report.read_previous(previous)            # read before writing, it may be the same file
    ch = report.changes(findings, prev)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(snap, findings, ch, title), encoding="utf-8")
    report.write_findings(findings, out / "findings.csv")
    (out / "health_check.md").write_text(report.health_md(snap, findings, ch), encoding="utf-8")
    sm = report.summary(snap, findings)
    sm["new"], sm["resolved"] = len(ch["new"]), len(ch["resolved"])
    return sm


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="adhealth", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="generate a fictional domain and build the outputs")
    d.add_argument("--out", type=Path, default=Path("output"))
    d.add_argument("--data", type=Path, default=Path("sample_data"))
    r = sub.add_parser("report", help="build the outputs from your own export")
    r.add_argument("export", type=Path, help="JSON from scripts/Export-ADHealth.ps1")
    r.add_argument("--out", type=Path, default=Path("output"))
    r.add_argument("--previous", type=Path, help="findings.csv from the last run, to list what is new and resolved")
    r.add_argument("--title", default="AD infrastructure health check")
    r.add_argument("--stale-days", type=int, default=90)
    r.add_argument("--krbtgt-days", type=int, default=180)
    r.add_argument("--max-domain-admins", type=int, default=5)
    a = p.parse_args(argv)

    if a.cmd == "demo":
        path = simulate.write_demo(a.data)
        sm = run(path, a.out, "AD infrastructure health check (demo data)", None, Thresholds())
    else:
        t = Thresholds(stale_days=a.stale_days, krbtgt_days=a.krbtgt_days, max_domain_admins=a.max_domain_admins)
        sm = run(a.export, a.out, a.title, a.previous, t)
    extra = f" · {sm['new']} new, {sm['resolved']} resolved" if a.cmd == "report" and a.previous else ""
    print(f"{sm['dcs_up']}/{sm['dcs']} DCs answering · {sm['links_failing']}/{sm['links']} replication links failing · "
          f"{sm['critical']} critical, {sm['warning']} warnings, {sm['info']} housekeeping{extra}. Outputs in {a.out}/")
    return 0
