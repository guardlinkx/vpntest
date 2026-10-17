"""vpntest — command line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from .catalog import Catalog
from .evidence import EvidenceStore
from .guard import Scope, ScopeError
from .model import Status
from .registry import coverage, discover
from .report import html_report, json_report
from .runner import Runner, summarize

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _paths(args):
    return (args.catalog or os.path.join(HERE, "catalog"),
            args.evidence_dir or os.path.join(HERE, "evidence"),
            args.out_dir or os.path.join(HERE, "reports"))


def cmd_run(args) -> int:
    catalog_dir, evidence_dir, out_dir = _paths(args)
    catalog = Catalog.load(catalog_dir)
    try:
        scope = Scope.load(args.scope)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2

    print(f"==> {scope.describe()}")
    if not scope.in_window():
        print("refusing to run: outside the authorized window", file=sys.stderr)
        return 2

    checks = discover()
    evidence = EvidenceStore(evidence_dir)
    runner = Runner(scope, catalog, evidence, options={"verbose": args.verbose})

    protocols = args.protocol or None

    # --only accepts both repeated flags and a comma-separated list, because
    # typing the comma form is the obvious guess and silently selecting
    # nothing is the worst possible response to it.
    only = None
    if args.only:
        only = [cid.strip().upper()
                for item in args.only for cid in item.split(",") if cid.strip()]
        unknown = [c for c in only if c not in checks]
        if unknown:
            # Refuse rather than run a subset. An empty run prints an empty
            # summary, which reads exactly like a clean pass.
            print(f"==> no such control(s): {', '.join(unknown)}", file=sys.stderr)
            return 2

    print(f"==> {len(checks)} check(s) available, {len(catalog)} control(s) in catalog")
    if only:
        print(f"==> limited to: {', '.join(only)}")

    findings = runner.run(checks, protocols=protocols, only=only)
    summary = summarize(findings)
    evidence.write_manifest()

    os.makedirs(out_dir, exist_ok=True)
    report = json_report.build(findings, scope, catalog, evidence, summary)
    jpath = json_report.write(report, os.path.join(out_dir, f"report-{evidence.run_id}.json"))
    hpath = html_report.write(report, os.path.join(out_dir, f"report-{evidence.run_id}.html"))

    print()
    for f in sorted(findings, key=lambda x: (x.status.value, x.check_id)):
        if f.status in (Status.FAIL, Status.WARN) or args.verbose:
            mark = {"fail": "FAIL", "warn": "WARN", "pass": "pass",
                    "n/a": "n/a ", "skip": "skip", "error": "ERR "}[f.status.value]
            print(f"  [{mark}] {f.check_id:<8} {f.target:<22} {f.summary}")

    print()
    print(f"==> {summary['by_status']}")
    if summary["problems_by_severity"]:
        print(f"==> problems: {summary['problems_by_severity']}")
    print(f"==> report:   {hpath}")
    print(f"==> json:     {jpath}")
    print(f"==> evidence: {evidence.dir}")

    # Non-zero when something failed, so CI can gate on it.
    return 1 if summary["by_status"].get("fail") else 0


def cmd_catalog(args) -> int:
    catalog_dir, _, _ = _paths(args)
    catalog = Catalog.load(catalog_dir)
    checks = discover()
    cov = coverage(checks, catalog)
    for proto in catalog.protocols():
        controls = catalog.by_protocol(proto)
        done = [c for c in controls if c.id in checks]
        print(f"\n{proto}  ({len(done)}/{len(controls)} implemented)")
        for c in sorted(controls, key=lambda x: x.id):
            mark = "x" if c.id in checks else " "
            print(f"  [{mark}] {c.id:<8} {c.severity.value:<8} {c.title}")
    print(f"\ntotals: {len(cov['implemented'])}/{len(catalog)} controls implemented")
    if cov["check_without_catalog"]:
        print(f"WARNING orphan checks: {cov['check_without_catalog']}")
    return 0


def main(argv: List[str] = None) -> int:
    p = argparse.ArgumentParser(prog="vpntest",
                                description="VPN security test harness")
    p.add_argument("--catalog", help="catalog directory")
    p.add_argument("--evidence-dir", help="where evidence is written")
    p.add_argument("--out-dir", help="where reports are written")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run checks against a scope")
    r.add_argument("--scope", required=True, help="authorization file")
    r.add_argument("--protocol", action="append",
                   help="limit to a protocol (repeatable)")
    r.add_argument("--only", action="append", help="run specific control ids")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("catalog", help="show controls and implementation status")
    c.set_defaults(func=cmd_catalog)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
