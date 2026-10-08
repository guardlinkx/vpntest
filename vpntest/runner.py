"""Schedule checks against targets, enforcing scope on every single pair."""

from __future__ import annotations

import time
import traceback
from typing import Any, Dict, List, Optional, Type

from .guard import Scope, ScopeError
from .model import Check, Context, Finding, Severity, Status, Target


class Runner:
    def __init__(self, scope: Scope, catalog, evidence, options: Optional[Dict] = None):
        self.scope = scope
        self.catalog = catalog
        self.evidence = evidence
        self.options = options or {}
        self.ctx = Context(scope=scope, evidence=evidence, catalog=catalog,
                           options=self.options)

    def _targets(self, protocol: str) -> List[Target]:
        out = []
        for entry in self.scope.targets_for(protocol):
            out.append(Target(
                host=entry["host"],
                label=entry.get("label", entry["host"]),
                port=entry.get("port"),
                protocols=list(entry.get("protocols") or []),
                meta=dict(entry.get("meta") or {}),
            ))
        return out

    def run(self, checks: Dict[str, Type[Check]],
            protocols: Optional[List[str]] = None,
            only: Optional[List[str]] = None) -> List[Finding]:
        findings: List[Finding] = []

        for check_id in sorted(checks):
            cls = checks[check_id]
            if only and check_id not in only:
                continue
            if protocols and cls.protocol not in protocols:
                continue

            # No catalog entry, no run — a finding must trace to a baseline.
            try:
                control = self.catalog.require(check_id)
            except KeyError as exc:
                findings.append(Finding(
                    check_id=check_id, status=Status.ERROR,
                    summary=str(exc), severity=Severity.INFO,
                ))
                continue

            check = cls()
            try:
                self.scope.assert_runnable(check)
            except ScopeError as exc:
                findings.append(Finding(
                    check_id=check_id, status=Status.SKIP, summary=str(exc),
                    severity=Severity.INFO,
                ))
                continue

            for target in self._targets(cls.protocol):
                started = time.time()
                try:
                    self.scope.assert_target(target.host)
                except ScopeError as exc:
                    findings.append(Finding(
                        check_id=check_id, status=Status.SKIP, target=str(target),
                        summary=str(exc), severity=Severity.INFO,
                    ))
                    continue

                try:
                    if not check.applicable(target, self.ctx):
                        findings.append(Finding(
                            check_id=check_id, status=Status.NA, target=str(target),
                            summary="Control does not apply to this target",
                            severity=Severity.INFO,
                        ))
                        continue
                    results = check.run(target, self.ctx) or []
                except ScopeError as exc:
                    results = [Finding(check_id=check_id, status=Status.SKIP,
                                       target=str(target), summary=str(exc),
                                       severity=Severity.INFO)]
                except Exception as exc:  # a broken check must not stop the run
                    detail = {"traceback": traceback.format_exc()[-2000:]}
                    results = [Finding(
                        check_id=check_id, status=Status.ERROR, target=str(target),
                        summary=f"Check raised {type(exc).__name__}: {exc}",
                        severity=Severity.INFO, detail=detail,
                    )]

                elapsed = time.time() - started
                for f in results:
                    f.duration_s = elapsed
                    # Fill from the catalog so checks stay terse and the
                    # severity/remediation live with the requirement.
                    if not f.remediation:
                        f.remediation = control.remediation
                    if f.status is Status.FAIL and f.severity is Severity.MEDIUM:
                        f.severity = control.severity
                findings.extend(results)

        return findings


def summarize(findings: List[Finding]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.status.value] = counts.get(f.status.value, 0) + 1
    problems = [f for f in findings if f.status.is_problem]
    by_sev: Dict[str, int] = {}
    for f in problems:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return {
        "total": len(findings),
        "by_status": counts,
        "problems_by_severity": by_sev,
        "failed_controls": sorted({f.check_id for f in findings
                                   if f.status is Status.FAIL}),
    }
