"""Core types every check and report is built from.

Deliberately small: the runner and the reporter must never need protocol
knowledge, so everything they touch lives here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Status(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    NA = "n/a"        # control does not apply to this target
    ERROR = "error"   # the check itself failed; says nothing about the target
    SKIP = "skip"     # not run: disruptive and not opted in, or out of scope

    @property
    def is_problem(self) -> bool:
        return self in (Status.FAIL, Status.WARN)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
        }[self.value]


@dataclass
class Finding:
    """One control's verdict against one target.

    `evidence` holds paths into the evidence store rather than raw data, so a
    report stays readable and a pcap full of someone's traffic never ends up
    inline in an HTML file.
    """

    check_id: str
    status: Status
    summary: str
    target: str = ""
    severity: Severity = Severity.MEDIUM
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "target": self.target,
            "evidence": list(self.evidence),
            "remediation": self.remediation,
            "detail": self.detail,
            "duration_s": round(self.duration_s, 3),
        }


@dataclass
class Target:
    """Something to test. A host, with whatever extra a check may need."""

    host: str
    label: str = ""
    port: Optional[int] = None
    protocols: List[str] = field(default_factory=list)
    # Per-target extras: API base URLs, SSH user/key for config review,
    # credentials for authenticated checks. Checks read what they need and
    # report NA when it is absent rather than failing.
    meta: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.label or self.host


class Check:
    """Base class for every control.

    Subclasses set the class attributes and implement `run`. The id must match
    a catalog entry; the runner refuses to run a check with no catalog entry,
    so a finding can always be traced to a named baseline.
    """

    id: str = ""
    protocol: str = ""          # ipsec | tls_vpn | wireguard | client | api
    access: str = "unauth"      # unauth | test-creds | config | agent
    disruptive: bool = False    # skipped unless the scope opts in by id
    requires: List[str] = field(default_factory=list)  # external tools needed

    def applicable(self, target: Target, ctx: "Context") -> bool:
        """Cheap pre-filter. Return False to report NA without running."""
        return True

    def run(self, target: Target, ctx: "Context") -> List[Finding]:
        raise NotImplementedError

    # -- helpers so checks stay terse -------------------------------------

    def _f(self, status: Status, summary: str, target: Target,
           severity: Severity = Severity.MEDIUM, **kw) -> Finding:
        return Finding(
            check_id=self.id, status=status, summary=summary,
            target=str(target), severity=severity, **kw
        )

    def ok(self, target, summary, **kw) -> Finding:
        return self._f(Status.PASS, summary, target, Severity.INFO, **kw)

    def fail(self, target, summary, severity=Severity.HIGH, **kw) -> Finding:
        return self._f(Status.FAIL, summary, target, severity, **kw)

    def warn(self, target, summary, severity=Severity.MEDIUM, **kw) -> Finding:
        return self._f(Status.WARN, summary, target, severity, **kw)

    def na(self, target, summary, **kw) -> Finding:
        return self._f(Status.NA, summary, target, Severity.INFO, **kw)

    def error(self, target, summary, **kw) -> Finding:
        return self._f(Status.ERROR, summary, target, Severity.INFO, **kw)


@dataclass
class Context:
    """Everything a check is allowed to use, passed in rather than imported.

    Keeping this explicit is what makes a check testable without a live target
    and keeps the scope guard impossible to bypass by accident.
    """

    scope: Any                      # Scope — the authorization file
    evidence: Any                   # EvidenceStore
    catalog: Any                    # Catalog
    started_at: float = field(default_factory=time.time)
    options: Dict[str, Any] = field(default_factory=dict)

    def rate_limit(self, name: str, default: int) -> int:
        return int(self.scope.limits.get(name, default))
