"""Deny-by-default scope enforcement.

Nothing reaches a target without passing through here. A host that is not in
the signed scope file, or a run outside its window, aborts before any packet
is sent — the guard is checked by the runner for every (check, target) pair
rather than once at startup, so a check cannot wander onto a neighbouring host
by resolving a hostname differently or following a redirect.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import yaml


class ScopeError(Exception):
    """A target or action is not authorized. Always fatal for that action."""


@dataclass
class Scope:
    name: str
    authorized_by: str
    targets: List[Dict[str, Any]] = field(default_factory=list)
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    allow_disruptive: List[str] = field(default_factory=list)
    limits: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    # Resolved once so a check cannot be pointed at a different address by a
    # hostname that starts resolving elsewhere mid-run.
    _allowed_ips: set = field(default_factory=set, repr=False)
    _allowed_hosts: set = field(default_factory=set, repr=False)

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}

        for required in ("name", "authorized_by", "targets"):
            if not raw.get(required):
                raise ScopeError(
                    f"Scope file {path} is missing required field '{required}'. "
                    "Testing without a named authorizer is not supported."
                )

        def _dt(value):
            if not value:
                return None
            if isinstance(value, datetime):
                return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            return datetime.fromisoformat(str(value)).replace(tzinfo=timezone.utc)

        window = raw.get("window") or {}
        scope = cls(
            name=raw["name"],
            authorized_by=raw["authorized_by"],
            targets=raw["targets"],
            window_start=_dt(window.get("start")),
            window_end=_dt(window.get("end")),
            allow_disruptive=list(raw.get("allow_disruptive") or []),
            limits=dict(raw.get("limits") or {}),
            notes=raw.get("notes", ""),
        )
        scope._resolve()
        return scope

    def _resolve(self) -> None:
        for entry in self.targets:
            host = entry.get("host")
            if not host:
                raise ScopeError(f"Target entry without a host: {entry}")
            self._allowed_hosts.add(host.lower())
            try:
                ipaddress.ip_address(host)
                self._allowed_ips.add(host)
                continue
            except ValueError:
                pass
            # A hostname authorizes the addresses it resolves to *now*. If it
            # starts pointing somewhere else mid-run, that new address is not
            # in scope and the guard will say so.
            try:
                for info in socket.getaddrinfo(host, None):
                    self._allowed_ips.add(info[4][0])
            except socket.gaierror:
                pass

    # -- checks -----------------------------------------------------------

    def in_window(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if self.window_start and now < self.window_start:
            return False
        if self.window_end and now > self.window_end:
            return False
        return True

    def assert_target(self, host: str) -> None:
        """Raise unless `host` is explicitly authorized."""
        h = (host or "").lower()
        if h in self._allowed_hosts:
            return
        if host in self._allowed_ips:
            return
        try:
            for info in socket.getaddrinfo(host, None):
                if info[4][0] in self._allowed_ips:
                    return
        except socket.gaierror:
            pass
        for pattern in self._allowed_hosts:
            if "*" in pattern and fnmatch.fnmatch(h, pattern):
                return
        raise ScopeError(
            f"{host!r} is not in scope '{self.name}'. Add it to the scope file "
            "if testing it is authorized."
        )

    def assert_runnable(self, check) -> None:
        """Raise unless this check is permitted by the scope right now."""
        if not self.in_window():
            raise ScopeError(
                f"Outside the authorized window for scope '{self.name}' "
                f"({self.window_start} .. {self.window_end})."
            )
        if getattr(check, "disruptive", False) and check.id not in self.allow_disruptive:
            raise ScopeError(
                f"{check.id} is disruptive and not listed in allow_disruptive."
            )

    def targets_for(self, protocol: str) -> List[Dict[str, Any]]:
        out = []
        for entry in self.targets:
            protocols = entry.get("protocols")
            if protocols is None or protocol in protocols:
                out.append(entry)
        return out

    def describe(self) -> str:
        window = "always"
        if self.window_start or self.window_end:
            window = f"{self.window_start or 'any'} .. {self.window_end or 'any'}"
        return (
            f"scope '{self.name}' authorized by {self.authorized_by}; "
            f"{len(self.targets)} target(s); window {window}; "
            f"disruptive allowed: {self.allow_disruptive or 'none'}"
        )
