"""LOG-01 and LOG-02 — what the VPN keeps about its own users.

Almost no VPN audit checks this, and the industry convention is an
unverifiable "no logs" claim. Two things can actually be observed: how much
the daemon writes, and how long it is kept. Both are tested against a policy
the operator declares in scope, so the result is a narrow claim a reader can
check rather than a broad one nobody can.

A deliberate asymmetry runs through both checks: a missing declaration is
`n/a`, never a pass. "We found no logs" is only meaningful if you know where
you were supposed to look, and a tool that reports a clean bill of health
because the scope forgot to tell it anything is worse than no tool.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Dict, List, Tuple

from ...model import Check, Context, Finding, Severity, Target

# Where connection records land if nobody has moved them. These are the
# general-purpose logs — anything per-connection reaching them is the finding.
SYSTEM_LOGS = ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
               "/var/log/secure")

# Daemons whose output identifies a connecting user.
VPN_DAEMONS = ("charon", "pluto", "openvpn", "strongswan", "wg-quick",
               "ocserv", "accel-ppp")

# strongSwan debug levels: -1 silent, 0 audit, 1 control (default), 2+ verbose.
# Anything above 0 writes per-connection detail.
QUIET_LEVELS = ("-1", "0")


def _ssh(target: Target, command: str, timeout: int = 25) -> Tuple[int, str, str]:
    user = target.meta.get("ssh_user")
    key = os.path.expanduser(target.meta.get("ssh_key", ""))
    argv = ["ssh", "-i", key, "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={min(timeout, 15)}",
            f"{user}@{target.host}", command]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, "", str(exc)


def _has_ssh(target: Target) -> bool:
    return bool(target.meta.get("ssh_user") and target.meta.get("ssh_key"))


def _tag_pattern(daemons: Tuple[str, ...]) -> str:
    """A grep pattern matching a syslog *tag*, not the word anywhere.

    This matters more than it looks. Counting any line containing "charon"
    also counts sudo's audit record of a command that mentioned charon — so an
    operator running the very command that inspects the logs inflates the
    count, and a check written that way fails against itself.
    """
    alts = "|".join(re.escape(d) for d in daemons)
    return f" ({alts})(\\[[0-9]+\\])?: "


class ConnectionLoggingMinimised(Check):
    """LOG-01 — per-connection detail must not reach a general system log."""

    id = "LOG-01"
    protocol = "logging"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        daemons = tuple(target.meta.get("vpn_log_daemons") or VPN_DAEMONS)
        pattern = _tag_pattern(daemons)
        detail: Dict[str, Any] = {"daemons": list(daemons), "system_logs": {}}
        problems: List[str] = []

        for path in SYSTEM_LOGS:
            rc, out, _ = _ssh(
                target,
                f"sudo sh -c 'test -f {path} && grep -cE \"{pattern}\" {path} "
                f"2>/dev/null || echo absent'")
            value = (out or "").strip().splitlines()[-1] if out.strip() else "absent"
            detail["system_logs"][path] = value
            if value.isdigit() and int(value) > 0:
                problems.append(f"{path} holds {value} connection record(s)")

        # Verbosity, where the daemon exposes it.
        rc, out, _ = _ssh(
            target,
            "sudo grep -hE '^[[:space:]]*charondebug' /etc/ipsec.conf 2>/dev/null || true")
        level_line = (out or "").strip()
        detail["charondebug"] = level_line or None
        if level_line:
            levels = re.findall(r"\b\w+\s+(-?\d+)", level_line)
            noisy = [lv for lv in levels if lv not in QUIET_LEVELS]
            detail["debug_levels"] = levels
            if noisy:
                problems.append(
                    f"charondebug is above audit level ({level_line.split('=', 1)[-1].strip()})")

        # Any log the scope names as required to be address-free.
        #
        # Without this the control passes trivially on a host that runs no VPN
        # daemon — a control plane can be writing a full client address on
        # every request and still look clean, because nothing named charon
        # appeared in auth.log. A web access log is connection metadata by
        # another name.
        ip_free = target.meta.get("logs_without_client_ips") or []
        detail["logs_required_address_free"] = list(ip_free)
        for path in ip_free:
            # A full dotted quad or a global IPv6. An anonymised address ends
            # in .0 or :: and is deliberately not matched.
            rc, out, _ = _ssh(
                target,
                "sudo sh -c 'test -f %s && grep -cE "
                "\"^([0-9]{1,3}\\.){3}(?!0 )[0-9]{1,3} |^[0-9a-f]{1,4}:[0-9a-f:]*[1-9a-f][0-9a-f]* \" "
                "%s 2>/dev/null || echo absent'" % (path, path))
            raw = (out or "").strip().splitlines()[-1] if out.strip() else "absent"
            # grep -E lacks lookahead; fall back to a simpler count and
            # subtract anonymised forms, which always end the address in .0
            if not raw.isdigit():
                rc, out, _ = _ssh(
                    target,
                    "sudo sh -c 'test -f {p} && echo $(( $(grep -cE \"^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}} \" {p} 2>/dev/null) - "
                    "$(grep -cE \"^([0-9]{{1,3}}\\.){{3}}0 \" {p} 2>/dev/null) )) || echo absent'".format(p=path))
                raw = (out or "").strip().splitlines()[-1] if out.strip() else "absent"
            detail.setdefault("address_free_logs", {})[path] = raw
            if raw.lstrip("-").isdigit() and int(raw) > 0:
                problems.append(
                    f"{path} records {raw} full client address(es)")

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "where connection records are written")

        if not detail["system_logs"] and not level_line and not ip_free:
            return [self.na(
                target,
                "No VPN daemon logging configuration or system log was readable "
                "on this host, so minimisation could not be assessed",
                evidence=[ev], detail=detail)]

        if problems:
            return [self.fail(
                target,
                "; ".join(problems)
                + ". Connection records in a general-purpose log inherit that "
                  "log's retention, which is usually weeks.",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]

        return [self.ok(
            target,
            "No per-connection records in any general-purpose system log"
            + (f"; debug level is {level_line.split('=', 1)[-1].strip()}"
               if level_line else ""),
            evidence=[ev], detail=detail)]


class LogRetentionPolicy(Check):
    """LOG-02 — nothing is kept longer than the declared window."""

    id = "LOG-02"
    protocol = "logging"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        days = target.meta.get("log_retention_days")
        log_path = target.meta.get("connection_log") or "/var/log/charon.log"

        if days is None:
            # No policy, no verdict. A retention check with nothing to compare
            # against can only ever rubber-stamp whatever it finds.
            return [self.na(
                target,
                "No log_retention_days declared in scope, so there is no policy "
                "to measure retention against. Declare the window the service "
                "commits to and this becomes testable.")]
        days = int(days)

        detail: Dict[str, Any] = {"declared_retention_days": days,
                                  "connection_log": log_path}

        # Rotation configured?
        #
        # Searched by the log's own path, not by guessing the config file's
        # name. Looking for files called charon/openvpn/connection missed
        # nginx's rule — which is named "nginx" and rotates the very path in
        # question — and reported retention as unenforced on a host where it
        # was enforced correctly.
        # Matched against the exact path first, then the containing directory,
        # because a rule routinely covers a glob rather than one file —
        # nginx's reads `/var/log/nginx/*.log`, so searching for the literal
        # path finds nothing and the control reports an unrotated log on a host
        # that rotates it daily.
        log_dir = log_path.rsplit("/", 1)[0] + "/"
        rc, rot, _ = _ssh(
            target,
            f"sudo sh -c 'grep -rlE \"{re.escape(log_path)}|{re.escape(log_dir)}\" "
            "/etc/logrotate.d/ /etc/logrotate.conf 2>/dev/null | head -5' || true")
        detail["logrotate_files"] = [f for f in (rot or "").split() if f]
        detail["logrotate_searched_for"] = [log_path, log_dir]

        # The real question: how old is the oldest retained record?
        rc, out, _ = _ssh(
            target,
            f"sudo sh -c 'ls -1 {log_path}* 2>/dev/null | while read f; do "
            f"printf \"%s %s\\n\" \"$(stat -c %Y \"$f\")\" \"$f\"; done' || true")
        oldest_age_days = None
        files: List[Dict[str, Any]] = []
        rc_now, now_s, _ = _ssh(target, "date +%s")
        try:
            now = int((now_s or "0").strip())
        except ValueError:
            now = 0

        for line in (out or "").splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            mtime, path = int(parts[0]), parts[1]
            age = (now - mtime) / 86400.0 if now else None
            files.append({"path": path, "age_days": round(age, 2) if age else None})
            if age is not None:
                oldest_age_days = age if oldest_age_days is None else max(oldest_age_days, age)

        detail["files"] = files
        detail["oldest_age_days"] = round(oldest_age_days, 2) if oldest_age_days else None

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "retained connection log archives")

        if not files:
            return [self.ok(
                target,
                f"No connection log retained at {log_path}; nothing is being "
                f"kept, which is within the {days}-day policy",
                evidence=[ev], detail=detail)]

        if not detail["logrotate_files"]:
            return [self.warn(
                target,
                f"{len(files)} connection log file(s) present but no logrotate "
                "rule was found for them, so retention is not enforced by "
                "anything — today's compliance is incidental",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]

        # One day of slack: rotation is a cron job, so a file can briefly
        # outlive the window before the job runs. Flagging that would make the
        # check fail daily for a few minutes and train people to ignore it.
        if oldest_age_days is not None and oldest_age_days > days + 1:
            return [self.fail(
                target,
                f"Oldest retained connection record is "
                f"{oldest_age_days:.1f} days old, beyond the declared "
                f"{days}-day retention policy",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]

        return [self.ok(
            target,
            f"Oldest retained connection record is "
            f"{(oldest_age_days or 0):.1f} days old, within the declared "
            f"{days}-day policy, with rotation configured",
            evidence=[ev], detail=detail)]
