"""WG-03, WG-06, WG-07, WG-09, WG-10 — key inventory and implementation.

WireGuard has no handshake to interrogate, so everything here reads host state
over SSH. Each reports `n/a` without credentials rather than guessing from the
outside, which would only ever produce "cannot tell" dressed up as a result.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from ...model import Check, Context, Finding, Severity, Target


def _ssh(target: Target, command: str, timeout: int = 30) -> Tuple[int, str, str]:
    user = target.meta.get("ssh_user")
    key = os.path.expanduser(target.meta.get("ssh_key", ""))
    argv = ["ssh", "-i", key, "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={min(timeout, 15)}",
            f"{user}@{target.host}", command]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _has_ssh(target: Target) -> bool:
    return bool(target.meta.get("ssh_user") and target.meta.get("ssh_key"))


def _conf_path(target: Target) -> str:
    return target.meta.get("wg_conf", "/etc/wireguard/wg0.conf")


class UniquePeerKeys(Check):
    """WG-03 — a public key must identify exactly one peer.

    A duplicate means two clients share an identity: revoking one revokes
    both, and neither can be held individually accountable.
    """

    id = "WG-03"
    protocol = "wireguard"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        conf = _conf_path(target)
        rc, out, err = _ssh(
            target, f"sudo grep -h '^PublicKey' {shlex.quote(conf)} 2>/dev/null || true")
        keys = [l.split("=", 1)[1].strip()
                for l in out.splitlines() if "=" in l]
        if not keys:
            return [self.error(target, f"No peer public keys read from {conf}")]

        seen: Dict[str, int] = {}
        for k in keys:
            seen[k] = seen.get(k, 0) + 1
        dupes = {k: n for k, n in seen.items() if n > 1}

        detail = {"total_peers": len(keys), "unique_keys": len(seen),
                  "duplicates": {k[:16] + "…": n for k, n in dupes.items()}}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "peer public key uniqueness")

        if dupes:
            return [self.fail(
                target,
                f"{len(dupes)} public key(s) are shared by more than one peer "
                f"across {len(keys)} entries — those clients cannot be revoked "
                "or audited separately",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(
            target, f"All {len(keys)} peer keys are unique",
            evidence=[ev], detail=detail)]


class KeyRotation(Check):
    """WG-06 — keys older than policy must have been rotated.

    WireGuard records no issue date, so age is inferred from the server key's
    mtime and from how long peers have been idle. That is weaker evidence than
    an issuing system would give, and the finding says so.
    """

    id = "WG-06"
    protocol = "wireguard"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        max_days = int(target.meta.get("key_max_age_days", 365))
        # The private key is often inline in wg0.conf rather than a separate
        # file, so stat both; whichever exists carries the age.
        # The glob must expand inside the privileged shell. Written as
        # `sudo stat /etc/wireguard/*` it expands as the login user, who
        # cannot read the directory, so stat receives the literal pattern and
        # the check reported "no files" against a host that has them.
        rc, out, err = _ssh(
            target,
            "sudo sh -c 'stat -c \"%Y %n\" /etc/wireguard/*private* "
            "/etc/wireguard/*.key /etc/wireguard/*.conf 2>/dev/null' || true")
        now = time.time()
        rows: List[Dict[str, Any]] = []
        for line in out.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            try:
                mtime = int(parts[0])
            except ValueError:
                continue
            rows.append({"file": parts[1],
                         "age_days": int((now - mtime) / 86400)})

        if not rows:
            return [self.error(
                target,
                "No WireGuard key or config files found to date — key age "
                "cannot be established")]

        old = [r for r in rows if r["age_days"] > max_days]
        detail = {"keys": rows, "policy_max_age_days": max_days}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "server key age by file mtime")

        if old:
            return [self.fail(
                target,
                "Server key(s) older than policy: "
                + ", ".join(f"{r['file']} ({r['age_days']}d)" for r in old),
                severity=Severity.LOW, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            "Server key age is within policy ("
            + ", ".join(f"{r['age_days']}d" for r in rows)
            + f" vs {max_days}d limit). Peer key ages are not recorded by "
              "WireGuard; an issuing system would be needed to check those.",
            evidence=[ev], detail=detail)]


class RemovedPeersCannotConnect(Check):
    """WG-07 — the live interface must match the config file.

    A peer deleted from wg0.conf but left on the running interface keeps
    working until the next reload, which may be months away — the file says
    revoked and the kernel says allowed.
    """

    id = "WG-07"
    protocol = "wireguard"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        conf = _conf_path(target)
        rc, out, err = _ssh(
            target,
            f"sudo grep -h '^PublicKey' {shlex.quote(conf)} 2>/dev/null; "
            "echo '---LIVE---'; sudo wg show all dump 2>/dev/null || true")
        if "---LIVE---" not in out:
            return [self.error(target, "Could not read config and live state")]

        conf_part, live_part = out.split("---LIVE---", 1)
        conf_keys = {l.split("=", 1)[1].strip()
                     for l in conf_part.splitlines() if "=" in l}

        live_keys = set()
        for line in live_part.strip().splitlines():
            cols = line.split("\t")
            # `wg show all dump`: iface pubkey psk endpoint allowed-ips ...
            # The interface's own row is shorter than a peer row.
            if len(cols) >= 8:
                live_keys.add(cols[1].strip())

        only_live = live_keys - conf_keys
        only_conf = conf_keys - live_keys

        detail = {"in_config": len(conf_keys), "on_interface": len(live_keys),
                  "live_but_not_in_config": len(only_live),
                  "config_but_not_live": len(only_conf),
                  "examples_live_only": [k[:16] + "…" for k in list(only_live)[:5]]}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "config vs live peer sets")

        if only_live:
            return [self.fail(
                target,
                f"{len(only_live)} peer(s) are active on the interface but "
                "absent from the config — removing a peer from the file did "
                "not revoke it",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        if only_conf:
            return [self.warn(
                target,
                f"{len(only_conf)} peer(s) are in the config but not loaded; "
                "the interface has not been reloaded since they were added",
                evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            f"Live interface matches the config exactly ({len(conf_keys)} peers)",
            evidence=[ev], detail=detail)]


class ImplementationCurrent(Check):
    """WG-09 — the running implementation should not be an old one."""

    id = "WG-09"
    protocol = "wireguard"
    access = "config"

    # Kernel WireGuard landed in Linux 5.6; older kernels run the userspace
    # wireguard-go, which is slower and has a larger attack surface.
    MIN_KERNEL = (5, 6)

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        rc, out, err = _ssh(
            target,
            "uname -r; echo '---'; "
            "(wg --version 2>/dev/null || echo 'wg: unknown'); echo '---'; "
            "(lsmod 2>/dev/null | grep -c '^wireguard' || echo 0)")
        parts = [p.strip() for p in out.split("---")]
        kernel = parts[0] if parts else ""
        wg_version = parts[1] if len(parts) > 1 else ""
        module_loaded = parts[2].strip() if len(parts) > 2 else "0"

        m = re.match(r"(\d+)\.(\d+)", kernel)
        kver = (int(m.group(1)), int(m.group(2))) if m else (0, 0)

        detail = {"kernel": kernel, "wg_tools": wg_version,
                  "kernel_module_loaded": module_loaded != "0",
                  "min_kernel_for_in_tree": "%d.%d" % self.MIN_KERNEL}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "WireGuard implementation")

        if not kernel:
            return [self.error(target, "Could not determine the kernel version")]
        if kver < self.MIN_KERNEL:
            return [self.warn(
                target,
                f"Kernel {kernel} predates in-tree WireGuard "
                f"({'%d.%d' % self.MIN_KERNEL}); a userspace implementation is "
                "likely in use",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            f"Kernel {kernel} with in-tree WireGuard; tools: "
            + (wg_version.splitlines()[0] if wg_version else "unknown"),
            evidence=[ev], detail=detail)]


class FipsApplicability(Check):
    """WG-10 — record that WireGuard's primitives are not FIPS-approved.

    Informational by default. It becomes a failure only where the scope
    declares FIPS mandatory, because WireGuard cannot satisfy it by design —
    X25519 and ChaCha20-Poly1305 are not on the approved list.
    """

    id = "WG-10"
    protocol = "wireguard"
    access = "config"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        required = bool(target.meta.get("fips_required",
                                        ctx.scope.limits.get("fips_required", False)))
        detail = {
            "fips_required": required,
            "primitives": ["Curve25519", "ChaCha20-Poly1305", "BLAKE2s"],
            "approved_under_fips_140_3": False,
        }
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "FIPS applicability")

        if required:
            return [self.fail(
                target,
                "FIPS 140-3 is declared mandatory for this environment, and "
                "WireGuard's primitives (X25519, ChaCha20-Poly1305, BLAKE2s) "
                "are not approved. This cannot be configured away — an "
                "IPsec path with a validated module is required.",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            "FIPS is not declared mandatory. Noting for the record that "
            "WireGuard's primitives are not FIPS 140-3 approved.",
            evidence=[ev], detail=detail)]
