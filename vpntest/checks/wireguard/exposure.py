"""WireGuard network-facing behaviour, plus config review over SSH.

WireGuard negotiates nothing, so there is no cipher policy to audit. The risk
lives in key handling, peer policy and what else the host exposes — most of
which can only be seen from the host, so the config checks read it over SSH
when the scope provides credentials and report NA when it does not.
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import subprocess
import time
from typing import List, Optional, Tuple

from ...model import Check, Context, Finding, Severity, Target

DEFAULT_WG_PORT = 51820


def _ssh(target: Target, command: str, timeout: int = 25) -> Tuple[int, str, str]:
    """Run a read-only command on the node. Requires ssh config in scope meta."""
    user = target.meta.get("ssh_user")
    key = target.meta.get("ssh_key")
    if not user or not key:
        raise RuntimeError("no ssh_user/ssh_key in target meta")
    key = os.path.expanduser(key)
    argv = [
        "ssh", "-i", key,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={min(timeout, 15)}",
        f"{user}@{target.host}", command,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def _has_ssh(target: Target) -> bool:
    return bool(target.meta.get("ssh_user") and target.meta.get("ssh_key"))


class WireGuardSilence(Check):
    """WG-01 — the port must not answer unauthenticated traffic."""

    id = "WG-01"
    protocol = "wireguard"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        port = int(target.meta.get("wg_port") or DEFAULT_WG_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        replied, data = False, b""
        try:
            sock.sendto(os.urandom(48), (target.host, port))
            data, _ = sock.recvfrom(2048)
            replied = True
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

        detail = {"port": port, "replied": replied,
                  "reply_hex": data[:64].hex() if data else None}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "random UDP to the WireGuard port")

        if replied:
            return [self.fail(
                target,
                f"Something replied to random UDP on {port}. WireGuard is "
                "silent by design, so a responder here is not WireGuard.",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(
            target, f"Silent to unauthenticated UDP on {port}",
            evidence=[ev], detail=detail)]


class WireGuardKeyPermissions(Check):
    """WG-02 — private key and config readable only by the service."""

    id = "WG-02"
    protocol = "wireguard"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        # Glob inside the root shell: expanded by the login user it matches
        # nothing, and this check then reported "0 files, all owner-only" —
        # a clean pass on a critical control it had not actually examined.
        cmd = ("sudo sh -c 'stat -c \"%n %a %U\" /etc/wireguard/*.conf "
               "/etc/wireguard/*private* 2>/dev/null' || true")
        rc, out, err = _ssh(target, cmd)
        if rc != 0 and not out:
            return [self.error(target, f"Could not read key permissions: {err.strip()[:200]}")]

        bad, rows = [], []

        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            name, mode, owner = parts
            rows.append({"file": name, "mode": mode, "owner": owner})
            # Group or other readable on a private key or config.
            if len(mode) == 3 and (mode[1] != "0" or mode[2] != "0"):
                if "public" not in name:
                    bad.append(f"{name} ({mode})")

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"),
                               {"files": rows}, "wireguard file permissions")
        if bad:
            return [self.fail(
                target, "Readable beyond the owner: " + ", ".join(bad),
                severity=Severity.CRITICAL, evidence=[ev], detail={"files": rows})]
        if not rows:
            return [self.error(
                target,
                "No WireGuard key or config files could be examined, so "
                "permissions were not verified")]
        return [self.ok(
            target, f"All {len(rows)} key/config files are owner-only",
            evidence=[ev], detail={"files": rows})]


class WireGuardPeerPolicy(Check):
    """WG-03/04/05/11 — peer inventory hygiene, read from the live config."""

    id = "WG-05"
    protocol = "wireguard"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        conf_path = target.meta.get("wg_conf", "/etc/wireguard/wg0.conf")
        rc, out, err = _ssh(target, f"sudo cat {shlex.quote(conf_path)} 2>/dev/null || true")
        if not out.strip():
            return [self.error(target, f"Could not read {conf_path}: {err.strip()[:200]}")]

        peers = re.split(r"^\[Peer\]\s*$", out, flags=re.M)[1:]
        pubkeys = re.findall(r"^\s*PublicKey\s*=\s*(\S+)", out, flags=re.M)
        allowed = re.findall(r"^\s*AllowedIPs\s*=\s*(.+)$", out, flags=re.M)
        psks = re.findall(r"^\s*PresharedKey\s*=", out, flags=re.M)

        broad = [a.strip() for a in allowed
                 if "0.0.0.0/0" in a or "::/0" in a]
        dupes = len(pubkeys) - len(set(pubkeys))

        detail = {
            "peers": len(peers),
            "unique_pubkeys": len(set(pubkeys)),
            "duplicate_pubkeys": dupes,
            "preshared_keys": len(psks),
            "broad_allowedips": broad[:10],
        }
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "wireguard peer inventory summary")

        findings: List[Finding] = []
        if broad:
            findings.append(self.fail(
                target,
                f"{len(broad)} server-side peer(s) have a catch-all AllowedIPs "
                "— any of them can impersonate any address",
                severity=Severity.CRITICAL, evidence=[ev], detail=detail))
        else:
            findings.append(self.ok(
                target,
                f"All {len(peers)} peers are scoped to their own addresses",
                evidence=[ev], detail=detail))
        return findings


class WireGuardPresharedKeys(Check):
    """WG-04 — a PSK on every peer, for post-quantum resistance."""

    id = "WG-04"
    protocol = "wireguard"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        conf_path = target.meta.get("wg_conf", "/etc/wireguard/wg0.conf")
        rc, out, err = _ssh(
            target,
            f"sudo sh -c 'grep -c \"^\\[Peer\\]\" {shlex.quote(conf_path)}; "
            f"grep -c PresharedKey {shlex.quote(conf_path)}' 2>/dev/null || true")
        nums = [int(n) for n in re.findall(r"^\d+$", out.strip(), flags=re.M)]
        if len(nums) < 2:
            return [self.error(target, f"Could not count peers/PSKs: {err.strip()[:200]}")]
        peers, psks = nums[0], nums[1]

        detail = {"peers": peers, "with_psk": psks}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "PresharedKey coverage")

        # A PSK must match on both ends, so a fleet mid-migration legitimately
        # has a mix: clients that have not yet updated cannot use one, and
        # forcing it on them would break every handshake. Report the split
        # rather than treating partial coverage as a flat failure.
        if peers and psks == 0:
            return [self.fail(
                target,
                f"No PresharedKey on any of {peers} peers. WireGuard's X25519 "
                "handshake alone is not resistant to a future quantum "
                "adversary recording traffic now.",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        if psks < peers:
            pct = 100 * psks // peers
            return [self.warn(
                target,
                f"{psks} of {peers} peers carry a PresharedKey ({pct}%). "
                "Remaining peers are clients that have not yet updated; they "
                "acquire one on their next connect.",
                severity=Severity.LOW, evidence=[ev], detail=detail)]
        return [self.ok(target, f"All {peers} peers carry a PresharedKey",
                        evidence=[ev], detail=detail)]


class WireGuardStalePeers(Check):
    """WG-11 — peers should track live users, not everyone who ever connected."""

    id = "WG-11"
    protocol = "wireguard"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        rc, out, err = _ssh(target, "sudo wg show all dump 2>/dev/null || true")
        if not out.strip():
            return [self.error(target, "Could not read live peer state (wg show)")]

        # `wg show all dump` prefixes every row with the interface name, so the
        # peer columns are shifted one right relative to `wg show <if> dump`:
        #   iface  pubkey  psk  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
        # The interface's own row is shorter (no endpoint/handshake), which is
        # how it is told apart from a peer.
        now = int(time.time())
        total, never, stale = 0, 0, 0
        idle_days = int(target.meta.get("stale_peer_idle_days", 30))
        for line in out.strip().splitlines():
            cols = line.split("\t")
            if len(cols) < 8:
                continue  # interface row, not a peer
            total += 1
            try:
                last = int(cols[5])
            except (IndexError, ValueError):
                continue
            if last == 0:
                never += 1
            elif now - last > idle_days * 86400:
                stale += 1

        threshold = int(target.meta.get("stale_peer_threshold", 500))
        detail = {"total_peers": total, "never_handshaked": never,
                  f"idle_over_{idle_days}d": stale, "threshold": threshold}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "live peer state")

        dead = never + stale
        if total > threshold or (total and dead > total * 0.5):
            return [self.fail(
                target,
                f"{total} peers configured; {never} never handshaked and "
                f"{stale} idle over {idle_days}d. Keys are issued and never "
                "reaped, so every key ever handed out still works.",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            f"{total} peers, {never} never used, {stale} idle over {idle_days}d",
            evidence=[ev], detail=detail)]
