"""IPS-06 to IPS-12 — controls that are only visible from the gateway.

ESP transforms, PFS, authentication method, lifetimes and DPD all live below
IKE_AUTH, so probing them from outside needs a working identity. Reading the
configuration instead is both more reliable and far less intrusive: the
evidence is the gateway's own policy rather than an inference from its
refusals. These therefore declare `access: config` and report n/a when the
scope supplies no credentials, which the report states plainly.

Supports both strongSwan layouts: the legacy ipsec.conf and swanctl.conf.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ...model import Check, Context, Finding, Severity, Target

WEAK_TOKENS = ("des", "3des", "md5", "sha1", "null", "modp768",
               "modp1024", "modp1536", "export")
# "sha1" must not match "sha128" etc., so match on transform boundaries.
WEAK_RE = re.compile(
    r"(?<![a-z0-9])(3?des|md5|sha1|null|modp768|modp1024|modp1536)(?![a-z0-9])",
    re.I)


def _ssh(target: Target, command: str, timeout: int = 25) -> Tuple[int, str, str]:
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


def _read_config(target: Target) -> Dict[str, str]:
    """Fetch whichever strongSwan configuration files exist."""
    cmd = (
        "for f in /etc/ipsec.conf /etc/swanctl/swanctl.conf "
        "/etc/strongswan.conf; do "
        "if sudo test -f $f; then echo \"===FILE:$f\"; sudo cat $f; fi; done")
    rc, out, err = _ssh(target, cmd)
    files: Dict[str, str] = {}
    current = None
    for line in out.splitlines():
        if line.startswith("===FILE:"):
            current = line.split(":", 1)[1].strip()
            files[current] = ""
        elif current:
            files[current] += line + "\n"
    return files


def _conf_text(files: Dict[str, str]) -> str:
    return "\n".join(files.values())


def _strip_comments(text: str) -> str:
    return "\n".join(l for l in text.splitlines()
                     if not l.strip().startswith("#"))


class EspTransforms(Check):
    """IPS-06 — ESP must be AEAD, or AES with SHA-2. No NULL, no SHA-1."""

    id = "IPS-06"
    protocol = "ipsec"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        files = _read_config(target)
        if not files:
            return [self.error(target, "No strongSwan configuration found")]
        text = _strip_comments(_conf_text(files))

        proposals = re.findall(r"^\s*(?:esp|esp_proposals)\s*=\s*(.+)$",
                               text, re.M | re.I)
        if not proposals:
            return [self.na(target, "No explicit ESP proposal configured "
                                    "(the daemon default applies)")]

        weak: List[str] = []
        for line in proposals:
            for transform in re.split(r"[,\s]+", line.strip().rstrip("!")):
                if transform and WEAK_RE.search(transform):
                    weak.append(transform)

        detail = {"esp_proposals": proposals, "weak_transforms": sorted(set(weak))}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "configured ESP proposals")

        if weak:
            return [self.fail(
                target,
                "ESP accepts weak transform(s): " + ", ".join(sorted(set(weak))),
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(
            target, f"All {len(proposals)} ESP proposal line(s) use approved transforms",
            evidence=[ev], detail=detail)]


class PerfectForwardSecrecy(Check):
    """IPS-07 — a DH group on the CHILD_SA, so rekey is forward-secret."""

    id = "IPS-07"
    protocol = "ipsec"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        files = _read_config(target)
        if not files:
            return [self.error(target, "No strongSwan configuration found")]
        text = _strip_comments(_conf_text(files))

        esp = re.findall(r"^\s*(?:esp|esp_proposals)\s*=\s*(.+)$", text, re.M | re.I)
        pfs_group = re.compile(r"(modp\d+|ecp\d+|curve25519|x25519)", re.I)
        with_pfs = [line for line in esp if pfs_group.search(line)]

        detail = {"esp_proposals": esp, "lines_with_dh_group": with_pfs}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "PFS configuration")

        if not esp:
            return [self.na(target, "No explicit ESP proposal to inspect",
                            evidence=[ev])]
        if not with_pfs:
            return [self.fail(
                target,
                "No DH group in the ESP proposal — CHILD_SA rekey carries no "
                "forward secrecy, so one compromised IKE SA exposes every "
                "rekeyed child",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(target, "ESP proposals include a DH group (PFS on rekey)",
                        evidence=[ev], detail=detail)]


class AuthenticationMethod(Check):
    """IPS-08 — certificate or EAP; a shared PSK is flagged."""

    id = "IPS-08"
    protocol = "ipsec"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        files = _read_config(target)
        if not files:
            return [self.error(target, "No strongSwan configuration found")]
        text = _strip_comments(_conf_text(files))

        left = re.findall(r"^\s*leftauth\s*=\s*(\S+)", text, re.M | re.I)
        right = re.findall(r"^\s*rightauth\s*=\s*(\S+)", text, re.M | re.I)
        auth = re.findall(r"^\s*auth\s*=\s*(\S+)", text, re.M | re.I)
        all_auth = [a.lower() for a in left + right + auth]

        rc, secrets, _ = _ssh(
            target,
            "sudo grep -cE ':\\s*PSK' /etc/ipsec.secrets 2>/dev/null || echo 0")
        psk_count = 0
        try:
            psk_count = int(secrets.strip().splitlines()[-1])
        except (ValueError, IndexError):
            pass

        detail = {"leftauth": left, "rightauth": right, "auth": auth,
                  "psk_entries_in_secrets": psk_count}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "configured authentication methods")

        uses_psk = any("psk" in a for a in all_auth) or psk_count > 0
        uses_cert = any("pubkey" in a or "rsa" in a or "ecdsa" in a
                        for a in all_auth)
        uses_eap = any("eap" in a for a in all_auth)

        if uses_psk:
            return [self.fail(
                target,
                "Pre-shared key authentication is configured. A PSK is shared "
                "by every peer that uses it and cannot be revoked individually.",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        if uses_cert or uses_eap:
            kinds = []
            if uses_cert:
                kinds.append("certificate")
            if uses_eap:
                kinds.append("EAP")
            return [self.ok(
                target, "Authentication uses " + " and ".join(kinds),
                evidence=[ev], detail=detail)]
        return [self.na(target, "No explicit authentication method configured",
                        evidence=[ev], detail=detail)]


class CertificateValidation(Check):
    """IPS-09 — revocation checking must actually be on."""

    id = "IPS-09"
    protocol = "ipsec"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        files = _read_config(target)
        if not files:
            return [self.error(target, "No strongSwan configuration found")]
        text = _strip_comments(_conf_text(files))

        strictcrl = re.search(r"^\s*strictcrlpolicy\s*=\s*(\S+)", text, re.M | re.I)
        revocation = re.search(r"revocation\s*{", text, re.I)
        rc, cacerts, _ = _ssh(
            target, "sudo ls /etc/ipsec.d/cacerts/ 2>/dev/null | wc -l")
        ca_count = 0
        try:
            ca_count = int(cacerts.strip().splitlines()[-1])
        except (ValueError, IndexError):
            pass

        detail = {
            "strictcrlpolicy": strictcrl.group(1) if strictcrl else None,
            "revocation_plugin_configured": bool(revocation),
            "ca_certificates": ca_count,
        }
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "certificate validation settings")

        strict = (strictcrl.group(1).lower() in ("yes", "ifuri")
                  if strictcrl else False)
        if ca_count == 0:
            return [self.warn(
                target,
                "No CA certificates installed, so peer certificates cannot be "
                "validated against a known issuer",
                evidence=[ev], detail=detail)]
        if not strict:
            return [self.warn(
                target,
                "strictcrlpolicy is not enabled — a revoked peer certificate "
                "may still be accepted when the CRL cannot be fetched",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(
            target, f"Revocation checking enabled with {ca_count} CA certificate(s)",
            evidence=[ev], detail=detail)]


class SaLifetimes(Check):
    """IPS-10 — lifetimes within policy."""

    id = "IPS-10"
    protocol = "ipsec"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def _seconds(self, value: str) -> Optional[int]:
        m = re.match(r"^(\d+)\s*([smhd]?)$", value.strip(), re.I)
        if not m:
            return None
        n, unit = int(m.group(1)), (m.group(2) or "s").lower()
        return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        files = _read_config(target)
        if not files:
            return [self.error(target, "No strongSwan configuration found")]
        text = _strip_comments(_conf_text(files))

        ike_life = re.search(r"^\s*(?:ikelifetime|rekey_time)\s*=\s*(\S+)",
                             text, re.M | re.I)
        child_life = re.search(r"^\s*(?:lifetime|life_time)\s*=\s*(\S+)",
                               text, re.M | re.I)
        max_ike = int(target.meta.get("max_ike_lifetime_s", 24 * 3600))
        max_child = int(target.meta.get("max_child_lifetime_s", 8 * 3600))

        ike_s = self._seconds(ike_life.group(1)) if ike_life else None
        child_s = self._seconds(child_life.group(1)) if child_life else None
        detail = {"ikelifetime": ike_life.group(1) if ike_life else None,
                  "child_lifetime": child_life.group(1) if child_life else None,
                  "ike_seconds": ike_s, "child_seconds": child_s,
                  "policy_max_ike_s": max_ike, "policy_max_child_s": max_child}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "SA lifetimes")

        problems = []
        if ike_s and ike_s > max_ike:
            problems.append(f"IKE SA {ike_s}s exceeds {max_ike}s")
        if child_s and child_s > max_child:
            problems.append(f"CHILD SA {child_s}s exceeds {max_child}s")

        if problems:
            return [self.fail(target, "; ".join(problems),
                              severity=Severity.LOW, evidence=[ev], detail=detail)]
        if ike_s is None and child_s is None:
            return [self.na(target, "No explicit lifetimes (daemon defaults apply)",
                            evidence=[ev], detail=detail)]
        return [self.ok(target, "SA lifetimes are within policy",
                        evidence=[ev], detail=detail)]


class DeadPeerDetection(Check):
    """IPS-11 — DPD must be on, so dead SAs are torn down."""

    id = "IPS-11"
    protocol = "ipsec"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        files = _read_config(target)
        if not files:
            return [self.error(target, "No strongSwan configuration found")]
        text = _strip_comments(_conf_text(files))

        action = re.search(r"^\s*dpdaction\s*=\s*(\S+)", text, re.M | re.I)
        delay = re.search(r"^\s*(?:dpddelay|dpd_delay)\s*=\s*(\S+)", text, re.M | re.I)
        detail = {"dpdaction": action.group(1) if action else None,
                  "dpddelay": delay.group(1) if delay else None}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "dead peer detection settings")

        if not action or action.group(1).lower() == "none":
            return [self.fail(
                target,
                "Dead peer detection is not enabled — half-dead SAs accumulate "
                "and hold address-pool leases",
                severity=Severity.LOW, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            f"DPD enabled (action={action.group(1)}"
            + (f", delay={delay.group(1)}" if delay else "") + ")",
            evidence=[ev], detail=detail)]


KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


class ImplementationVersion(Check):
    """IPS-12 — the running daemon must not be a KEV-listed version."""

    id = "IPS-12"
    protocol = "ipsec"
    access = "config"

    def applicable(self, target, ctx):
        return _has_ssh(target)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        rc, out, err = _ssh(
            target,
            "(ipsec version 2>/dev/null || swanctl --version 2>/dev/null || "
            "strongswan version 2>/dev/null) | head -3")
        banner = out.strip()
        if not banner:
            return [self.error(target, "Could not determine the IPsec daemon version")]

        version = None
        m = re.search(r"(\d+\.\d+\.\d+)", banner)
        if m:
            version = m.group(1)

        # KEV lookup, cached per run.
        kev = ctx.options.get("_kev")
        if kev is None:
            try:
                with urllib.request.urlopen(KEV_URL, timeout=25) as resp:
                    kev = json.loads(resp.read().decode()).get("vulnerabilities", [])
            except Exception:
                kev = []
            ctx.options["_kev"] = kev

        matches = [
            {"cve": e.get("cveID"), "product": e.get("product")}
            for e in kev
            if "strongswan" in (e.get("vendorProject", "") + e.get("product", "")).lower()
        ]

        detail = {"banner": banner, "version": version,
                  "kev_matches": matches, "kev_entries_checked": len(kev)}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "IPsec daemon version and KEV lookup")

        if matches:
            return [self.warn(
                target,
                f"strongSwan {version or '?'} — {len(matches)} KEV entr"
                f"{'y' if len(matches) == 1 else 'ies'} exist for this product; "
                "confirm this version is not affected",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            f"strongSwan {version or banner.splitlines()[0]} — no KEV entry "
            "for this product",
            evidence=[ev], detail=detail)]
