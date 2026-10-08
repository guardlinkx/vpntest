"""API transport security — TLS posture of the control plane itself.

The VPN data plane gets the attention, but the API that hands out VPN
credentials is ordinary HTTPS and fails in ordinary ways.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import requests

from ...model import Check, Context, Finding, Severity, Target

WEAK_PROTOCOLS = {
    "SSLv2": ssl.PROTOCOL_TLS_CLIENT,
    "SSLv3": ssl.PROTOCOL_TLS_CLIENT,
}


def _host_port(target: Target):
    base = target.meta.get("api_base")
    if base:
        u = urlparse(base)
        return u.hostname, (u.port or (443 if u.scheme == "https" else 80))
    return target.host, (target.port or 443)


class ApiTransportTls(Check):
    """API-06 — HTTPS only, valid chain, no obsolete protocol versions."""

    id = "API-06"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(target.meta.get("api_base") or target.port == 443)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        host, port = _host_port(target)
        findings: List[Finding] = []
        detail = {}

        # 1. Certificate and negotiated version.
        try:
            ctx_ssl = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=12) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    detail["negotiated"] = tls.version()
                    detail["cipher"] = tls.cipher()[0] if tls.cipher() else None
                    not_after = cert.get("notAfter")
                    detail["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    detail["notAfter"] = not_after
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp = exp.replace(tzinfo=timezone.utc)
                        detail["days_left"] = (exp - datetime.now(timezone.utc)).days
        except ssl.SSLCertVerificationError as exc:
            return [self.fail(target, f"Certificate does not verify: {exc}",
                              severity=Severity.CRITICAL, detail=detail)]
        except (OSError, socket.timeout) as exc:
            return [self.error(target, f"Could not connect to {host}:{port}: {exc}")]

        # 2. Are obsolete versions still accepted?
        obsolete = []
        for name, const in (("TLSv1", ssl.TLSVersion.TLSv1),
                            ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c.check_hostname = False
                c.verify_mode = ssl.CERT_NONE
                c.minimum_version = const
                c.maximum_version = const
                with socket.create_connection((host, port), timeout=8) as s:
                    with c.wrap_socket(s, server_hostname=host):
                        obsolete.append(name)
            except Exception:
                pass
        detail["obsolete_accepted"] = obsolete

        # 3. Does plain HTTP serve content instead of redirecting?
        cleartext = None
        try:
            r = requests.get(f"http://{host}/", timeout=8, allow_redirects=False)
            cleartext = r.status_code
            detail["http_status"] = r.status_code
            detail["http_location"] = r.headers.get("Location")
        except requests.RequestException:
            detail["http_status"] = "no listener"

        ev = ctx.evidence.data(self.id, host.replace(".", "_"), detail,
                               "TLS posture of the API endpoint")

        if obsolete:
            findings.append(self.fail(
                target, f"Obsolete TLS accepted: {', '.join(obsolete)}",
                severity=Severity.HIGH, evidence=[ev], detail=detail))
        if cleartext and 200 <= cleartext < 300:
            findings.append(self.fail(
                target, "Plain HTTP serves content instead of redirecting to HTTPS",
                severity=Severity.HIGH, evidence=[ev], detail=detail))
        days = detail.get("days_left")
        if isinstance(days, int) and days < 21:
            findings.append(self.warn(
                target, f"Certificate expires in {days} days",
                evidence=[ev], detail=detail))

        if not findings:
            findings.append(self.ok(
                target,
                f"TLS {detail.get('negotiated')} with a valid chain; no obsolete "
                f"versions; certificate valid for {days} days",
                evidence=[ev], detail=detail))
        return findings
