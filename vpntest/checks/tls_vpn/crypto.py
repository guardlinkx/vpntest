"""SSL-01 to SSL-04 and SSL-06 — the TLS posture of a VPN portal.

All five read one cached sslyze scan per target, so a full run costs a single
handshake matrix rather than one per control.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ...model import Check, Context, Finding, Severity, Target
from ...wrappers import sslyze_wrap as sz

# Anything here in an accepted suite is a finding. Keyword match rather than
# an allow-list of names, because suite naming varies between stacks.
BAD_SUITE_TOKENS = (
    "NULL", "EXPORT", "anon", "ADH", "AECDH", "RC4", "DES", "3DES",
    "IDEA", "SEED", "MD5", "PSK",
)
# AEAD or nothing, per SP 800-52r2 preference.
AEAD_TOKENS = ("GCM", "CHACHA20", "CCM")


def _ocsp_uri(cert):
    """The OCSP responder URL from the certificate's AIA extension, if any.

    Absent on certificates from issuers that have retired OCSP. Without it a
    server physically cannot staple, so the control does not apply.
    """
    try:
        from cryptography.x509 import AuthorityInformationAccess
        from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for d in aia:
            if d.access_method == AuthorityInformationAccessOID.OCSP:
                return d.access_location.value
    except Exception:
        pass
    return None


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host_matches(host: str, sans: List[str]) -> bool:
    """RFC 6125 name matching, wildcards limited to the left-most label."""
    host = host.lower().rstrip(".")
    for san in sans:
        san = san.lower().rstrip(".")
        if san == host:
            return True
        if san.startswith("*."):
            # A wildcard covers exactly one label, not several.
            if host.count(".") == san.count(".") and host.endswith(san[1:]):
                return True
    return False


def _port(target: Target) -> int:
    return int(target.port or target.meta.get("tls_port") or 443)


def _scan(target: Target):
    return sz.scan(target.host, _port(target))


class TlsProtocolVersions(Check):
    """SSL-01 — TLS 1.2+ only; SSLv2/3, TLS 1.0 and 1.1 must not negotiate."""

    id = "SSL-01"
    protocol = "tls_vpn"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        try:
            result = _scan(target)
        except Exception as exc:
            return [self.error(target, str(exc))]

        versions = {
            "SSL 2.0": "ssl_2_0_cipher_suites",
            "SSL 3.0": "ssl_3_0_cipher_suites",
            "TLS 1.0": "tls_1_0_cipher_suites",
            "TLS 1.1": "tls_1_1_cipher_suites",
            "TLS 1.2": "tls_1_2_cipher_suites",
            "TLS 1.3": "tls_1_3_cipher_suites",
        }
        accepted: Dict[str, int] = {}
        for label, attr in versions.items():
            res = sz.attempt(result, attr)
            accepted[label] = len(res.accepted_cipher_suites) if res else 0

        obsolete = [v for v in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
                    if accepted.get(v)]
        modern = [v for v in ("TLS 1.2", "TLS 1.3") if accepted.get(v)]

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"),
                               accepted, "suites accepted per TLS version")

        if obsolete:
            return [self.fail(
                target,
                "Obsolete protocol versions negotiate: " + ", ".join(obsolete),
                severity=Severity.HIGH, evidence=[ev], detail=accepted)]
        if not modern:
            return [self.fail(
                target, "Neither TLS 1.2 nor 1.3 negotiated — nothing usable",
                severity=Severity.HIGH, evidence=[ev], detail=accepted)]
        if "TLS 1.3" not in modern:
            return [self.warn(
                target, "TLS 1.2 only; 1.3 is preferred",
                evidence=[ev], detail=accepted)]
        return [self.ok(
            target, "Only " + " and ".join(modern) + " negotiate",
            evidence=[ev], detail=accepted)]


class TlsCipherSuites(Check):
    """SSL-02 — AEAD with forward secrecy; nothing legacy."""

    id = "SSL-02"
    protocol = "tls_vpn"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        try:
            result = _scan(target)
        except Exception as exc:
            return [self.error(target, str(exc))]

        all_suites: List[str] = []
        for attr in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
                     "tls_1_0_cipher_suites", "tls_1_1_cipher_suites",
                     "tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
            res = sz.attempt(result, attr)
            if not res:
                continue
            all_suites += [a.cipher_suite.name for a in res.accepted_cipher_suites]

        weak = sorted({s for s in all_suites
                       if any(t.lower() in s.lower() for t in BAD_SUITE_TOKENS)})
        # TLS 1.3 suites are AEAD and forward-secret by construction.
        non_aead = sorted({
            s for s in all_suites
            if not s.startswith("TLS_AES") and not s.startswith("TLS_CHACHA")
            and not any(t in s.upper() for t in AEAD_TOKENS)
        })
        no_pfs = sorted({
            s for s in all_suites
            if s.startswith("TLS_RSA_") or "_DH_" in s
        })

        detail = {"accepted": sorted(set(all_suites)), "weak": weak,
                  "non_aead": non_aead, "without_forward_secrecy": no_pfs}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "accepted cipher suites")

        findings: List[Finding] = []
        if weak:
            findings.append(self.fail(
                target, f"{len(weak)} legacy/insecure suite(s) accepted: "
                + ", ".join(weak[:6]) + ("…" if len(weak) > 6 else ""),
                severity=Severity.HIGH, evidence=[ev], detail=detail))
        if no_pfs:
            findings.append(self.fail(
                target, f"{len(no_pfs)} suite(s) without forward secrecy: "
                + ", ".join(no_pfs[:6]),
                severity=Severity.HIGH, evidence=[ev], detail=detail))
        if non_aead and not weak and not no_pfs:
            findings.append(self.warn(
                target, f"{len(non_aead)} non-AEAD suite(s) accepted: "
                + ", ".join(non_aead[:6]),
                evidence=[ev], detail=detail))
        if not findings:
            findings.append(self.ok(
                target,
                f"All {len(set(all_suites))} accepted suites are AEAD with "
                "forward secrecy",
                evidence=[ev], detail=detail))
        return findings


class TlsCertificate(Check):
    """SSL-03 — trusted chain, adequate key, matching SAN, stapling."""

    id = "SSL-03"
    protocol = "tls_vpn"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        try:
            result = _scan(target)
        except Exception as exc:
            return [self.error(target, str(exc))]

        res = sz.attempt(result, "certificate_info")
        if not res:
            return [self.error(target, "sslyze could not retrieve certificate info")]

        findings: List[Finding] = []
        detail: Dict[str, Any] = {"deployments": []}

        for dep in res.certificate_deployments:
            leaf = dep.received_certificate_chain[0]
            pub = leaf.public_key()
            bits = getattr(pub, "key_size", None)
            key_type = type(pub).__name__
            # sslyze exposes trust per trust-store rather than a single
            # "matches hostname" boolean; derive the match from the SANs.
            sans: List[str] = []
            try:
                from cryptography.x509.oid import ExtensionOID
                ext = leaf.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = list(ext.value.get_values_for_type(
                    __import__("cryptography.x509", fromlist=["DNSName"]).DNSName))
            except Exception:
                sans = []
            hostname_ok = _host_matches(target.host, sans)

            info = {
                "subject": leaf.subject.rfc4514_string(),
                "issuer": leaf.issuer.rfc4514_string(),
                "key": f"{key_type} {bits}" if bits else key_type,
                "not_after": str(leaf.not_valid_after_utc),
                "trusted": bool(dep.verified_certificate_chain),
                "sans": sans,
                "hostname_matches": hostname_ok,
                "ocsp_stapled": dep.ocsp_response is not None,
                "ocsp_uri": _ocsp_uri(leaf),
                "signature": leaf.signature_hash_algorithm.name
                             if leaf.signature_hash_algorithm else None,
            }
            detail["deployments"].append(info)

            if not info["trusted"]:
                findings.append(self.fail(
                    target, "Certificate chain does not validate to a trusted root",
                    severity=Severity.CRITICAL, detail=info))
            # An IP target legitimately will not appear in a SAN list; only
            # flag a mismatch when the scope gave us a hostname to match.
            if not info["hostname_matches"] and not _is_ip(target.host):
                findings.append(self.fail(
                    target,
                    f"Certificate SANs {sans} do not cover {target.host}",
                    severity=Severity.CRITICAL, detail=info))
            if "RSA" in key_type and bits and bits < 2048:
                findings.append(self.fail(
                    target, f"RSA key is only {bits} bits",
                    severity=Severity.CRITICAL, detail=info))
            if info["signature"] in ("md5", "sha1"):
                findings.append(self.fail(
                    target, f"Certificate signed with {info['signature']}",
                    severity=Severity.HIGH, detail=info))
            days = (leaf.not_valid_after_utc - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(self.fail(
                    target, "Certificate has expired",
                    severity=Severity.CRITICAL, detail=info,
                    remediation="Reissue and redeploy the certificate."))
            elif days < 21:
                findings.append(self.warn(
                    target, f"Certificate expires in {days} days", detail=info,
                    remediation="Confirm automatic renewal is running and will "
                                "complete before expiry."))
            # Stapling is only possible if the certificate names a responder.
            # Let's Encrypt retired OCSP in 2025 — it stopped embedding
            # responder URLs and shut the responders down, moving to CRLs — so
            # on an LE certificate `ssl_stapling on` is a no-op that logs "no
            # OCSP responder URL in the certificate". Warning about it would
            # send an operator to change a setting that cannot do anything.
            if not info["ocsp_stapled"] and not info["ocsp_uri"]:
                findings.append(self.na(
                    target,
                    "The certificate carries no OCSP responder URL, so stapling "
                    "is not possible. Issuers including Let's Encrypt have "
                    "retired OCSP in favour of CRLs; this is the issuer's "
                    "choice, not a server misconfiguration.",
                    detail=info))
            elif not info["ocsp_stapled"]:
                # The control's catalog remediation is about the certificate
                # itself, which is not the problem here — the cert is fine and
                # the gap is purely a server setting. Say the actual action.
                findings.append(self.warn(
                    target, "No OCSP stapling — revocation cannot be checked cheaply",
                    severity=Severity.LOW, detail=info,
                    remediation="Enable OCSP stapling on the terminating server "
                                "(nginx: ssl_stapling on, ssl_stapling_verify on, "
                                "plus a resolver) so clients get revocation status "
                                "in the handshake."))

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "certificate deployments")
        for f in findings:
            f.evidence = [ev]
        if not findings:
            findings = [self.ok(
                target, "Certificate is trusted, matches, and is current",
                evidence=[ev], detail=detail)]
        return findings


class TlsKnownVulnerabilities(Check):
    """SSL-04 — compression, renegotiation, Heartbleed, CCS, ROBOT."""

    id = "SSL-04"
    protocol = "tls_vpn"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        try:
            result = _scan(target)
        except Exception as exc:
            return [self.error(target, str(exc))]

        problems, detail = [], {}

        comp = sz.attempt(result, "tls_compression")
        if comp is not None:
            detail["compression"] = comp.supports_compression
            if comp.supports_compression:
                problems.append("TLS compression enabled (CRIME)")

        reneg = sz.attempt(result, "session_renegotiation")
        if reneg is not None:
            detail["secure_renegotiation"] = reneg.supports_secure_renegotiation
            detail["client_renegotiation_dos"] = reneg.is_vulnerable_to_client_renegotiation_dos
            if not reneg.supports_secure_renegotiation:
                problems.append("insecure renegotiation")
            if reneg.is_vulnerable_to_client_renegotiation_dos:
                problems.append("client-initiated renegotiation DoS")

        hb = sz.attempt(result, "heartbleed")
        if hb is not None:
            detail["heartbleed"] = hb.is_vulnerable_to_heartbleed
            if hb.is_vulnerable_to_heartbleed:
                problems.append("Heartbleed (CVE-2014-0160)")

        ccs = sz.attempt(result, "openssl_ccs_injection")
        if ccs is not None:
            detail["ccs_injection"] = ccs.is_vulnerable_to_ccs_injection
            if ccs.is_vulnerable_to_ccs_injection:
                problems.append("CCS injection (CVE-2014-0224)")

        robot = sz.attempt(result, "robot")
        if robot is not None:
            name = getattr(robot.robot_result, "name", str(robot.robot_result))
            detail["robot"] = name
            # startswith, not `in`: the enum has NOT_VULNERABLE_NO_ORACLE and
            # NOT_VULNERABLE_RSA_NOT_SUPPORTED, both of which contain the
            # substring "VULNERABLE" and were being reported as critical.
            if name.upper().startswith("VULNERABLE"):
                problems.append(f"ROBOT ({name})")
            elif name.upper().startswith("UNKNOWN"):
                detail["robot_note"] = "inconsistent results; re-run to confirm"

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "known TLS vulnerability probes")

        if problems:
            return [self.fail(
                target, "Vulnerable: " + "; ".join(problems),
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]
        if not detail:
            return [self.error(target, "No vulnerability probes completed")]
        return [self.ok(
            target, f"Clean against {len(detail)} known-vulnerability probes",
            evidence=[ev], detail=detail)]


KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def _load_kev(ctx: Context) -> Optional[List[Dict[str, Any]]]:
    """Fetch the KEV catalog, cached per run and on disk for offline use."""
    cached = ctx.options.get("_kev")
    if cached is not None:
        return cached
    path = os.path.join(os.path.expanduser("~"), ".cache", "vpntest", "kev.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = None
    try:
        with urllib.request.urlopen(KEV_URL, timeout=25) as resp:
            data = json.loads(resp.read().decode())
        with open(path, "w") as fh:
            json.dump(data, fh)
    except Exception:
        if os.path.exists(path):
            with open(path) as fh:
                data = json.load(fh)
    vulns = (data or {}).get("vulnerabilities")
    ctx.options["_kev"] = vulns
    return vulns


class PortalVersionKev(Check):
    """SSL-06 — fingerprint the portal and look it up in the KEV catalog.

    Fingerprint-and-lookup only. The tool never runs an exploit, so a match
    here means "this product appears in KEV, go and check your version against
    the advisory", not "this host is exploitable".
    """

    id = "SSL-06"
    protocol = "tls_vpn"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        import requests

        port = _port(target)
        url = f"https://{target.host}:{port}/"
        banner: Dict[str, Any] = {}
        try:
            resp = requests.get(url, timeout=15, verify=False,
                                allow_redirects=False)
            banner["status"] = resp.status_code
            banner["server"] = resp.headers.get("Server")
            banner["powered_by"] = resp.headers.get("X-Powered-By")
            body = resp.text[:4000]
            title = re.search(r"<title[^>]*>(.*?)</title>", body,
                              re.I | re.S)
            banner["title"] = title.group(1).strip()[:120] if title else None
        except Exception as exc:
            return [self.error(target, f"Could not fingerprint the portal: {exc}")]

        kev = _load_kev(ctx)
        if kev is None:
            return [self.error(target, "KEV catalog unavailable (no network, no cache)")]

        haystack = " ".join(str(v) for v in banner.values() if v).lower()
        vendors = {"fortinet", "pulse", "ivanti", "citrix", "sonicwall",
                   "palo alto", "globalprotect", "sophos", "watchguard",
                   "cisco", "openvpn", "f5", "big-ip", "array", "barracuda"}
        hits = sorted({v for v in vendors if v in haystack})

        matches = []
        if hits:
            for entry in kev:
                blob = (entry.get("vendorProject", "") + " " +
                        entry.get("product", "")).lower()
                if any(h in blob for h in hits):
                    matches.append({
                        "cve": entry.get("cveID"),
                        "product": entry.get("product"),
                        "name": entry.get("vulnerabilityName"),
                    })

        detail = {"fingerprint": banner, "vendor_hits": hits,
                  "kev_entries": matches[:25], "kev_total": len(kev)}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "portal fingerprint and KEV lookup")

        if matches:
            return [self.warn(
                target,
                f"Portal fingerprint suggests {', '.join(hits)}, which has "
                f"{len(matches)} KEV entr{'y' if len(matches)==1 else 'ies'}. "
                "Confirm the running version against those advisories.",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            "No KEV-listed VPN appliance vendor identified in the banner"
            + (f" (server: {banner.get('server')})" if banner.get("server") else ""),
            evidence=[ev], detail=detail)]
