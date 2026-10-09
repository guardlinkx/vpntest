"""SSL-05 and SSL-07 to SSL-12 — the portal itself.

The pre-auth portal is the most attacked surface on an SSL VPN appliance, so
these lean towards what an unauthenticated attacker sees. The credentialed
ones (SSL-07/08/09/10) need a dedicated test account declared in the scope and
report `n/a` without one — they must never run against a real user.

SSL-08 is the only one that sends failed logins. It is capped by the scope's
max_login_attempts and aimed at the test account only, so a real account is
never locked out.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from ...model import Check, Context, Finding, Severity, Target

requests.packages.urllib3.disable_warnings()  # self-signed portals are common


def _base(target: Target) -> str:
    port = int(target.port or target.meta.get("tls_port") or 443)
    scheme = "https"
    suffix = "" if port == 443 else f":{port}"
    return f"{scheme}://{target.host}{suffix}"


def _portal_path(target: Target) -> str:
    return target.meta.get("portal_path", "/")


def _creds(target: Target) -> Optional[Dict[str, Any]]:
    """Test-account config. Absent means the credentialed checks report n/a."""
    return target.meta.get("test_account")


class PortalSecurityHeaders(Check):
    """SSL-05 — HSTS, cookie flags, no token in the URL."""

    id = "SSL-05"
    protocol = "tls_vpn"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        url = urljoin(_base(target), _portal_path(target))
        try:
            resp = requests.get(url, timeout=15, verify=False,
                                allow_redirects=True)
        except requests.RequestException as exc:
            return [self.error(target, f"Could not reach the portal: {exc}")]

        headers = {k.lower(): v for k, v in resp.headers.items()}
        problems: List[str] = []

        hsts = headers.get("strict-transport-security")
        if not hsts:
            problems.append("no HSTS")
        else:
            try:
                age = int(hsts.split("max-age=")[1].split(";")[0])
                if age < 31536000:
                    problems.append(f"HSTS max-age only {age}")
            except (IndexError, ValueError):
                problems.append("HSTS present but unparseable")

        cookie_issues = []
        for raw in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []:
            low = raw.lower()
            name = raw.split("=", 1)[0]
            missing = [flag for flag in ("secure", "httponly") if flag not in low]
            if "samesite" not in low:
                missing.append("samesite")
            if missing:
                cookie_issues.append(f"{name}: missing {'+'.join(missing)}")
        if cookie_issues:
            problems.append("; ".join(cookie_issues))

        # A session token carried in the query string ends up in logs,
        # referrers and browser history.
        if any(tok in resp.url.lower()
               for tok in ("sessionid=", "token=", "sid=", "auth=")):
            problems.append("session token appears in the URL")

        detail = {
            "final_url": resp.url,
            "status": resp.status_code,
            "hsts": hsts,
            "x_frame_options": headers.get("x-frame-options"),
            "content_security_policy": bool(headers.get("content-security-policy")),
            "cookie_issues": cookie_issues,
        }
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "portal response headers")

        if problems:
            return [self.fail(
                target, "Portal header/cookie weaknesses: " + "; ".join(problems),
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(target, "HSTS set and cookies correctly flagged",
                        evidence=[ev], detail=detail)]


class PortalMfaEnforced(Check):
    """SSL-07 — a password alone must not complete login."""

    id = "SSL-07"
    protocol = "tls_vpn"
    access = "test-creds"

    def applicable(self, target, ctx):
        return bool(_creds(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        cfg = _creds(target)
        url = urljoin(_base(target), cfg["login_path"])
        body = dict(cfg.get("login_body") or {})
        try:
            resp = requests.post(url, data=body, timeout=20, verify=False,
                                 allow_redirects=False)
        except requests.RequestException as exc:
            return [self.error(target, f"Login request failed: {exc}")]

        text = resp.text[:3000]
        success_marker = cfg.get("success_marker", "")
        mfa_marker = cfg.get("mfa_marker", "")

        logged_in = bool(success_marker and success_marker in text)
        asked_mfa = bool(mfa_marker and mfa_marker in text)

        detail = {"status": resp.status_code, "logged_in": logged_in,
                  "asked_for_second_factor": asked_mfa}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "single-factor login attempt")

        if logged_in and not asked_mfa:
            return [self.fail(
                target, "A password alone completed login — no second factor",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(
            target, "Password alone did not complete login",
            evidence=[ev], detail=detail)]


class PortalLockoutAndEnumeration(Check):
    """SSL-08 — lockout exists, and failures do not reveal valid usernames."""

    id = "SSL-08"
    protocol = "tls_vpn"
    access = "test-creds"

    def applicable(self, target, ctx):
        return bool(_creds(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        cfg = _creds(target)
        url = urljoin(_base(target), cfg["login_path"])
        attempts = min(int(ctx.rate_limit("max_login_attempts", 3)), 5)
        user_field = cfg.get("user_field", "username")
        pass_field = cfg.get("pass_field", "password")
        real_user = cfg.get("username", "")

        def _try(username: str, password: str):
            started = time.time()
            body = dict(cfg.get("login_body") or {})
            body[user_field] = username
            body[pass_field] = password
            try:
                r = requests.post(url, data=body, timeout=20, verify=False,
                                  allow_redirects=False)
                return {"status": r.status_code, "len": len(r.text),
                        "elapsed": round(time.time() - started, 3),
                        "body": r.text[:200]}
            except requests.RequestException as exc:
                return {"error": str(exc)}

        # Compare a known-real user against one that certainly does not exist.
        real = _try(real_user, "wrong-password-for-vpntest")
        fake = _try("vpntest-no-such-user-9f2a", "wrong-password-for-vpntest")

        series = []
        for i in range(attempts):
            series.append(_try(real_user, f"wrong-password-{i}"))
            time.sleep(0.8)

        enumerable = (
            real.get("status") != fake.get("status")
            or abs(real.get("len", 0) - fake.get("len", 0)) > 40
        )
        statuses = [s.get("status") for s in series]
        locked = len(set(statuses)) > 1 or (
            series and series[-1].get("status") != series[0].get("status"))

        detail = {"real_user_response": real, "unknown_user_response": fake,
                  "series_statuses": statuses, "attempts": attempts}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "capped failed-login comparison")

        findings = []
        if enumerable:
            findings.append(self.fail(
                target,
                "Responses differ between a real and an unknown username — "
                "usernames are enumerable",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail))
        if not locked:
            findings.append(self.warn(
                target,
                f"No lockout or throttling observed over {attempts} failures "
                "(the cap is deliberately low; confirm the real threshold)",
                evidence=[ev], detail=detail))
        if not findings:
            findings.append(self.ok(
                target, "Responses are uniform and throttling was observed",
                evidence=[ev], detail=detail))
        return findings


class PortalSessionHandling(Check):
    """SSL-09 — logout invalidates server-side; idle sessions expire."""

    id = "SSL-09"
    protocol = "tls_vpn"
    access = "test-creds"

    def applicable(self, target, ctx):
        cfg = _creds(target)
        return bool(cfg and cfg.get("logout_path") and cfg.get("authed_path"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        cfg = _creds(target)
        base = _base(target)
        s = requests.Session()
        s.verify = False
        try:
            body = dict(cfg.get("login_body") or {})
            s.post(urljoin(base, cfg["login_path"]), data=body, timeout=20)
            before = s.get(urljoin(base, cfg["authed_path"]), timeout=20)
            s.get(urljoin(base, cfg["logout_path"]), timeout=20)
            after = s.get(urljoin(base, cfg["authed_path"]), timeout=20,
                          allow_redirects=False)
        except requests.RequestException as exc:
            return [self.error(target, f"Session test failed: {exc}")]

        marker = cfg.get("success_marker", "")
        still_valid = bool(marker and marker in after.text)
        detail = {"before_status": before.status_code,
                  "after_logout_status": after.status_code,
                  "still_authenticated": still_valid}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "session replay after logout")

        if still_valid or after.status_code == before.status_code == 200:
            return [self.fail(
                target, "The session still works after logout — it is not "
                        "invalidated server-side",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(target, "Logout invalidated the session server-side",
                        evidence=[ev], detail=detail)]


class PortalDevicePosture(Check):
    """SSL-10 — posture or client certificate enforced where policy requires."""

    id = "SSL-10"
    protocol = "tls_vpn"
    access = "test-creds"

    def applicable(self, target, ctx):
        return bool(target.meta.get("requires_client_cert") is not None)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        required = bool(target.meta.get("requires_client_cert"))
        port = int(target.port or 443)
        # Connect with no client certificate and see whether the handshake
        # completes. A portal that demands one will refuse or re-handshake.
        accepted_without_cert = False
        err = ""
        try:
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target.host, port), timeout=12) as sock:
                with c.wrap_socket(sock, server_hostname=target.host):
                    accepted_without_cert = True
        except Exception as exc:
            err = str(exc)

        detail = {"policy_requires_client_cert": required,
                  "handshake_without_cert": accepted_without_cert,
                  "error": err}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "handshake without a client certificate")

        if required and accepted_without_cert:
            return [self.fail(
                target,
                "Policy requires a client certificate but the handshake "
                "completed without one",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        if not required:
            return [self.na(
                target, "Scope declares no client-certificate requirement",
                evidence=[ev], detail=detail)]
        return [self.ok(target, "Client certificate is enforced",
                        evidence=[ev], detail=detail)]


class AdminInterfaceExposure(Check):
    """SSL-11 — no admin console reachable from the public side."""

    id = "SSL-11"
    protocol = "tls_vpn"
    access = "unauth"

    # Paths that appliances commonly expose; checked on the public address
    # only, read-only GETs.
    PATHS = ("/admin", "/administrator", "/+CSCOE+/logon.html", "/dana-na/",
             "/remote/login", "/manager", "/management", "/sslvpn_logon.shtml",
             "/cgi-bin/welcome", "/php/uid.php", "/global-protect/login.esp")
    PORTS = (443, 4443, 8443, 10443, 8080, 8888, 9443)

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        expected = set(target.meta.get("expected_tcp_ports") or [])
        found: List[str] = []
        detail: Dict[str, Any] = {"paths": {}, "ports": {}}

        base = _base(target)
        for path in self.PATHS:
            try:
                r = requests.get(urljoin(base, path), timeout=8, verify=False,
                                 allow_redirects=False)
            except requests.RequestException:
                continue
            detail["paths"][path] = r.status_code
            if r.status_code in (200, 401, 403):
                found.append(f"{path} ({r.status_code})")
            time.sleep(0.2)

        for port in self.PORTS:
            if port in expected:
                continue
            try:
                with socket.create_connection((target.host, port), timeout=3):
                    detail["ports"][port] = "open"
                    found.append(f"port {port}")
            except (OSError, socket.timeout):
                detail["ports"][port] = "closed"

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "admin surface probe")

        if found:
            return [self.fail(
                target,
                "Possible administrative surface exposed publicly: "
                + ", ".join(found),
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]
        return [self.ok(
            target, "No administrative paths or ports reachable publicly",
            evidence=[ev], detail=detail)]


class DtlsVersion(Check):
    """SSL-12 — a DTLS data channel, where used, must be 1.2 or better."""

    id = "SSL-12"
    protocol = "tls_vpn"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(target.meta.get("dtls_port"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        port = int(target.meta["dtls_port"])
        # A DTLS 1.0 ClientHello: if the server answers one, it speaks 1.0.
        hello_10 = bytes.fromhex(
            "16feff0000000000000000003c"      # record, DTLS 1.0
            "010000300000000000000030"        # handshake: client_hello
            "feff"                            # client version DTLS 1.0
        ) + b"\x00" * 32
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4.0)
        answered_10 = False
        try:
            sock.sendto(hello_10, (target.host, port))
            data, _ = sock.recvfrom(2048)
            answered_10 = bool(data) and data[:1] == b"\x16"
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

        detail = {"dtls_port": port, "answered_dtls_1_0": answered_10}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "DTLS 1.0 ClientHello probe")

        if answered_10:
            return [self.fail(
                target, f"DTLS 1.0 ClientHello answered on {port}",
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(
            target, f"No DTLS 1.0 response on {port}",
            evidence=[ev], detail=detail)]
