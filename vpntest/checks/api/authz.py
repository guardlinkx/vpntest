"""API authorization checks.

The highest-impact VPN API bugs are not cryptographic. They are endpoints that
hand out entitlement or credentials to whoever asks. A real example found in
the field: a purchase-verification endpoint that took `product_id` and
`transaction_id` from the request body and granted permanent paid access, with
no store verification and no expiry — one unauthenticated POST.

These checks are deliberately read-mostly. They probe for *acceptance*, and
the destructive variants are left to a human.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

from ...model import Check, Context, Finding, Severity, Status, Target

# Endpoints whose names suggest they grant something. A 200 from any of these
# without credentials is the finding.
MUTATION_HINTS = (
    "verify", "activate", "redeem", "grant", "upgrade", "purchase",
    "register", "provision", "connect", "reset", "admin", "entitle",
)


def _api_base(target: Target) -> Optional[str]:
    return target.meta.get("api_base")


def _endpoints(target: Target) -> List[Dict[str, Any]]:
    """Endpoints to probe, from the scope file.

    Supplied rather than guessed: blindly fuzzing paths on someone's
    production API is neither polite nor in scope.
    """
    return list(target.meta.get("endpoints") or [])


def _post(url: str, body: dict, timeout: int = 15, headers: Optional[dict] = None):
    return requests.post(url, json=body, timeout=timeout,
                         headers=headers or {"Content-Type": "application/json"})


class UnauthenticatedMutation(Check):
    """API-01 — does an unauthenticated caller get to change state?"""

    id = "API-01"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(_api_base(target) and _endpoints(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        base = _api_base(target).rstrip("/")
        findings: List[Finding] = []
        accepted: List[Dict[str, Any]] = []
        by_design: List[Dict[str, Any]] = []
        transcript = []

        for ep in _endpoints(target):
            path = ep.get("path")
            if not path:
                continue
            if not ep.get("mutating") and not any(h in path for h in MUTATION_HINTS):
                continue
            # A body the endpoint would plausibly accept, with invented ids.
            body = dict(ep.get("sample_body") or {})
            url = f"{base}{path}"
            try:
                resp = _post(url, body)
            except requests.RequestException as exc:
                transcript.append(f"{path}: request failed: {exc}")
                continue

            transcript.append(
                f"POST {path} -> {resp.status_code} {resp.text[:200]}"
            )
            if 200 <= resp.status_code < 300:
                try:
                    payload = resp.json()
                except ValueError:
                    payload = {}
                # A 200 carrying an error is a refusal in disguise, which is
                # sloppy but not a grant.
                if not payload.get("error"):
                    # Some endpoints are unauthenticated on purpose — anonymous
                    # device enrolment, for instance. The scope must say so
                    # explicitly and give a reason, which is then carried into
                    # the report as an accepted exception rather than silently
                    # dropped. Unjustified exceptions do not count.
                    reason = ep.get("expected_unauthenticated")
                    if reason:
                        by_design.append({"path": path, "reason": str(reason)})
                    else:
                        accepted.append({"path": path, "body": payload})

            time.sleep(1.0 / max(ctx.rate_limit("requests_per_second", 5), 1))

        ev = ctx.evidence.text(self.id, str(target).replace(".", "_"),
                               "\n".join(transcript),
                               "unauthenticated POST transcript")

        detail = {"accepted": accepted, "unauthenticated_by_design": by_design}

        if accepted:
            findings.append(self.fail(
                target,
                f"{len(accepted)} mutating endpoint(s) accepted an "
                f"unauthenticated request: "
                + ", ".join(a["path"] for a in accepted),
                severity=Severity.CRITICAL, evidence=[ev], detail=detail,
            ))
        else:
            note = ""
            if by_design:
                note = (f" ({len(by_design)} unauthenticated by design: "
                        + ", ".join(b["path"] for b in by_design) + ")")
            findings.append(self.ok(
                target,
                f"No unintended unauthenticated mutations across "
                f"{len(transcript)} probes" + note,
                evidence=[ev], detail=detail,
            ))
        return findings


class ReceiptForgery(Check):
    """API-02 — is a purchase receipt actually verified with the store?"""

    id = "API-02"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(_api_base(target) and target.meta.get("purchase_verify"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        cfg = target.meta["purchase_verify"]
        base = _api_base(target).rstrip("/")
        url = f"{base}{cfg['path']}"

        # Three shapes of lie: no receipt at all, a nonsense receipt, and a
        # structurally valid but unsigned JWS.
        fake_jws = (
            "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJBQUEiXX0"
            ".eyJwcm9kdWN0SWQiOiJmYWtlIn0.c2lnbmF0dXJl"
        )
        attempts = [
            ("no receipt", dict(cfg.get("body_no_receipt") or {})),
            ("nonsense receipt", dict(cfg.get("body_fake_receipt") or {})),
            ("unsigned JWS", {**(cfg.get("body_fake_receipt") or {}),
                              cfg.get("receipt_field", "signed_transaction"): fake_jws}),
        ]

        transcript, granted = [], []
        for label, body in attempts:
            if not body:
                continue
            try:
                resp = _post(url, body)
            except requests.RequestException as exc:
                transcript.append(f"{label}: request failed: {exc}")
                continue
            try:
                payload = resp.json()
            except ValueError:
                payload = {}
            transcript.append(f"{label}: {resp.status_code} {resp.text[:250]}")
            if 200 <= resp.status_code < 300 and not payload.get("error"):
                granted.append(label)
            time.sleep(0.5)

        ev = ctx.evidence.text(self.id, str(target).replace(".", "_"),
                               "\n".join(transcript), "forged receipt attempts")

        if granted:
            return [self.fail(
                target,
                "Entitlement granted against a forged receipt (" +
                ", ".join(granted) + "). The endpoint trusts the client.",
                severity=Severity.CRITICAL, evidence=[ev],
                detail={"granted_for": granted},
            )]
        return [self.ok(
            target, "Forged and unsigned receipts were all rejected",
            evidence=[ev],
        )]


class CredentialIssuanceRateLimit(Check):
    """API-05 — can anyone mint unlimited licences or VPN credentials?"""

    id = "API-05"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(_api_base(target) and target.meta.get("register_endpoint"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        base = _api_base(target).rstrip("/")
        cfg = target.meta["register_endpoint"]
        url = f"{base}{cfg['path']}"
        field = cfg.get("id_field", "device_id")
        burst = min(int(ctx.rate_limit("max_registrations", 8)), 20)

        codes, issued = [], 0
        for _ in range(burst):
            body = dict(cfg.get("body") or {})
            body[field] = uuid.uuid4().hex   # 32 hex chars, a common format
            try:
                resp = _post(url, body, timeout=12)
            except requests.RequestException:
                codes.append("err")
                continue
            codes.append(resp.status_code)
            # Any 2xx is a successful issuance. Counting only 200 made this
            # report "throttled" against an endpoint returning 201 Created —
            # a security check claiming a control exists when it does not.
            if 200 <= resp.status_code < 300:
                issued += 1
            time.sleep(0.2)

        ev = ctx.evidence.data(self.id, str(target).replace(".", "_"),
                               {"status_codes": codes, "issued": issued},
                               f"{burst} back-to-back registrations")

        if issued == burst:
            return [self.fail(
                target,
                f"{issued}/{burst} back-to-back identity registrations all "
                "succeeded — no rate limit on credential issuance",
                severity=Severity.HIGH, evidence=[ev],
            )]
        if issued > burst * 0.6:
            return [self.warn(
                target,
                f"{issued}/{burst} registrations succeeded; throttling looks weak",
                evidence=[ev],
            )]
        return [self.ok(
            target, f"Registration throttled after {issued}/{burst} attempts",
            evidence=[ev],
        )]


class AdminEndpointAuth(Check):
    """API-08 — admin routes must require a secret and fail closed."""

    id = "API-08"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(_api_base(target) and target.meta.get("admin_endpoints"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        base = _api_base(target).rstrip("/")
        transcript, open_routes = [], []

        for ep in target.meta["admin_endpoints"]:
            path = ep if isinstance(ep, str) else ep.get("path")
            body = {} if isinstance(ep, str) else dict(ep.get("body") or {})
            url = f"{base}{path}"
            for label, headers in (
                ("no token", None),
                ("wrong token", {"Content-Type": "application/json",
                                 "X-Admin-Token": "definitely-not-the-token"}),
            ):
                try:
                    resp = _post(url, body, headers=headers)
                except requests.RequestException as exc:
                    transcript.append(f"{path} [{label}]: failed: {exc}")
                    continue
                transcript.append(f"{path} [{label}]: {resp.status_code} {resp.text[:160]}")
                if 200 <= resp.status_code < 300:
                    open_routes.append(f"{path} ({label})")
                time.sleep(0.3)

        ev = ctx.evidence.text(self.id, str(target).replace(".", "_"),
                               "\n".join(transcript), "admin route probes")

        if open_routes:
            return [self.fail(
                target,
                "Admin route(s) reachable without a valid token: " +
                ", ".join(open_routes),
                severity=Severity.CRITICAL, evidence=[ev],
            )]
        return [self.ok(
            target, "Admin routes rejected both missing and wrong tokens",
            evidence=[ev],
        )]
