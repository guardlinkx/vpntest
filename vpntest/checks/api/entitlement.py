"""API-03, API-04, API-07 — entitlement lifecycle and data separation.

These need two identities to be meaningful, so the tool mints its own: a
throwaway device registered through the normal enrolment path. That keeps the
test self-contained and means it never touches a real customer's record.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests

from ...model import Check, Context, Finding, Severity, Target

# Field names that should never appear in a response to a client.
SECRET_FIELD_RE = re.compile(
    r"(?i)\b(node_secret|private_key|privatekey|secret_key|api_key|"
    r"password|passwd|admin_token|session_secret|db_password)\b")

# Anything that looks like an internal address being handed to a client.
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b")


def _base(target: Target) -> Optional[str]:
    b = target.meta.get("api_base")
    return b.rstrip("/") if b else None


def _enrol(target: Target) -> Optional[Dict[str, Any]]:
    """Register a throwaway identity and return what the API gave back."""
    cfg = target.meta.get("register_endpoint")
    base = _base(target)
    if not cfg or not base:
        return None
    body = dict(cfg.get("body") or {})
    field = cfg.get("id_field", "device_id")
    device_id = uuid.uuid4().hex
    body[field] = device_id
    try:
        r = requests.post(f"{base}{cfg['path']}", json=body, timeout=20)
        if not (200 <= r.status_code < 300):
            return None
        payload = r.json()
    except (requests.RequestException, ValueError):
        return None
    payload["_device_id"] = device_id
    return payload


class EntitlementExpires(Check):
    """API-03 — a granted entitlement must carry an end date.

    An entitlement with no expiry never lapses, so a cancelled or refunded
    purchase keeps working indefinitely. This reads what the API reports for a
    freshly enrolled identity and for whatever reference records the scope
    supplies.
    """

    id = "API-03"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(_base(target) and target.meta.get("register_endpoint"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        enrolled = _enrol(target)
        if not enrolled:
            return [self.error(target, "Could not enrol a test identity")]

        ent = enrolled.get("entitlement") or {}
        field = target.meta.get("entitlement_expiry_field", "access_ends_at")
        state_field = target.meta.get("entitlement_state_field", "state")

        detail: Dict[str, Any] = {"fresh_entitlement": ent}
        findings: List[Finding] = []

        # A brand-new identity legitimately has no end date if its window has
        # not started, so that alone is not a finding. The question is whether
        # the field exists in the contract at all.
        if field not in ent:
            findings.append(self.fail(
                target,
                f"The entitlement object has no '{field}' field, so nothing "
                "communicates when access ends",
                severity=Severity.HIGH, detail=detail))

        # Any paid state must carry an expiry.
        paid_states = set(target.meta.get("paid_states")
                          or ["subscribed", "pass", "active", "individual"])
        for label, record in (target.meta.get("reference_licenses") or {}).items():
            cfg = target.meta.get("license_status_endpoint")
            if not cfg:
                break
            try:
                r = requests.post(f"{_base(target)}{cfg['path']}",
                                  json={cfg.get("key_field", "license_key"): record},
                                  timeout=20)
                payload = r.json()
            except (requests.RequestException, ValueError):
                continue
            ref_ent = payload.get("entitlement") or {}
            detail[f"reference_{label}"] = ref_ent
            if str(ref_ent.get(state_field, "")).lower() in paid_states \
                    and not ref_ent.get(field):
                findings.append(self.fail(
                    target,
                    f"Reference licence '{label}' is in state "
                    f"'{ref_ent.get(state_field)}' with no {field} — paid "
                    "access that never lapses",
                    severity=Severity.HIGH, detail=detail))
            time.sleep(0.4)

        ev = ctx.evidence.data(self.id, str(target).replace(".", "_"), detail,
                               "entitlement expiry contract")
        for f in findings:
            f.evidence = [ev]
        if not findings:
            findings = [self.ok(
                target,
                f"The entitlement contract includes '{field}'"
                + (f" (fresh identity: {ent.get(state_field)})" if ent else ""),
                evidence=[ev], detail=detail)]
        return findings


class CrossTenantAccess(Check):
    """API-04 — one identity must not reach another's record.

    Enrols two throwaway identities, then tries to use the first's credential
    against the second's identifier. Read-only: it asks for data, never
    mutates the other record.
    """

    id = "API-04"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(_base(target)
                    and target.meta.get("register_endpoint")
                    and target.meta.get("license_status_endpoint"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        a = _enrol(target)
        time.sleep(0.5)
        b = _enrol(target)
        if not a or not b:
            return [self.error(target, "Could not enrol two test identities")]

        key_field = target.meta.get("license_key_field", "license_key")
        key_a, key_b = a.get(key_field), b.get(key_field)
        if not key_a or not key_b or key_a == key_b:
            return [self.error(
                target,
                "The two test identities did not receive distinct credentials, "
                "so cross-tenant access cannot be assessed")]

        cfg = target.meta["license_status_endpoint"]
        url = f"{_base(target)}{cfg['path']}"
        detail: Dict[str, Any] = {"identity_a": key_a, "identity_b": key_b}
        problems: List[str] = []

        # 1. A's credential paired with B's device id.
        connect_cfg = target.meta.get("connect_endpoint")
        if connect_cfg:
            try:
                r = requests.post(
                    f"{_base(target)}{connect_cfg['path']}",
                    json={key_field: key_a,
                          "device_id": b["_device_id"],
                          "protocol": connect_cfg.get("protocol", "wireguard"),
                          "client_public_key": connect_cfg.get(
                              "client_public_key",
                              "K5m2vQ8bW7xR1tY4uI6oP3aS9dF0gH2jK4lZ8cV6nB0=")},
                    timeout=25)
                detail["mismatched_device_status"] = r.status_code
                detail["mismatched_device_body"] = r.text[:300]
                if 200 <= r.status_code < 300 and "error" not in r.text[:200]:
                    problems.append(
                        "a licence key was accepted alongside a device id "
                        "belonging to a different identity")
            except requests.RequestException:
                pass

        # 2. Does a status lookup leak anything identifying about the owner?
        try:
            r = requests.post(url, json={cfg.get("key_field", "license_key"): key_b},
                              timeout=20)
            detail["status_for_b"] = r.text[:400]
            owner_fields = [f for f in ("email", "owner_email", "name",
                                        "owner_name", "phone")
                            if f'"{f}"' in r.text and f'"{f}": null' not in r.text
                            and f'"{f}":null' not in r.text]
            detail["owner_fields_returned"] = owner_fields
            if owner_fields:
                problems.append(
                    "a status lookup by licence key alone returns owner "
                    "details: " + ", ".join(owner_fields))
        except requests.RequestException:
            pass

        ev = ctx.evidence.data(self.id, str(target).replace(".", "_"), detail,
                               "cross-identity probes")

        if problems:
            return [self.fail(
                target, "; ".join(problems),
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            "A credential from one identity did not grant access to another's "
            "record",
            evidence=[ev], detail=detail)]


class ResponseSecretLeakage(Check):
    """API-07 — responses must not carry internal detail to a client."""

    id = "API-07"
    protocol = "api"
    access = "unauth"

    def applicable(self, target, ctx):
        return bool(_base(target) and target.meta.get("endpoints"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        base = _base(target)
        findings_detail: Dict[str, Any] = {"responses": {}}
        problems: List[str] = []

        enrolled = _enrol(target)
        key = (enrolled or {}).get(
            target.meta.get("license_key_field", "license_key"))

        for ep in target.meta["endpoints"]:
            path = ep.get("path")
            if not path:
                continue
            body = dict(ep.get("sample_body") or {})
            if key and target.meta.get("license_key_field", "license_key") in body:
                body[target.meta.get("license_key_field", "license_key")] = key
            if enrolled and "device_id" in body:
                body["device_id"] = enrolled["_device_id"]
            try:
                r = requests.post(f"{base}{path}", json=body, timeout=20)
            except requests.RequestException:
                continue

            text = r.text[:6000]
            findings_detail["responses"][path] = {
                "status": r.status_code, "excerpt": text[:300]}

            for m in SECRET_FIELD_RE.finditer(text):
                problems.append(f"{path} returns a '{m.group(1)}' field")
                break
            # Internal addresses are expected inside a tunnel config; only
            # flag them on endpoints the scope has not marked as such.
            if not ep.get("returns_tunnel_config"):
                ips = set(PRIVATE_IP_RE.findall(text))
                if ips:
                    problems.append(
                        f"{path} exposes internal address(es): "
                        + ", ".join(sorted(ips)[:3]))
            # A stack trace is both a leak and a reliability signal.
            if "Traceback (most recent call last)" in text:
                problems.append(f"{path} returned a Python traceback")
            time.sleep(1.0 / max(ctx.rate_limit("requests_per_second", 5), 1))

        ev = ctx.evidence.data(self.id, str(target).replace(".", "_"),
                               findings_detail, "response bodies")

        if problems:
            return [self.fail(
                target, "; ".join(sorted(set(problems))),
                severity=Severity.HIGH, evidence=[ev], detail=findings_detail)]
        return [self.ok(
            target,
            f"No secret fields, internal addresses or tracebacks across "
            f"{len(findings_detail['responses'])} response(s)",
            evidence=[ev], detail=findings_detail)]
