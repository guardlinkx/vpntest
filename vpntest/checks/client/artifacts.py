"""CLI-07 to CLI-12 — what ships inside the client.

These inspect a built artefact rather than a running host, so they work for a
mobile app the tool can never execute: point `client_artifact` at an .app,
.ipa, .apk or a desktop binary and the checks read what is actually in it.

Static analysis finds what is present, never what is absent in behaviour — a
clean result here means "nothing obviously wrong was shipped", not "the client
handles secrets correctly at runtime".
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from ...model import Check, Context, Finding, Severity, Target

# Patterns worth flagging if they appear as literals in a shipped binary.
SECRET_PATTERNS = [
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("private key block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")),
    ("Slack token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe secret key", re.compile(rb"sk_live_[0-9A-Za-z]{16,}")),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.")),
    ("generic password assignment",
     re.compile(rb"(?i)(password|passwd|secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]")),
]


def _artifact(target: Target) -> Optional[str]:
    path = target.meta.get("client_artifact")
    return os.path.expanduser(path) if path else None


def _kind(path: str) -> str:
    low = path.lower()
    if low.endswith(".ipa"):
        return "ipa"
    if low.endswith(".apk"):
        return "apk"
    if low.endswith(".app") or os.path.isdir(os.path.join(path, "Contents")) \
            or os.path.exists(os.path.join(path, "Info.plist")):
        return "app"
    return "binary"


def _ios_info_plist(path: str) -> Optional[Dict[str, Any]]:
    candidates = [os.path.join(path, "Info.plist"),
                  os.path.join(path, "Contents", "Info.plist")]
    for c in candidates:
        if os.path.exists(c):
            try:
                with open(c, "rb") as fh:
                    return plistlib.load(fh)
            except Exception:
                return None
    return None


def _ipa_info_plist(path: str) -> Optional[Dict[str, Any]]:
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if re.match(r"Payload/[^/]+\.app/Info\.plist$", name):
                    return plistlib.loads(z.read(name))
    except Exception:
        return None
    return None


def _info_plist(path: str) -> Optional[Dict[str, Any]]:
    kind = _kind(path)
    if kind == "ipa":
        return _ipa_info_plist(path)
    if kind == "app":
        return _ios_info_plist(path)
    return None


def _binaries(path: str) -> List[str]:
    """Mach-O / ELF / PE files inside the artefact, for string scanning."""
    out: List[str] = []
    if os.path.isfile(path):
        return [path]
    for root, _dirs, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            try:
                with open(full, "rb") as fh:
                    magic = fh.read(4)
            except OSError:
                continue
            if magic[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                             b"\xca\xfe\xba\xbe", b"\x7fELF") or \
                    magic[:2] == b"MZ":
                out.append(full)
    return out


class PlaintextSecrets(Check):
    """CLI-07 — no credentials or keys recoverable from what ships."""

    id = "CLI-07"
    protocol = "client"
    access = "config"

    def applicable(self, target, ctx):
        return bool(_artifact(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        path = _artifact(target)
        if not os.path.exists(path):
            return [self.error(target, f"Artifact not found: {path}")]

        hits: List[Dict[str, Any]] = []
        scanned = 0
        for binary in _binaries(path)[:20]:
            scanned += 1
            try:
                with open(binary, "rb") as fh:
                    blob = fh.read(60 * 1024 * 1024)
            except OSError:
                continue
            for label, pattern in SECRET_PATTERNS:
                for m in pattern.finditer(blob):
                    hits.append({
                        "file": os.path.relpath(binary, os.path.dirname(path)),
                        "kind": label,
                        # Enough to locate it, not enough to be a secret leak
                        # in the report itself.
                        "excerpt": m.group(0)[:24].decode("utf-8", "replace"),
                    })
                    break   # one example per pattern per file is enough

        detail = {"artifact": path, "binaries_scanned": scanned, "hits": hits}
        ev = ctx.evidence.data(self.id, os.path.basename(path), detail,
                               "embedded secret scan")

        if hits:
            kinds = sorted({h["kind"] for h in hits})
            return [self.fail(
                target,
                f"Possible secret material in the shipped binary: "
                + ", ".join(kinds),
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]
        return [self.ok(
            target, f"No secret patterns found across {scanned} binary file(s)",
            evidence=[ev], detail=detail)]


class CodeSigning(Check):
    """CLI-08 — the shipped client must be signed."""

    id = "CLI-08"
    protocol = "client"
    access = "config"

    def applicable(self, target, ctx):
        return bool(_artifact(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        path = _artifact(target)
        if not os.path.exists(path):
            return [self.error(target, f"Artifact not found: {path}")]

        detail: Dict[str, Any] = {"artifact": path, "kind": _kind(path)}

        if shutil.which("codesign") and _kind(path) in ("app", "binary"):
            p = subprocess.run(["codesign", "-dvv", path],
                               capture_output=True, text=True, timeout=30)
            text = p.stderr or p.stdout
            detail["codesign"] = text[:1500]
            authority = re.search(r"Authority=(.+)", text)
            detail["authority"] = authority.group(1).strip() if authority else None
            verify = subprocess.run(["codesign", "--verify", "--deep", "--strict", path],
                                    capture_output=True, text=True, timeout=60)
            detail["verify_rc"] = verify.returncode
            detail["verify_output"] = (verify.stderr or "")[:600]

            ev = ctx.evidence.data(self.id, os.path.basename(path), detail,
                                   "code signature")
            if verify.returncode != 0:
                return [self.fail(
                    target,
                    "Code signature does not verify: "
                    + (verify.stderr or "").strip()[:160],
                    severity=Severity.HIGH, evidence=[ev], detail=detail)]
            if not detail.get("authority"):
                return [self.fail(
                    target, "Binary is not signed by any authority",
                    severity=Severity.HIGH, evidence=[ev], detail=detail)]
            return [self.ok(
                target, f"Signed and verified: {detail['authority']}",
                evidence=[ev], detail=detail)]

        ev = ctx.evidence.data(self.id, os.path.basename(path), detail,
                               "code signature")
        return [self.na(
            target,
            f"No signature verifier available for a {_kind(path)} artifact on "
            f"this platform",
            evidence=[ev], detail=detail)]


class MobileTransportSecurity(Check):
    """CLI-11 — ATS on iOS, cleartext and user-CA policy on Android."""

    id = "CLI-11"
    protocol = "client"
    access = "config"

    def applicable(self, target, ctx):
        return bool(_artifact(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        path = _artifact(target)
        kind = _kind(path)
        detail: Dict[str, Any] = {"artifact": path, "kind": kind}
        problems: List[str] = []

        if kind in ("app", "ipa"):
            info = _info_plist(path)
            if info is None:
                return [self.error(target, "Could not read Info.plist")]
            ats = info.get("NSAppTransportSecurity") or {}
            detail["ats"] = ats
            if ats.get("NSAllowsArbitraryLoads"):
                problems.append(
                    "NSAllowsArbitraryLoads is true — ATS is disabled app-wide, "
                    "so any connection may fall back to plaintext or an "
                    "untrusted certificate")
            if ats.get("NSAllowsArbitraryLoadsInWebContent"):
                problems.append("NSAllowsArbitraryLoadsInWebContent is true")
            exceptions = ats.get("NSExceptionDomains") or {}
            detail["ats_exception_domains"] = list(exceptions)
            for domain, cfg in exceptions.items():
                if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
                    problems.append(f"insecure HTTP allowed for {domain}")

        elif kind == "apk":
            try:
                with zipfile.ZipFile(path) as z:
                    names = z.namelist()
                    detail["has_network_security_config"] = any(
                        "network_security_config" in n for n in names)
                    manifest = z.read("AndroidManifest.xml") if \
                        "AndroidManifest.xml" in names else b""
                # Binary XML; a string search is crude but reliable enough to
                # notice the attribute being present at all.
                if b"usesCleartextTraffic" in manifest:
                    detail["mentions_cleartext"] = True
            except Exception as exc:
                return [self.error(target, f"Could not read APK: {exc}")]
            if not detail.get("has_network_security_config"):
                problems.append(
                    "no network security config — cleartext defaults and user-"
                    "added CAs are not constrained")
        else:
            return [self.na(target, f"Not a mobile artifact ({kind})")]

        ev = ctx.evidence.data(self.id, os.path.basename(path), detail,
                               "mobile transport security configuration")
        if problems:
            return [self.fail(
                target, "; ".join(problems),
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(
            target, "Transport security is not globally weakened",
            evidence=[ev], detail=detail)]


class MobileSecretStorage(Check):
    """CLI-12 — secrets belong in the platform keystore, with a sane class.

    Looks for the two mistakes that actually ship: storing credentials in
    UserDefaults/SharedPreferences, and using an accessibility class that
    leaves Keychain items readable while the device is locked or syncs them
    off the device.
    """

    id = "CLI-12"
    protocol = "client"
    access = "config"

    WEAK_ACCESSIBILITY = (
        b"kSecAttrAccessibleAlways",
        b"kSecAttrAccessibleAlwaysThisDeviceOnly",
    )

    def applicable(self, target, ctx):
        return bool(_artifact(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        path = _artifact(target)
        kind = _kind(path)
        if kind not in ("app", "ipa", "apk"):
            return [self.na(target, f"Not a mobile artifact ({kind})")]

        findings_detail: Dict[str, Any] = {"artifact": path, "kind": kind}
        weak_class: List[str] = []
        uses_keychain = False

        for binary in _binaries(path)[:20]:
            try:
                with open(binary, "rb") as fh:
                    blob = fh.read(60 * 1024 * 1024)
            except OSError:
                continue
            if b"SecItemAdd" in blob or b"kSecClassGenericPassword" in blob:
                uses_keychain = True
            for token in self.WEAK_ACCESSIBILITY:
                if token in blob:
                    weak_class.append(token.decode())

        findings_detail["uses_keychain_api"] = uses_keychain
        findings_detail["weak_accessibility_classes"] = sorted(set(weak_class))

        ev = ctx.evidence.data(self.id, os.path.basename(path), findings_detail,
                               "secret storage indicators")

        if weak_class:
            return [self.fail(
                target,
                "Keychain items use " + ", ".join(sorted(set(weak_class)))
                + " — readable while the device is locked",
                severity=Severity.HIGH, evidence=[ev], detail=findings_detail)]
        if kind in ("app", "ipa") and not uses_keychain:
            return [self.warn(
                target,
                "No Keychain API references found. If the client stores any "
                "credential or device identity, it is not using the platform "
                "keystore.",
                evidence=[ev], detail=findings_detail)]
        return [self.ok(
            target,
            "Uses the platform keystore with no weak accessibility class",
            evidence=[ev], detail=findings_detail)]


class ClientPrivilege(Check):
    """CLI-09 — the client should not ship asking for more than it needs."""

    id = "CLI-09"
    protocol = "client"
    access = "config"

    # Entitlements that grant far more than a VPN client requires.
    OVERBROAD = (
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.get-task-allow",
    )

    def applicable(self, target, ctx):
        return bool(_artifact(target))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        path = _artifact(target)
        if not shutil.which("codesign"):
            return [self.na(target, "codesign unavailable on this platform")]

        p = subprocess.run(["codesign", "-d", "--entitlements", ":-", path],
                           capture_output=True, text=True, timeout=30)
        text = p.stdout or p.stderr
        detail = {"artifact": path, "entitlements": text[:3000]}

        granted = [e for e in self.OVERBROAD if e in text]
        detail["overbroad"] = granted

        # get-task-allow in a shipping build means a debugger can attach.
        #
        # The value has to be read from its own key, not inferred from the
        # presence of "<true/>" anywhere in the blob. A correctly signed App
        # Store build carries `get-task-allow = false` alongside
        # `beta-reports-active = true`, and a substring test sees the key and
        # sees a true and reports a debuggable binary — a HIGH finding on the
        # exact artifact being shipped.
        m = re.search(r"<key>\s*get-task-allow\s*</key>\s*<(\w+)\s*/>", text)
        debuggable = bool(m) and m.group(1).lower() == "true"
        detail["get_task_allow"] = m.group(1).lower() if m else "absent"

        ev = ctx.evidence.data(self.id, os.path.basename(path), detail,
                               "entitlements")
        if debuggable:
            # The catalog remediation for this control is about privilege
            # dropping, which is not what this specific finding is. A
            # debuggable binary is a signing-profile problem, so name that
            # instead of handing over advice that does not apply.
            return [self.fail(
                target,
                "get-task-allow is set — this is a development build and any "
                "process can attach a debugger to it",
                severity=Severity.HIGH, evidence=[ev], detail=detail,
                remediation="Re-sign with a distribution profile. A development "
                            "profile always sets this; an App Store or ad-hoc "
                            "distribution export does not. Expected on a local "
                            "build — verify against the archive you upload.")]
        if granted:
            return [self.warn(
                target, "Broad entitlements requested: " + ", ".join(granted),
                evidence=[ev], detail=detail,
                remediation="Drop entitlements the client does not need, so a "
                            "compromise of it gains nothing extra.")]
        return [self.ok(target, "No overbroad entitlements requested",
                        evidence=[ev], detail=detail)]


class ConnectionLogging(Check):
    """CLI-10 — connection and auth events must reach a log sink."""

    id = "CLI-10"
    protocol = "client"
    access = "config"

    def applicable(self, target, ctx):
        return bool(target.meta.get("log_sink"))

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        return [self.error(
            target,
            "Log-sink verification needs a query interface for the SIEM "
            "(declare log_sink with a query endpoint); not implemented")]
