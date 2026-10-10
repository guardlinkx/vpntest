"""IPS-02, IPS-03, IPS-04, IPS-05, IPS-13 — what the gateway will agree to.

Each algorithm check varies one dimension against a fixed baseline, so an
accept or refuse maps to exactly one transform. The baseline itself is
verified first: if the gateway refuses it, every subsequent "refused" result
would be meaningless, so the check reports an error instead of a clean sweep
of passes.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from ...model import Check, Context, Finding, Severity, Target
from ...wrappers import ikev2 as ike

# Encryption: (label, transform id, key length) and whether policy allows it.
ENCR_CANDIDATES = [
    ("DES",               (ike.ENCR["DES"], None),        False),
    ("3DES",              (ike.ENCR["3DES"], None),       False),
    ("NULL",              (ike.ENCR["NULL"], None),       False),
    ("AES-CBC-128",       (ike.ENCR["AES_CBC"], 128),     True),
    ("AES-CBC-192",       (ike.ENCR["AES_CBC"], 192),     True),
    ("AES-CBC-256",       (ike.ENCR["AES_CBC"], 256),     True),
    ("AES-GCM-16-128",    (ike.ENCR["AES_GCM_16"], 128),  True),
    ("AES-GCM-16-256",    (ike.ENCR["AES_GCM_16"], 256),  True),
    ("CHACHA20-POLY1305", (ike.ENCR["CHACHA20_POLY1305"], None), True),
]

DH_CANDIDATES = [
    ("group 1 (modp768)",   ike.DH["MODP_768"],   False),
    ("group 2 (modp1024)",  ike.DH["MODP_1024"],  False),
    ("group 5 (modp1536)",  ike.DH["MODP_1536"],  False),
    ("group 14 (modp2048)", ike.DH["MODP_2048"],  True),
    ("group 15 (modp3072)", ike.DH["MODP_3072"],  True),
    ("group 16 (modp4096)", ike.DH["MODP_4096"],  True),
    ("group 19 (ecp256)",   ike.DH["ECP_256"],    True),
    ("group 20 (ecp384)",   ike.DH["ECP_384"],    True),
    ("group 21 (ecp521)",   ike.DH["ECP_521"],    True),
    ("group 31 (x25519)",   ike.DH["CURVE25519"], True),
]

PRF_CANDIDATES = [
    ("HMAC-MD5",      ike.PRF["HMAC_MD5"],      False),
    ("HMAC-SHA1",     ike.PRF["HMAC_SHA1"],     False),
    ("AES128-XCBC",   ike.PRF["AES128_XCBC"],   True),
    ("HMAC-SHA2-256", ike.PRF["HMAC_SHA2_256"], True),
    ("HMAC-SHA2-384", ike.PRF["HMAC_SHA2_384"], True),
    ("HMAC-SHA2-512", ike.PRF["HMAC_SHA2_512"], True),
]

INTEG_CANDIDATES = [
    ("HMAC-MD5-96",       ike.INTEG["HMAC_MD5_96"],       False),
    ("HMAC-SHA1-96",      ike.INTEG["HMAC_SHA1_96"],      False),
    ("AES-XCBC-96",       ike.INTEG["AES_XCBC_96"],       True),
    ("HMAC-SHA2-256-128", ike.INTEG["HMAC_SHA2_256_128"], True),
    ("HMAC-SHA2-384-192", ike.INTEG["HMAC_SHA2_384_192"], True),
    ("HMAC-SHA2-512-256", ike.INTEG["HMAC_SHA2_512_256"], True),
]


def _baseline_ok(target: Target) -> Tuple[bool, str]:
    """Confirm the gateway answers a known-good proposal before we trust refusals."""
    r = ike.probe(target.host, ike.BASE["encr"], ike.BASE["prf"],
                  ike.BASE["integ"], ike.BASE["dh"], retries=2)
    if not r.get("answered"):
        return False, "the gateway did not answer IKE_SA_INIT at all"
    if not ike.accepted(r):
        return False, (f"the gateway refused the baseline proposal "
                       f"({ike.rejected_reason(r)}); refusals below would be "
                       "meaningless")
    return True, ""


def _sweep(target: Target, ctx: Context, kind: str,
           candidates) -> Tuple[Dict[str, Optional[bool]], List[str],
                                List[str], List[str]]:
    """Offer each candidate alone; return accepted map plus policy verdicts."""
    results: Dict[str, Optional[bool]] = {}
    bad_accepted: List[str] = []
    good_refused: List[str] = []
    undetermined: List[str] = []
    pace = 1.0 / max(ctx.rate_limit("requests_per_second", 5), 1)

    for label, value, allowed in candidates:
        if kind == "encr":
            r = ike.probe(target.host, value, ike.BASE["prf"],
                          ike.BASE["integ"], ike.BASE["dh"])
        elif kind == "dh":
            r = ike.probe(target.host, ike.BASE["encr"], ike.BASE["prf"],
                          ike.BASE["integ"], value)
        elif kind == "prf":
            r = ike.probe(target.host, ike.BASE["encr"], value,
                          ike.BASE["integ"], ike.BASE["dh"])
        else:
            r = ike.probe(target.host, ike.BASE["encr"], ike.BASE["prf"],
                          value, ike.BASE["dh"])

        ok = ike.accepted(r)
        # A probe that drew no answer at all tells us nothing: UDP is lossy
        # and a busy gateway drops SA_INITs. Retry once before recording a
        # refusal, or transient loss gets written down as policy.
        if not ok and not r.get("answered"):
            time.sleep(pace)
            if kind == "encr":
                r = ike.probe(target.host, value, ike.BASE["prf"],
                              ike.BASE["integ"], ike.BASE["dh"], retries=1)
            elif kind == "dh":
                r = ike.probe(target.host, ike.BASE["encr"], ike.BASE["prf"],
                              ike.BASE["integ"], value, retries=1)
            elif kind == "prf":
                r = ike.probe(target.host, ike.BASE["encr"], value,
                              ike.BASE["integ"], ike.BASE["dh"], retries=1)
            else:
                r = ike.probe(target.host, ike.BASE["encr"], ike.BASE["prf"],
                              value, ike.BASE["dh"], retries=1)
            ok = ike.accepted(r)

        # Three states, not two. A gateway issuing cookie challenges gives no
        # policy answer at all, and recording that as "refused" would report a
        # permissive gateway as a clean one.
        if not ok and ike.undetermined(r):
            results[label] = None
            undetermined.append(label)
        else:
            results[label] = ok
            if ok and not allowed:
                bad_accepted.append(label)
            if not ok and allowed:
                good_refused.append(label)
        time.sleep(pace)

    return results, bad_accepted, good_refused, undetermined


class IkeEncryption(Check):
    """IPS-03 — approved IKE encryption only."""

    id = "IPS-03"
    protocol = "ipsec"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        ok, why = _baseline_ok(target)
        if not ok:
            return [self.error(target, why)]

        results, bad, _, unknown = _sweep(target, ctx, "encr", ENCR_CANDIDATES)
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), results,
                               "one-transform IKE encryption sweep")
        if bad:
            return [self.fail(
                target, "Obsolete or null encryption accepted: " + ", ".join(bad),
                severity=Severity.CRITICAL if "NULL" in " ".join(bad) else Severity.HIGH,
                evidence=[ev], detail=results)]
        accepted = [k for k, v in results.items() if v]
        note = f" ({len(unknown)} undetermined)" if unknown else ""
        return [self.ok(
            target,
            "Only approved encryption accepted: " + ", ".join(accepted) + note,
            evidence=[ev], detail=results)]


class IkeDhGroups(Check):
    """IPS-04 — group 14 or better; the small groups must be refused."""

    id = "IPS-04"
    protocol = "ipsec"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        ok, why = _baseline_ok(target)
        if not ok:
            return [self.error(target, why)]

        results, bad, _, unknown = _sweep(target, ctx, "dh", DH_CANDIDATES)
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), results,
                               "Diffie-Hellman group sweep")

        findings: List[Finding] = []
        if bad:
            findings.append(self.fail(
                target, "Weak DH group(s) accepted: " + ", ".join(bad),
                severity=Severity.HIGH, evidence=[ev], detail=results))
        modern = [k for k, v in results.items()
                  if v and ("ecp" in k or "x25519" in k)]
        ec_unknown = [k for k in unknown if "ecp" in k or "x25519" in k]
        if not modern and not bad and ec_unknown:
            findings.append(self.warn(
                target,
                "Could not determine whether elliptic-curve groups are "
                "accepted — the gateway answered with cookie challenges for "
                + ", ".join(ec_unknown)
                + ". Re-run when it is less busy.",
                severity=Severity.LOW, evidence=[ev], detail=results))
        elif not modern and not bad:
            findings.append(self.warn(
                target,
                "No elliptic-curve group accepted; groups 19-21 or x25519 are "
                "preferred over modp",
                evidence=[ev], detail=results))
        if not findings:
            accepted = [k for k, v in results.items() if v]
            findings.append(self.ok(
                target, "Only strong groups accepted: " + ", ".join(accepted),
                evidence=[ev], detail=results))
        return findings


class IkePrfAndIntegrity(Check):
    """IPS-05 — SHA-2 family only; no MD5 or SHA-1."""

    id = "IPS-05"
    protocol = "ipsec"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        ok, why = _baseline_ok(target)
        if not ok:
            return [self.error(target, why)]

        prf_res, prf_bad, _, prf_unknown = _sweep(target, ctx, "prf", PRF_CANDIDATES)
        int_res, int_bad, _, int_unknown = _sweep(target, ctx, "integ", INTEG_CANDIDATES)
        unknown = prf_unknown + int_unknown

        detail = {"prf": prf_res, "integrity": int_res}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "PRF and integrity sweeps")

        problems = []
        if prf_bad:
            problems.append("PRF: " + ", ".join(prf_bad))
        if int_bad:
            problems.append("integrity: " + ", ".join(int_bad))

        if problems:
            return [self.fail(
                target, "MD5 or SHA-1 still accepted — " + "; ".join(problems),
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(
            target, "Only SHA-2 family PRF and integrity accepted",
            evidence=[ev], detail=detail)]


class IkeV1AggressiveMode(Check):
    """IPS-02 — IKEv1 aggressive mode leaks a PSK hash offline; it must be off.

    The discriminator is the *exchange type* of the reply, not whether one
    arrived. An IKEv2-only gateway answers an IKEv1 packet with an
    Informational exchange carrying a notify such as INVALID-MAJOR-VERSION or
    PAYLOAD-MALFORMED — which is correct behaviour, not a weakness. Only an
    Aggressive exchange (type 4) coming back means aggressive mode is live.
    """

    id = "IPS-02"
    protocol = "ipsec"
    access = "unauth"

    # ISAKMP notify types (RFC 2408 section 3.14.1) that are plainly refusals.
    REFUSALS = {
        1: "INVALID-PAYLOAD-TYPE", 5: "INVALID-MAJOR-VERSION",
        6: "INVALID-MINOR-VERSION", 7: "INVALID-EXCHANGE-TYPE",
        8: "INVALID-FLAGS", 14: "NO-PROPOSAL-CHOSEN",
        16: "PAYLOAD-MALFORMED", 17: "INVALID-KEY-INFORMATION",
    }
    EXCHANGE_AGGRESSIVE = 4
    EXCHANGE_INFORMATIONAL = 5
    PAYLOAD_SA_V1 = 1
    PAYLOAD_NOTIFY_V1 = 11

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        import os as _os
        spi = _os.urandom(8)
        pkt = struct.pack("!8s8sBBBBII", spi, b"\x00" * 8,
                          self.PAYLOAD_SA_V1, 0x10,
                          self.EXCHANGE_AGGRESSIVE, 0, 0, 28)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4.0)
        data = b""
        try:
            sock.sendto(pkt, (target.host, ike.IKE_PORT))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

        detail: Dict[str, Any] = {"answered": bool(data),
                                  "reply_hex": data[:48].hex() if data else None}

        if not data or len(data) < 28:
            detail["verdict"] = "no reply"
            ev = ctx.evidence.data(self.id, target.host.replace(".", "_"),
                                   detail, "IKEv1 aggressive-mode probe")
            return [self.ok(target, "No response to an IKEv1 aggressive-mode request",
                            evidence=[ev], detail=detail)]

        next_payload, version, exchange = data[16], data[17], data[18]
        detail.update(major_version=version >> 4, exchange_type=exchange,
                      next_payload=next_payload)

        notify = None
        if next_payload == self.PAYLOAD_NOTIFY_V1 and len(data) >= 40:
            notify = struct.unpack("!H", data[38:40])[0]
            detail["notify"] = self.REFUSALS.get(notify, f"type {notify}")

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "IKEv1 aggressive-mode probe")

        if exchange == self.EXCHANGE_AGGRESSIVE and next_payload == self.PAYLOAD_SA_V1:
            return [self.fail(
                target,
                "The gateway answered with an IKEv1 Aggressive exchange — "
                "aggressive mode is enabled and will expose a PSK hash",
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]

        reason = detail.get("notify") or f"exchange type {exchange}"
        return [self.ok(
            target,
            f"Aggressive mode refused ({reason})",
            evidence=[ev], detail=detail)]


class IkeCookieDefence(Check):
    """IPS-13 — the gateway should demand a COOKIE when half-open SAs pile up.

    Disruptive: it deliberately creates half-open SAs. Off unless the scope
    enables it by id, and capped hard even then.
    """

    id = "IPS-13"
    protocol = "ipsec"
    access = "unauth"
    disruptive = True

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        burst = min(int(ctx.rate_limit("max_half_open_sa", 20)), 40)
        saw_cookie = False
        answered = 0

        for _ in range(burst):
            r = ike.probe(target.host, ike.BASE["encr"], ike.BASE["prf"],
                          ike.BASE["integ"], ike.BASE["dh"], timeout=1.5)
            if r.get("answered"):
                answered += 1
                if any(n["name"] == "COOKIE" for n in r.get("notifies", [])):
                    saw_cookie = True
                    break
            time.sleep(0.05)

        detail = {"attempts": burst, "answered": answered,
                  "cookie_issued": saw_cookie}
        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "half-open SA burst")

        if saw_cookie:
            return [self.ok(
                target, f"COOKIE challenge issued after {answered} half-open SAs",
                evidence=[ev], detail=detail)]
        return [self.warn(
            target,
            f"No COOKIE challenge after {answered} half-open SAs. The burst is "
            "deliberately small, so this is a hint rather than proof the "
            "threshold is absent.",
            evidence=[ev], detail=detail)]
