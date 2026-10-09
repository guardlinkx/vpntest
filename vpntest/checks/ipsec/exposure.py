"""IKEv2 reachability and gateway exposure.

Implemented with raw sockets rather than shelling out to ike-scan, so the tool
runs anywhere Python does. `ike-scan` is still the better instrument for deep
proposal enumeration and the wrappers package can call it when present; these
checks cover what can be established without it.
"""

from __future__ import annotations

import os
import random
import socket
import struct
from typing import List, Optional, Tuple

from ...model import Check, Context, Finding, Severity, Target

IKE_PORT = 500
NATT_PORT = 4500

# Ports that should never face the internet on a VPN gateway. Anything here
# that answers is reported; the catalog decides how badly.
SENSITIVE_TCP = {
    22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3389: "RDP",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9090: "admin", 10000: "webmin",
    5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB",
}


def _ike_sa_init(initiator_spi: bytes, exchange: int = 34,
                 version: int = 0x20) -> bytes:
    """A minimal IKE header with no payloads.

    Enough to find out whether something is listening and speaking IKE: a
    gateway answers an unparseable SA_INIT with a notify (usually
    INVALID_SYNTAX or NO_PROPOSAL_CHOSEN) rather than silence.
    """
    responder_spi = b"\x00" * 8
    next_payload = 0           # none
    flags = 0x08               # initiator
    message_id = 0
    length = 28
    return struct.pack(
        "!8s8sBBBBII",
        initiator_spi, responder_spi, next_payload, version,
        exchange, flags, message_id, length,
    )


def _probe_ike(host: str, port: int, timeout: float = 3.0,
               version: int = 0x20) -> Tuple[bool, Optional[bytes]]:
    spi = os.urandom(8)
    pkt = _ike_sa_init(spi, version=version)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        return True, data
    except (socket.timeout, OSError):
        return False, None
    finally:
        sock.close()


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


class IkeVersionExposure(Check):
    """IPS-01 — the gateway answers IKEv2 and not IKEv1."""

    id = "IPS-01"
    protocol = "ipsec"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        detail = {}
        v2_alive, v2_data = _probe_ike(target.host, IKE_PORT, version=0x20)
        v1_alive, v1_data = _probe_ike(target.host, IKE_PORT, version=0x10)
        detail["ikev2_responded"] = v2_alive
        detail["ikev1_responded"] = v1_alive

        # An IKEv2-only gateway still answers an IKEv1 packet, with an
        # Informational exchange refusing it. Only a non-Informational IKEv1
        # reply means the v1 stack is actually serving.
        v1_serving = False
        if v1_data and len(v1_data) >= 19:
            v1_exchange = v1_data[18]
            detail["ikev1_exchange_type"] = v1_exchange
            v1_serving = (v1_data[17] >> 4) == 1 and v1_exchange != 5
        if v2_data:
            detail["ikev2_reply_hex"] = v2_data[:64].hex()
        if v1_data:
            detail["ikev1_reply_hex"] = v1_data[:64].hex()

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "IKE version probes on UDP/500")

        if not v2_alive and not v1_alive:
            return [self.na(
                target,
                "Nothing answered IKE on UDP/500 — either no IPsec here, or it "
                "is silent to malformed initiators (some gateways are)",
                evidence=[ev], detail=detail)]
        if v1_serving:
            return [self.fail(
                target, "The gateway serves IKEv1, not only IKEv2",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            "IKEv2 responds; IKEv1 is refused"
            + (" (Informational rejection)" if v1_alive else " (no reply)"),
            evidence=[ev], detail=detail)]


class GatewayPortExposure(Check):
    """IPS-14 — only IKE and NAT-T should face the internet."""

    id = "IPS-14"
    protocol = "ipsec"
    access = "unauth"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        expected = set(target.meta.get("expected_tcp_ports") or [])
        open_ports, detail = [], {}

        for port, name in sorted(SENSITIVE_TCP.items()):
            if _tcp_open(target.host, port):
                open_ports.append((port, name))
        detail["open_tcp"] = [{"port": p, "service": n} for p, n in open_ports]

        udp = {}
        for port in (IKE_PORT, NATT_PORT):
            alive, _ = _probe_ike(target.host, port)
            udp[port] = alive
        detail["ike_udp"] = udp

        ev = ctx.evidence.data(self.id, target.host.replace(".", "_"), detail,
                               "gateway port exposure")

        unexpected = [f"{p}/{n}" for p, n in open_ports if p not in expected]
        if unexpected:
            sev = Severity.CRITICAL if any(
                p in (3389, 5432, 3306, 6379, 27017) for p, _ in open_ports
            ) else Severity.HIGH
            return [self.fail(
                target,
                "Publicly reachable beyond IKE: " + ", ".join(unexpected) +
                ". Declare intended ports in the scope file to silence expected ones.",
                severity=sev, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            "No unexpected TCP services exposed" +
            (f" (allowed: {sorted(expected)})" if expected else ""),
            evidence=[ev], detail=detail)]
