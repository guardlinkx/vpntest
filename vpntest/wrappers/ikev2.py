"""Minimal IKEv2 (RFC 7296) packet construction for policy probing.

Written against the RFC rather than wrapping ike-scan or Scapy, so the tool has
no external dependency for its core protocol work and the exact bytes on the
wire are visible here.

The technique is one transform per IKE_SA_INIT. A gateway answers an
acceptable proposal with an SA_INIT response naming the transform it chose,
and an unacceptable one with NO_PROPOSAL_CHOSEN. Offering a single transform
at a time therefore reads the gateway's policy precisely, where a combined
proposal would only reveal its favourite.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Dict, List, Optional, Tuple

IKE_PORT = 500

# Payload type numbers (RFC 7296 section 3.2)
PAYLOAD_NONE = 0
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_NONCE = 40
PAYLOAD_NOTIFY = 41

EXCHANGE_IKE_SA_INIT = 34
FLAG_INITIATOR = 0x08

# Transform types
T_ENCR, T_PRF, T_INTEG, T_DH = 1, 2, 3, 4

ENCR = {
    "DES": 2, "3DES": 3, "RC5": 4, "IDEA": 5, "CAST": 6, "BLOWFISH": 7,
    "NULL": 11, "AES_CBC": 12, "AES_CTR": 13,
    "AES_CCM_8": 14, "AES_CCM_12": 15, "AES_CCM_16": 16,
    "AES_GCM_8": 18, "AES_GCM_12": 19, "AES_GCM_16": 20,
    "CHACHA20_POLY1305": 28,
}
PRF = {
    "HMAC_MD5": 1, "HMAC_SHA1": 2, "AES128_XCBC": 4,
    "HMAC_SHA2_256": 5, "HMAC_SHA2_384": 6, "HMAC_SHA2_512": 7,
}
INTEG = {
    "NONE": 0, "HMAC_MD5_96": 1, "HMAC_SHA1_96": 2, "AES_XCBC_96": 5,
    "HMAC_SHA2_256_128": 12, "HMAC_SHA2_384_192": 13, "HMAC_SHA2_512_256": 14,
}
DH = {
    "MODP_768": 1, "MODP_1024": 2, "MODP_1536": 5, "MODP_2048": 14,
    "MODP_3072": 15, "MODP_4096": 16, "MODP_6144": 17, "MODP_8192": 18,
    "ECP_256": 19, "ECP_384": 20, "ECP_521": 21,
    "MODP_1024_160": 22, "MODP_2048_224": 23, "MODP_2048_256": 24,
    "ECP_192": 25, "ECP_224": 26, "CURVE25519": 31, "CURVE448": 32,
}
# Key-exchange payload size per group, in bytes. A mismatch draws
# INVALID_KE_PAYLOAD, which is itself a useful answer.
KE_SIZE = {
    1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024,
    19: 64, 20: 96, 21: 132, 22: 128, 23: 256, 24: 256,
    25: 48, 26: 56, 31: 32, 32: 56,
}

NOTIFY = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_SYNTAX",
    5: "INVALID_MESSAGE_ID", 7: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
    16390: "COOKIE", 16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP", 16404: "MULTIPLE_AUTH_SUPPORTED",
    16430: "SIGNATURE_HASH_ALGORITHMS", 16406: "REDIRECT_SUPPORTED",
    16395: "IKEV2_FRAGMENTATION_SUPPORTED",
}


def _transform(ttype: int, tid: int, last: bool, keylen: Optional[int] = None) -> bytes:
    """One transform substructure, optionally with a key-length attribute."""
    attrs = b""
    if keylen is not None:
        # AF=1 (TV form), attribute type 14 = key length.
        attrs = struct.pack("!HH", 0x800E, keylen)
    length = 8 + len(attrs)
    return struct.pack("!BBHBBH", 0 if last else 3, 0, length, ttype, 0, tid) + attrs


def _sa_payload(transforms: List[bytes], next_payload: int) -> bytes:
    body = b"".join(transforms)
    # Proposal: last (0), reserved, length, num=1, protocol=IKE(1), SPI size 0.
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(body), 1, 1, 0,
                           len(transforms)) + body
    return struct.pack("!BBH", next_payload, 0, 4 + len(proposal)) + proposal


def _ke_payload(group: int, next_payload: int) -> bytes:
    size = KE_SIZE.get(group, 256)
    # Random data is fine: we never complete the exchange, and the responder
    # validates the group before the value.
    data = os.urandom(size)
    body = struct.pack("!HH", group, 0) + data
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def _nonce_payload(next_payload: int, size: int = 32) -> bytes:
    data = os.urandom(size)
    return struct.pack("!BBH", next_payload, 0, 4 + len(data)) + data


def build_sa_init(encr: Tuple[int, Optional[int]], prf: int, integ: int,
                  dh: int, spi: Optional[bytes] = None,
                  cookie: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """An IKE_SA_INIT offering exactly one transform of each type."""
    spi = spi or os.urandom(8)
    encr_id, encr_keylen = encr

    transforms = [
        _transform(T_ENCR, encr_id, False, encr_keylen),
        _transform(T_PRF, prf, False),
        _transform(T_INTEG, integ, False),
        _transform(T_DH, dh, True),
    ]

    first_payload = PAYLOAD_SA
    body = b""
    if cookie is not None:
        # A COOKIE notify must come first when echoing one back.
        notify = struct.pack("!BBHBBH", 0, 0, 0, 0, 0, 16390)[:8]
        notify = struct.pack("!BBH", PAYLOAD_SA, 0, 8 + len(cookie)) + \
                 struct.pack("!BBH", 0, 0, 16390) + cookie
        body += notify
        first_payload = PAYLOAD_NOTIFY

    body += _sa_payload(transforms, PAYLOAD_KE)
    body += _ke_payload(dh, PAYLOAD_NONCE)
    body += _nonce_payload(PAYLOAD_NONE)

    header = struct.pack(
        "!8s8sBBBBII",
        spi, b"\x00" * 8, first_payload, 0x20, EXCHANGE_IKE_SA_INIT,
        FLAG_INITIATOR, 0, 28 + len(body),
    )
    return header + body, spi


def parse_response(data: bytes) -> Dict:
    """Pull the interesting parts out of an SA_INIT response."""
    out: Dict = {"notifies": [], "accepted": None, "raw_len": len(data),
                 "is_response": False}
    if len(data) < 28:
        out["error"] = "short packet"
        return out

    (_, _, next_payload, version, exchange, flags, _, length) = struct.unpack(
        "!8s8sBBBBII", data[:28])
    out["version"] = f"{version >> 4}.{version & 0xF}"
    out["exchange"] = exchange
    out["is_response"] = bool(flags & 0x20)

    offset, nxt = 28, next_payload
    while nxt != PAYLOAD_NONE and offset + 4 <= len(data):
        p_next, _crit, p_len = struct.unpack("!BBH", data[offset:offset + 4])
        if p_len < 4 or offset + p_len > len(data):
            break
        body = data[offset + 4: offset + p_len]

        if nxt == PAYLOAD_NOTIFY and len(body) >= 4:
            _proto, spi_size, msg_type = struct.unpack("!BBH", body[:4])
            out["notifies"].append({
                "type": msg_type,
                "name": NOTIFY.get(msg_type, f"UNKNOWN_{msg_type}"),
                "data": body[4 + spi_size:][:64].hex(),
            })
        elif nxt == PAYLOAD_SA and len(body) >= 8:
            # The responder echoes the single proposal it accepted.
            chosen = {}
            p_off = 0
            while p_off + 8 <= len(body):
                _last, _r, prop_len, _num, _proto, spi_size, n_tr = struct.unpack(
                    "!BBHBBBB", body[p_off:p_off + 8])
                t_off = p_off + 8 + spi_size
                for _ in range(n_tr):
                    if t_off + 8 > len(body):
                        break
                    _tl, _tr2, t_len, t_type, _tr3, t_id = struct.unpack(
                        "!BBHBBH", body[t_off:t_off + 8])
                    chosen.setdefault(t_type, []).append(t_id)
                    if t_len < 8:
                        break
                    t_off += t_len
                if prop_len < 8:
                    break
                p_off += prop_len
            out["accepted"] = chosen

        offset += p_len
        nxt = p_next
    return out


def probe(host: str, encr: Tuple[int, Optional[int]], prf: int, integ: int,
          dh: int, port: int = IKE_PORT, timeout: float = 3.0,
          retries: int = 1) -> Dict:
    """Offer one transform set and report what came back."""
    for _ in range(retries + 1):
        pkt, _spi = build_sa_init(encr, prf, integ, dh)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(8192)
            parsed = parse_response(data)
            parsed["answered"] = True
            return parsed
        except (socket.timeout, OSError):
            continue
        finally:
            sock.close()
    return {"answered": False, "notifies": [], "accepted": None}


def accepted(result: Dict) -> bool:
    """True when the gateway agreed to the offered transform set."""
    if not result.get("answered"):
        return False
    names = {n["name"] for n in result.get("notifies", [])}
    if "NO_PROPOSAL_CHOSEN" in names or "INVALID_KE_PAYLOAD" in names:
        return False
    return bool(result.get("accepted"))


def rejected_reason(result: Dict) -> str:
    if not result.get("answered"):
        return "no response"
    names = [n["name"] for n in result.get("notifies", [])]
    return ", ".join(names) if names else "no proposal echoed"


# A baseline transform set that most gateways accept, used as the control when
# varying one dimension at a time.
BASE = {
    "encr": (ENCR["AES_CBC"], 256),
    "prf": PRF["HMAC_SHA2_256"],
    "integ": INTEG["HMAC_SHA2_256_128"],
    "dh": DH["MODP_2048"],
}
