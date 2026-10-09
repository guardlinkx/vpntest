"""One sslyze scan, shared by every SSL-xx check that needs it.

sslyze does a full handshake matrix, which is slow and noisy. Running it once
per target and caching the result keeps a twelve-control run to a single scan
instead of twelve, and keeps the target's logs proportionate to what we are
actually asking.

sslyze is optional: if it is not installed the checks that need it report
`error` with a clear reason rather than the whole run collapsing.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

_CACHE: Dict[str, Any] = {}

try:
    from sslyze import (
        Scanner,
        ScanCommand,
        ServerNetworkLocation,
        ServerScanRequest,
        ServerScanStatusEnum,
    )
    AVAILABLE = True
    IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - depends on environment
    AVAILABLE = False
    IMPORT_ERROR = str(exc)


ALL_COMMANDS = None
if AVAILABLE:
    ALL_COMMANDS = {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.TLS_COMPRESSION,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.HEARTBLEED,
        ScanCommand.OPENSSL_CCS_INJECTION,
        ScanCommand.ROBOT,
    }


class SslyzeUnavailable(RuntimeError):
    pass


def scan(host: str, port: int = 443, timeout: int = 60):
    """Scan once per (host, port) and reuse the result for the whole run."""
    if not AVAILABLE:
        raise SslyzeUnavailable(
            f"sslyze is not installed ({IMPORT_ERROR}). "
            "Install it to enable the SSL-xx checks: uv pip install sslyze"
        )

    key = f"{host}:{port}"
    if key in _CACHE:
        return _CACHE[key]

    location = ServerNetworkLocation(hostname=host, port=port)
    request = ServerScanRequest(server_location=location,
                                scan_commands=ALL_COMMANDS)
    scanner = Scanner()
    scanner.queue_scans([request])

    result = None
    for r in scanner.get_results():
        result = r
        break

    if result is None:
        raise RuntimeError(f"sslyze returned no result for {key}")
    if result.scan_status != ServerScanStatusEnum.COMPLETED:
        raise RuntimeError(
            f"sslyze could not connect to {key}: "
            f"{getattr(result, 'connectivity_error_trace', 'unknown')}"
        )

    _CACHE[key] = result
    return result


def attempt(result, name: str):
    """Return a completed scan attempt's result, or None.

    Every sslyze command can fail independently; a check must treat a failed
    command as "unknown", never as "passed".
    """
    attempts = result.scan_result
    att = getattr(attempts, name, None)
    if att is None:
        return None
    if getattr(att, "status", None) is None:
        return None
    if att.status.name != "COMPLETED":
        return None
    return att.result


def clear_cache() -> None:
    _CACHE.clear()
