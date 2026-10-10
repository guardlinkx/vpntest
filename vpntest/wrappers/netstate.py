"""Read the local host's network state, portably.

Leak testing is only meaningful from the endpoint while the tunnel is up, so
these helpers run against the machine executing the tool. macOS and Linux are
implemented natively; Windows is left to the C# agent, which can see things
(WFP filters, adapter metrics) that no subprocess output exposes cleanly.

Everything here shells out to the platform's own tools rather than parsing
/proc or IOKit directly: the output is what an operator would see, which makes
a finding reproducible by hand.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

SYSTEM = platform.system()          # Darwin | Linux | Windows

# Interface name prefixes that indicate a tunnel rather than physical hardware.
TUNNEL_PREFIXES = ("utun", "ipsec", "tun", "tap", "wg", "ppp", "gpd", "nordlynx")


def _run(argv: List[str], timeout: int = 10) -> str:
    if not shutil.which(argv[0]):
        return ""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def is_tunnel_interface(name: str) -> bool:
    return any(name.lower().startswith(p) for p in TUNNEL_PREFIXES)


def interfaces() -> List[Dict[str, Any]]:
    """Up interfaces with their addresses."""
    out: List[Dict[str, Any]] = []
    if SYSTEM in ("Darwin", "Linux"):
        text = _run(["ifconfig"]) or _run(["ip", "addr"])
        current = None
        for line in text.splitlines():
            m = re.match(r"^(\w[\w.:@-]*):?\s", line) or \
                re.match(r"^\d+:\s+([\w.:@-]+):", line)
            if m and not line.startswith((" ", "\t")):
                current = {"name": m.group(1).rstrip(":"), "ipv4": [], "ipv6": [],
                           "is_tunnel": is_tunnel_interface(m.group(1))}
                out.append(current)
            if current is None:
                continue
            for addr in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", line):
                current["ipv4"].append(addr)
            for addr in re.findall(r"inet6 ([0-9a-f:]+)", line):
                current["ipv6"].append(addr)
    return out


def default_route(family: int = 4) -> Dict[str, Any]:
    """Which interface carries the default route."""
    info: Dict[str, Any] = {"family": family, "interface": None,
                            "gateway": None, "raw": ""}
    if SYSTEM == "Darwin":
        target = "default" if family == 4 else "-inet6 default"
        text = _run(["route", "-n", "get"] + target.split())
        info["raw"] = text
        m = re.search(r"interface:\s*(\S+)", text)
        if m:
            info["interface"] = m.group(1)
        m = re.search(r"gateway:\s*(\S+)", text)
        if m:
            info["gateway"] = m.group(1)
    elif SYSTEM == "Linux":
        args = ["ip", "-6" if family == 6 else "-4", "route", "show", "default"]
        text = _run(args)
        info["raw"] = text
        m = re.search(r"dev\s+(\S+)", text)
        if m:
            info["interface"] = m.group(1)
        m = re.search(r"via\s+(\S+)", text)
        if m:
            info["gateway"] = m.group(1)
    return info


def route_for(destination: str) -> Dict[str, Any]:
    """Which interface a specific destination would use."""
    info: Dict[str, Any] = {"destination": destination, "interface": None,
                            "raw": ""}
    if SYSTEM == "Darwin":
        text = _run(["route", "-n", "get", destination])
        info["raw"] = text
        m = re.search(r"interface:\s*(\S+)", text)
        if m:
            info["interface"] = m.group(1)
    elif SYSTEM == "Linux":
        text = _run(["ip", "route", "get", destination])
        info["raw"] = text
        m = re.search(r"dev\s+(\S+)", text)
        if m:
            info["interface"] = m.group(1)
    return info


def resolvers() -> List[Dict[str, Any]]:
    """Configured DNS resolvers, with the interface each would be reached on."""
    found: List[str] = []
    if SYSTEM == "Darwin":
        text = _run(["scutil", "--dns"])
        found = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", text)
    elif SYSTEM == "Linux":
        text = _run(["resolvectl", "status"]) or ""
        found = re.findall(r"DNS Servers?:\s*(.+)", text)
        found = [a for line in found for a in line.split()]
        if not found:
            try:
                with open("/etc/resolv.conf") as fh:
                    found = re.findall(r"^nameserver\s+(\S+)", fh.read(), re.M)
            except OSError:
                found = []

    out, seen = [], set()
    for addr in found:
        if addr in seen:
            continue
        seen.add(addr)
        route = route_for(addr)
        out.append({
            "address": addr,
            "interface": route.get("interface"),
            "via_tunnel": is_tunnel_interface(route.get("interface") or ""),
        })
    return out


def ipv6_enabled() -> bool:
    for iface in interfaces():
        for addr in iface.get("ipv6", []):
            # Ignore link-local, which is always present and never routed.
            if not addr.lower().startswith("fe80"):
                return True
    return False


def tunnel_is_up() -> Optional[str]:
    """Name of the interface carrying the default route, if it is a tunnel."""
    iface = default_route(4).get("interface")
    return iface if iface and is_tunnel_interface(iface) else None


def firewall_rules() -> Dict[str, Any]:
    """Whatever the platform will tell us about a default-deny posture."""
    info: Dict[str, Any] = {"backend": None, "enabled": None, "raw": ""}
    if SYSTEM == "Darwin":
        text = _run(["pfctl", "-s", "info"])
        info["backend"] = "pf"
        info["raw"] = text[:2000]
        info["enabled"] = "Status: Enabled" in text
    elif SYSTEM == "Linux":
        text = _run(["nft", "list", "ruleset"]) or _run(["iptables", "-S"])
        info["backend"] = "nftables/iptables"
        info["raw"] = text[:2000]
        info["enabled"] = bool(text.strip())
        info["default_drop"] = bool(
            re.search(r"-P\s+(INPUT|OUTPUT|FORWARD)\s+DROP", text)
            or re.search(r"policy\s+drop", text))
    return info


def supported() -> bool:
    return SYSTEM in ("Darwin", "Linux")
