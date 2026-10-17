"""Observe a mobile client from the network it sits on.

A phone cannot be asked for its routing table, so the local-netstate approach
in `netstate.py` cannot test an iOS or Android client at all. The vantage point
that does work is the network: put the handset on a segment this machine
serves, then watch what it emits while the tunnel is up. Anything that leaves
in the clear is a leak by definition, with no inference required.

Two decisions shape everything here.

**The device is identified by MAC, not IP.** A `host 192.168.2.2` filter is an
IPv4 filter: the phone's IPv6 traffic has a v6 source address and would never
match it, so the one leak this is most needed for would be invisible. Filtering
on `ether host` catches both families, and the phone's DHCP lease moving
between runs stops mattering.

**Classification decides whether the result means anything.** The naive reading
— "any packet not going to the VPN endpoint is a leak" — produces false
criticals on traffic that bypasses the tunnel entirely legitimately:

* **Link-local and multicast.** Router solicitations, neighbour discovery, MLD,
  mDNS, ARP. These never leave the segment; a tunnel does not carry them and
  should not.
* **The local segment.** Clients that set `excludeLocalNetworks` (the right
  default) deliberately leave LAN traffic outside the tunnel.
* **Apple push.** On iOS 16.4+ `excludeAPNs` defaults to true even with
  `includeAllNetworks` set, so traffic to 17.0.0.0/8 bypasses the tunnel by
  Apple's design, not the client's mistake.

Everything surviving those exclusions genuinely escaped.

One rule governs the module: **an empty capture is never a pass.** If the
handset emitted nothing, the test did not run and has to say so. Reporting "no
leaks observed" after observing nothing is the precise failure this harness
exists to avoid.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

SYSTEM = platform.system()

# Ports that carry a VPN tunnel. Traffic to a scope-declared endpoint on one of
# these is the tunnel working, not a leak.
TUNNEL_PORTS = {51820, 500, 4500, 1701, 443}

# Apple push. Excluded from tunnels by Apple's own default on iOS 16.4+.
APNS_NET = ipaddress.ip_network("17.0.0.0/8")

# Resolver ports, called out separately because a DNS leak is the most damaging
# kind: it reveals every site visited even when payloads are tunnelled.
DNS_PORTS = {53, 853, 5353}

MIN_PACKETS_FOR_A_VERDICT = 20


def available() -> Tuple[bool, str]:
    """Whether a capture can run here at all."""
    if SYSTEM not in ("Darwin", "Linux"):
        return False, f"packet capture is not implemented for {SYSTEM}"
    if not shutil.which("tcpdump"):
        return False, "tcpdump is not installed"
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        return False, ("capture needs passwordless sudo for tcpdump; run "
                       "`sudo -v` in this shell first and re-run")
    return True, ""


def _run(argv: List[str], timeout: int = 15) -> str:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _norm_mac(mac: str) -> str:
    """Normalise to colon-separated lowercase with no zero padding dropped.

    tcpdump and arp both print `a:b:c:d:e:f` for `0a:0b:...`, so comparisons
    have to go through one canonical form or they silently never match.
    """
    parts = [p for p in re.split(r"[:\-]", mac.strip()) if p != ""]
    if len(parts) != 6:
        return mac.strip().lower()
    return ":".join(f"{int(p, 16):02x}" for p in parts)


# ---------------------------------------------------------------------------
# Finding the shared segment and the device on it
# ---------------------------------------------------------------------------

def sharing_interfaces() -> List[Dict[str, Any]]:
    """Interfaces that look like they serve a network to other devices.

    macOS Internet Sharing creates `bridge100`. Linux access points vary, so
    anything with an address that is not loopback or a tunnel is offered as a
    candidate and the scope can pin one explicitly.
    """
    out: List[Dict[str, Any]] = []
    text = _run(["ifconfig"]) or _run(["ip", "addr"])
    current: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        m = re.match(r"^(\w[\w.:@-]*):?\s", line) or \
            re.match(r"^\d+:\s+([\w.:@-]+):", line)
        if m and not line.startswith((" ", "\t")):
            name = m.group(1).rstrip(":")
            current = {"name": name, "ipv4": None, "prefix": None,
                       "likely_sharing": name.startswith(("bridge", "ap", "wlan"))}
            out.append(current)
        if current is None:
            continue
        m_cidr = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m_cidr and current["ipv4"] is None:
            current["ipv4"], current["prefix"] = m_cidr.group(1), int(m_cidr.group(2))
            continue
        m4 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", line)
        if m4 and current["ipv4"] is None:
            current["ipv4"] = m4.group(1)
            mask = m4.group(2)
            try:
                current["prefix"] = (bin(int(mask, 16)).count("1")
                                     if mask.startswith("0x")
                                     else ipaddress.IPv4Network(
                                         f"0.0.0.0/{mask}").prefixlen)
            except ValueError:
                current["prefix"] = 24
    return [i for i in out
            if i["ipv4"] and not i["name"].startswith(
                ("lo", "utun", "ipsec", "gif", "stf"))]


def pick_interface(declared: Optional[str]) -> Tuple[Optional[str], str]:
    """Resolve the capture interface, preferring what the scope declared."""
    ifaces = sharing_interfaces()
    names = [i["name"] for i in ifaces]
    if declared:
        if declared in names:
            return declared, ""
        return None, (f"declared capture_interface '{declared}' has no address; "
                      f"interfaces with one: {', '.join(names) or 'none'}")
    likely = [i["name"] for i in ifaces if i["likely_sharing"]]
    if len(likely) == 1:
        return likely[0], ""
    if not likely:
        return None, ("no shared-network interface found. On macOS enable "
                      "System Settings > General > Sharing > Internet Sharing, "
                      "join the phone to that Wi-Fi network, and bridge100 "
                      "appears. Or set capture_interface in scope.")
    return None, (f"several candidate interfaces ({', '.join(likely)}); set "
                  "capture_interface in scope to choose one")


def segment_for(iface: str) -> Optional[ipaddress.IPv4Network]:
    """The IPv4 network the interface serves, for local-traffic exclusion."""
    for i in sharing_interfaces():
        if i["name"] == iface and i["ipv4"]:
            try:
                return ipaddress.ip_network(
                    f"{i['ipv4']}/{i['prefix'] or 24}", strict=False)
            except ValueError:
                return None
    return None


def neighbours(iface: str) -> List[Dict[str, str]]:
    """Devices currently visible on the segment, from the ARP table."""
    out = []
    for line in _run(["arp", "-an"]).splitlines():
        if iface not in line:
            continue
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})", line)
        if m and "incomplete" not in line.lower():
            out.append({"ip": m.group(1), "mac": _norm_mac(m.group(2))})
    return out


def find_dut(iface: str, dut_ip: Optional[str],
             dut_mac: Optional[str]) -> Tuple[Optional[str], Optional[str], str]:
    """Locate the device under test. Returns (ip, mac, error).

    The MAC is what the capture filters on, so it is required; an IP in scope
    is resolved through ARP to get it.
    """
    seen = neighbours(iface)
    visible = ", ".join(f"{n['ip']}/{n['mac']}" for n in seen) or "none"

    if dut_mac:
        want = _norm_mac(dut_mac)
        match = next((n for n in seen if n["mac"] == want), None)
        # An address is useful for reporting but not required: the filter is
        # the MAC, and a phone that has only IPv6 on-link still captures.
        return (match["ip"] if match else dut_ip), want, ""

    if dut_ip:
        match = next((n for n in seen if n["ip"] == dut_ip), None)
        if not match:
            return None, None, (
                f"{dut_ip} is not in the ARP table for {iface}, so its MAC "
                "cannot be resolved and IPv6 traffic could not be captured. "
                f"Visible: {visible}. Make the phone send something, or set "
                "dut_mac in scope.")
        return match["ip"], match["mac"], ""

    gateways = {i["ipv4"] for i in sharing_interfaces()}
    candidates = [n for n in seen if n["ip"] not in gateways]
    if len(candidates) == 1:
        return candidates[0]["ip"], candidates[0]["mac"], ""
    if not candidates:
        return None, None, (f"no devices on {iface}. Join the phone to the "
                            "shared network and confirm it has an address.")
    return None, None, (f"several devices on {iface} "
                        f"({', '.join(n['ip'] for n in candidates)}); set "
                        "dut_mac or dut_ip in scope to choose one")


# ---------------------------------------------------------------------------
# Capture and parse
# ---------------------------------------------------------------------------

def capture(iface: str, dut_mac: str, seconds: int,
            out_path: Optional[str] = None) -> Tuple[str, str]:
    """Capture both directions for the device, for a fixed window.

    Returns (pcap path, error). The pcap is kept as evidence: it is the raw
    observation a finding rests on, and it lets anyone re-derive the verdict
    without trusting this parser.

    `-s 128` keeps headers and discards payload — enough to classify, and it
    means the evidence file holds no message content.
    """
    path = out_path or os.path.join(
        tempfile.mkdtemp(prefix="vpntest-pcap-"), "dut.pcap")
    argv = ["sudo", "-n", "tcpdump", "-i", iface, "-nn", "-s", "128",
            "-w", path, "-U", "ether", "host", dut_mac]
    try:
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE)
    except OSError as e:
        return "", f"could not start tcpdump: {e}"
    try:
        _, err = p.communicate(timeout=seconds)
        # Returning inside the window means it failed to start, not finished.
        return "", (err.decode(errors="replace").strip()[:300]
                    or "tcpdump exited early")
    except subprocess.TimeoutExpired:
        p.terminate()
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return "", "tcpdump produced no capture file"
    return path, ""


class Blackhole:
    """Temporarily make the VPN endpoints unreachable, to break the tunnel.

    This machine is the phone's gateway, so dropping the route to the gateway
    addresses is enough to kill the tunnel from the handset's point of view —
    which is the only way to actually test a kill switch rather than infer it
    from configuration.

    A route is used rather than a packet-filter rule on purpose: it needs no
    anchors, no enable-reference counting, and `route delete` puts things back
    exactly as they were. Firewall surgery that half-fails leaves the user's
    machine altered, and this runs on someone's laptop.

    Restoration happens in `__exit__` whatever else went wrong, and reports
    anything it could not undo rather than failing silently.
    """

    def __init__(self, endpoints: List[str]):
        self.endpoints = endpoints
        self.installed: List[str] = []
        self.errors: List[str] = []

    def __enter__(self) -> "Blackhole":
        for ep in self.endpoints:
            if SYSTEM == "Darwin":
                argv = ["sudo", "-n", "route", "-n", "add", "-host", ep,
                        "-blackhole"]
            else:
                argv = ["sudo", "-n", "ip", "route", "add", "blackhole", ep]
            p = subprocess.run(argv, capture_output=True, text=True)
            if p.returncode == 0:
                self.installed.append(ep)
            else:
                self.errors.append(
                    f"{ep}: {(p.stderr or p.stdout).strip()[:120]}")
        return self

    def __exit__(self, *_exc) -> None:
        for ep in self.installed:
            if SYSTEM == "Darwin":
                argv = ["sudo", "-n", "route", "-n", "delete", "-host", ep]
            else:
                argv = ["sudo", "-n", "ip", "route", "del", "blackhole", ep]
            p = subprocess.run(argv, capture_output=True, text=True)
            if p.returncode != 0:
                self.errors.append(
                    f"COULD NOT RESTORE route to {ep}: "
                    f"{(p.stderr or p.stdout).strip()[:120]} — remove it by "
                    f"hand with: sudo route delete -host {ep}")


def _split_addr_port(token: str) -> Tuple[str, Optional[int]]:
    """Separate tcpdump's "address.port" into its parts.

    Needs care in both families: an IPv4 address with no port has four
    dot-separated parts and five with one, while an IPv6 address carries its
    port after the final dot but has colons throughout.
    """
    token = token.rstrip(":")
    if ":" in token:                                  # IPv6
        head, dot, tail = token.rpartition(".")
        return (head, int(tail)) if dot and tail.isdigit() else (token, None)
    parts = token.split(".")
    if len(parts) == 5 and parts[4].isdigit():
        return ".".join(parts[:4]), int(parts[4])
    return token, None


# With -e, each line starts with the ethernet header, which is what makes
# direction unambiguous for both address families.
_ETH = re.compile(
    r"^(\d+\.\d+)\s+([0-9a-f:]{11,17})\s+>\s+([0-9a-f:]{11,17}),\s+"
    r"ethertype\s+(\S+)[^:]*:\s*(.*)$", re.I)
_L3 = re.compile(r"^(\S+)\s+>\s+(\S+):\s*(.*)$")


def read_packets(pcap_path: str) -> List[Dict[str, Any]]:
    """Parse the capture into records.

    Reads back through tcpdump rather than a pcap library on purpose: the text
    is what an operator would see running the same command by hand, which keeps
    every finding reproducible without this tool.
    """
    text = _run(["sudo", "-n", "tcpdump", "-nn", "-tt", "-q", "-e",
                 "-r", pcap_path], timeout=180)
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        m = _ETH.match(line.strip())
        if not m:
            continue
        ts, eth_src, eth_dst, ethertype, rest = m.groups()
        et = ethertype.lower()
        family = 6 if "ipv6" in et else 4 if "ipv4" in et else 0
        rec: Dict[str, Any] = {
            "ts": float(ts), "eth_src": _norm_mac(eth_src),
            "eth_dst": _norm_mac(eth_dst), "family": family,
            "ethertype": ethertype, "src": None, "sport": None,
            "dst": None, "dport": None, "proto": "other",
            "raw": line.strip()[:220],
        }
        m3 = _L3.match(rest)
        if m3 and family:
            src_tok, dst_tok, tail = m3.groups()
            rec["src"], rec["sport"] = _split_addr_port(src_tok)
            rec["dst"], rec["dport"] = _split_addr_port(dst_tok)
            low = tail.lower()
            rec["proto"] = ("esp" if "esp" in low else
                            "udp" if "udp" in low else
                            "icmp" if "icmp" in low else
                            "tcp" if any(k in low for k in
                                         ("tcp", "ack", "seq", "flags")) else
                            "other")
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _addr(value: Optional[str]):
    try:
        return ipaddress.ip_address(value) if value else None
    except ValueError:
        return None


def classify(packets: List[Dict[str, Any]], dut_mac: str,
             endpoints: List[str],
             segment: Optional[ipaddress.IPv4Network]) -> Dict[str, Any]:
    """Partition what the device sent into expected traffic and escapes.

    Only packets *from* the device count, decided on the ethernet source.
    Inbound traffic says nothing about what the client chose to route where,
    and counting it would let a port scan of the handset register as the
    handset leaking.
    """
    want = _norm_mac(dut_mac)
    r: Dict[str, Any] = {
        "from_dut": 0, "tunnel_carrier": 0, "local_segment": 0,
        "link_local_or_multicast": 0, "apns": 0, "non_ip": 0,
        "escaped": [], "escaped_dns": [], "escaped_ipv6": [],
        "endpoints_seen": set(),
    }
    endpoint_addrs = set(endpoints)

    for p in packets:
        if p["eth_src"] != want:
            continue
        r["from_dut"] += 1

        # ARP and friends: layer 2, never routed, never a leak.
        if not p["family"] or not p["dst"]:
            r["non_ip"] += 1
            continue

        src, dst = _addr(p["src"]), _addr(p["dst"])

        # Never-leaves-the-link traffic: ND, MLD, mDNS, SSDP, DHCP broadcast.
        if (dst is not None and (dst.is_multicast or dst.is_link_local)) or \
           (src is not None and src.is_link_local):
            r["link_local_or_multicast"] += 1
            continue

        # The tunnel itself.
        if p["dst"] in endpoint_addrs and (p["proto"] == "esp"
                                           or p["dport"] in TUNNEL_PORTS):
            r["tunnel_carrier"] += 1
            r["endpoints_seen"].add(p["dst"])
            continue

        # Local segment — legitimately outside the tunnel when the client sets
        # excludeLocalNetworks, which is the sane default.
        if segment is not None and dst is not None and dst.version == 4 \
                and dst in segment:
            r["local_segment"] += 1
            continue

        # Apple push: excluded from the tunnel by Apple's own default.
        if dst is not None and dst.version == 4 and dst in APNS_NET:
            r["apns"] += 1
            continue

        rec = {"dst": p["dst"], "dport": p["dport"], "proto": p["proto"],
               "family": p["family"], "sample": p["raw"]}
        r["escaped"].append(rec)
        if p["dport"] in DNS_PORTS or p["sport"] in DNS_PORTS:
            r["escaped_dns"].append(rec)
        if p["family"] == 6:
            r["escaped_ipv6"].append(rec)

    r["endpoints_seen"] = sorted(r["endpoints_seen"])
    return r


def summarize_escapes(escaped: List[Dict[str, Any]], limit: int = 6) -> str:
    """A readable list of distinct destinations, for a finding summary."""
    seen: List[str] = []
    for e in escaped:
        label = f"{e['dst']}:{e['dport']}" if e["dport"] else str(e["dst"])
        if label not in seen:
            seen.append(label)
    shown = ", ".join(seen[:limit])
    if len(seen) > limit:
        shown += f", and {len(seen) - limit} more"
    return shown
