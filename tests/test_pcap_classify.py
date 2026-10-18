"""Regression tests for the network-vantage leak classifier.

Classification is where this strategy can go wrong, and both directions are
damaging: calling neighbour discovery a leak produces a critical finding on a
correctly-configured client, and missing an IPv6 escape produces a clean pass
on the exact gap the capture exists to find.

Every case below is something the naive version of this code got wrong, or
would have.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ipaddress

from vpntest.wrappers import pcap

DUT = "aa:bb:cc:dd:ee:ff"
GW = "11:22:33:44:55:66"
SEGMENT = ipaddress.ip_network("192.168.2.0/24")
ENDPOINTS = ["192.0.2.10", "192.0.2.11"]


def pkt(dst, dport=None, family=4, proto="udp", src="192.168.2.2",
        sport=54321, eth_src=DUT):
    return {"ts": 1.0, "eth_src": eth_src, "eth_dst": GW, "family": family,
            "ethertype": "IPv6" if family == 6 else "IPv4",
            "src": src, "sport": sport, "dst": dst, "dport": dport,
            "proto": proto, "raw": f"{src}.{sport} > {dst}.{dport}"}


def classify(packets):
    return pcap.classify(packets, DUT, ENDPOINTS, SEGMENT)


# ---------------------------------------------------------------------------
# Address and port splitting — four shapes, two of them easy to get wrong
# ---------------------------------------------------------------------------

def test_split_addr_port_handles_both_families():
    """IPv4 without a port has four dot-parts; naive rsplit mangles it.

    `"192.168.2.2".rsplit(".", 1)` yields ("192.168.2", "2") — an address that
    does not exist and a port of 2.
    """
    assert pcap._split_addr_port("192.168.2.2.54321") == ("192.168.2.2", 54321)
    assert pcap._split_addr_port("192.168.2.2") == ("192.168.2.2", None)
    assert pcap._split_addr_port("2001:db8:f00d::1.443") == ("2001:db8:f00d::1", 443)
    assert pcap._split_addr_port("fe80::1") == ("fe80::1", None)
    assert pcap._split_addr_port("8.8.8.8.53:") == ("8.8.8.8", 53)


def test_mac_normalisation_matches_tcpdump_and_arp():
    """tcpdump and arp drop leading zeros; comparison must survive that.

    Without this, the capture filter and the direction test disagree and every
    packet is treated as inbound — which reports a serene pass on a device
    leaking everything.
    """
    assert pcap._norm_mac("a:b:c:d:e:f") == "0a:0b:0c:0d:0e:0f"
    assert pcap._norm_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert pcap._norm_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"


# ---------------------------------------------------------------------------
# What must NOT be reported as a leak
# ---------------------------------------------------------------------------

def test_ipv6_neighbour_discovery_is_not_a_leak():
    """ND, MLD and mDNS never leave the segment.

    Counting link-local or multicast IPv6 would make every correct client fail
    CLI-02 with a CRITICAL.
    """
    r = classify([
        pkt("ff02::1:ff00:1", 0, family=6, src="fe80::1", proto="icmp"),
        pkt("ff02::fb", 5353, family=6, src="fe80::1"),
        pkt("ff02::16", 0, family=6, src="fe80::1", proto="icmp"),
    ])
    assert r["escaped_ipv6"] == []
    assert r["escaped"] == []
    assert r["link_local_or_multicast"] == 3


def test_local_segment_traffic_is_not_a_leak():
    """excludeLocalNetworks is the right default; LAN traffic is expected."""
    r = classify([pkt("192.168.2.1", 53), pkt("192.168.2.5", 445, proto="tcp")])
    assert r["escaped"] == []
    assert r["local_segment"] == 2


def test_apple_push_is_not_a_leak():
    """excludeAPNs defaults true on iOS 16.4+ even with includeAllNetworks.

    17.0.0.0/8 bypassing the tunnel is Apple's design, not the client's bug.
    """
    r = classify([pkt("17.0.0.1", 5223, proto="tcp")])
    assert r["escaped"] == []
    assert r["apns"] == 1


def test_tunnel_traffic_is_not_a_leak():
    r = classify([pkt("192.0.2.10", 51820), pkt("192.0.2.11", 4500)])
    assert r["escaped"] == []
    assert r["tunnel_carrier"] == 2
    assert set(r["endpoints_seen"]) == {"192.0.2.10", "192.0.2.11"}


def test_inbound_traffic_is_ignored_entirely():
    """Only what the device sent says anything about its routing.

    Counting inbound would let a port scan of the handset register as the
    handset leaking.
    """
    r = classify([pkt("192.168.2.2", 443, src="8.8.8.8", eth_src=GW)])
    assert r["from_dut"] == 0
    assert r["escaped"] == []


def test_arp_is_not_a_leak():
    """Layer 2 has no destination address to classify; it is never routed."""
    r = classify([{"ts": 1.0, "eth_src": DUT, "eth_dst": "ff:ff:ff:ff:ff:ff",
                   "family": 0, "ethertype": "ARP", "src": None, "sport": None,
                   "dst": None, "dport": None, "proto": "other", "raw": "ARP"}])
    assert r["escaped"] == []
    assert r["non_ip"] == 1


# ---------------------------------------------------------------------------
# What must be reported
# ---------------------------------------------------------------------------

def test_cleartext_dns_is_a_leak():
    r = classify([pkt("8.8.8.8", 53), pkt("1.1.1.1", 53)])
    assert len(r["escaped_dns"]) == 2
    assert len(r["escaped"]) == 2


def test_routable_ipv6_is_a_leak():
    """The gap the whole capture path exists to find."""
    r = classify([pkt("2001:db8:f00d::1", 443, family=6)])
    assert len(r["escaped_ipv6"]) == 1
    assert r["link_local_or_multicast"] == 0


def test_offsegment_app_traffic_is_a_leak():
    r = classify([pkt("198.51.100.5", 443, proto="tcp")])
    assert len(r["escaped"]) == 1
    assert r["escaped_dns"] == []
    assert r["escaped_ipv6"] == []


def test_tunnel_port_to_a_stranger_is_still_a_leak():
    """A tunnel port only counts toward a declared endpoint.

    Otherwise anything on 443 — most of the internet — would be waved through.
    """
    r = classify([pkt("198.51.100.5", 443)])
    assert len(r["escaped"]) == 1
    assert r["tunnel_carrier"] == 0


# ---------------------------------------------------------------------------
# The silent-pass trap
# ---------------------------------------------------------------------------

def test_quiet_capture_cannot_reach_a_verdict():
    """An idle phone must not produce "no leaks found".

    The threshold is what separates "observed nothing bad" from "observed
    nothing", which are opposite results.
    """
    assert pcap.MIN_PACKETS_FOR_A_VERDICT > 0
    r = classify([pkt("192.0.2.10", 51820)])
    assert r["from_dut"] < pcap.MIN_PACKETS_FOR_A_VERDICT


def test_ethernet_line_parses_with_mac_and_l3():
    """The -e form is what makes direction unambiguous across families."""
    line = ("1760000000.123456 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, "
            "ethertype IPv4 (0x0800), length 90: "
            "192.168.2.2.54321 > 8.8.8.8.53: UDP, length 40")
    m = pcap._ETH.match(line)
    assert m, "ethernet header did not parse"
    assert pcap._norm_mac(m.group(2)) == DUT
    assert "IPv4" in m.group(4)
    m3 = pcap._L3.match(m.group(5))
    assert m3 and pcap._split_addr_port(m3.group(2)) == ("8.8.8.8", 53)


def test_ipv6_ethernet_line_parses():
    line = ("1760000000.1 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, "
            "ethertype IPv6 (0x86dd), length 110: "
            "2001:db8:1::1.54321 > 2001:db8:f00d::1.443: UDP, length 48")
    m = pcap._ETH.match(line)
    assert m and "IPv6" in m.group(4)
    m3 = pcap._L3.match(m.group(5))
    assert m3 and pcap._split_addr_port(m3.group(2)) == ("2001:db8:f00d::1", 443)
