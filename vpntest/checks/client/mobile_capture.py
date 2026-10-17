"""One network observation of a mobile client, shared by CLI-01 to CLI-04.

The four leak controls all ask a question about the same thing: what left the
handset while the tunnel was up. Capturing separately for each would take four
times as long and — worse — let them disagree, because each would see a
different slice of traffic. So the capture happens once per run and all four
read it.

This keeps the controls themselves unchanged. CLI-02 is "IPv6 must not bypass
the tunnel" whether it was proven by reading a routing table or by watching the
wire; a verdict should not depend on which instrument reached it. What changes
is only the measurement strategy, selected by the target.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from ...model import Context, Target
from ...wrappers import pcap

# Keyed by target label: one capture per device per run.
_CACHE: Dict[str, Dict[str, Any]] = {}


def is_dut(target: Target) -> bool:
    """Whether this target is a device observed from the network."""
    return bool(target.meta.get("dut"))


def _do_capture(target: Target, ctx: Context) -> Dict[str, Any]:
    meta = target.meta
    seconds = int(meta.get("capture_seconds", 45))

    ok, why = pcap.available()
    if not ok:
        return {"usable": False, "reason": why}

    iface, err = pcap.pick_interface(meta.get("capture_interface"))
    if not iface:
        return {"usable": False, "reason": err}

    dut_ip, dut_mac, err = pcap.find_dut(iface, meta.get("dut_ip"),
                                          meta.get("dut_mac"))
    if not dut_mac:
        return {"usable": False, "reason": err}

    endpoints = [str(e) for e in (meta.get("vpn_endpoints") or [])]
    if not endpoints:
        return {"usable": False, "reason": (
            "no vpn_endpoints declared in scope for this device, so tunnelled "
            "traffic could not be told apart from a leak. List the gateway "
            "addresses the client connects to.")}

    print(f"    capturing {seconds}s on {iface} for {dut_mac}"
          f"{f' ({dut_ip})' if dut_ip else ''} — "
          "use the phone now: browse, stream, anything that makes traffic")

    path, err = pcap.capture(iface, dut_mac, seconds)
    if not path:
        return {"usable": False, "reason": f"capture failed: {err}"}

    packets = pcap.read_packets(path)
    segment = pcap.segment_for(iface)
    result = pcap.classify(packets, dut_mac, endpoints, segment)

    # The pcap is the primary evidence — a reader can re-derive every verdict
    # from it without trusting this parser.
    try:
        with open(path, "rb") as fh:
            blob = ctx.evidence.blob(
                "CLI-capture", f"{str(target).replace(' ', '_')}.pcap",
                fh.read(), f"{seconds}s on {iface}, ether host {dut_mac}")
    except OSError:
        blob = ""
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    return {
        "usable": True, "interface": iface, "dut_ip": dut_ip,
        "dut_mac": dut_mac, "endpoints": endpoints, "seconds": seconds,
        "segment": str(segment) if segment else None,
        "packets_total": len(packets), "evidence": blob,
        **result,
    }


def observation(target: Target, ctx: Context) -> Dict[str, Any]:
    """The capture for this device, taken once and reused."""
    key = str(target)
    if key not in _CACHE:
        _CACHE[key] = _do_capture(target, ctx)
    return _CACHE[key]


def precondition(check, target: Target, ctx: Context) -> Tuple[Optional[Any],
                                                               Dict[str, Any]]:
    """Shared gate. Returns (finding_to_return_or_None, observation).

    Three distinct non-results, deliberately not collapsed:

    * the capture could not be set up — `n/a`, with what to fix;
    * the device sent almost nothing — `n/a`, because a quiet capture is not
      evidence of a quiet client. This is the trap the whole module is built
      to avoid: "no leaks seen" after seeing nothing reads as a pass and is
      worth less than no result at all;
    * no tunnel traffic at all — `n/a`, since the client was plainly not
      connected and leak testing a disconnected client proves nothing.
    """
    obs = observation(target, ctx)

    if not obs.get("usable"):
        return check.na(target, obs.get("reason", "capture unavailable")), obs

    sent = obs["from_dut"]
    if sent < pcap.MIN_PACKETS_FOR_A_VERDICT:
        return check.na(target, (
            f"The device sent only {sent} packet(s) during the "
            f"{obs['seconds']}s capture — too little to conclude anything. "
            "Re-run and actively use the phone while it captures.")), obs

    if obs["tunnel_carrier"] == 0:
        return check.na(target, (
            f"No traffic to any declared VPN endpoint "
            f"({', '.join(obs['endpoints'])}) in {sent} packets from the "
            "device, so the tunnel was not up. Connect the client, confirm it "
            "says connected, then re-run.")), obs

    return None, obs
