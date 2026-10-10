"""CLI-01 to CLI-06 — what escapes the tunnel.

These are only meaningful from the endpoint while the tunnel is up, so they
run against the host executing the tool. That makes the tool itself the test
client, which is the honest arrangement: a leak is a property of this machine's
routing and resolver state, not something inferable from the gateway.

Every one reports `n/a` when no tunnel is up rather than passing, because "no
leak observed while not connected" is not evidence of anything. A check that
quietly passes when it could not run is worse than one that fails.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, List

from ...model import Check, Context, Finding, Severity, Target
from ...wrappers import netstate as ns


def _tunnel_or_na(check: Check, target: Target, ctx: Context):
    """Shared precondition: a tunnel must actually be carrying the default route."""
    if not ns.supported():
        return check.na(
            target,
            f"Local leak testing is not implemented for {ns.SYSTEM}; "
            "use the agent on that platform")
    tun = ns.tunnel_is_up()
    if not tun:
        return check.na(
            target,
            "No VPN tunnel is carrying the default route on this host, so a "
            "leak test would prove nothing. Connect the client and re-run.")
    return None


class DnsLeak(Check):
    """CLI-01 — every resolver must be reachable only through the tunnel."""

    id = "CLI-01"
    protocol = "client"
    access = "agent"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        blocked = _tunnel_or_na(self, target, ctx)
        if blocked:
            return [blocked]

        tun = ns.tunnel_is_up()
        resolvers = ns.resolvers()
        outside = [r for r in resolvers if not r["via_tunnel"]]

        detail: Dict[str, Any] = {"tunnel_interface": tun,
                                  "resolvers": resolvers}
        ev = ctx.evidence.data(self.id, "local", detail,
                               "configured resolvers and their egress interface")

        if not resolvers:
            return [self.error(target, "Could not read the system resolvers")]
        if outside:
            return [self.fail(
                target,
                f"{len(outside)} of {len(resolvers)} resolver(s) are reached "
                "outside the tunnel: "
                + ", ".join(f"{r['address']} via {r['interface']}" for r in outside),
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            f"All {len(resolvers)} resolver(s) egress through {tun}",
            evidence=[ev], detail=detail)]


class Ipv6Leak(Check):
    """CLI-02 — IPv6 must be tunnelled or disabled, never left routed around."""

    id = "CLI-02"
    protocol = "client"
    access = "agent"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        blocked = _tunnel_or_na(self, target, ctx)
        if blocked:
            return [blocked]

        tun = ns.tunnel_is_up()
        v6_default = ns.default_route(6)
        v6_iface = v6_default.get("interface")
        has_v6 = ns.ipv6_enabled()

        detail = {"tunnel_interface": tun, "ipv6_addresses_present": has_v6,
                  "ipv6_default_route": v6_default}
        ev = ctx.evidence.data(self.id, "local", detail,
                               "IPv6 routing state while connected")

        if not has_v6:
            return [self.ok(
                target, "No routable IPv6 address on this host; nothing to leak",
                evidence=[ev], detail=detail)]
        if v6_iface and not ns.is_tunnel_interface(v6_iface):
            return [self.fail(
                target,
                f"IPv6 default route is on {v6_iface}, outside the tunnel "
                f"({tun}). On a dual-stack network every IPv6-capable "
                "destination bypasses the VPN entirely.",
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]
        if not v6_iface:
            return [self.ok(
                target,
                "IPv6 is present but has no default route, so it cannot carry "
                "traffic off-link",
                evidence=[ev], detail=detail)]
        return [self.ok(target, f"IPv6 default route is inside the tunnel ({v6_iface})",
                        evidence=[ev], detail=detail)]


class KillSwitch(Check):
    """CLI-03 — traffic must stop when the tunnel drops.

    Two modes. By default it inspects the firewall for a default-deny posture,
    which is evidence but not proof. With the disruptive variant enabled in
    scope, the agent drops the tunnel and captures — that is the only way to
    prove it, and it is deliberately opt-in because it cuts the host off.
    """

    id = "CLI-03"
    protocol = "client"
    access = "agent"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        blocked = _tunnel_or_na(self, target, ctx)
        if blocked:
            return [blocked]

        fw = ns.firewall_rules()
        detail = {"tunnel_interface": ns.tunnel_is_up(), "firewall": fw}
        ev = ctx.evidence.data(self.id, "local", detail,
                               "firewall posture while connected")

        if fw.get("enabled") and fw.get("default_drop"):
            return [self.ok(
                target,
                f"{fw['backend']} is enforcing a default-drop policy, which is "
                "consistent with a kill switch. Enable the disruptive variant "
                "to prove it by dropping the tunnel.",
                evidence=[ev], detail=detail)]
        if fw.get("enabled"):
            return [self.warn(
                target,
                f"{fw['backend']} is active but no default-drop policy was "
                "found. A kill switch cannot be confirmed from configuration "
                "alone — this is inconclusive, not a pass.",
                evidence=[ev], detail=detail)]
        return [self.fail(
            target,
            "No host firewall is enforcing anything, so nothing blocks traffic "
            "if the tunnel drops",
            severity=Severity.HIGH, evidence=[ev], detail=detail)]


class SplitTunnelPolicy(Check):
    """CLI-04 — the route table must match the documented policy."""

    id = "CLI-04"
    protocol = "client"
    access = "agent"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        blocked = _tunnel_or_na(self, target, ctx)
        if blocked:
            return [blocked]

        policy = target.meta.get("split_tunnel_policy")
        tun = ns.tunnel_is_up()
        v4 = ns.default_route(4)
        detail = {"tunnel_interface": tun, "ipv4_default": v4,
                  "declared_policy": policy}
        ev = ctx.evidence.data(self.id, "local", detail, "route table vs policy")

        if policy is None:
            return [self.na(
                target,
                "No split_tunnel_policy declared in scope; there is nothing to "
                "compare the route table against",
                evidence=[ev], detail=detail)]

        if policy == "full" and not ns.is_tunnel_interface(v4.get("interface") or ""):
            return [self.fail(
                target,
                "Policy is full-tunnel but the IPv4 default route is on "
                f"{v4.get('interface')}",
                severity=Severity.HIGH, evidence=[ev], detail=detail)]

        excluded = target.meta.get("split_tunnel_excluded") or []
        wrong = []
        for dest in excluded:
            r = ns.route_for(dest)
            if ns.is_tunnel_interface(r.get("interface") or ""):
                wrong.append(f"{dest} -> {r.get('interface')}")
        detail["excluded_checked"] = excluded
        detail["unexpectedly_tunnelled"] = wrong

        if wrong:
            return [self.fail(
                target,
                "Destinations the policy excludes are being tunnelled: "
                + ", ".join(wrong),
                severity=Severity.MEDIUM, evidence=[ev], detail=detail)]
        return [self.ok(target, f"Route table matches the '{policy}' policy",
                        evidence=[ev], detail=detail)]


class DhcpRouteInjection(Check):
    """CLI-05 — TunnelVision (CVE-2024-3661), DHCP option 121.

    Needs a rogue DHCP server on an isolated segment. Disruptive and
    lab-only — it is never run against a production network.
    """

    id = "CLI-05"
    protocol = "client"
    access = "agent"
    disruptive = True

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        lab = target.meta.get("lab_network")
        if not lab:
            return [self.na(
                target,
                "Requires an isolated lab segment with a controllable DHCP "
                "server; declare lab_network in scope to enable it")]
        return [self.error(
            target,
            "Rogue-DHCP harness not implemented. It must run on an isolated "
            "segment with its own DHCP server offering option 121 routes; "
            "running it anywhere else would hijack other hosts on the network.")]


class LocalNetAttack(Check):
    """CLI-06 — TunnelCrack LocalNet and ServerIP. Lab-only, same reasoning."""

    id = "CLI-06"
    protocol = "client"
    access = "agent"
    disruptive = True

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        lab = target.meta.get("lab_network")
        if not lab:
            return [self.na(
                target,
                "Requires a lab access point that can hand out the target's "
                "own address range; declare lab_network in scope to enable it")]
        return [self.error(
            target,
            "LocalNet/ServerIP harness not implemented. It requires a "
            "controlled access point, which cannot be stood up safely on a "
            "production network.")]
