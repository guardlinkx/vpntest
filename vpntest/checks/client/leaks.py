"""CLI-01 to CLI-06 — what escapes the tunnel.

A leak is a property of the client, so it has to be measured at the client.
There are two ways to stand there, and which one applies depends on what the
client runs on:

* **On this host.** When the tool runs on the machine holding the tunnel, it
  reads the routing table, resolvers and firewall directly. Precise, and the
  only way to see firewall posture.
* **On the network.** A phone cannot be asked for its routing table, so for a
  mobile client the tool watches the segment the handset sits on and classifies
  what leaves it. See `mobile_capture` and `wrappers/pcap`.

The control is the same either way — CLI-02 is "IPv6 must not bypass the
tunnel" however it was proven — so the two strategies share one id, one
baseline and one verdict vocabulary. A target carrying `dut: true` is measured
from the network; everything else is measured locally.

Every check reports `n/a` rather than passing when it could not observe, because
"no leak seen while not connected" — or while the phone sat idle — is not
evidence of anything. A check that quietly passes when it did not run is worse
than one that fails.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, List

from ...model import Check, Context, Finding, Severity, Target
from ...wrappers import netstate as ns
from . import mobile_capture as mc


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
        if mc.is_dut(target):
            return self._from_network(target, ctx)

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

    def _from_network(self, target: Target, ctx: Context) -> List[Finding]:
        """A resolver query seen on the wire is a leak, with nothing inferred.

        This is stronger evidence than the local variant: it does not ask what
        the client intended to do, it records what it did.
        """
        blocked, obs = mc.precondition(self, target, ctx)
        if blocked:
            return [blocked]

        from ...wrappers import pcap
        leaked = obs["escaped_dns"]
        if leaked:
            return [self.fail(
                target,
                f"{len(leaked)} DNS query/queries left the device outside the "
                f"tunnel, to {pcap.summarize_escapes(leaked)}. Every name the "
                "user looked up was visible to the local network.",
                severity=Severity.CRITICAL,
                evidence=[obs["evidence"]], detail=obs)]
        return [self.ok(
            target,
            f"No cleartext DNS in {obs['from_dut']} packets from the device "
            f"over {obs['seconds']}s while the tunnel carried traffic",
            evidence=[obs["evidence"]], detail=obs)]


class Ipv6Leak(Check):
    """CLI-02 — IPv6 must be tunnelled or disabled, never left routed around."""

    id = "CLI-02"
    protocol = "client"
    access = "agent"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        if mc.is_dut(target):
            return self._from_network(target, ctx)

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

    def _from_network(self, target: Target, ctx: Context) -> List[Finding]:
        """Routable IPv6 observed leaving the device is a leak outright.

        Link-local and multicast v6 are excluded upstream in `pcap.classify`:
        neighbour discovery and MLD never leave the segment, and counting them
        would make every correctly-configured client look broken.
        """
        blocked, obs = mc.precondition(self, target, ctx)
        if blocked:
            return [blocked]

        from ...wrappers import pcap
        leaked = obs["escaped_ipv6"]
        if leaked:
            return [self.fail(
                target,
                f"{len(leaked)} IPv6 packet(s) left the device outside the "
                f"tunnel, to {pcap.summarize_escapes(leaked)}. On a dual-stack "
                "network every IPv6-capable destination bypasses the VPN.",
                severity=Severity.CRITICAL,
                evidence=[obs["evidence"]], detail=obs)]
        return [self.ok(
            target,
            "No routable IPv6 left the device outside the tunnel over "
            f"{obs['seconds']}s ({obs['link_local_or_multicast']} link-local "
            "or multicast packet(s) seen and correctly ignored)",
            evidence=[obs["evidence"]], detail=obs)]


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

    # Opt-in id for the variant that actually breaks the tunnel. The class
    # itself is not marked disruptive, because the local firewall-inspection
    # form is read-only and should keep running by default.
    BREAK_VARIANT = "CLI-03:break-tunnel"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        if mc.is_dut(target):
            return self._from_network(target, ctx)

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

    def _from_network(self, target: Target, ctx: Context) -> List[Finding]:
        """Break the tunnel and see whether the device keeps talking.

        There is no way to infer this one from a healthy capture. A kill switch
        is defined entirely by what happens when the tunnel fails, so observing
        a working tunnel says nothing at all about it — hence `n/a` rather than
        a pass when the disruptive variant is not enabled. Reporting a pass
        here would be the worst kind of wrong: a confident green on the control
        most likely to matter.
        """
        blocked, obs = mc.precondition(self, target, ctx)
        if blocked:
            return [blocked]

        from ...wrappers import pcap

        if self.BREAK_VARIANT not in (ctx.scope.allow_disruptive or []):
            return [self.na(target, (
                "A kill switch can only be proven by dropping the tunnel and "
                "watching what the device does next, which briefly cuts its "
                f"connectivity. Add '{self.BREAK_VARIANT}' to allow_disruptive "
                "to enable it. The tunnel being healthy right now is not "
                "evidence either way."), detail=obs)]

        seconds = int(target.meta.get("killswitch_capture_seconds", 25))
        print(f"    breaking the tunnel for {seconds}s — the phone should go "
              "dark if the kill switch works; keep using it")

        with pcap.Blackhole(obs["endpoints"]) as bh:
            if not bh.installed:
                return [self.error(target, (
                    "Could not blackhole any VPN endpoint, so the tunnel was "
                    "never broken and nothing was tested: "
                    + "; ".join(bh.errors)), detail=obs)]
            path, err = pcap.capture(obs["interface"], obs["dut_mac"], seconds)
            packets = pcap.read_packets(path) if path else []

        after = pcap.classify(packets, obs["dut_mac"], obs["endpoints"],
                              pcap.segment_for(obs["interface"]))
        detail = {"while_connected": obs, "after_tunnel_broken": after,
                  "blackholed": bh.installed, "route_errors": bh.errors,
                  "capture_error": err}
        ev = ctx.evidence.data(self.id, str(target).replace(" ", "_"), detail,
                               "traffic after the tunnel was broken")

        # A restore failure has to surface loudly — it altered the operator's
        # machine and left it that way.
        unrestored = [e for e in bh.errors if "COULD NOT RESTORE" in e]
        if unrestored:
            return [self.error(target, "; ".join(unrestored), evidence=[ev],
                               detail=detail)]
        if not path:
            return [self.error(target, f"capture after the break failed: {err}",
                               evidence=[ev], detail=detail)]

        escaped = after["escaped"]
        if escaped:
            return [self.fail(
                target,
                f"With the tunnel broken the device sent {len(escaped)} "
                f"packet(s) in the clear, to {pcap.summarize_escapes(escaped)}. "
                "There is no kill switch in effect: traffic falls back to the "
                "physical interface.",
                severity=Severity.CRITICAL, evidence=[ev], detail=detail)]
        return [self.ok(
            target,
            f"With the tunnel broken the device sent nothing outside it over "
            f"{seconds}s ({after['from_dut']} packet(s) seen, all local, "
            "link-local or tunnel retries). The kill switch holds.",
            evidence=[ev], detail=detail)]


class SplitTunnelPolicy(Check):
    """CLI-04 — the route table must match the documented policy."""

    id = "CLI-04"
    protocol = "client"
    access = "agent"

    def run(self, target: Target, ctx: Context) -> List[Finding]:
        if mc.is_dut(target):
            return self._from_network(target, ctx)

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

    def _from_network(self, target: Target, ctx: Context) -> List[Finding]:
        """Under a full-tunnel policy, nothing should leave except the tunnel.

        DNS and IPv6 escapes are reported by CLI-01 and CLI-02; this one covers
        everything else, so a finding here means ordinary application traffic
        went out around the tunnel. The expected exclusions — local segment and
        Apple push — are already separated by `pcap.classify`, and are reported
        as counts so a reader can see what was permitted and why.
        """
        blocked, obs = mc.precondition(self, target, ctx)
        if blocked:
            return [blocked]

        from ...wrappers import pcap
        policy = target.meta.get("split_tunnel_policy")
        if policy is None:
            return [self.na(target, (
                "No split_tunnel_policy declared in scope, so there is nothing "
                "to compare the observed traffic against"), detail=obs)]

        if policy != "full":
            return [self.na(target, (
                f"Policy is '{policy}'. Only a full-tunnel policy can be "
                "checked from the network, because a split policy needs the "
                "list of destinations that may legitimately bypass the tunnel "
                "— declare split_tunnel_excluded to compare against."),
                detail=obs)]

        other = [e for e in obs["escaped"]
                 if e not in obs["escaped_dns"] and e not in obs["escaped_ipv6"]]
        allowed = (f"{obs['local_segment']} local-segment, {obs['apns']} Apple "
                   f"push, {obs['link_local_or_multicast']} link-local or "
                   "multicast packet(s) were correctly excluded")

        if other:
            return [self.fail(
                target,
                f"Policy is full-tunnel but {len(other)} packet(s) reached "
                f"{pcap.summarize_escapes(other)} outside it",
                severity=Severity.HIGH,
                evidence=[obs["evidence"]], detail=obs)]
        return [self.ok(
            target,
            f"All {obs['tunnel_carrier']} off-segment packet(s) went through "
            f"the tunnel to {', '.join(obs['endpoints_seen'])}; {allowed}",
            evidence=[obs["evidence"]], detail=obs)]


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
