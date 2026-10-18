# vpntest — VPN security test harness

Vendor-neutral security testing for VPN deployments: IPsec/IKEv2, SSL/TLS VPN,
WireGuard, the control-plane API, and the client. Every check traces to a named
baseline, so a finding reads as "fails control X" rather than "looks weak".

**This is a security harness, not a functional test suite.** It covers the
testable controls of the named baselines. It is not proof of security:
implementation bugs, certification, and design review stay outside any
automated tool.

## Quick start

```bash
uv venv --python 3.12 .venv          # or any Python 3.9+
VIRTUAL_ENV=.venv uv pip install pyyaml requests cryptography jinja2

cp scope/example-authorization.yaml scope/mine.yaml   # edit it
.venv/bin/python -m vpntest.cli catalog               # what exists
.venv/bin/python -m vpntest.cli run --scope scope/mine.yaml
```

Exits non-zero when any control fails, so CI can gate on it.

```bash
# Narrow a run
... run --scope scope/mine.yaml --protocol api
... run --scope scope/mine.yaml --only WG-04 --only WG-11 -v
```

## Authorization is mandatory

Nothing is tested unless it appears in a scope file naming who authorized it.
The guard is consulted for **every (check, target) pair**, not once at startup,
so a check cannot drift onto a neighbouring host via a redirect or a hostname
that starts resolving elsewhere mid-run. Disruptive checks are refused unless
listed by id. Rate limits come from the scope, not from the check.

## Layout

```
catalog/     controls as data — id, requirement, baseline, severity, remediation
scope/       authorization files (gitignored except the example)
vpntest/
  model.py     Check / Finding / Status / Severity / Target / Context
  guard.py     deny-by-default scope enforcement
  catalog.py   loads controls; a check with no control cannot run
  registry.py  discovers plugins by walking the package
  runner.py    schedules, isolates failures, fills severity from the catalog
  evidence.py  hashed, timestamped artefacts, referenced by path not inlined
  checks/      one file per area: ipsec/ tls_vpn/ wireguard/ api/ client/
  report/      JSON + self-contained HTML
evidence/    per-run artefacts with a SHA-256 MANIFEST
reports/     report-<run>.json and .html
```

## Adding a control

1. Add it to the right `catalog/*.yaml` with its baseline and remediation.
2. Add a `Check` subclass with a matching `id` under `vpntest/checks/<area>/`.

The runner never changes. A check whose id has no catalog entry is refused, so
findings always trace to a baseline.

```python
class MyCheck(Check):
    id = "WG-42"
    protocol = "wireguard"
    access = "unauth"        # unauth | test-creds | config | agent
    disruptive = False       # True -> skipped unless the scope opts in

    def applicable(self, target, ctx):
        return bool(target.meta.get("wg_port"))

    def run(self, target, ctx):
        ev = ctx.evidence.data(self.id, target.host, {...}, "what this is")
        return [self.fail(target, "what is wrong", evidence=[ev])]
```

Report `na` when a control does not apply and `error` when the check itself
could not run — neither is a pass, and the report distinguishes all three.

## Status

57 controls catalogued. The API family is an addition to the original design:
the highest-impact VPN API bugs are endpoints that hand out entitlement or
credentials to whoever asks, which no protocol-level check would ever see.

Config-review checks (`access: config`) read target state over SSH, read-only,
and report `n/a` when the scope supplies no credentials.

## Testing a phone

A handset cannot be asked for its routing table, so the local measurements in
`wrappers/netstate.py` cannot test a mobile client at all. Instead the tool
watches the network the phone sits on and classifies what leaves it. Same
controls — CLI-01 to CLI-04 — different instrument.

Setup, on macOS:

1. **System Settings > General > Sharing > Internet Sharing**, share your
   connection to Wi-Fi, and turn it on. This creates `bridge100`.
2. Join the phone to that Wi-Fi network.
3. `sudo -v` in the shell you will run from — capture needs tcpdump as root.
4. Add the device to your scope with `dut: true` (see `scope/your-scope.yaml`),
   listing `vpn_endpoints` so tunnelled traffic can be told from a leak.
5. Connect the VPN on the phone, confirm it reports connected, then run.
6. **Use the phone while it captures.** Browse, stream, anything. A silent
   handset produces `n/a`, not a pass — see below.

```bash
vpntest run --scope scope/your-scope.yaml --only CLI-01,CLI-02,CLI-04
```

The capture is taken once per run and shared by all four checks, so they
cannot disagree about what was on the wire. The `.pcap` is kept as evidence
with payload truncated to 128 bytes, which is enough to classify and holds no
message content.

**Classification is the part that matters.** "Anything not going to the VPN
endpoint is a leak" is wrong and produces criticals on healthy clients, so
these are excluded deliberately: link-local and multicast IPv6 (neighbour
discovery, MLD, mDNS never leave the segment), the local subnet (clients
rightly set `excludeLocalNetworks`), Apple push to 17.0.0.0/8 (`excludeAPNs`
defaults true on iOS 16.4+ even with `includeAllNetworks`), and ARP. Each
exclusion is counted in the finding so you can see what was permitted.

**An empty capture is never a pass.** Below 20 packets from the device, or
with no traffic to any declared endpoint, every check reports `n/a` with the
reason. "No leaks observed" after observing nothing reads as a pass and is
worth less than no result.

### Proving the kill switch

A kill switch is defined by what happens when the tunnel *fails*, so a healthy
capture says nothing about it — CLI-03 reports `n/a` rather than guessing. To
actually test it, opt in:

```yaml
allow_disruptive: ["CLI-03:break-tunnel"]
```

The tool then blackhole-routes the VPN endpoints on this machine (which is the
phone's gateway), captures while the tunnel is down, and restores the routes
afterwards. A route is used rather than a firewall rule so restoration is a
single `route delete`; if restoration fails the check reports `error` and
prints the command to undo it by hand. The phone loses connectivity for the
duration.

## Known limits

- **Desktop client checks need an agent.** On a machine running the tunnel the
  tool measures locally, but Windows posture (WFP filters, adapter metrics) is
  not exposed cleanly to a subprocess and wants the C#/.NET agent. Mobile is
  covered by the capture path above.
- **No exploit code.** Vulnerable versions are identified by fingerprint and
  advisory lookup, never by exploitation.
- **Deep IKE proposal enumeration** wants `ike-scan` or Scapy; the built-in
  probes establish reachability and version, not the full transform matrix.

## Using this against someone else's infrastructure

Don't, without written authorization. The scope file is not a formality: the
runner re-checks it for every (check, target) pair rather than once at startup,
so a check cannot wander onto a neighbouring host by following a redirect or a
hostname that starts resolving elsewhere mid-run. Checks marked `disruptive`
are skipped unless opted in by id.

That design protects you as much as the target. It does not make unauthorized
testing legal.

## Contributing

A control is a catalog entry plus a check class; nothing registers itself by
hand. See **Adding a control** above.

Two conventions are worth keeping, because most of the bugs found in this tool
so far were violations of them:

- **A check that cannot run reports `n/a`, never `pass`.** A clean result on a
  test that never executed is worse than no result, because it gets trusted.
  Say why it could not run.
- **Prove a new check can fail.** Six passes on a brand-new control usually
  means it cannot fail at all. Feed it a synthetic violation and confirm it
  fires before trusting a green.

Real-world addresses do not belong in test fixtures. Use the ranges reserved
for documentation: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and
`2001:db8::/32`.

## License

MIT — see [LICENSE](LICENSE).
