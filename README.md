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

## Known limits

- **Client checks need an agent.** DNS/IPv6 leaks, kill switch and route
  injection can only be proven from the endpoint while the tunnel is up. The
  desktop agent is C#/.NET; mobile needs an on-device harness.
- **No exploit code.** Vulnerable versions are identified by fingerprint and
  advisory lookup, never by exploitation.
- **Deep IKE proposal enumeration** wants `ike-scan` or Scapy; the built-in
  probes establish reachability and version, not the full transform matrix.
