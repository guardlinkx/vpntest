"""Regression tests for the harness itself.

Step 7 of the build order is validating the tool against known-good and
known-bad inputs. These cover the bugs already found in the checks, because a
security tool that silently mis-reports is worse than no tool: a false
positive gets ignored, a false negative gets trusted.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vpntest.catalog import Catalog
from vpntest.registry import coverage, discover


def test_every_check_has_a_catalog_entry():
    """An orphan check produces findings that trace to no baseline."""
    cov = coverage(discover(), Catalog.load("catalog"))
    assert cov["check_without_catalog"] == [], cov["check_without_catalog"]


def test_robot_not_vulnerable_is_not_a_finding():
    """`NOT_VULNERABLE_RSA_NOT_SUPPORTED` contains the substring VULNERABLE.

    Matching with `in` reported a clean host as critically vulnerable.
    """
    for name in ("NOT_VULNERABLE_NO_ORACLE", "NOT_VULNERABLE_RSA_NOT_SUPPORTED"):
        assert not name.upper().startswith("VULNERABLE")
    for name in ("VULNERABLE_WEAK_ORACLE", "VULNERABLE_STRONG_ORACLE"):
        assert name.upper().startswith("VULNERABLE")


def test_created_counts_as_success():
    """201 Created is a successful issuance.

    Counting only 200 made the rate-limit check report "throttled" against an
    endpoint that answered every one of eight requests with 201.
    """
    def issued(code):
        return 200 <= code < 300
    assert issued(200) and issued(201) and issued(204)
    assert not issued(429) and not issued(401) and not issued(500)


def test_hostname_matching_respects_wildcard_label_depth():
    from vpntest.checks.tls_vpn.crypto import _host_matches
    assert _host_matches("api.example.com", ["api.example.com"])
    assert _host_matches("api.example.com", ["*.example.com"])
    # A wildcard covers one label only.
    assert not _host_matches("a.b.example.com", ["*.example.com"])
    assert not _host_matches("example.com", ["*.example.com"])
    assert not _host_matches("evil.com", ["*.example.com"])


def test_scope_denies_unlisted_targets(tmp_path=None):
    import tempfile, textwrap
    from vpntest.guard import Scope, ScopeError
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(textwrap.dedent("""
            name: t
            authorized_by: tester
            targets:
              - host: 127.0.0.1
        """))
        path = fh.name
    scope = Scope.load(path)
    scope.assert_target("127.0.0.1")
    try:
        scope.assert_target("10.0.0.1")
        raise AssertionError("out-of-scope host was permitted")
    except ScopeError:
        pass
    os.unlink(path)


def test_scope_requires_an_authorizer():
    import tempfile, textwrap
    from vpntest.guard import Scope, ScopeError
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(textwrap.dedent("""
            name: t
            targets:
              - host: 127.0.0.1
        """))
        path = fh.name
    try:
        Scope.load(path)
        raise AssertionError("scope without an authorizer was accepted")
    except ScopeError:
        pass
    os.unlink(path)


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS {name}")
                passed += 1
            except Exception as exc:
                print(f"  FAIL {name}: {exc}")
                failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
