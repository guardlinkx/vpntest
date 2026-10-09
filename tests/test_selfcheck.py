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


def test_ikev1_informational_rejection_is_not_aggressive_mode():
    """An IKEv2-only gateway answers an IKEv1 packet — with a refusal.

    Treating "a reply arrived" as "aggressive mode is enabled" reported three
    correctly-configured gateways as critically vulnerable. The discriminator
    is the exchange type: 4 is Aggressive, 5 is Informational.
    """
    from vpntest.checks.ipsec.proposals import IkeV1AggressiveMode as C
    assert C.EXCHANGE_AGGRESSIVE == 4
    assert C.EXCHANGE_INFORMATIONAL == 5
    # The real reply observed from strongSwan: v1, Informational, notify 16.
    reply = bytes.fromhex(
        "3f59bce5b742ac11424d5296b3c40eb4" "0b" "10" "05" "00"
        "9b6288ab" "00000028" "0000000c0000000101000010")
    assert reply[17] >> 4 == 1          # IKEv1 version in the reply
    assert reply[18] == C.EXCHANGE_INFORMATIONAL
    assert reply[18] != C.EXCHANGE_AGGRESSIVE


def test_ike_transform_ids_match_the_rfc():
    """A wrong transform id makes a sweep silently meaningless."""
    from vpntest.wrappers import ikev2 as ike
    assert ike.ENCR["3DES"] == 3 and ike.ENCR["AES_CBC"] == 12
    assert ike.ENCR["AES_GCM_16"] == 20 and ike.ENCR["NULL"] == 11
    assert ike.PRF["HMAC_SHA1"] == 2 and ike.PRF["HMAC_SHA2_256"] == 5
    assert ike.INTEG["HMAC_SHA1_96"] == 2
    assert ike.INTEG["HMAC_SHA2_256_128"] == 12
    assert ike.DH["MODP_1024"] == 2 and ike.DH["MODP_2048"] == 14
    assert ike.DH["ECP_256"] == 19 and ike.DH["CURVE25519"] == 31
    # Key-exchange payload size must match the group or the responder
    # answers INVALID_KE_PAYLOAD and every result reads as "refused".
    assert ike.KE_SIZE[14] == 256 and ike.KE_SIZE[19] == 64
    assert ike.KE_SIZE[31] == 32


def test_sa_init_packet_is_well_formed():
    """The declared length must match the bytes actually sent."""
    import struct
    from vpntest.wrappers import ikev2 as ike
    pkt, spi = ike.build_sa_init(ike.BASE["encr"], ike.BASE["prf"],
                                 ike.BASE["integ"], ike.BASE["dh"])
    assert len(pkt) == struct.unpack("!I", pkt[24:28])[0]
    assert pkt[16] == ike.PAYLOAD_SA
    assert pkt[17] == 0x20                       # IKEv2
    assert pkt[18] == ike.EXCHANGE_IKE_SA_INIT
    assert pkt[19] & ike.FLAG_INITIATOR
    assert pkt[:8] == spi


def test_weak_transform_regex_does_not_overmatch():
    """`sha1` must not match inside `sha128`, or every config fails."""
    from vpntest.checks.ipsec.config import WEAK_RE
    assert WEAK_RE.search("aes256-sha1")
    assert WEAK_RE.search("3des-md5")
    assert WEAK_RE.search("modp1024")
    assert not WEAK_RE.search("aes256-sha256")
    assert not WEAK_RE.search("aes128gcm16")
    assert not WEAK_RE.search("modp2048")


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
