"""setname, draft/pre-away, no-implicit-names, extended-monitor (ircv3base)."""
import pytest
import time

from conftest import make_znc, FakeServer, ZNC_USER, ZNC_PASS


@pytest.fixture
def znc_fake(workdir, built_modules):
    fake = FakeServer(caps={"message-tags": "", "server-time": "", "batch": ""})  # no setname
    z = make_znc(workdir, {"fake": fake}, built_modules)
    fake.wait_registered()
    yield z, fake
    z.stop()
    fake.stop()


def test_setname_roundtrip_via_ergo(znc):
    cap = znc.login("cap", "ergo1", extra_caps=("setname",))
    assert "setname" in cap.caps_enabled
    plain = znc.login("plain", "ergo1")
    for c in (cap, plain):
        c.drain(0.3)
    cap.send("SETNAME :Alice Renamed")
    m = cap.expect_cmd("SETNAME")
    assert m.nick == ZNC_USER and m.params[-1] == "Alice Renamed"
    plain.not_expected(lambda m: m.command == "SETNAME")
    # ZNC's view of the realname changed too (reported by *status).
    cap.send("PRIVMSG *status :ListNetworks")
    cap.drain(0.3)
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    peer.send(f"WHOIS {ZNC_USER}")
    m = peer.expect_cmd("311")
    assert m.params[-1] == "Alice Renamed"
    peer.close()
    cap.close()
    plain.close()


def test_setname_fails_without_upstream_support(znc_fake):
    z, fake = znc_fake
    c = z.login("c", "fake", extra_caps=("setname",))
    c.send("SETNAME :nope")
    m = c.expect_cmd("FAIL")
    assert m.params[:2] == ["SETNAME", "CANNOT_CHANGE_REALNAME"]
    fake_seen = []
    while not fake.received.empty():
        fake_seen.append(fake.received.get())
    assert not any(m.command == "SETNAME" for m in fake_seen)
    c.close()


def test_pre_away(znc):
    c = znc.client("c", None)
    c.cap_ls()
    assert "draft/pre-away" in c.caps_available
    c.cap_req("draft/pre-away", "message-tags")
    c.send("AWAY :gone fishing")
    c.send(f"PASS {ZNC_USER}/ergo1:{ZNC_PASS}")
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :x")
    c.cap_end()
    c.expect_cmd("001")
    c.expect_cmd("306", timeout=5)  # RPL_NOWAWAY from Ergo
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    peer.send(f"WHOIS {ZNC_USER}")
    m = peer.expect(lambda m: m.command in ("301", "318"), what="whois away")
    assert m.command == "301" and m.params[-1] == "gone fishing"
    peer.close()
    c.close()


def test_no_implicit_names(znc):
    c = znc.login("c", "ergo1", extra_caps=("no-implicit-names",))
    assert "no-implicit-names" in c.caps_enabled
    msgs = c.drain(1.0)
    assert not any(m.command in ("353", "366") for m in msgs), [m.raw for m in msgs if m.command in ("353", "366")]
    assert any(m.command == "JOIN" and m.params[0] == "#test" for m in msgs)
    # Explicit NAMES still works.
    c.send("NAMES #test")
    m = c.expect_cmd("353")
    assert m.params[2] == "#test"
    c.expect_cmd("366")
    # A fresh join: no NAMES either.
    c.send("JOIN #second")
    c.expect(lambda m: m.command == "JOIN" and m.params[0] == "#second")
    c.not_expected(lambda m: m.command in ("353", "366"))
    # The plain client still gets NAMES on attach and join.
    plain = znc.login("plain", "ergo1")
    msgs = plain.drain(1.0)
    assert any(m.command == "366" for m in msgs)
    c.close()
    plain.close()


def test_extended_monitor_offered_after_attach(znc):
    c = znc.login("c", "ergo1")
    # Server-dependent caps are announced with CAP NEW once attached.
    m = c.expect(lambda m: m.command == "CAP" and m.params[1] == "NEW" and "extended-monitor" in m.params[-1], what="CAP NEW extended-monitor")
    assert c.cap_req("extended-monitor")
    c.close()


def test_extended_monitor_forwards_changes_for_monitored_nicks(znc, ergos):
    """AWAY/SETNAME from a monitored nick we share no channel with reach only
    clients that enabled extended-monitor (the core drops them otherwise)."""
    c = znc.login("c", "ergo1")
    c.expect(lambda m: m.command == "CAP" and m.params[1] == "NEW" and "extended-monitor" in m.params[-1],
             what="CAP NEW extended-monitor")
    assert c.cap_req("extended-monitor", "away-notify", "setname")
    plain = znc.login("plain", "ergo1")
    plain.expect(lambda m: m.command == "CAP" and m.params[1] == "NEW" and "away-notify" in m.params[-1],
                 what="CAP NEW away-notify")
    assert plain.cap_req("away-notify", "setname")

    c.send("MONITOR + soldertest")
    c.expect(lambda m: m.command == "731", what="RPL_MONOFFLINE")
    d = ergos["ergo1"].client("soldertest")
    d.register("soldertest", "soldertest")
    c.expect(lambda m: m.command == "730" and "soldertest" in m.params[-1], what="RPL_MONONLINE")
    c.drain(0.3)
    plain.drain(0.3)

    d.send("AWAY :testing")
    m = c.expect(lambda m: m.command == "AWAY" and m.nick == "soldertest", what="AWAY of monitored nick")
    assert m.params[-1] == "testing"
    plain.not_expected(lambda m: m.command == "AWAY")

    d.send("SETNAME :Solder Tester")
    c.expect(lambda m: m.command == "SETNAME" and m.nick == "soldertest", what="SETNAME of monitored nick")
    plain.not_expected(lambda m: m.command == "SETNAME")

    d.send("AWAY")
    m = c.expect(lambda m: m.command == "AWAY" and m.nick == "soldertest", what="AWAY (back)")
    assert "testing" not in m.params

    # Once the nick is no longer monitored nothing is forwarded.
    c.send("MONITOR - soldertest")
    time.sleep(0.3)
    d.send("AWAY :again")
    c.not_expected(lambda m: m.command == "AWAY")
    for x in (c, plain, d):
        x.close()
