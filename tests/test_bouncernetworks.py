"""soju.im/bouncer-networks against two Ergo servers in Docker."""
import pytest

from conftest import make_znc, FakeServer, ZNC_USER, ZNC_PASS
from ircclient import unescape_tag


def attrs(s: str) -> dict:
    out = {}
    for kv in s.split(";"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k] = unescape_tag(v)
        else:
            out[kv] = ""
    return out

CAP = "soju.im/bouncer-networks"
NOTIFY = "soju.im/bouncer-networks-notify"
MODS = ("ircv3base", "bouncernetworks")


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


def list_networks(c):
    c.send("BOUNCER LISTNETWORKS")
    start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="LISTNETWORKS batch")
    assert start.params[1] == "soju.im/bouncer-networks"
    inner = c.collect_batch(start)
    nets = {}
    for m in inner:
        assert m.command == "BOUNCER" and m.params[0] == "NETWORK", m.raw
        nets[m.params[1]] = attrs(m.params[2])
    return nets


def bind_login(znc, netid: str, name="bound", notify=False, sasl=True):
    """Full soju-style login: CAP LS 302, REQ, SASL, BOUNCER BIND, CAP END."""
    c = znc.client(name, None)
    caps = c.cap_ls()
    assert CAP in caps and NOTIFY in caps
    want = ["message-tags", "server-time", "batch", "sasl", CAP] + ([NOTIFY] if notify else [])
    assert c.cap_req(*want)
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :x")
    if sasl:
        c.sasl_plain(ZNC_USER, ZNC_PASS)
    else:
        c.send(f"PASS {ZNC_USER}:{ZNC_PASS}")
    c.send(f"BOUNCER BIND {netid}")
    c.cap_end()
    return c


def test_caps_advertised_and_list(znc):
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    assert CAP in c.caps_enabled
    nets = list_networks(c)
    assert len(nets) == 2
    by_name = {a["name"]: (nid, a) for nid, a in nets.items()}
    assert set(by_name) == {"ergo1", "ergo2"}
    nid, a = by_name["ergo1"]
    assert a["state"] == "connected"
    assert a["host"] == znc.networks["ergo1"].host
    assert a["port"] == str(znc.networks["ergo1"].port)
    assert a["tls"] == "0"
    assert a["nickname"] == ZNC_USER
    assert a["username"] == ZNC_USER
    assert a["realname"] == "Alice Example"
    # A connection that chose its network the ZNC way is still "bound".
    isup = [m for m in c.log if m.command == "005" and any(p.startswith("BOUNCER_NETID=") for p in m.params)]
    assert isup and f"BOUNCER_NETID={nid}" in isup[0].params
    c.close()


def test_bind_selects_network(znc):
    probe = znc.login("probe", "ergo1", extra_caps=(CAP,))
    nets = list_networks(probe)
    ergo2_id = next(nid for nid, a in nets.items() if a["name"] == "ergo2")
    probe.close()

    c = bind_login(znc, ergo2_id)
    c.expect_cmd("001")
    m = c.expect(lambda m: m.command == "005" and any(p.startswith("NETWORK=") for p in m.params), what="005 NETWORK")
    assert "NETWORK=ergo2" in m.params, m.raw
    m = c.expect(lambda m: m.command == "005" and any(p.startswith("BOUNCER_NETID=") for p in m.params), what="BOUNCER_NETID")
    assert f"BOUNCER_NETID={ergo2_id}" in m.params
    # Messages flow from ergo2.
    peer = znc.networks["ergo2"].client("peer")
    peer.register("peer", "peer")
    peer.join("#test")
    peer.privmsg("#test", "via ergo2")
    c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "via ergo2")
    peer.close()
    c.close()


def test_bind_with_pass_auth(znc):
    probe = znc.login("probe", "ergo1", extra_caps=(CAP,))
    ergo2_id = next(nid for nid, a in list_networks(probe).items() if a["name"] == "ergo2")
    probe.close()
    c = bind_login(znc, ergo2_id, sasl=False)
    c.expect_cmd("001")
    m = c.expect(lambda m: m.command == "005" and any(p.startswith("NETWORK=") for p in m.params), what="005 NETWORK")
    assert "NETWORK=ergo2" in m.params
    c.drain(0.5)
    assert not any(m.nick == "*status" and "Selecting network" in m.params[-1] for m in c.log)
    c.close()


def test_bind_invalid_id_fails_and_closes(znc):
    c = bind_login(znc, "999")
    m = c.expect_cmd("FAIL")
    assert m.params[:3] == ["BOUNCER", "INVALID_NETID", "BIND"]
    with pytest.raises((ConnectionError, AssertionError)):
        c.expect_cmd("001", timeout=2)


def test_bind_after_registration_rejected(znc):
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    c.send("BOUNCER BIND 1")
    m = c.expect_cmd("FAIL")
    assert m.params[:3] == ["BOUNCER", "REGISTRATION_IS_COMPLETED", "BIND"]
    c.send("BOUNCER FROBNICATE")
    m = c.expect_cmd("FAIL")
    assert m.params[:2] == ["BOUNCER", "UNKNOWN_COMMAND"]
    c.close()


def test_bind_requires_auth_first(znc):
    c = znc.client("c", None)
    c.cap_ls()
    c.cap_req(CAP)
    c.send("BOUNCER BIND 1")
    m = c.expect_cmd("FAIL")
    assert m.params[:3] == ["BOUNCER", "ACCOUNT_REQUIRED", "BIND"]
    c.sock.close()


def test_notify_initial_list_and_state_changes(znc):
    c = znc.login("c", "ergo1", extra_caps=(CAP, NOTIFY))
    # The initial list arrives as a batch right after login.
    start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+") and m.params[1] == "soju.im/bouncer-networks", what="initial list")
    inner = c.collect_batch(start)
    assert len(inner) == 2
    ids = {m.params[1]: m.params[2] for m in inner}
    ergo2_id = next(i for i, a in ids.items() if "name=ergo2" in a)
    # Bounce ergo2 by kicking ZNC off the server from Ergo's side: simplest
    # is to ask ZNC to disconnect and reconnect the network.
    c.send("PRIVMSG *status :Jump")  # current network is ergo1
    m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and "state=disconnected" in m.params[2], what="disconnected notify")
    m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and "state=connecting" in m.params[2], what="connecting notify", timeout=45)
    m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and "state=connected" in m.params[2], what="connected notify", timeout=45)
    c.close()


def test_add_change_delete_network(znc, workdir):
    fake = FakeServer(name="added")
    try:
        c = znc.login("c", "ergo1", extra_caps=(CAP, NOTIFY))
        c.drain(0.5)
        # Missing host
        c.send("BOUNCER ADDNETWORK name=nohost")
        m = c.expect_cmd("FAIL")
        assert m.params[:3] == ["BOUNCER", "NEED_ATTRIBUTE", "ADDNETWORK"]
        # Bad attribute
        c.send(f"BOUNCER ADDNETWORK host={fake.host};port=abc")
        m = c.expect_cmd("FAIL")
        assert m.params[:2] == ["BOUNCER", "INVALID_ATTRIBUTE"]
        c.send(f"BOUNCER ADDNETWORK host={fake.host};bogus=1")
        m = c.expect_cmd("FAIL")
        assert m.params[:2] == ["BOUNCER", "UNKNOWN_ATTRIBUTE"]
        # Good
        c.send(f"BOUNCER ADDNETWORK name=added;host={fake.host};port={fake.port};tls=0;nickname=bob;realname=Bob\\sB;pass=s3cret")
        m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "ADDNETWORK", what="ADDNETWORK reply")
        new_id = m.params[1]
        m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and m.params[1] == new_id, what="notify add")
        assert "name=added" in m.params[2] and "nickname=bob" in m.params[2] and "realname=Bob\\sB" in m.params[2]
        assert "pass" not in attrs(m.params[2]), m.raw  # write-only
        fake.wait_registered()
        assert fake.nick == "bob"
        c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and m.params[1] == new_id and "state=connected" in m.params[2], what="connected", timeout=15)
        nets = list_networks(c)
        assert nets[new_id]["name"] == "added" and nets[new_id]["host"] == fake.host and nets[new_id]["tls"] == "0"
        assert "pass" not in nets[new_id]
        assert fake.password == "s3cret"
        # Change: rename + nick, no server change
        c.send(f"BOUNCER CHANGENETWORK {new_id} name=renamed;nickname=bobby")
        m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "CHANGENETWORK", what="CHANGENETWORK reply")
        m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and m.params[1] == new_id and "name=renamed" in m.params[2], what="rename notify")
        nets = list_networks(c)
        assert nets[new_id]["name"] == "renamed" and nets[new_id]["nickname"] == "bobby"
        # Read-only attribute
        c.send(f"BOUNCER CHANGENETWORK {new_id} state=connected")
        m = c.expect_cmd("FAIL")
        assert m.params[:2] == ["BOUNCER", "READ_ONLY_ATTRIBUTE"]
        # A second client bound to the new network gets detached on delete.
        d = bind_login(znc, new_id, name="d", notify=True)
        d.expect_cmd("001")
        d.drain(0.5)
        c.send(f"BOUNCER DELNETWORK {new_id}")
        m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "DELNETWORK", what="DELNETWORK reply")
        m = c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and m.params[1] == new_id and m.params[2] == "*", what="delete notify")
        d.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and m.params[1] == new_id and m.params[2] == "*", what="delete notify on bound client")
        assert new_id not in list_networks(c)
        c.send(f"BOUNCER CHANGENETWORK {new_id} name=x")
        m = c.expect_cmd("FAIL")
        assert m.params[:2] == ["BOUNCER", "INVALID_NETID"]
        c.close()
        d.close()
    finally:
        fake.stop()


def test_ids_survive_restart(znc, workdir, ergos, built_modules):
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    before = {a["name"]: nid for nid, a in list_networks(c).items()}
    c.close()
    znc.stop()
    z2 = make_znc(workdir / "second", ergos, built_modules, global_modules=MODS, reuse_datadir=znc.datadir)
    try:
        c = z2.login("c", "ergo1", extra_caps=(CAP,))
        after = {a["name"]: nid for nid, a in list_networks(c).items()}
        assert after == before
        c.close()
    finally:
        z2.stop()


def test_unbound_connection_without_bind(znc):
    """soju semantics: cap negotiated, no BIND, no user/network -> unbound."""
    c = znc.client("main", None)
    c.cap_ls()
    assert c.cap_req("message-tags", "server-time", "batch", "sasl", CAP, NOTIFY)
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :x")
    c.sasl_plain(ZNC_USER, ZNC_PASS)
    c.cap_end()
    m = c.expect_cmd("001")
    assert m.prefix == "irc.znc.in"
    start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+") and m.params[1] == "soju.im/bouncer-networks", what="network list")
    inner = c.collect_batch(start)
    assert len(inner) == 2
    # Not bound: no BOUNCER_NETID, no channel joins, no upstream 005, and
    # none of ZNC's "Selecting network" status notices.
    msgs = c.drain(1.0)
    assert not any(m.nick == "*status" and "Selecting network" in m.params[-1] for m in c.log), [m.raw for m in c.log if m.nick == "*status"]
    assert not any(m.command == "005" and any(p.startswith("BOUNCER_NETID=") for p in m.params) for m in c.log)
    assert not any(m.command == "005" and any(p.startswith("NETWORK=ergo") for p in m.params) for m in c.log)
    assert not any(m.command == "JOIN" for m in c.log), [m.raw for m in c.log if m.command == "JOIN"]
    # It still receives notifications and can manage networks.
    ergo2_id = next(m.params[1] for m in inner if "name=ergo2" in m.params[2])
    c.send(f"BOUNCER CHANGENETWORK {ergo2_id} realname=Changed\\sName")
    c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "CHANGENETWORK")
    c.expect(lambda m: m.command == "BOUNCER" and m.params[0] == "NETWORK" and m.params[1] == ergo2_id and "realname=" in m.params[2])
    # A second connection binding to ergo2 works alongside it.
    d = bind_login(znc, ergo2_id, name="child")
    d.expect_cmd("001")
    m = d.expect(lambda m: m.command == "005" and any(p.startswith("NETWORK=") for p in m.params), what="005 NETWORK")
    assert "NETWORK=ergo2" in m.params
    c.close()
    d.close()
