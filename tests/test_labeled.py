"""labeled-response."""
import pytest

from conftest import make_znc, FakeServer, ZNC_USER

CAP = "labeled-response"
# labeled last: it reorders itself ahead of the modules that answer commands.
MODS = ("ircv3base", "chathistory", "bouncernetworks", "labeled")


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


@pytest.fixture
def znc_nolabels(workdir, built_modules):
    fake = FakeServer(caps={"message-tags": "", "server-time": "", "batch": ""})
    z = make_znc(workdir, {"fake": fake}, built_modules, global_modules=MODS)
    fake.wait_registered()
    yield z, fake
    z.stop()
    fake.stop()


def test_upstream_reply_routed_only_to_requester(znc):
    a = znc.login("a", "ergo1", extra_caps=(CAP,))
    assert CAP in a.caps_enabled
    b = znc.login("b", "ergo1")
    for c in (a, b):
        c.drain(0.3)
    a.send(f"@label=w1 WHOIS {ZNC_USER}")
    m = a.expect(lambda m: m.tags.get("label") == "w1", what="labeled reply")
    assert m.command == "BATCH" and m.params[1] == "labeled-response", m.raw
    inner = a.collect_batch(m)
    cmds = [x.command for x in inner]
    assert "311" in cmds and "318" in cmds, cmds
    assert all(x.tags.get("batch") == m.params[0][1:] for x in inner)
    assert all("label" not in x.tags for x in inner)
    b.not_expected(lambda m: m.command in ("311", "318"))
    # The upstream saw a ZNC-private label, never "w1" (check via Ergo's echo
    # in a labeled PRIVMSG below).
    a.close()
    b.close()


def test_ping_and_module_commands_are_labeled(znc):
    a = znc.login("a", "ergo1", extra_caps=(CAP,))
    a.drain(0.3)
    a.send("@label=p1 PING :hello")
    m = a.expect(lambda m: m.command == "PONG", what="PONG")
    assert m.tags.get("label") == "p1", m.raw
    # A znc-ircv3 module command answered with a batch.
    a.send("@label=h1 CHATHISTORY LATEST #test * 5")
    m = a.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="chathistory batch")
    assert m.tags.get("label") == "h1", m.raw
    a.collect_batch(m)
    a.send("@label=b1 BOUNCER LISTNETWORKS")
    m = a.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="LISTNETWORKS batch")
    assert m.tags.get("label") == "b1", m.raw
    a.collect_batch(m)
    # *status replies bypass the module hooks in ZNC's core, so they cannot
    # be labeled; the label is ACKed when the next command arrives.
    a.send("@label=s1 PRIVMSG *status :Version")
    m = a.expect(lambda m: m.nick == "*status", what="*status reply")
    assert "label" not in m.tags
    a.send("@label=p2 PING :again")
    m = a.expect(lambda m: m.command == "ACK", what="late ACK")
    assert m.tags.get("label") == "s1", m.raw
    m = a.expect(lambda m: m.command == "PONG", what="PONG")
    assert m.tags.get("label") == "p2", m.raw
    a.close()


def test_echo_message_echo_is_labeled_and_label_does_not_leak(znc):
    a = znc.login("a", "ergo1", extra_caps=(CAP, "echo-message"))
    b = znc.login("b", "ergo1")
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    peer.join("#test")
    for c in (a, b):
        c.drain(0.3)
    a.send("@label=m1 PRIVMSG #test :labeled hello")
    m = a.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "labeled hello", what="echo")
    assert m.tags.get("label") == "m1", m.raw
    m = b.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "labeled hello", what="other client")
    assert "label" not in m.tags, m.raw
    m = peer.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "labeled hello", what="upstream")
    assert "label" not in m.tags, m.raw
    peer.close()
    a.close()
    b.close()


def test_ack_when_upstream_has_no_labels(znc_nolabels):
    z, fake = znc_nolabels
    a = z.login("a", "fake", extra_caps=(CAP,))
    a.drain(0.3)
    a.send(f"@label=x1 WHOIS {ZNC_USER}")
    m = a.expect(lambda m: m.tags.get("label") == "x1", what="ACK")
    assert m.command == "ACK", m.raw
    up = fake.expect(lambda m: m.command == "WHOIS")
    assert "label" not in up.tags
    a.close()


def test_label_without_cap_is_ignored(znc):
    a = znc.login("a", "ergo1")  # no labeled-response
    a.drain(0.3)
    a.send("@label=n1 PING :x")
    m = a.expect(lambda m: m.command == "PONG", what="PONG")
    assert "label" not in m.tags
    a.close()
