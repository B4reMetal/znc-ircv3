"""echo-message from the server: own messages carry the server's msgid."""
import pytest

from conftest import make_znc, FakeServer, ZNC_USER

MODS = ("ircv3base", "chathistory", "multiline", "labeled")
CH = "draft/chathistory"


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


def peer_on(znc, name="peer"):
    p = znc.networks["ergo1"].client(name)
    p.register(name, name, caps=("message-tags", "server-time"))
    p.join("#test")
    return p


def test_channel_echo_uses_server_msgid_once(znc):
    peer = peer_on(znc)
    a = znc.login("a", "ergo1", extra_caps=("echo-message",))
    b = znc.login("b", "ergo1")  # no echo-message: still sees a's message as a self-message
    for c in (a, b):
        c.drain(0.3)
    a.send("PRIVMSG #test :server echo please")
    echo = a.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "server echo please", what="echo")
    seen = peer.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "server echo please", what="peer copy")
    assert echo.tags["msgid"] == seen.tags["msgid"] and not echo.tags["msgid"].startswith("znc-"), (echo.raw, seen.raw)
    assert echo.tags["time"] == seen.tags["time"]
    assert echo.nick == ZNC_USER
    other = b.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "server echo please", what="other client")
    assert other.tags["msgid"] == seen.tags["msgid"]
    a.not_expected(lambda m: m.command == "PRIVMSG" and m.params[-1] == "server echo please", idle=1.0)
    b.not_expected(lambda m: m.command == "PRIVMSG" and m.params[-1] == "server echo please", idle=0.5)
    # Sender without echo-message gets nothing back.
    b.send("PRIVMSG #test :from b")
    a.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "from b")
    b.not_expected(lambda m: m.command == "PRIVMSG" and m.params[-1] == "from b", idle=1.0)
    # Buffered once, with the server id: a late plain client replays it once.
    plain = znc.login("plain", "ergo1")
    lines = [m for m in plain.drain(1.5) if m.command == "PRIVMSG" and m.params[-1] == "server echo please"]
    assert len(lines) == 1 and lines[0].tags.get("msgid") == seen.tags["msgid"], [m.raw for m in lines]
    for c in (a, b, plain, peer):
        c.close()


def test_private_echo_lands_in_the_right_buffer(znc):
    peer = peer_on(znc)
    a = znc.login("a", "ergo1", extra_caps=("echo-message", CH))
    b = znc.login("b", "ergo1", extra_caps=("znc.in/self-message",))
    for c in (a, b):
        c.drain(0.3)
    a.send("PRIVMSG peer :private echo")
    echo = a.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "private echo", what="echo")
    seen = peer.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "private echo", what="peer copy")
    assert echo.tags["msgid"] == seen.tags["msgid"] and echo.params[0] == "peer"
    copy = b.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "private echo", what="self-message copy")
    assert copy.params[0] == "peer" and copy.nick == ZNC_USER
    # chathistory filed it under the peer, with the server id.
    a.send("CHATHISTORY LATEST peer * 5")
    start = a.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"))
    inner = a.collect_batch(start)
    mine = [m for m in inner if m.params[-1] == "private echo"]
    assert len(mine) == 1 and mine[0].tags["msgid"] == seen.tags["msgid"] and mine[0].nick == ZNC_USER, [m.raw for m in inner]
    a.send(f"CHATHISTORY LATEST {ZNC_USER} * 5")
    start = a.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"))
    assert a.collect_batch(start) == []  # nothing filed under our own nick
    for c in (a, b, peer):
        c.close()


def test_labeled_echo_keeps_label_and_server_id(znc):
    peer = peer_on(znc)
    a = znc.login("a", "ergo1", extra_caps=("echo-message", "labeled-response"))
    b = znc.login("b", "ergo1")
    for c in (a, b):
        c.drain(0.3)
    a.send("@label=e1 PRIVMSG #test :labeled echo")
    echo = a.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "labeled echo", what="echo")
    seen = peer.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "labeled echo")
    assert echo.tags.get("label") == "e1" and echo.tags["msgid"] == seen.tags["msgid"], echo.raw
    other = b.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "labeled echo")
    assert "label" not in other.tags
    a.send("@label=p1 PING :x")
    m = a.expect(lambda m: m.command in ("PONG", "ACK"))
    assert m.command == "PONG" and m.tags.get("label") == "p1", m.raw  # no stray ACK for e1
    for c in (a, b, peer):
        c.close()


def test_unsolicited_server_echo_is_dropped(workdir, built_modules):
    """A server that echoes own messages without echo-message (Seedpool with
    seedpool/enhanced): clients see one line, history stores one copy."""
    fake = FakeServer(caps={"message-tags": "", "server-time": ""}, echo_without_cap=True)
    z = make_znc(workdir, {"fake": fake}, built_modules, global_modules=MODS)
    try:
        fake.wait_registered()
        a = z.login("a", "fake", extra_caps=("echo-message", CH))
        b = z.login("b", "fake")
        for c in (a, b):
            c.drain(0.3)
        a.send("PRIVMSG #test :only once please")
        echo = a.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "only once please")
        assert echo.tags["msgid"].startswith("znc-"), echo.raw
        fake.expect(lambda m: m.command == "PRIVMSG")
        b.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "only once please")
        a.not_expected(lambda m: m.command == "PRIVMSG" and m.params[-1] == "only once please", idle=1.0)
        b.not_expected(lambda m: m.command == "PRIVMSG" and m.params[-1] == "only once please", idle=0.5)
        a.send("CHATHISTORY LATEST #test * 10")
        start = a.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+") and m.params[1] == "chathistory")
        inner = a.collect_batch(start)
        assert [m.params[-1] for m in inner].count("only once please") == 1, [m.raw for m in inner]
        a.close()
        b.close()
    finally:
        z.stop()
        fake.stop()
