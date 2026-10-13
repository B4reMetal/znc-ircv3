"""draft/multiline pass-through and flattening."""
import pytest

from conftest import make_znc, FakeServer

CAP = "draft/multiline"
MODS = ("ircv3base", "multiline")


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


@pytest.fixture
def znc_fake(workdir, built_modules):
    fake = FakeServer(caps={"message-tags": "", "server-time": "", "batch": ""})  # no multiline
    z = make_znc(workdir, {"fake": fake}, built_modules, global_modules=MODS)
    fake.wait_registered()
    yield z, fake
    z.stop()
    fake.stop()


def send_multiline(c, ref, target, lines):
    c.send(f"BATCH +{ref} draft/multiline {target}")
    for l in lines:
        c.send(f"@batch={ref} PRIVMSG {target} :{l}")
    c.send(f"BATCH -{ref}")


def test_passthrough_both_directions_with_ergo(znc):
    a = znc.login("a", "ergo1", extra_caps=(CAP,))
    assert CAP in a.caps_enabled and CAP + "=" not in str(a.caps_available)  # value parsed separately
    assert a.caps_available[CAP] == "max-bytes=4096,max-lines=100"
    b = znc.login("b", "ergo1")  # batch, but no multiline
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer", caps=("message-tags", "server-time", "batch", CAP))
    assert CAP in peer.caps_enabled
    peer.join("#test")
    for c in (a, b):
        c.drain(0.3)

    # client -> server: the upstream relays it as a multiline batch.
    send_multiline(a, "ml1", "#test", ["first line", "second line"])
    start = peer.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="multiline batch at peer")
    assert start.params[1] == CAP and start.params[2] == "#test"
    inner = peer.collect_batch(start)
    assert [m.params[-1] for m in inner] == ["first line", "second line"]
    # The other ZNC client gets plain lines, no framing.
    got = [m for m in b.drain(1.0) if m.command in ("PRIVMSG", "BATCH")]
    assert [m.command for m in got] == ["PRIVMSG", "PRIVMSG"], [m.raw for m in got]
    assert all("batch" not in m.tags for m in got)

    # server -> client: a sees the batch, b sees flat lines.
    send_multiline(peer, "ml2", "#test", ["peer one", "peer two"])
    start = a.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+") and m.params[1] == CAP, what="multiline batch at a")
    inner = a.collect_batch(start)
    assert [m.params[-1] for m in inner] == ["peer one", "peer two"]
    got = [m for m in b.drain(1.0) if m.command in ("PRIVMSG", "BATCH")]
    assert [m.command for m in got] == ["PRIVMSG", "PRIVMSG"], [m.raw for m in got]
    assert all("batch" not in m.tags for m in got)
    a.close()
    b.close()
    peer.close()


def test_flattened_when_upstream_lacks_multiline(znc_fake):
    z, fake = znc_fake
    a = z.login("a", "fake", extra_caps=(CAP,))
    a.join("#test")
    while not fake.received.empty():
        fake.received.get()
    send_multiline(a, "ml3", "#test", ["one", "two"])
    m1 = fake.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "one")
    m2 = fake.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "two")
    assert "batch" not in m1.tags and "batch" not in m2.tags
    seen = []
    while not fake.received.empty():
        seen.append(fake.received.get())
    assert not any(m.command == "BATCH" for m in seen)
    a.close()
