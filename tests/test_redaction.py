"""draft/message-redaction (chathistory module)."""
import pytest

from conftest import make_znc, FakeServer

CAP = "draft/message-redaction"
HIST = "draft/chathistory"
MODS = ("ircv3base", "chathistory")


@pytest.fixture
def znc_fake(workdir, built_modules):
    fake = FakeServer(caps={"message-tags": "", "server-time": "", "batch": "", CAP: ""})
    z = make_znc(workdir, {"fake": fake}, built_modules, global_modules=MODS)
    fake.wait_registered()
    yield z, fake
    z.stop()
    fake.stop()


@pytest.fixture
def znc_plain(workdir, built_modules):
    fake = FakeServer(caps={"message-tags": "", "server-time": "", "batch": ""})
    z = make_znc(workdir / "plain", {"fake": fake}, built_modules, global_modules=MODS)
    fake.wait_registered()
    yield z, fake
    z.stop()
    fake.stop()


def test_upstream_redact_removes_from_history_and_playback(znc_fake):
    z, fake = znc_fake
    assert CAP in fake.enabled_caps
    r = z.login("r", "fake", extra_caps=(CAP, HIST))
    assert CAP in r.caps_enabled
    p = z.login("p", "fake")
    r.join("#test")
    for c in (r, p):
        c.drain(0.3)
    fake.send("@msgid=m1 :peer!u@h PRIVMSG #test :to be removed")
    fake.send("@msgid=m2 :peer!u@h PRIVMSG #test :stays")
    p.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "stays")
    r.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "stays")
    fake.send(":peer!u@h REDACT #test m1 :oops")
    m = r.expect_cmd("REDACT")
    assert m.params[:2] == ["#test", "m1"]
    p.not_expected(lambda m: m.command == "REDACT")

    r.send("CHATHISTORY LATEST #test * 10")
    start = r.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="history")
    inner = r.collect_batch(start)
    assert [m.params[-1] for m in inner] == ["stays"]

    # A fresh plain client's playback no longer contains the redacted line.
    q = z.login("q", "fake")
    lines = [m.params[-1] for m in q.drain(1.0) if m.command == "PRIVMSG" and m.params[0] == "#test"]
    assert "stays" in lines and "to be removed" not in lines, lines
    for c in (r, p, q):
        c.close()


def test_client_redact_forwarded_or_refused(znc_fake, znc_plain):
    z, fake = znc_fake
    r = z.login("r", "fake", extra_caps=(CAP,))
    r.drain(0.3)
    while not fake.received.empty():
        fake.received.get()
    r.send("REDACT #test m2 :mistake")
    up = fake.expect(lambda m: m.command == "REDACT")
    assert up.params[:2] == ["#test", "m2"]
    r.close()

    z2, fake2 = znc_plain
    r2 = z2.login("r2", "fake", extra_caps=(CAP,))
    r2.send("REDACT #test m2 :mistake")
    m = r2.expect_cmd("FAIL")
    assert m.params[:2] == ["REDACT", "REDACT_FORBIDDEN"]
    r2.close()
