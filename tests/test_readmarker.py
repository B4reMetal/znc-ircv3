"""draft/read-marker and soju.im/read."""
import pytest

from conftest import make_znc

DRAFT = "draft/read-marker"
SOJU = "soju.im/read"
T1 = "timestamp=2026-10-12T10:00:00.000Z"
T2 = "timestamp=2026-10-12T10:05:00.000Z"


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=("ircv3base", "readmarker"))
    yield z
    z.stop()


def test_cap_and_roundtrip(znc):
    a = znc.login("a", "ergo1", extra_caps=(DRAFT,))
    assert DRAFT in a.caps_enabled
    b = znc.login("b", "ergo1", extra_caps=(SOJU,))
    assert SOJU in b.caps_enabled
    for c in (a, b):
        c.drain(0.3)

    a.send("MARKREAD #test")
    m = a.expect_cmd("MARKREAD")
    assert m.params == ["#test", "*"]

    a.send(f"MARKREAD #test {T1}")
    m = a.expect_cmd("MARKREAD")
    assert m.params == ["#test", T1]
    # The other client hears about it in its own dialect.
    m = b.expect_cmd("READ")
    assert m.params == ["#test", T1]

    # Moving backwards is ignored, the stored value comes back.
    a.send("MARKREAD #test timestamp=2026-10-12T09:00:00.000Z")
    m = a.expect_cmd("MARKREAD")
    assert m.params == ["#test", T1]
    b.not_expected(lambda m: m.command == "READ")

    # soju dialect can advance it too.
    b.send(f"READ #test {T2}")
    m = b.expect_cmd("READ")
    assert m.params == ["#test", T2]
    m = a.expect_cmd("MARKREAD")
    assert m.params == ["#test", T2]

    # Errors
    a.send("MARKREAD")
    m = a.expect_cmd("FAIL")
    assert m.params[:2] == ["MARKREAD", "NEED_MORE_PARAMS"]
    a.send("MARKREAD #test yesterday")
    m = a.expect_cmd("FAIL")
    assert m.params[:2] == ["MARKREAD", "INVALID_PARAMS"]
    a.close()
    b.close()


def test_marker_replayed_on_attach_and_join(znc):
    a = znc.login("a", "ergo1", extra_caps=(DRAFT,))
    a.drain(0.3)
    a.send(f"MARKREAD #test {T1}")
    a.expect_cmd("MARKREAD")
    a.close()

    c = znc.login("c", "ergo1", extra_caps=(DRAFT,))
    m = c.expect_cmd("MARKREAD")
    assert m.params == ["#test", T1]
    # Joining a new channel with a stored marker announces it.
    c.send(f"MARKREAD #other {T2}")
    c.expect_cmd("MARKREAD")
    c.send("JOIN #other")
    c.expect(lambda m: m.command == "JOIN" and m.params[0] == "#other")
    m = c.expect(lambda m: m.command == "MARKREAD" and m.params[0] == "#other", what="MARKREAD after join")
    assert m.params[1] == T2
    c.close()


def test_never_forwarded_upstream(znc):
    a = znc.login("a", "ergo1", extra_caps=(DRAFT,))
    direct = znc.networks["ergo1"].client("direct")
    direct.register("direct", "direct", caps=("message-tags", "server-time", "batch", DRAFT))
    direct.join("#test")
    a.send(f"MARKREAD #test {T1}")
    a.expect_cmd("MARKREAD")
    direct.not_expected(lambda m: m.command == "MARKREAD")
    a.close()
    direct.close()


def test_without_cap_nothing_is_sent(znc):
    a = znc.login("a", "ergo1", extra_caps=(DRAFT,))
    plain = znc.login("plain", "ergo1")
    plain.drain(0.3)
    a.send(f"MARKREAD #test {T1}")
    a.expect_cmd("MARKREAD")
    plain.not_expected(lambda m: m.command in ("MARKREAD", "READ"))
    a.close()
    plain.close()
