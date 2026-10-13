"""solder.chat/webpush-rules: bouncer-side push rules (docs/webpush-rules.md)."""
import time

import pytest

from conftest import make_znc, ZNC_USER, ZNC_PASS
from test_webpush import PushEndpoint, CAP

RULES = "solder.chat/webpush-rules"
MODS = ("ircv3base", "bouncernetworks", "readmarker", "webpush")


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


@pytest.fixture
def endpoint():
    e = PushEndpoint()
    yield e
    e.stop()


def rules(c):
    c.send("WEBPUSH RULES")
    start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="RULES batch")
    assert start.params[1] == RULES
    return sorted((m.params[1], m.params[2]) for m in c.collect_batch(start))


def rule(c, action, kind, value=None):
    c.send(f"WEBPUSH RULE {action} {kind}" + (f" :{value}" if value is not None else ""))
    return c.expect(lambda m: m.command in ("WEBPUSH", "FAIL"), what=f"RULE {action} reply")


def pushed_texts(endpoint, n, timeout=3.0):
    got = endpoint.wait(n, timeout=timeout)
    time.sleep(0.5)
    assert len(endpoint.received) == n, [endpoint.decrypt(b).decode() for _, _, b in endpoint.received]
    return [endpoint.decrypt(b).decode() for _, _, b in got]


def test_manage_rules(znc):
    c = znc.login("c", "ergo1", extra_caps=(CAP, RULES))
    assert RULES in c.caps_enabled
    assert rules(c) == []
    m = rule(c, "ADD", "highlight", "build failed")
    assert m.command == "WEBPUSH" and m.params == ["RULE", "ADD", "highlight", "build failed"], m.raw
    rule(c, "ADD", "highlight", "build failed")  # duplicate: silent success
    rule(c, "ADD", "mute", "#noise")
    rule(c, "ADD", "all", "#ops")
    rule(c, "ADD", "ignore", "spam*!*@*")
    rule(c, "ADD", "highlight", "/fo+bar/")
    assert rules(c) == [("all", "#ops"), ("highlight", "/fo+bar/"), ("highlight", "build failed"),
                        ("ignore", "spam*!*@*"), ("mute", "#noise")]
    # Errors
    m = rule(c, "ADD", "bogus", "x")
    assert m.command == "FAIL" and m.params[:3] == ["WEBPUSH", "INVALID_PARAMS", "RULE"], m.raw
    m = rule(c, "ADD", "highlight", "/(unclosed/")
    assert m.command == "FAIL" and m.params[1] == "INVALID_PARAMS", m.raw
    c.send("WEBPUSH RULE ADD highlight")
    m = c.expect(lambda m: m.command == "FAIL")
    assert m.params[1] == "INVALID_PARAMS"
    m = rule(c, "ADD", "highlight", "x" * 201)
    assert m.command == "FAIL" and m.params[1] == "INVALID_PARAMS"
    # Delete, clear one kind, clear all
    m = rule(c, "DEL", "highlight", "/fo+bar/")
    assert m.params == ["RULE", "DEL", "highlight", "/fo+bar/"]
    rule(c, "DEL", "highlight", "never existed")  # silent
    m = rule(c, "CLEAR", "highlight")
    assert m.params == ["RULE", "CLEAR", "highlight"]
    assert rules(c) == [("all", "#ops"), ("ignore", "spam*!*@*"), ("mute", "#noise")]
    m = rule(c, "CLEAR", "")
    assert m.params == ["RULE", "CLEAR"]
    assert rules(c) == []
    # Limit
    for i in range(100):
        rule(c, "ADD", "highlight", f"word{i}")
    m = rule(c, "ADD", "highlight", "one too many")
    assert m.command == "FAIL" and m.params[1] == "LIMIT_EXCEEDED", m.raw
    c.close()


def test_rules_without_cap_are_refused(znc):
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    c.send("WEBPUSH RULES")
    m = c.expect(lambda m: m.command in ("WEBPUSH", "FAIL", "BATCH"))
    assert m.command == "FAIL" and m.params[1] == "INVALID_PARAMS", m.raw
    c.close()


def test_decisions(znc, endpoint):
    c = znc.login("c", "ergo1", extra_caps=(CAP, RULES))
    c.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    c.expect(lambda m: m.command == "WEBPUSH")
    rule(c, "ADD", "highlight", "build failed")
    rule(c, "ADD", "highlight", "/dep(loy|loyment)s?\\b/")
    rule(c, "ADD", "mute", "#QUIET")
    rule(c, "ADD", "all", "#ops")
    rule(c, "ADD", "ignore", "troll")
    c.join("#quiet")
    c.join("#ops")
    c.close()  # nobody present: pushes are immediate
    time.sleep(0.5)

    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    troll = znc.networks["ergo1"].client("troll")
    troll.register("troll", "troll")
    for p in (peer, troll):
        p.join("#test")
        p.join("#quiet")
        p.join("#ops")
    time.sleep(0.3)
    # Whole-word nick and highlight patterns; substrings do not count.
    peer.privmsg("#test", f"{ZNC_USER}2 is not you")
    peer.privmsg("#test", "builds failed is not the phrase")
    peer.privmsg("#test", "the deployed thing")  # regex wants deploy/deployment(s) as a word
    peer.privmsg("#test", f"hey {ZNC_USER}, look")
    peer.privmsg("#test", "The BUILD FAILED again")
    peer.privmsg("#test", "deployments done")
    texts = pushed_texts(endpoint, 3)
    assert all(any(s in t for s in ("hey alice, look", "BUILD FAILED", "deployments done")) for t in texts), texts
    # mute beats highlights and DMs; all pushes everything; ignore beats all.
    peer.privmsg("#quiet", f"{ZNC_USER}: muted")
    peer.privmsg("#ops", "routine line")
    troll.privmsg("#ops", "ignored even here")
    troll.privmsg(ZNC_USER, "ignored dm")
    peer.privmsg(ZNC_USER, "real dm")
    texts = pushed_texts(endpoint, 5)
    assert "routine line" in texts[3] and "real dm" in texts[4], texts
    # INVITE to the user is pushed.
    peer.join("#inv")
    time.sleep(0.2)
    peer.send(f"INVITE {ZNC_USER} #inv")
    texts = pushed_texts(endpoint, 6)
    assert "INVITE" in texts[5] and "#inv" in texts[5], texts
    peer.close()
    troll.close()


def unbound_login(znc, name):
    c = znc.client(name, None)
    c.cap_ls()
    assert c.cap_req("message-tags", "server-time", "batch", CAP, RULES, "soju.im/bouncer-networks")
    c.send(f"PASS {ZNC_USER}:{ZNC_PASS}")
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :x")
    c.cap_end()
    c.expect_cmd("001")
    return c


def test_account_wide_rules_from_unbound_connection(znc, endpoint):
    main = unbound_login(znc, "main")
    rule(main, "ADD", "highlight", "everywhere")
    assert rules(main) == [("highlight", "everywhere")]
    main.send("WEBPUSH RULES")
    main.collect_batch(main.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+")))
    bound = znc.login("bound", "ergo2", extra_caps=(CAP, RULES))
    assert rules(bound) == []  # network scope is separate...
    bound.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    bound.expect(lambda m: m.command == "WEBPUSH")
    main.close()
    bound.close()
    time.sleep(0.5)
    peer = znc.networks["ergo2"].client("peer")
    peer.register("peer", "peer")
    peer.join("#test")
    peer.privmsg("#test", "it applies everywhere though")  # ...but the union applies
    texts = pushed_texts(endpoint, 1)
    assert "everywhere" in texts[0]
    peer.close()


def test_rules_survive_restart(znc, workdir, ergos, built_modules):
    c = znc.login("c", "ergo1", extra_caps=(CAP, RULES))
    rule(c, "ADD", "mute", "#noise")
    c.close()
    znc.stop()
    z2 = make_znc(workdir / "second", ergos, built_modules, global_modules=MODS, reuse_datadir=znc.datadir)
    try:
        c = z2.login("c", "ergo1", extra_caps=(CAP, RULES))
        assert rules(c) == [("mute", "#noise")]
        c.send("PRIVMSG *webpush :rules")
        rows = [m.params[-1] for m in c.drain(1.0) if m.nick == "*webpush"]
        assert any("#noise" in r for r in rows), rows
        c.close()
    finally:
        z2.stop()
