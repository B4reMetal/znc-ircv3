"""draft/chathistory and draft/event-playback against Ergo in Docker."""
import pytest

from conftest import make_znc, ZNC_USER

CAP = "draft/chathistory"
EV = "draft/event-playback"
MODS = ("ircv3base", "chathistory")


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


def seed(znc, n=6, chan="#test"):
    """A direct Ergo client talks in #test; a ZNC client answers once.
    Returns the texts in order and the (not yet closed) peer."""
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    peer.join(chan)
    a = znc.login("seeder", "ergo1")
    a.join(chan)
    texts = []
    import time
    for i in range(n):
        time.sleep(0.01)  # distinct millisecond timestamps
        if i == n // 2:
            a.privmsg(chan, "reply from alice")
            texts.append("reply from alice")
            peer.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "reply from alice")
            time.sleep(0.01)
        t = f"msg {i}"
        peer.privmsg(chan, t)
        texts.append(t)
        a.expect(lambda m, t=t: m.command == "PRIVMSG" and m.params[-1] == t)
    a.close()
    return texts, peer


def history(c, sub, *args):
    c.send(f"CHATHISTORY {sub} " + " ".join(str(a) for a in args))
    start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+") and m.params[1] in ("chathistory", "draft/chathistory-targets"), what=f"CHATHISTORY {sub} batch")
    inner = c.collect_batch(start)
    return start, inner


def test_caps_isupport_and_no_autoplayback(znc):
    texts, peer = seed(znc)
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    assert CAP in c.caps_enabled
    m = c.expect(lambda m: m.command == "005" and m.prefix == "irc.znc.in" and any(p.startswith("CHATHISTORY=") for p in m.params), what="ZNC 005 CHATHISTORY")
    assert "CHATHISTORY=1000" in m.params and "MSGREFTYPES=timestamp,msgid" in m.params
    # Inside the registration burst, once; the upstream's own token is dropped.
    end = c.expect(lambda m: m.command in ("376", "422"), what="end of MOTD")
    assert c.log.index(m) < c.log.index(end)
    assert sum(1 for x in c.log if x.command == "005" and any(p.startswith("CHATHISTORY=") for p in x.params)) == 1
    c.not_expected(lambda m: m.command == "005", idle=1.0)
    # No buffer playback for this client...
    c.not_expected(lambda m: m.command == "PRIVMSG" and m.params[-1].startswith("msg "), idle=1.0)
    # ...but a plain client still gets it.
    plain = znc.login("plain", "ergo1")
    plain.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "msg 0")
    c.close()
    plain.close()
    peer.close()


def test_latest_before_after_between_around(znc):
    texts, peer = seed(znc, 6)
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    start, inner = history(c, "LATEST", "#test", "*", 100)
    assert start.params[2] == "#test"
    assert "draft/chathistory-end" in start.tags
    got = [m.params[-1] for m in inner]
    assert got == texts, got
    assert all(m.command == "PRIVMSG" for m in inner)
    assert all("msgid" in m.tags and "time" in m.tags for m in inner)
    assert all("batch" in m.tags for m in inner)
    # Own message carries our nick as prefix.
    own = next(m for m in inner if m.params[-1] == "reply from alice")
    assert own.nick == "alice"

    # LATEST with a limit returns the newest ones, oldest first.
    _, inner = history(c, "LATEST", "#test", "*", 2)
    assert [m.params[-1] for m in inner] == texts[-2:]

    ids = {m.params[-1]: m.tags["msgid"] for m in inner}
    times = {m.params[-1]: m.tags["time"] for m in inner}
    full_start, full = history(c, "LATEST", "#test", "*", 100)
    ids = {m.params[-1]: m.tags["msgid"] for m in full}
    times = {m.params[-1]: m.tags["time"] for m in full}

    # BEFORE by msgid excludes the message itself.
    _, inner = history(c, "BEFORE", "#test", f"msgid={ids['msg 3']}", 100)
    assert [m.params[-1] for m in inner] == texts[:texts.index("msg 3")]
    # BEFORE with a limit gives the newest ones before the selector.
    _, inner = history(c, "BEFORE", "#test", f"msgid={ids['msg 3']}", 2)
    assert [m.params[-1] for m in inner] == texts[texts.index("msg 3") - 2:texts.index("msg 3")]
    # AFTER by timestamp.
    _, inner = history(c, "AFTER", "#test", f"timestamp={times['msg 1']}", 100)
    assert [m.params[-1] for m in inner] == texts[texts.index("msg 1") + 1:]
    # BETWEEN by msgids, forward and backward.
    _, inner = history(c, "BETWEEN", "#test", f"msgid={ids['msg 0']}", f"msgid={ids['msg 4']}", 100)
    assert [m.params[-1] for m in inner] == texts[texts.index("msg 0") + 1:texts.index("msg 4")]
    _, inner = history(c, "BETWEEN", "#test", f"timestamp={times['msg 4']}", f"timestamp={times['msg 0']}", 2)
    assert [m.params[-1] for m in inner] == texts[texts.index("msg 4") - 2:texts.index("msg 4")]
    # AROUND includes the message and neighbours.
    _, inner = history(c, "AROUND", "#test", f"msgid={ids['msg 2']}", 3)
    got = [m.params[-1] for m in inner]
    assert "msg 2" in got and len(got) == 3
    # Unknown msgid
    c.send("CHATHISTORY BEFORE #test msgid=nope 10")
    m = c.expect_cmd("FAIL")
    assert m.params[:2] == ["CHATHISTORY", "MESSAGE_ERROR"]
    # Bad params
    c.send("CHATHISTORY LATEST #test")
    assert c.expect_cmd("FAIL").params[:2] == ["CHATHISTORY", "NEED_MORE_PARAMS"]
    c.send("CHATHISTORY LATEST #test yesterday 10")
    assert c.expect_cmd("FAIL").params[:2] == ["CHATHISTORY", "INVALID_PARAMS"]
    c.send("CHATHISTORY FOO #test * 10")
    assert c.expect_cmd("FAIL").params[:2] == ["CHATHISTORY", "INVALID_PARAMS"]
    # Empty history still yields an (empty) batch.
    start, inner = history(c, "LATEST", "#nothing", "*", 10)
    assert inner == [] and "draft/chathistory-end" in start.tags
    c.close()
    peer.close()


def test_event_playback_and_queries(znc):
    texts, peer = seed(znc, 2)
    # Make some events: peer parts and rejoins, changes topic, sends a PM.
    peer.send("PART #test :brb")
    peer.expect(lambda m: m.command == "PART")
    peer.join("#test")
    t = znc.login("topicsetter", "ergo1")
    t.send("TOPIC #test :history topic")
    t.expect(lambda m: m.command == "TOPIC")
    t.close()
    peer.privmsg("alice", "private hello")
    import time
    time.sleep(0.5)

    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    _, inner = history(c, "LATEST", "#test", "*", 100)
    assert all(m.command == "PRIVMSG" for m in inner), [m.raw for m in inner]
    c.close()

    e = znc.login("e", "ergo1", extra_caps=(CAP, EV))
    _, inner = history(e, "LATEST", "#test", "*", 100)
    cmds = [m.command for m in inner]
    assert "PART" in cmds and "JOIN" in cmds and "TOPIC" in cmds and "PRIVMSG" in cmds, cmds
    assert all("znc.in/event" not in m.tags for m in inner)
    # Query history is stored under the peer's nick.
    _, inner = history(e, "LATEST", "peer", "*", 10)
    assert [m.params[-1] for m in inner] == ["private hello"]
    # TARGETS lists both conversations, newest first.
    _, inner = history(e, "TARGETS", "timestamp=2000-01-01T00:00:00.000Z", "timestamp=2100-01-01T00:00:00.000Z", 10)
    targets = [m.params[1] for m in inner]
    assert targets[0] == "peer" and "#test" in targets, targets
    e.close()
    peer.close()


def test_history_survives_restart(znc, workdir, ergos, built_modules):
    texts, peer = seed(znc, 3)
    peer.close()
    znc.stop()
    z2 = make_znc(workdir / "second", ergos, built_modules, global_modules=MODS, reuse_datadir=znc.datadir)
    try:
        c = z2.login("c", "ergo1", extra_caps=(CAP,))
        _, inner = history(c, "LATEST", "#test", "*", 100)
        assert [m.params[-1] for m in inner] == texts
        c.close()
    finally:
        z2.stop()


def test_without_batch_cap_lines_are_flat(znc):
    texts, peer = seed(znc, 2)
    c = znc.login("c", "ergo1", caps=("message-tags", "server-time"), extra_caps=(CAP,))
    c.send("CHATHISTORY LATEST #test * 10")
    got = [m for m in c.drain(1.0) if m.command == "PRIVMSG"]
    assert [m.params[-1] for m in got] == texts
    assert all("batch" not in m.tags for m in got)
    c.close()
    peer.close()


def test_out_of_order_day_file_is_served_sorted(znc, workdir, ergos, built_modules):
    """An import appends older lines after live ones in the same day file;
    every query must still return time order and honour selectors."""
    texts, peer = seed(znc)
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    _, inner = history(c, "LATEST", "#test", "*", 3)
    assert len(inner) == 3
    first_time = inner[0].tags["time"]
    c.close()
    peer.close()
    znc.stop()
    # Append a line that is older than the live ones, and one between them.
    day_dir = next((znc.datadir / "moddata" / "chathistory" / ZNC_USER / "ergo1" / "#test").glob("*.log")).parent
    day_file = sorted(day_dir.glob("*.log"))[-1]
    older = first_time[:19] + ".000Z"
    older = older[:17] + ("00" if older[17:19] != "00" else "01") + ".000Z"
    t1 = inner[1].tags["time"]
    between = t1[:20] + f"{int(t1[20:23]) + 1:03d}Z"  # one millisecond after inner[1]
    day_file.write_text(day_file.read_text()
                        + f"@msgid=znc-import-aaaa;time={older} :old!~import@znc.import PRIVMSG #test :appended older\n"
                        + f"@msgid=znc-import-bbbb;time={between} :old!~import@znc.import PRIVMSG #test :appended between\n")
    z2 = make_znc(workdir / "second", ergos, built_modules, global_modules=MODS, reuse_datadir=znc.datadir)
    try:
        c = z2.login("c", "ergo1", extra_caps=(CAP,))
        _, got = history(c, "LATEST", "#test", "*", 100)
        stamps = [m.tags["time"] for m in got]
        assert stamps == sorted(stamps), stamps
        msgs = [m.params[-1] for m in got]
        assert msgs.index("appended older") < msgs.index(inner[0].params[-1]) < msgs.index("appended between") < msgs.index(inner[2].params[-1]), msgs
        # AFTER walks forward through the merged order and finds the appended line.
        _, got = history(c, "AFTER", "#test", f"timestamp={t1}", 2)
        assert [m.params[-1] for m in got] == ["appended between", inner[2].params[-1]], [m.raw for m in got]
        _, got = history(c, "BEFORE", "#test", f"timestamp={inner[2].tags['time']}", 1)
        assert [m.params[-1] for m in got] == ["appended between"], [m.raw for m in got]
        c.close()
    finally:
        z2.stop()
