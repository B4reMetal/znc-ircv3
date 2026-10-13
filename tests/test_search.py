"""soju.im/search over the chathistory store."""
import sqlite3
import time

import pytest

from conftest import make_znc, ZNC_USER, ZNC_PASS

CAP = "soju.im/search"
CH = "draft/chathistory"
MODS = ("ircv3base", "bouncernetworks", "chathistory", "labeled")


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


def seed(znc):
    """peer and other talk in #test; peer also DMs the user."""
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    other = znc.networks["ergo1"].client("other")
    other.register("other", "other")
    for p in (peer, other):
        p.join("#test")
    sent = []
    for who, target, text in (
        (peer, "#test", "deploy started"),
        (other, "#test", "Deploy looks fine so far"),
        (peer, "#test", "unrelated chatter"),
        (peer, ZNC_USER, "private: deploy done"),
        (other, "#test", "redeploying the thing"),
    ):
        who.privmsg(target, text)
        sent.append(text)
        time.sleep(0.15)
    peer.send("NOTICE #test :notice about deploy")
    time.sleep(0.3)
    return peer, other


def search(c, attrs, label=None):
    c.send((f"@label={label} " if label else "") + f"SEARCH {attrs}")
    m = c.expect(lambda m: (m.command == "BATCH" and m.params[0].startswith("+")) or m.command == "FAIL", what="SEARCH reply")
    if m.command == "FAIL":
        return m, None
    assert m.params[1] == "soju.im/search", m.raw
    return m, c.collect_batch(m)


def texts(inner):
    return [m.params[-1] for m in inner]


def test_search_text_in_from_limit_and_order(znc):
    peer, other = seed(znc)
    c = znc.login("c", "ergo1", extra_caps=(CH, CAP, "labeled-response"))
    assert CAP in c.caps_enabled
    c.drain(0.3)
    start, inner = search(c, "in=#test;text=deploy", label="s1")
    assert start.tags.get("label") == "s1", start.raw
    assert texts(inner) == ["deploy started", "Deploy looks fine so far", "redeploying the thing", "notice about deploy"]
    assert [m.command for m in inner] == ["PRIVMSG", "PRIVMSG", "PRIVMSG", "NOTICE"]
    assert all("msgid" in m.tags and "time" in m.tags for m in inner)
    assert [m.tags["time"] for m in inner] == sorted(m.tags["time"] for m in inner)
    # from= narrows to one sender; case-insensitive text
    _, inner = search(c, "in=#test;text=DEPLOY;from=other")
    assert texts(inner) == ["Deploy looks fine so far", "redeploying the thing"]
    # Without in=, every target of the network is searched (DMs too).
    _, inner = search(c, "text=deploy")
    assert "private: deploy done" in texts(inner) and len(inner) == 5
    # limit keeps the newest when searching backwards...
    _, inner = search(c, "in=#test;text=deploy;limit=2")
    assert texts(inner) == ["redeploying the thing", "notice about deploy"]
    # ...and the oldest when searching forward from after=
    first_time = search(c, "in=#test;text=deploy")[1][0].tags["time"]
    _, inner = search(c, f"in=#test;text=deploy;after={first_time};limit=2")
    assert texts(inner) == ["deploy started", "Deploy looks fine so far"]
    # before= bounds the end
    _, inner = search(c, f"in=#test;text=deploy;before={first_time}")
    assert texts(inner) == ["deploy started"]
    # Values with spaces: escaped as \s, as a trailing parameter, or bare.
    for attrs in ("in=#test;text=looks\\sfine", ":in=#test;text=looks fine", "in=#test;text=looks fine"):
        _, inner = search(c, attrs)
        assert texts(inner) == ["Deploy looks fine so far"], attrs
    # no match: empty batch
    _, inner = search(c, "in=#test;text=nothingmatchesthis")
    assert inner == []
    # Unknown target: empty batch, not an error
    _, inner = search(c, "in=#nowhere;text=deploy")
    assert inner == []
    c.close()
    peer.close()
    other.close()


def test_search_errors(znc):
    c = znc.login("c", "ergo1", extra_caps=(CH, CAP))
    c.drain(0.3)
    for attrs, attr in (("", "*"), ("bogus=1", "bogus"), ("in=#test;after=yesterday", "after"),
                        ("in=#test;before=2026", "before"), ("in=#test;limit=abc", "limit"), ("limit=5", "*")):
        m, _ = search(c, attrs)
        assert m.command == "FAIL" and m.params[:3] == ["SEARCH", "INVALID_PARAMS", attr], (attrs, m.raw)
    c.close()


def test_search_cap_withdrawn_on_unbound_connection(znc):
    c = znc.client("main", None)
    c.cap_ls()
    assert c.cap_req("message-tags", "server-time", "batch", CH, CAP, "soju.im/bouncer-networks")
    c.send(f"PASS {ZNC_USER}:{ZNC_PASS}")
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :x")
    c.cap_end()
    c.expect_cmd("001")
    m = c.expect(lambda m: m.command == "CAP" and m.params[1] == "DEL", timeout=3, what="CAP DEL")
    assert CAP in m.params[2], m.raw
    c.send("SEARCH text=x")
    m = c.expect(lambda m: m.command in ("FAIL", "BATCH"))
    assert m.command == "FAIL" and m.params[1] == "INVALID_PARAMS", m.raw
    c.close()


def index_db(z):
    return z.datadir / "moddata" / "chathistory" / ZNC_USER / ".search.db"


def test_search_index_is_built_and_answers(znc):
    peer, other = seed(znc)
    c = znc.login("c", "ergo1", extra_caps=(CH, CAP, "standard-replies"))
    c.drain(0.3)
    # Formatting is stripped for matching and substrings inside words count.
    peer.privmsg("#test", "\x02bold\x02 pneumonoultramicroscopic word")
    time.sleep(0.5)
    db = index_db(znc)
    assert db.exists(), db
    con = sqlite3.connect(db)
    assert con.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] == "2"
    assert con.execute("SELECT count(*) FROM msg WHERE text LIKE '%deploy%'").fetchone()[0] >= 4
    assert con.execute("SELECT text FROM msg WHERE text LIKE '%pneumono%'").fetchone()[0] == "bold pneumonoultramicroscopic word"
    con.close()
    before = len(c.log)
    m, inner = search(c, "text=ultramicro")
    assert texts(inner) == ["\x02bold\x02 pneumonoultramicroscopic word"]
    m, inner = search(c, "text=bold;in=#test")
    assert len(inner) == 1
    m, inner = search(c, "text=deploy")
    assert len(inner) == 5
    assert not any(x.command == "NOTE" for x in c.log[before:]), "no truncation expected"
    c.close()


def test_search_sync_indexes_files_changed_on_disk(znc):
    seed(znc)
    c = znc.login("c", "ergo1", extra_caps=(CH, CAP, "standard-replies"))
    c.drain(0.3)
    store = znc.datadir / "moddata" / "chathistory" / ZNC_USER / "ergo1" / "#test"
    day = sorted(store.glob("*.log"))[-1]
    with day.open("a") as f:  # what the log importer does while ZNC runs
        f.write("@time=2026-01-02T03:04:05.000Z;msgid=ext-1 :ghost!g@h PRIVMSG #test :xylophone from the importer\n")
    c.send("PRIVMSG *chathistory :sync")
    c.expect(lambda m: m.nick == "*chathistory" and "sync" in m.params[-1].lower(), what="sync reply")
    deadline = time.time() + 5
    while True:
        m, inner = search(c, "text=xylophone")
        if texts(inner) == ["xylophone from the importer"] or time.time() > deadline:
            break
        time.sleep(0.3)
    assert texts(inner) == ["xylophone from the importer"]
    c.send("PRIVMSG *chathistory :status")
    m = c.expect(lambda m: m.nick == "*chathistory" and "Search index" in m.params[-1], what="status")
    assert "schema 2" in m.params[-1] and "ready" in m.params[-1], m.raw
    c.close()


def test_search_without_usable_index_scans_and_reports_truncation(znc, workdir, ergos, built_modules):
    seed(znc)
    znc.stop()
    con = sqlite3.connect(index_db(znc))
    con.execute("UPDATE meta SET value='99' WHERE key='schema'")  # a future schema this module must refuse
    con.commit()
    con.close()
    z2 = make_znc(workdir / "second", ergos, built_modules,
                  global_modules=("ircv3base", "bouncernetworks", "chathistory searchlines=2", "labeled"),
                  reuse_datadir=znc.datadir)
    try:
        c = z2.login("c", "ergo1", extra_caps=(CH, CAP, "standard-replies"))
        c.drain(0.3)
        c.send("PRIVMSG *chathistory :status")
        m = c.expect(lambda m: m.nick == "*chathistory" and "Search index" in m.params[-1], what="status")
        assert "unavailable" in m.params[-1] and "newer" in m.params[-1], m.raw
        c.send("SEARCH text=deploy")
        m = c.expect(lambda m: m.command in ("NOTE", "BATCH", "FAIL"), what="search reply")
        assert m.command == "NOTE" and m.params[:2] == ["SEARCH", "TRUNCATED"], m.raw
        m = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="batch")
        inner = c.collect_batch(m)
        assert len(inner) <= 2
        c.close()
    finally:
        z2.stop()


def test_search_survives_a_rewritten_day_file(znc):
    """The importer rewrites day files in place (lines re-sorted, new ones
    added); until the next sync the index's byte offsets are stale. Hits are
    then found by msgid, and nothing is silently dropped."""
    seed(znc)
    c = znc.login("c", "ergo1", extra_caps=(CH, CAP, "standard-replies"))
    c.drain(0.3)
    store = znc.datadir / "moddata" / "chathistory" / ZNC_USER / "ergo1" / "#test"
    day = sorted(store.glob("*.log"))[-1]
    lines = day.read_text().splitlines()
    lines.insert(0, "@time=2026-01-02T03:04:05.000Z;msgid=ext-2 :ghost!g@h PRIVMSG #test :an earlier imported line")
    day.write_text("\n".join(lines) + "\n")  # every offset after the first line moved
    _, inner = search(c, "in=#test;text=deploy")
    assert texts(inner) == ["deploy started", "Deploy looks fine so far", "redeploying the thing", "notice about deploy"]
    assert not any(m.command == "NOTE" for m in c.log[-12:])
    c.close()
