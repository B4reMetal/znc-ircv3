"""All modules loaded together: the ordering and interaction problems that
client authors reported (ISUPPORT after MOTD, labels dropped by other
modules, status notices on BIND connections, replayed JOINs, cap refused
after CAP NEW)."""
import time
from datetime import datetime, timezone

import pytest

from conftest import make_znc, ZNC_USER, ZNC_PASS

# labeled deliberately last: it must still see commands before the
# modules that answer them.
MODS = ("ircv3base", "bouncernetworks", "readmarker", "chathistory", "multiline", "webpush", "labeled")
CAPS = ("message-tags", "server-time", "batch", "labeled-response", "draft/chathistory", "soju.im/webpush",
        "soju.im/bouncer-networks", "soju.im/bouncer-networks-notify")


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules, global_modules=MODS)
    yield z
    z.stop()


def soju_login(znc, name, bind=None, pass_first=True):
    """PASS/NICK/USER before CAP REQ (as some clients do) or after."""
    c = znc.client(name, None)
    c.cap_ls()
    creds = [f"PASS {ZNC_USER}:{ZNC_PASS}", f"NICK {ZNC_USER}", f"USER {ZNC_USER} 0 * :x"]
    if pass_first:
        for line in creds:
            c.send(line)
    assert c.cap_req(*CAPS)
    if not pass_first:
        for line in creds:
            c.send(line)
    if bind:
        c.send(f"BOUNCER BIND {bind}")
    c.cap_end()
    c.expect_cmd("001")
    return c


def burst(c):
    """Lines from the last 001 up to and including the end of the MOTD."""
    end = c.expect(lambda m: m.command in ("376", "422"), what="end of MOTD")
    start = max(i for i, m in enumerate(c.log) if m.command == "001")
    return c.log[start:c.log.index(end) + 1]


def isupport(lines):
    toks = {}
    for m in lines:
        if m.command == "005":
            for p in m.params[1:-1]:
                k, _, v = p.partition("=")
                toks.setdefault(k, []).append(v)
    return toks


def status_notices(c):
    return [m.raw for m in c.log if m.nick == "*status"]


def netids(c):
    c.send("@label=L1 BOUNCER LISTNETWORKS")
    start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="LISTNETWORKS batch")
    assert start.tags.get("label") == "L1", start.raw
    inner = c.collect_batch(start)
    return {m.params[2].split("name=")[1].split(";")[0]: m.params[1] for m in inner}


def test_isupport_once_and_inside_burst_on_bound_connection(znc):
    c = znc.login("c", "ergo1", extra_caps=CAPS)
    toks = isupport(burst(c))
    for k in ("BOUNCER_NETID", "CHATHISTORY", "VAPID", "MSGREFTYPES"):
        assert len(toks[k]) == 1, (k, toks)
    c.not_expected(lambda m: m.command == "005", idle=1.0)
    c.close()


def test_pass_before_cap_req_unbound_then_bind(znc):
    main = soju_login(znc, "main", pass_first=True)
    lines = burst(main)
    assert lines[-1].command == "422"
    toks = isupport(lines)
    assert toks["NETWORK"] == ["ZNC"] and len(toks["VAPID"]) == 1 and len(toks["CHATHISTORY"]) == 1, toks
    assert "BOUNCER_NETID" not in toks
    main.drain(0.5)
    assert status_notices(main) == []
    assert not any(m.command == "JOIN" for m in main.log)
    ids = netids(main)
    child = soju_login(znc, "child", bind=ids["ergo2"], pass_first=True)
    lines = burst(child)
    toks = isupport(lines)
    assert toks["BOUNCER_NETID"] == [ids["ergo2"]] and "ergo2" in toks["NETWORK"], toks
    assert len(toks["CHATHISTORY"]) == 1 and len(toks["VAPID"]) == 1
    child.drain(0.5)
    assert status_notices(child) == []
    # Labeled answers from modules loaded before labeled.
    child.send("@label=h1 CHATHISTORY LATEST #test * 5")
    m = child.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="chathistory batch")
    assert m.tags.get("label") == "h1", m.raw
    child.collect_batch(m)
    netids(child)
    main.close()
    child.close()


def test_replayed_join_carries_original_join_time(znc):
    time.sleep(1.5)
    before = datetime.now(timezone.utc)
    c = znc.login("c", "ergo1")
    m = c.expect(lambda m: m.command == "JOIN" and m.params[0] == "#test", what="replayed JOIN")
    joined = datetime.strptime(m.tags["time"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert (before - joined).total_seconds() > 1.0, m.raw
    c.close()


def test_extended_monitor_granted_after_cap_new(znc):
    c = znc.login("c", "ergo1")
    try:
        m = c.expect(lambda m: m.command == "CAP" and m.params[1] == "NEW" and "extended-monitor" in m.params[2],
                     timeout=3, what="CAP NEW extended-monitor")
    except AssertionError:
        pytest.skip("server offers no extended-monitor")
    c.send("CAP REQ :extended-monitor")
    m = c.expect(lambda m: m.command == "CAP" and m.params[1] in ("ACK", "NAK"), what="CAP reply")
    assert m.params[1] == "ACK", m.raw
    c.close()


def test_bad_password_is_reported_before_close(znc):
    c = znc.client("bad", None)
    c.cap_ls()
    assert c.cap_req(*CAPS)
    c.send(f"PASS {ZNC_USER}:wrong")
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :x")
    c.cap_end()
    m = c.expect(lambda m: m.command in ("464", "ERROR"), timeout=5, what="464 before the close")
    assert m.command == "464", m.raw
    c.close()
