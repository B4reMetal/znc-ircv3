"""tools/import_znc_logs.py: log module files -> chathistory store."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import import_znc_logs as imp  # noqa: E402
from conftest import make_znc, ZNC_USER  # noqa: E402

LOG_DAY1 = """[23:58:00] *** Joins: peer (~p@host.example)
[23:58:30] <peer> good evening
[23:59:10] * peer waves
[23:59:40] -peer- a notice
"""
LOG_DAY2 = """[00:00:05] <alice> past midnight
[00:01:00] *** peer changes topic to 'imported topic'
[00:02:00] *** peer sets mode: +o alice
[00:03:00] *** peer is now known as peer2
[00:04:00] *** Parts: peer2 (~p@host.example) (bye)
[00:05:00] *** Quits: other (~o@h) (Ping timeout)
[00:06:00] *** alice was kicked by peer2 (reason here)
[00:07:00] Connected to IRC (irrelevant status line)
"""


def make_logs(root: Path):
    d = root / "log" / ZNC_USER / "ergo1" / "#test"
    d.mkdir(parents=True)
    (d / "2024-03-30.log").write_text(LOG_DAY1)
    (d / "2024-03-31.log").write_text(LOG_DAY2)
    q = root / "log" / ZNC_USER / "ergo1" / "peer"
    q.mkdir(parents=True)
    (q / "2024-03-31.log").write_text("[10:00:00] <peer> private line\n")
    return root / "log"


def test_conversion_and_store_layout(tmp_path):
    logdir = make_logs(tmp_path)
    store = tmp_path / "chathistory"
    rc = imp.main(["--logdir", str(logdir), "--store", str(store), "--tz", "Europe/Berlin"])
    assert rc == 0
    chan = store / "alice" / "ergo1" / "#test"
    # Berlin is UTC+1 at these times (the DST switch on the 31st is at 02:00
    # local), so every line lands in the 2024-03-30 UTC file, sorted by time.
    assert sorted(p.name for p in chan.glob("*.log")) == ["2024-03-30.log"]
    day = (chan / "2024-03-30.log").read_text().splitlines()
    assert len(day) == 11, day
    assert day[0].startswith("@time=2024-03-30T22:58:00.000Z;msgid=znc-import-") and ";znc.in/event :peer!~p@host.example JOIN #test" in day[0]
    assert " PRIVMSG #test :good evening" in day[1]
    assert " PRIVMSG #test :\x01ACTION waves\x01" in day[2]
    assert " NOTICE #test :a notice" in day[3]
    assert day[4].startswith("@time=2024-03-30T23:00:05.000Z") and ":alice!~import@znc.import PRIVMSG #test :past midnight" in day[4]
    cmds = [l.split(" ")[2] for l in day[5:]]
    assert cmds == ["TOPIC", "MODE", "NICK", "PART", "QUIT", "KICK"], cmds
    assert all("znc.in/event" in l for l in day[5:])
    assert ":peer2!~import@znc.import KICK #test alice :reason here" in day[-1]
    times = [l.split(";")[0] for l in day]
    assert times == sorted(times)
    assert (chan / "name").read_text().strip() == "#test"
    assert (chan / "latest").read_text().strip() == "2024-03-30T23:06:00.000Z"
    assert (store / "alice" / "ergo1" / "peer" / "2024-03-31.log").read_text().count("\n") == 1

    # Re-running adds nothing.
    rc = imp.main(["--logdir", str(logdir), "--store", str(store), "--tz", "Europe/Berlin"])
    assert rc == 0
    assert len((chan / "2024-03-30.log").read_text().splitlines()) == 11

    # --no-events keeps only messages; --dry-run writes nothing.
    store2 = tmp_path / "ch2"
    imp.main(["--logdir", str(logdir), "--store", str(store2), "--tz", "UTC", "--no-events"])
    assert all("znc.in/event" not in l for f in (store2 / "alice" / "ergo1" / "#test").glob("*.log") for l in f.read_text().splitlines())
    store3 = tmp_path / "ch3"
    imp.main(["--logdir", str(logdir), "--store", str(store3), "--tz", "UTC", "--dry-run"])
    assert not store3.exists()


def test_imported_history_is_served(workdir, ergos, built_modules, tmp_path):
    """Import into a fresh ZNC datadir, start ZNC, query it."""
    logdir = make_logs(tmp_path)
    pre = workdir / "pre" / "moddata" / "chathistory"
    imp.main(["--logdir", str(logdir), "--store", str(pre), "--tz", "UTC"])
    z = make_znc(workdir, ergos, built_modules, global_modules=("ircv3base", "chathistory days=0"), reuse_datadir=workdir / "pre")
    try:
        c = z.login("c", "ergo1", extra_caps=("draft/chathistory",))
        c.send("CHATHISTORY LATEST #test * 100")
        start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="batch")
        inner = c.collect_batch(start)
        texts = [m.params[-1] for m in inner if m.command == "PRIVMSG"]
        assert texts == ["good evening", "\x01ACTION waves\x01", "past midnight"]
        assert all(m.tags["msgid"].startswith("znc-import-") for m in inner)
        # BEFORE by an imported msgid works too.
        mid = inner[-1].tags["msgid"]
        c.send(f"CHATHISTORY BEFORE #test msgid={mid} 10")
        start = c.expect(lambda m: m.command == "BATCH" and m.params[0].startswith("+"), what="batch")
        inner = c.collect_batch(start)
        assert [m.params[-1] for m in inner if m.command == "PRIVMSG"] == ["good evening", "\x01ACTION waves\x01"]
        c.close()
    finally:
        z.stop()


def test_future_timestamps_are_clamped(tmp_path, capsys):
    import datetime as dt
    tomorrow = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).strftime("%Y-%m-%d")
    d = tmp_path / "log" / ZNC_USER / "ergo1" / "#test"
    d.mkdir(parents=True)
    (d / f"{tomorrow}.log").write_text("[00:00:01] <peer> from the future\n")
    store = tmp_path / "chathistory"
    rc = imp.main(["--logdir", str(tmp_path / "log"), "--store", str(store), "--tz", "UTC"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 lines were in the future and clamped" in out, out
    files = list((store / ZNC_USER / "ergo1" / "#test").glob("*.log"))
    assert len(files) == 1
    line = files[0].read_text().strip()
    stamp = line.split("time=")[1].split(";")[0].split(" ")[0]
    assert stamp <= dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"), line


def test_lines_already_recorded_live_are_skipped(tmp_path, capsys):
    """The live store has a message at 12:00:00.400Z; the log has the same
    sender/text at [12:00:00] (second precision): skip it, keep the rest."""
    store = tmp_path / "chathistory"
    chan = store / ZNC_USER / "ergo1" / "#test"
    chan.mkdir(parents=True)
    (chan / "2024-03-30.log").write_text(
        "@msgid=znc-abcd-1;time=2024-03-30T12:00:00.400Z :peer!~u@host PRIVMSG #test :already here\n")
    d = tmp_path / "log" / ZNC_USER / "ergo1" / "#test"
    d.mkdir(parents=True)
    (d / "2024-03-30.log").write_text("[12:00:00] <peer> already here\n[12:00:05] <peer> new one\n[12:00:03] <other> already here\n")
    rc = imp.main(["--logdir", str(tmp_path / "log"), "--store", str(store), "--tz", "UTC"])
    assert rc == 0
    assert "1 skipped as already recorded live" in capsys.readouterr().out
    lines = (chan / "2024-03-30.log").read_text().splitlines()
    assert len(lines) == 3, lines
    assert sum(1 for l in lines if ":peer!" in l and "already here" in l) == 1
    assert any(":other!" in l and "already here" in l for l in lines)  # different sender: kept
