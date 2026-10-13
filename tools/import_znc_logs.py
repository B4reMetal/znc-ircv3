#!/usr/bin/env python3
"""Import ZNC `log` module files into the chathistory module's store.

The log module writes one file per window and day:
    <moddata>/log/<user>/<network>/<window>/YYYY-MM-DD.log   (global module)
    <moddata>/log/<network>/<window>/YYYY-MM-DD.log          (user module)
    <moddata>/log/<window>/YYYY-MM-DD.log                    (network module)
with lines such as
    [12:34:56] <nick> hello
    [12:34:56] * nick waves
    [12:34:56] -nick- notice text
    [12:34:56] *** Joins: nick (ident@host)
    [12:34:56] *** Parts: nick (ident@host) (reason)
    [12:34:56] *** Quits: nick (ident@host) (reason)
    [12:34:56] *** nick was kicked by op (reason)
    [12:34:56] *** old is now known as new
    [12:34:56] *** nick changes topic to 'topic'
    [12:34:56] *** nick sets mode: +o nick

This script rebuilds IRC lines from them and appends them to the
chathistory store (<datadir>/moddata/chathistory), tagged with the
message time in UTC and a deterministic msgid ("znc-import-<hash>") so the
import can be re-run without creating duplicates. Hostmasks are not in the
logs; imported lines use nick!~import@znc.import unless the log line
carried an ident@host.

Timestamps in ZNC logs are in the user's timezone (the Timezone setting
in ZNC, otherwise the zone of the host ZNC runs on, often UTC on a
server); pass --tz accordingly. Check one line against a known event
first: a wrong zone shifts the whole import, and lines that would land in
the future are clamped to the import time.

Usage:
  import_znc_logs.py --logdir ~/.znc/moddata/log --store ~/.znc/moddata/chathistory
                     [--user alice] [--network libera] [--tz Europe/Berlin]
                     [--since 2024-01-01] [--no-events] [--dry-run]
Stop ZNC (or at least unload chathistory) while importing.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

NOW = dt.datetime.now(dt.timezone.utc)
FUTURE = [0]  # lines clamped to NOW
DUPLICATES = [0]  # lines already recorded live

SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789#&+!-_[]{}|^`\\")
EVENT_TAG = "znc.in/event"
LINE_RE = re.compile(r"^\[(\d\d):(\d\d):(\d\d)\] (.*)$")
DAY_RE = re.compile(r"^(\d{4}-\d\d-\d\d)\.log$")


def safe_name(target: str) -> str:
    """Same mapping as SafeName() in chathistory.cpp."""
    out = []
    for ch in target.lower():
        if ch in SAFE_CHARS:
            out.append(ch)
        else:
            out.extend("%%%02X" % b for b in ch.encode("utf-8"))
    s = "".join(out)
    if not s or s[0] == ".":
        s = "%2E" + s
    return s


def escape_tag(value: str) -> str:
    return (value.replace("\\", "\\\\").replace(";", "\\:").replace(" ", "\\s")
            .replace("\r", "\\r").replace("\n", "\\n"))


def prefix(nick: str, userhost: str | None) -> str:
    return f"{nick}!{userhost}" if userhost else f"{nick}!~import@znc.import"


def convert_line(body: str, target: str) -> tuple[str, bool] | None:
    """Return (irc line without tags, is_event) or None for lines to skip."""
    m = re.match(r"^<([^>]+)> (.*)$", body)
    if m:
        return f":{prefix(m[1], None)} PRIVMSG {target} :{m[2]}", False
    m = re.match(r"^\* (\S+) (.*)$", body)
    if m:
        return f":{prefix(m[1], None)} PRIVMSG {target} :\x01ACTION {m[2]}\x01", False
    m = re.match(r"^-([^-\s][^\s]*)- (.*)$", body)
    if m:
        return f":{prefix(m[1], None)} NOTICE {target} :{m[2]}", False
    if not body.startswith("*** "):
        return None
    rest = body[4:]
    m = re.match(r"^Joins: (\S+) \(([^)]*)\)$", rest)
    if m:
        return f":{prefix(m[1], m[2])} JOIN {target}", True
    m = re.match(r"^Parts: (\S+) \(([^)]*)\) \((.*)\)$", rest)
    if m:
        return f":{prefix(m[1], m[2])} PART {target} :{m[3]}", True
    m = re.match(r"^Quits: (\S+) \(([^)]*)\) \((.*)\)$", rest)
    if m:
        return f":{prefix(m[1], m[2])} QUIT :{m[3]}", True
    m = re.match(r"^(\S+) was kicked by (\S+) \((.*)\)$", rest)
    if m:
        return f":{prefix(m[2], None)} KICK {target} {m[1]} :{m[3]}", True
    m = re.match(r"^(\S+) is now known as (\S+)$", rest)
    if m:
        return f":{prefix(m[1], None)} NICK :{m[2]}", True
    m = re.match(r"^(\S+) changes topic to '(.*)'$", rest)
    if m:
        return f":{prefix(m[1], None)} TOPIC {target} :{m[2]}", True
    m = re.match(r"^(\S+) sets mode: (.*)$", rest)
    if m:
        return f":{prefix(m[1], None)} MODE {target} {m[2]}", True
    return None


KEY_RE = re.compile(r"^(?:@\S+ )?:([^!\s]+)\S* (\S+) (\S+)(?: :?(.*))?$")


def line_key(line: str) -> tuple[str, str, str] | None:
    """(nick, command, text) of a stored or converted IRC line."""
    m = KEY_RE.match(line)
    if not m:
        return None
    return (m[1].lower(), m[2], m[4] or "")


def parse_time(tag: str) -> float:
    return dt.datetime.strptime(tag, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc).timestamp()


def msgid_for(time_tag: str, line: str) -> str:
    return "znc-import-" + hashlib.sha1(f"{time_tag} {line}".encode("utf-8")).hexdigest()[:16]


class Store:
    """Append-only writer for one target directory with dedupe by msgid."""

    def __init__(self, target_dir: Path, target: str, dry_run: bool):
        self.dir = target_dir
        self.target = target
        self.dry_run = dry_run
        self.days: dict[str, list[tuple[str, str]]] = {}   # day -> [(time, line)]
        self.known: set[str] = set()
        self.touched: set[str] = set()
        # Lines ZNC recorded live, keyed by (nick, command, text) -> times, so
        # an import of the same period does not add a second copy.
        self.live: dict[tuple[str, str, str], list[float]] = {}
        if self.dir.exists():
            for f in self.dir.glob("*.log"):
                day = f.name[:-4]
                entries = []
                for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not raw:
                        continue
                    t = re.search(r"(?:^@|;)time=([^; ]+)", raw)
                    i = re.search(r"(?:^@|;)msgid=([^; ]+)", raw)
                    if i:
                        self.known.add(i[1])
                    if t and not (i and i[1].startswith("znc-import-")):
                        key = line_key(raw)
                        if key:
                            self.live.setdefault(key, []).append(parse_time(t[1]))
                    entries.append((t[1] if t else "", raw))
                self.days[day] = entries

    def add(self, time_tag: str, line: str, event: bool) -> bool:
        mid = msgid_for(time_tag, line)
        if mid in self.known:
            return False
        key = line_key(line)
        if key and key in self.live:
            t = parse_time(time_tag)
            if any(abs(t - lt) <= 1.0 for lt in self.live[key]):
                DUPLICATES[0] += 1
                return False
        self.known.add(mid)
        tags = f"time={time_tag};msgid={mid}"
        if event:
            tags += f";{EVENT_TAG}"
        self.days.setdefault(time_tag[:10], []).append((time_tag, f"@{tags} {line}"))
        self.touched.add(time_tag[:10])
        return True

    def flush(self) -> None:
        if self.dry_run or not self.touched:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        latest = ""
        for day in self.touched:
            entries = sorted(self.days[day], key=lambda e: e[0])  # stable: keeps arrival order on ties
            (self.dir / f"{day}.log").write_text("".join(e[1] + "\n" for e in entries), encoding="utf-8")
        for entries in self.days.values():
            for t, _ in entries:
                latest = max(latest, t)
        (self.dir / "latest").write_text(latest + "\n")
        name_file = self.dir / "name"
        if not name_file.exists():
            name_file.write_text(self.target + "\n")


def import_window(window_dir: Path, store_dir: Path, tz: ZoneInfo, since: str | None,
                  events: bool, dry_run: bool) -> tuple[int, int]:
    target = window_dir.name  # already lowercased by the log module
    store = Store(store_dir / safe_name(target), target, dry_run)
    added = skipped = 0
    for f in sorted(window_dir.iterdir()):
        m = DAY_RE.match(f.name)
        if not m or (since and m[1] < since):
            continue
        day = dt.date.fromisoformat(m[1])
        for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
            lm = LINE_RE.match(raw)
            if not lm:
                continue
            conv = convert_line(lm[4], target)
            if conv is None or (conv[1] and not events):
                continue
            local = dt.datetime(day.year, day.month, day.day, int(lm[1]), int(lm[2]), int(lm[3]), tzinfo=tz)
            utc = local.astimezone(dt.timezone.utc)
            if utc > NOW:
                # A wrong --tz puts lines in the future; a server-time later
                # than now confuses clients. Clamp and report.
                FUTURE[0] += 1
                utc = NOW
            time_tag = utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            if store.add(time_tag, conv[0], conv[1]):
                added += 1
            else:
                skipped += 1
    store.flush()
    return added, skipped


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logdir", required=True, type=Path, help="log module data dir (…/moddata/log)")
    ap.add_argument("--store", required=True, type=Path, help="chathistory data dir (…/moddata/chathistory)")
    ap.add_argument("--user", help="user name when the log module ran as a user or network module")
    ap.add_argument("--network", help="network name when the log module ran as a network module")
    ap.add_argument("--tz", default=None, help="timezone the logs were written in (IANA name); default: local")
    ap.add_argument("--since", default=None, help="only import files from this date (YYYY-MM-DD)")
    ap.add_argument("--no-events", action="store_true", help="skip joins/parts/quits/modes/topics/nicks")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    tz = ZoneInfo(a.tz) if a.tz else dt.datetime.now().astimezone().tzinfo
    if not a.logdir.is_dir():
        print(f"no such directory: {a.logdir}", file=sys.stderr)
        return 2

    # Enumerate (user, network, window_dir) for the three layouts.
    jobs: list[tuple[str, str, Path]] = []
    if a.user and a.network:
        jobs = [(a.user, a.network, w) for w in sorted(a.logdir.iterdir()) if w.is_dir()]
    elif a.user:
        for net in sorted(a.logdir.iterdir()):
            if net.is_dir():
                jobs += [(a.user, net.name, w) for w in sorted(net.iterdir()) if w.is_dir()]
    else:
        for user in sorted(a.logdir.iterdir()):
            if not user.is_dir():
                continue
            for net in sorted(user.iterdir()):
                if net.is_dir():
                    jobs += [(user.name, net.name, w) for w in sorted(net.iterdir()) if w.is_dir()]

    total_added = total_skipped = 0
    for user, network, window in jobs:
        if window.name in ("status",):
            continue
        store_dir = a.store / safe_name(user) / safe_name(network)
        added, skipped = import_window(window, store_dir, tz, a.since, not a.no_events, a.dry_run)
        total_added += added
        total_skipped += skipped
        print(f"{user}/{network}/{window.name}: {added} imported, {skipped} already present")
    print(f"total: {total_added} imported, {total_skipped} skipped{' (dry run)' if a.dry_run else ''}"
          + (f", {FUTURE[0]} lines were in the future and clamped to now (check --tz)" if FUTURE[0] else "")
          + (f", {DUPLICATES[0]} skipped as already recorded live" if DUPLICATES[0] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
