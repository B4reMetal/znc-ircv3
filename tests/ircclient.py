"""Scripted IRCv3 client for the test-suite.

Synchronous, socket based, deliberately simple: every test drives the
protocol explicitly and asserts on the raw lines, so the client only
parses tags/prefix/command/params and offers waiting helpers.
"""
from __future__ import annotations

import base64
import re
import socket
import time
from dataclasses import dataclass, field


_TAG_UNESCAPE = {":": ";", "s": " ", "\\": "\\", "r": "\r", "n": "\n"}


def unescape_tag(value: str) -> str:
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            out.append(_TAG_UNESCAPE.get(value[i + 1], value[i + 1]))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def escape_tag(value: str) -> str:
    return (value.replace("\\", "\\\\").replace(";", "\\:").replace(" ", "\\s")
            .replace("\r", "\\r").replace("\n", "\\n"))


@dataclass
class Message:
    raw: str
    tags: dict = field(default_factory=dict)
    prefix: str | None = None
    command: str = ""
    params: list = field(default_factory=list)

    @property
    def nick(self) -> str | None:
        if not self.prefix:
            return None
        return self.prefix.split("!", 1)[0]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{self.raw}>"


def parse(line: str) -> Message:
    m = Message(raw=line)
    rest = line
    if rest.startswith("@"):
        tagstr, rest = rest[1:].split(" ", 1)
        for item in tagstr.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                m.tags[k] = unescape_tag(v)
            else:
                m.tags[item] = ""
        rest = rest.lstrip(" ")
    if rest.startswith(":"):
        m.prefix, rest = rest[1:].split(" ", 1)
        rest = rest.lstrip(" ")
    if " :" in rest:
        head, trailing = rest.split(" :", 1)
        m.params = head.split()
        m.command = m.params.pop(0) if m.params else ""
        m.params.append(trailing)
    elif rest.startswith(":"):
        m.command = ""
        m.params = [rest[1:]]
    else:
        parts = rest.split()
        m.command = parts.pop(0) if parts else ""
        m.params = parts
    m.command = m.command.upper()
    return m


class IRCClient:
    def __init__(self, host: str, port: int, name: str = "client", timeout: float = 5.0):
        self.name = name
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.timeout = timeout
        self.buf = b""
        self.log: list[Message] = []
        self.pending: list[Message] = []
        self.caps_available: dict[str, str] = {}
        self.caps_enabled: set[str] = set()

    # ---- raw I/O ---------------------------------------------------------
    def send(self, line: str) -> None:
        data = line.encode("utf-8") + b"\r\n"
        self.sock.sendall(data)

    def _read_more(self, deadline: float) -> bool:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self.sock.settimeout(remaining)
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return False
        if not chunk:
            raise ConnectionError(f"{self.name}: connection closed")
        self.buf += chunk
        while b"\n" in self.buf:
            raw, self.buf = self.buf.split(b"\n", 1)
            line = raw.rstrip(b"\r").decode("utf-8", "replace")
            if not line:
                continue
            msg = parse(line)
            self.log.append(msg)
            self.pending.append(msg)
            if msg.command == "PING":
                self.send("PONG :" + (msg.params[-1] if msg.params else ""))
        return True

    def next(self, timeout: float | None = None) -> Message | None:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while not self.pending:
            if not self._read_more(deadline):
                return None
        return self.pending.pop(0)

    def expect(self, pred, timeout: float | None = None, what: str = "") -> Message:
        """Consume messages until one satisfies pred; return it."""
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            while self.pending:
                msg = self.pending.pop(0)
                if pred(msg):
                    return msg
            if not self._read_more(deadline):
                recent = "\n".join(m.raw for m in self.log[-15:])
                raise AssertionError(f"{self.name}: timed out waiting for {what or pred}\nrecent:\n{recent}")

    def expect_cmd(self, command: str, timeout: float | None = None, **kw) -> Message:
        command = command.upper()
        return self.expect(lambda m: m.command == command, timeout, what=command, **kw)

    def drain(self, idle: float = 0.3) -> list[Message]:
        """Read everything that arrives until the line goes quiet."""
        out = []
        deadline = time.monotonic() + idle
        while True:
            while self.pending:
                out.append(self.pending.pop(0))
            if not self._read_more(deadline):
                break
            deadline = time.monotonic() + idle
        return out

    def not_expected(self, pred, idle: float = 0.5) -> None:
        for m in self.drain(idle):
            assert not pred(m), f"{self.name}: unexpected line {m.raw}"

    def collect_batch(self, start: Message, timeout: float | None = None) -> list[Message]:
        """start is the 'BATCH +ref ...' line; return the inner messages."""
        ref = start.params[0][1:]
        assert re.fullmatch(r"[A-Za-z0-9]+", ref), f"{self.name}: bad batch ref {ref!r}"
        inner = []
        while True:
            m = self.expect(lambda x: True, timeout, what=f"end of batch {ref}")
            if m.command == "BATCH" and m.params[0] == "-" + ref:
                return inner
            inner.append(m)

    # ---- protocol helpers ----------------------------------------------
    def cap_ls(self, version: int = 302) -> dict[str, str]:
        self.send(f"CAP LS {version}")
        caps: dict[str, str] = {}
        while True:
            m = self.expect(lambda x: x.command == "CAP" and x.params[1] == "LS", what="CAP LS")
            more = m.params[2] == "*"
            for tok in m.params[-1].split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                else:
                    k, v = tok, ""
                caps[k] = v
            if not more:
                break
        self.caps_available = caps
        return caps

    def cap_req(self, *caps: str) -> bool:
        self.send("CAP REQ :" + " ".join(caps))
        m = self.expect(lambda x: x.command == "CAP" and x.params[1] in ("ACK", "NAK"), what="CAP ACK/NAK")
        if m.params[1] == "ACK":
            for c in m.params[-1].split():
                if c.startswith("-"):
                    self.caps_enabled.discard(c[1:])
                else:
                    self.caps_enabled.add(c)
            return True
        return False

    def cap_end(self) -> None:
        self.send("CAP END")

    def sasl_plain(self, user: str, password: str, authzid: str = "") -> None:
        self.send("AUTHENTICATE PLAIN")
        self.expect(lambda m: m.command == "AUTHENTICATE" and m.params[0] == "+", what="AUTHENTICATE +")
        payload = base64.b64encode(f"{authzid}\0{user}\0{password}".encode()).decode()
        self.send("AUTHENTICATE " + payload)
        self.expect(lambda m: m.command in ("903", "904"), what="SASL result")
        last = self.log[-1]
        assert last.command == "903", f"SASL failed: {last.raw}"

    def register(self, nick: str, user: str, password: str | None = None,
                 caps: tuple[str, ...] = ("message-tags", "server-time", "batch"),
                 sasl: tuple[str, str] | None = None, cap_end: bool = True) -> list[str]:
        """CAP LS 302, optional SASL, NICK/USER, CAP END; returns the caps that
        were acked. Returns after 001 when cap_end is True."""
        self.cap_ls()
        wanted = [c for c in caps if c in self.caps_available]
        if sasl:
            wanted.append("sasl")
        if wanted:
            self.cap_req(*wanted)
        if password is not None:
            self.send(f"PASS {password}")
        self.send(f"NICK {nick}")
        self.send(f"USER {user} 0 * :{user}")
        if sasl:
            self.sasl_plain(*sasl)
        if cap_end:
            self.cap_end()
            self.expect_cmd("001")
        return sorted(self.caps_enabled)

    def join(self, channel: str) -> None:
        self.send(f"JOIN {channel}")
        self.expect(lambda m: m.command == "JOIN" and m.params[0].lower() == channel.lower(), what=f"JOIN {channel}")
        self.expect_cmd("366")

    def privmsg(self, target: str, text: str, tags: dict | None = None) -> None:
        prefix = ""
        if tags:
            prefix = "@" + ";".join(f"{k}={escape_tag(v)}" if v else k for k, v in tags.items()) + " "
        self.send(f"{prefix}PRIVMSG {target} :{text}")

    def close(self) -> None:
        try:
            self.send("QUIT :bye")
        except OSError:
            pass
        self.sock.close()


def msgs_matching(msgs, command: str, **params) -> list[Message]:
    return [m for m in msgs if m.command == command.upper()]
