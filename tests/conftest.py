"""Fixtures: Ergo IRC servers and a ZNC instance loaded with the modules.

Layout assumed (override with environment variables):
  ZNC_BIN      ../deps/znc-install/bin/znc
  ERGO_IMAGE   ghcr.io/ergochat/ergo:v2.19.1  (Ergo runs in Docker)
  IRCV3_BUILD  ../build   (directory with the compiled *.so modules)
"""
from __future__ import annotations

import glob
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from ircclient import IRCClient

ROOT = Path(__file__).resolve().parent.parent
ZNC_BIN = Path(os.environ.get("ZNC_BIN", ROOT / "deps/znc-install/bin/znc"))
BUILD_DIR = Path(os.environ.get("IRCV3_BUILD", ROOT / "build"))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, timeout: float = 10.0, proc: subprocess.Popen | None = None, host: str = "127.0.0.1") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"process exited with {proc.returncode}")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} did not open")


ERGO_IMAGE = os.environ.get("ERGO_IMAGE", "ghcr.io/ergochat/ergo:v2.19.1")
ERGO_DEFAULT_YAML = ROOT / "docker" / "ergo-default.yaml"


def docker(*args: str, check: bool = True) -> str:
    r = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


_loopback_counter = [1]


def next_loopback() -> str:
    """Each server gets its own 127.0.0.N so ZNC's per-hostname connect
    throttle (30 s between connections to the same server name) does not
    serialise the networks."""
    _loopback_counter[0] += 1
    return f"127.0.0.{_loopback_counter[0]}"


class Ergo:
    """One Ergo server in a Docker container (ghcr.io/ergochat/ergo).

    The container runs as root with /ircd as its data dir; we bind-mount a
    per-server directory holding ircd.yaml. Ports are published on random
    loopback ports. legacy=True disables the modern caps so fallback paths
    can be tested."""

    def __init__(self, workdir: Path, name: str, legacy: bool = False, websocket: bool = False):
        self.name = name
        self.dir = workdir / name
        self.dir.mkdir(parents=True)
        self.dir.chmod(0o777)
        cfg = yaml.safe_load(ERGO_DEFAULT_YAML.read_text())
        cfg["network"]["name"] = name
        cfg["server"]["name"] = f"{name}.test"
        listeners = {":6667": None}
        if websocket:
            listeners[":8097"] = {"websocket": True}
        cfg["server"]["listeners"] = listeners
        cfg["server"].pop("motd", None)
        cfg["server"]["lookup-hostnames"] = False
        cfg["server"]["ip-cloaking"]["enabled"] = False
        cfg["server"]["sts"]["enabled"] = False
        cfg["server"].pop("tor-listeners", None)
        cfg["server"]["enforce-utf8"] = True
        cfg["datastore"]["path"] = "/ircd/ircd.db"
        cfg["languages"] = {"enabled": False}
        cfg["logging"] = [{"method": "stderr", "type": "* -userinput -useroutput", "level": "info"}]
        cfg["accounts"]["registration"]["enabled"] = True
        cfg["accounts"]["registration"]["allow-before-connect"] = True
        cfg["accounts"]["registration"]["throttling"] = {"enabled": False}
        cfg["accounts"]["login-throttling"]["enabled"] = False
        cfg["accounts"]["nick-reservation"]["enabled"] = False
        cfg["fakelag"]["enabled"] = False
        cfg["history"]["enabled"] = not legacy
        cfg["history"]["autoreplay-on-join"] = 0
        if legacy:
            # Ergo has no switch per cap, but no history disables chathistory
            # and event-playback, and no multiline disables that cap.
            cfg["limits"]["multiline"] = {"max-bytes": 0, "max-lines": 0}
        (self.dir / "ircd.yaml").write_text(yaml.safe_dump(cfg))
        self.host = next_loopback()
        publish = ["-p", f"{self.host}::6667"]
        if websocket:
            publish += ["-p", f"{self.host}::8097"]
        self.cid = docker("run", "-d", "--rm", "--name", f"znc-ircv3-{name}-{os.getpid()}-{free_port()}",
                          *publish, "-v", f"{self.dir}:/ircd", ERGO_IMAGE)
        self.port = self._published(6667)
        self.ws_port = self._published(8097) if websocket else None
        wait_port(self.port, host=self.host)

    def _published(self, container_port: int) -> int:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            out = docker("port", self.cid, str(container_port), check=False)
            for line in out.splitlines():
                if line.startswith(self.host + ":"):
                    return int(line.rsplit(":", 1)[1])
            time.sleep(0.1)
        raise TimeoutError(f"no published port for {container_port}: {docker('logs', self.cid, check=False)}")

    def logs(self) -> str:
        r = subprocess.run(["docker", "logs", self.cid], capture_output=True, text=True)
        return r.stdout + r.stderr

    def client(self, name: str = "direct", **kw) -> IRCClient:
        return IRCClient(self.host, self.port, name=name, **kw)

    def stop(self) -> None:
        docker("rm", "-f", self.cid, check=False)


class FakeServer:
    """A scripted upstream IRC server ZNC connects to. Handles registration,
    CAP negotiation (with the caps given), JOIN and PING; everything else is
    queued for the test to inspect, and the test can push raw lines to ZNC
    with send(). Runs in a thread; one ZNC connection at a time."""

    def __init__(self, caps: dict[str, str] | None = None, name: str = "fake", echo_without_cap: bool = False):
        self.echo_without_cap = echo_without_cap  # echo own PRIVMSGs although echo-message was not negotiated
        import threading
        import queue
        self.name = name
        self.caps = caps if caps is not None else {"message-tags": "", "server-time": "", "batch": "",
                                                  "standard-replies": "", "echo-message": ""}
        self.host = next_loopback()
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind((self.host, 0))
        self.port = self.lsock.getsockname()[1]
        self.lsock.listen(4)
        self.conn: socket.socket | None = None
        self.received: "queue.Queue[Message]" = queue.Queue()
        self.enabled_caps: set[str] = set()
        self.registered = threading.Event()
        self.nick = "alice"
        self.password = None
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        from ircclient import parse
        while not self._stop:
            try:
                self.lsock.settimeout(0.5)
                conn, _ = self.lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.conn = conn
            buf = b""
            conn.settimeout(0.5)
            while not self._stop:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.rstrip(b"\r").decode("utf-8", "replace")
                    if line:
                        self._handle(parse(line))
            self.registered.clear()
            self.enabled_caps.clear()
            conn.close()
            self.conn = None

    def _reply(self, line: str):
        if self.conn:
            try:
                self.conn.sendall(line.encode() + b"\r\n")
            except OSError:
                pass

    def send(self, line: str):
        """Push a raw line to ZNC."""
        self._reply(line)

    def _handle(self, m):
        c = m.command
        self.received.put(m)
        if c == "CAP":
            sub = m.params[0].upper()
            if sub == "LS":
                self._reply(":fake.test CAP * LS :" + " ".join(f"{k}={v}" if v else k for k, v in self.caps.items()))
            elif sub == "REQ":
                wanted = m.params[-1].split()
                if all(w.lstrip("-") in self.caps for w in wanted):
                    for w in wanted:
                        if w.startswith("-"):
                            self.enabled_caps.discard(w[1:])
                        else:
                            self.enabled_caps.add(w)
                    self._reply(":fake.test CAP * ACK :" + " ".join(wanted))
                else:
                    self._reply(":fake.test CAP * NAK :" + " ".join(wanted))
            elif sub == "END":
                pass
        elif c == "PASS":
            self.password = m.params[0]
        elif c == "NICK":
            self.nick = m.params[0]
        elif c == "USER":
            n = self.nick
            self._reply(f":fake.test 001 {n} :Welcome to the fake network {n}")
            self._reply(f":fake.test 002 {n} :Your host is fake.test")
            self._reply(f":fake.test 003 {n} :This server was created now")
            self._reply(f":fake.test 004 {n} fake.test fake-1.0 iw ntC")
            self._reply(f":fake.test 005 {n} NETWORK={self.name} CHANTYPES=# PREFIX=(ov)@+ CASEMAPPING=ascii :are supported by this server")
            self._reply(f":fake.test 376 {n} :End of MOTD")
            self.registered.set()
        elif c == "JOIN":
            for chan in m.params[0].split(","):
                self._reply(f":{self.nick}!~u@{self.host} JOIN {chan}")
                self._reply(f":fake.test 353 {self.nick} = {chan} :@{self.nick} peer")
                self._reply(f":fake.test 366 {self.nick} {chan} :End of NAMES")
        elif c == "PING":
            self._reply(":fake.test PONG fake.test :" + (m.params[-1] if m.params else ""))
        elif c == "MODE" and len(m.params) == 1:
            self._reply(f":fake.test 324 {self.nick} {m.params[0]} +nt")
        elif c == "PRIVMSG" and ("echo-message" in self.enabled_caps or self.echo_without_cap):
            import uuid
            tags = ";".join(f"{k}={v}" if v else k for k, v in m.tags.items() if k.startswith("+"))
            if self.echo_without_cap:
                tags = (tags + ";" if tags else "") + f"msgid={uuid.uuid4()}"
            prefix = f"@{tags} " if tags else ""
            self._reply(f"{prefix}:{self.nick}!~u@{self.host} PRIVMSG {m.params[0]} :{m.params[-1]}")

    def expect(self, pred, timeout: float = 5.0, what: str = ""):
        import queue
        deadline = time.monotonic() + timeout
        seen = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"fake server: timed out waiting for {what or pred}; saw {[m.raw for m in seen][-10:]}")
            try:
                m = self.received.get(timeout=remaining)
            except queue.Empty:
                continue
            seen.append(m)
            if pred(m):
                return m

    def expect_cmd(self, command: str, timeout: float = 5.0):
        return self.expect(lambda m: m.command == command.upper(), timeout, what=command)

    def wait_registered(self, timeout: float = 20.0):
        assert self.registered.wait(timeout), "ZNC did not register with the fake server"

    def stop(self):
        self._stop = True
        try:
            self.lsock.close()
        except OSError:
            pass
        if self.conn:
            try:
                self.conn.close()
            except OSError:
                pass


ZNC_USER = "alice"
ZNC_PASS = "secret"


class ZNC:
    def __init__(self, workdir: Path, networks: dict, global_modules: list[str],
                 user_modules: list[str], network_modules: list[str], extra_user_conf: str = "",
                 reuse_datadir: Path | None = None):
        self.port = free_port()
        self.datadir = workdir / "znc"
        (self.datadir / "configs").mkdir(parents=True)
        if reuse_datadir is not None and (reuse_datadir / "moddata").exists():
            # Keep module state (NV registries) across a restart; the config
            # is regenerated with fresh ports.
            shutil.copytree(reuse_datadir / "moddata", self.datadir / "moddata")
        mods = self.datadir / "modules"
        mods.mkdir()
        for so in BUILD_DIR.glob("*.so"):
            os.symlink(so, mods / so.name)
        self.networks = networks
        self.log_path = self.datadir / "znc.log"
        self.conf_path = self.datadir / "configs" / "znc.conf"
        self.write_conf(global_modules, user_modules, network_modules, extra_user_conf)
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen([str(ZNC_BIN), "--foreground", "--debug", "--datadir", str(self.datadir)],
                                     stdout=self.log, stderr=subprocess.STDOUT)
        wait_port(self.port, proc=self.proc)

    def write_conf(self, global_modules, user_modules, network_modules, extra_user_conf=""):
        version = subprocess.run([str(ZNC_BIN), "--version"], capture_output=True, text=True).stdout.split()[1]
        lines = [f"Version = {version}", "ConnectDelay = 0",
                 "<Listener l>", "  AllowIRC = true", "  AllowWeb = true", "  Host = 127.0.0.1",
                 "  IPv4 = true", "  IPv6 = false", f"  Port = {self.port}", "  SSL = false", "  URIPrefix = /",
                 "</Listener>"]
        lines += [f"LoadModule = {m}" for m in ("saslplainauth", "corecaps", *global_modules)]
        lines += [f"<User {ZNC_USER}>", "  Admin = true", "  MaxNetworks = 20", "  <Pass password>", "    Method = Plain",
                  f"    Hash = {ZNC_PASS}", "  </Pass>", f"  Nick = {ZNC_USER}", f"  AltNick = {ZNC_USER}_",
                  f"  Ident = {ZNC_USER}", "  RealName = Alice Example", "  Buffer = 500", "  AutoClearChanBuffer = false",
                  "  AutoClearQueryBuffer = false"]
        # chansaver: channels joined from a client are only written to the
        # config by this module (stock ZNC creates them with InConfig=false).
        lines += [f"  LoadModule = {m}" for m in ("chansaver", *user_modules)]
        if extra_user_conf:
            lines.append(extra_user_conf)
        for name, ergo in self.networks.items():
            lines += [f"  <Network {name}>", f"    Server = {ergo.host} {ergo.port}", f"    Nick = {ZNC_USER}",
                      "    IRCConnectEnabled = true", "    FloodRate = 0", "    FloodBurst = 100"]
            lines += [f"    LoadModule = {m}" for m in network_modules]
            lines += ["    <Chan #test>", "    </Chan>", "  </Network>"]
        lines.append("</User>")
        self.conf_path.write_text("\n".join(lines) + "\n")

    def client(self, name: str = "client", network: str | None = None, **kw) -> IRCClient:
        """A raw client connected to ZNC (not yet registered)."""
        c = IRCClient("127.0.0.1", self.port, name=name, **kw)
        c.znc_user = ZNC_USER + (f"/{network}" if network else "")
        return c

    def login(self, name: str = "client", network: str | None = "ergo1", caps=("message-tags", "server-time", "batch"),
              sasl: bool = False, extra_caps: tuple[str, ...] = ()) -> IRCClient:
        c = self.client(name, network)
        ident = ZNC_USER + (f"/{network}" if network else "")
        if sasl:
            c.register(ZNC_USER, ident, None, caps=tuple(caps) + extra_caps, sasl=(ident, ZNC_PASS))
        else:
            c.register(ZNC_USER, ident, f"{ident}:{ZNC_PASS}", caps=tuple(caps) + extra_caps)
        return c

    def wait_network_connected(self, name: str, timeout: float = 15.0) -> None:
        """Poll the log until ZNC reports the IRC connection for the network."""
        deadline = time.monotonic() + timeout
        needle = f"({ZNC_USER}/{name})"
        while time.monotonic() < deadline:
            text = self.log_path.read_text(errors="replace")
            if needle in text and " 001 " in text:
                return
            time.sleep(0.1)
        raise TimeoutError(f"network {name} did not connect; log tail:\n" + self.log_path.read_text()[-3000:])

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


@pytest.fixture(scope="session")
def built_modules():
    sos = sorted(p.name for p in BUILD_DIR.glob("*.so"))
    assert sos, f"no modules built in {BUILD_DIR}; run cmake --build first"
    return sos


@pytest.fixture
def workdir(tmp_path):
    return tmp_path


@pytest.fixture
def ergos(workdir):
    servers = {"ergo1": Ergo(workdir, "ergo1"), "ergo2": Ergo(workdir, "ergo2")}
    yield servers
    for e in servers.values():
        e.stop()


@pytest.fixture
def fake():
    f = FakeServer()
    yield f
    f.stop()


@pytest.fixture
def legacy_ergo(workdir):
    e = Ergo(workdir, "legacy", legacy=True)
    yield e
    e.stop()


def make_znc(workdir, ergos, built_modules, global_modules=("ircv3base",), user_modules=(), network_modules=(),
             extra_user_conf="", reuse_datadir=None):
    z = ZNC(workdir, ergos, list(global_modules), list(user_modules), list(network_modules), extra_user_conf,
            reuse_datadir=reuse_datadir)
    for name in ergos:
        z.wait_network_connected(name)
    return z


@pytest.fixture
def znc(workdir, ergos, built_modules):
    z = make_znc(workdir, ergos, built_modules)
    yield z
    z.stop()
