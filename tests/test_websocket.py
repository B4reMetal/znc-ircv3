"""IRC over WebSocket (websocket module)."""
import time

import pytest
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect

from conftest import make_znc, free_port, ZNC_USER, ZNC_PASS
from ircclient import parse


class WSIRC:
    def __init__(self, url, subprotocols=("text.ircv3.net",), **kw):
        self.ws = connect(url, subprotocols=list(subprotocols), open_timeout=5, **kw)
        self.log = []

    def send(self, line):
        self.ws.send(line)

    def expect(self, pred, timeout=5.0, what=""):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"ws: timed out waiting for {what}; recent: {[m.raw for m in self.log[-10:]]}")
            try:
                data = self.ws.recv(timeout=remaining)
            except TimeoutError:
                continue
            if isinstance(data, bytes):
                data = data.decode()
            for line in data.split("\n"):
                line = line.rstrip("\r")
                if not line:
                    continue
                m = parse(line)
                self.log.append(m)
                if m.command == "PING":
                    self.send("PONG :" + m.params[-1])
                if pred(m):
                    return m

    def close(self):
        self.ws.close()


@pytest.fixture
def znc_ws(workdir, ergos, built_modules):
    port = free_port()
    z = make_znc(workdir, ergos, built_modules,
                 global_modules=("ircv3base", f"websocket port={port} path=/socket origins=http://allowed.example,http://*.also.example"))
    z.ws_port = port
    yield z
    z.stop()


def test_login_and_relay_over_websocket(znc_ws):
    url = f"ws://127.0.0.1:{znc_ws.ws_port}/socket"
    c = WSIRC(url, additional_headers={"Origin": "http://allowed.example"})
    assert c.ws.subprotocol == "text.ircv3.net"
    c.send("CAP LS 302")
    m = c.expect(lambda m: m.command == "CAP" and m.params[1] == "LS", what="CAP LS")
    assert "standard-replies" in m.params[-1]
    c.send("CAP REQ :message-tags server-time")
    c.expect(lambda m: m.command == "CAP" and m.params[1] == "ACK", what="ACK")
    c.send(f"PASS {ZNC_USER}/ergo1:{ZNC_PASS}")
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :ws")
    c.send("CAP END")
    c.expect(lambda m: m.command == "001", what="001")
    c.expect(lambda m: m.command == "JOIN" and m.params[0] == "#test", what="JOIN replay")
    peer = znc_ws.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    peer.join("#test")
    peer.privmsg("#test", "hello websocket")
    m = c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "hello websocket", what="relayed PRIVMSG")
    assert "time" in m.tags
    # Outbound works too, and the echo reaches a TCP client of the same user.
    tcp = znc_ws.login("tcp", "ergo1")
    tcp.drain(0.3)
    c.send("PRIVMSG #test :from the browser")
    peer.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "from the browser")
    tcp.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "from the browser")
    # A protocol-level ping round-trips.
    c.ws.ping().wait(5)
    c.close()
    tcp.close()
    peer.close()


def test_binary_subprotocol_fallback(znc_ws):
    c = WSIRC(f"ws://127.0.0.1:{znc_ws.ws_port}/socket", subprotocols=("binary.ircv3.net",))
    assert c.ws.subprotocol == "binary.ircv3.net"
    c.send("CAP LS 302")
    c.expect(lambda m: m.command == "CAP", what="CAP LS over binary")
    c.close()


def test_wrong_path_and_origin_are_rejected(znc_ws):
    with pytest.raises(InvalidStatus) as e:
        connect(f"ws://127.0.0.1:{znc_ws.ws_port}/nope", open_timeout=5)
    assert e.value.response.status_code == 404
    with pytest.raises(InvalidStatus) as e:
        connect(f"ws://127.0.0.1:{znc_ws.ws_port}/socket", open_timeout=5,
                additional_headers={"Origin": "http://evil.example"})
    assert e.value.response.status_code == 403
    # Wildcard origin allowed.
    c = connect(f"ws://127.0.0.1:{znc_ws.ws_port}/socket", open_timeout=5,
                additional_headers={"Origin": "http://web.also.example"})
    c.close()


def test_closing_websocket_disconnects_client(znc_ws):
    c = WSIRC(f"ws://127.0.0.1:{znc_ws.ws_port}/socket")
    c.send(f"PASS {ZNC_USER}/ergo1:{ZNC_PASS}")
    c.send(f"NICK {ZNC_USER}")
    c.send(f"USER {ZNC_USER} 0 * :ws")
    c.expect(lambda m: m.command == "001", what="001")
    c.close()
    time.sleep(0.5)
    tcp = znc_ws.login("tcp", "ergo1")
    tcp.send("PRIVMSG *status :ListClients")
    lines = [m.params[-1] for m in tcp.drain(1.0) if m.nick == "*status"]
    assert not any("WS::" in l for l in lines), lines
    tcp.close()
