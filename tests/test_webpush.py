"""soju.im/webpush: registration, encryption (RFC 8291), VAPID (RFC 8292)."""
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from conftest import make_znc, free_port, ZNC_USER

CAP = "soju.im/webpush"
MODS = ("ircv3base", "readmarker", "webpush")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class PushEndpoint:
    """Fake push service: records POSTs, decrypts them with the test keys."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub_raw = self.priv.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint)
        self.auth = os.urandom(16)
        self.received = []
        self.status = 201
        endpoint = self
        self.lock = threading.Lock()

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                with endpoint.lock:
                    endpoint.received.append((self.path, dict(self.headers), body))
                self.send_response(endpoint.status)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/push/abc"

    def keys(self):
        return f"p256dh={b64url(self.pub_raw)};auth={b64url(self.auth)}"

    def wait(self, n=1, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if len(self.received) >= n:
                    return list(self.received)
            time.sleep(0.05)
        raise AssertionError(f"expected {n} push(es), got {len(self.received)}")

    def decrypt(self, body: bytes) -> bytes:
        salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
        # goguma's decoder requires a single record whose size equals the
        # whole payload; anything else is rejected before decryption.
        assert rs == len(body), f"rs={rs} != payload length {len(body)}"
        server_pub = body[21:21 + idlen]
        cipher = body[21 + idlen:]
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub)
        secret = self.priv.exchange(ec.ECDH(), peer)
        ikm = HKDF(hashes.SHA256(), 32, self.auth, b"WebPush: info\0" + self.pub_raw + server_pub).derive(secret)
        cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\0").derive(ikm)
        nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\0").derive(ikm)
        plain = AESGCM(cek).decrypt(nonce, cipher, None)
        assert plain.endswith(b"\x02")
        return plain[:-1]

    def stop(self):
        self.server.shutdown()


def verify_vapid(auth_header: str, vapid_pub_b64: str, origin: str):
    assert auth_header.startswith("vapid ")
    parts = dict(p.strip().split("=", 1) for p in auth_header[6:].split(","))
    assert parts["k"] == vapid_pub_b64
    t = parts["t"]
    h, c, s = t.split(".")
    header = json.loads(b64url_decode(h))
    claims = json.loads(b64url_decode(c))
    assert header["alg"] == "ES256"
    assert claims["aud"] == origin
    assert claims["exp"] > time.time()
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64url_decode(vapid_pub_b64))
    sig = b64url_decode(s)
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pub.verify(der, f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256()))


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


def test_register_and_push_on_highlight_and_pm(znc, endpoint):
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    assert CAP in c.caps_enabled
    m = c.expect(lambda m: m.command == "005" and m.prefix == "irc.znc.in" and any(p.startswith("VAPID=") for p in m.params), what="VAPID")
    vapid = next(p for p in m.params if p.startswith("VAPID=")).split("=", 1)[1]
    c.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    m = c.expect(lambda m: m.command == "WEBPUSH", what="REGISTER reply")
    assert m.params == ["REGISTER", endpoint.url]
    # Errors
    c.send("WEBPUSH REGISTER notaurl p256dh=x;auth=y")
    assert c.expect_cmd("FAIL").params[:3] == ["WEBPUSH", "INVALID_PARAMS", "REGISTER"]
    c.send("WEBPUSH FROB x")
    assert c.expect_cmd("FAIL").params[:2] == ["WEBPUSH", "INVALID_PARAMS"]
    c.close()  # no client attached -> pushes flow
    time.sleep(0.5)

    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    peer.join("#test")
    peer.privmsg("#test", "nothing for anyone")
    peer.privmsg("#test", f"hey {ZNC_USER} look at this")
    peer.privmsg(ZNC_USER, "private ping")
    got = endpoint.wait(2)
    assert len(got) == 2, [endpoint.decrypt(b) for _, _, b in got]
    for path, headers, body in got:
        assert path == "/push/abc"
        assert headers["Content-Encoding"] == "aes128gcm"
        assert headers["TTL"] == "86400"
        verify_vapid(headers["Authorization"], vapid, f"http://127.0.0.1:{endpoint.port}")
    lines = [endpoint.decrypt(b).decode() for _, _, b in got]
    assert any(f"PRIVMSG #test :hey {ZNC_USER} look at this" in l for l in lines), lines
    assert any(f"PRIVMSG {ZNC_USER} :private ping" in l for l in lines), lines
    assert all(l.startswith("@") and "msgid=" in l and "time=" in l and ":peer!" in l for l in lines), lines
    peer.close()


def test_present_client_grace_period_read_marker_and_away(znc, endpoint):
    c = znc.login("c", "ergo1", extra_caps=(CAP, "draft/read-marker"))
    c.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    c.expect(lambda m: m.command == "WEBPUSH")
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    # A present client delays the push (soju's grace period) but does not
    # cancel it when nobody reads the message.
    peer.privmsg(ZNC_USER, "while attached")
    m = c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "while attached")
    time.sleep(1.0)
    assert endpoint.received == []
    got = endpoint.wait(1, timeout=8)
    assert len(got) == 1 and "while attached" in endpoint.decrypt(got[0][2]).decode()
    # Read within the grace period: no push.
    peer.privmsg(ZNC_USER, "read quickly")
    m = c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "read quickly")
    c.send(f"MARKREAD peer timestamp={m.tags['time']}")
    c.expect(lambda m: m.command == "MARKREAD")
    time.sleep(7.0)
    assert len(endpoint.received) == 1
    # Away clients are absent: immediate push.
    c.send("AWAY :afk")
    c.expect_cmd("306")
    peer.privmsg(ZNC_USER, "while away")
    got = endpoint.wait(2, timeout=2)
    assert len(got) == 2 and "while away" in endpoint.decrypt(got[1][2]).decode()
    # Unregister stops it.
    c.send(f"WEBPUSH UNREGISTER {endpoint.url}")
    m = c.expect(lambda m: m.command == "WEBPUSH")
    assert m.params == ["UNREGISTER", endpoint.url]
    peer.privmsg(ZNC_USER, "after unregister")
    time.sleep(1.0)
    assert len(endpoint.received) == 2
    c.close()
    peer.close()


def test_subscriptions_are_scoped_per_network(znc, endpoint):
    a = znc.login("a", "ergo1", extra_caps=(CAP,))
    a.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    a.expect(lambda m: m.command == "WEBPUSH")
    b = znc.login("b", "ergo2", extra_caps=(CAP,))
    b.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    b.expect(lambda m: m.command == "WEBPUSH")
    a.send("PRIVMSG *webpush :list")
    rows = [m.params[-1] for m in a.drain(1.0) if m.nick == "*webpush"]
    assert sum(1 for r in rows if endpoint.url in r) == 2, rows
    a.close()
    b.close()
    time.sleep(0.5)
    for net, text in (("ergo1", "on ergo1"), ("ergo2", "on ergo2")):
        peer = znc.networks[net].client("peer")
        peer.register("peer", "peer")
        peer.privmsg(ZNC_USER, text)
        peer.close()
    got = endpoint.wait(2, timeout=3)
    time.sleep(1.0)
    assert len(endpoint.received) == 2
    texts = sorted(endpoint.decrypt(b).decode().split(" :")[-1] for _, _, b in got)
    assert texts == ["on ergo1", "on ergo2"]


def test_gone_endpoint_is_dropped(znc, endpoint):
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    c.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    c.expect(lambda m: m.command == "WEBPUSH")
    c.close()
    endpoint.status = 410
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    peer.privmsg(ZNC_USER, "first")
    endpoint.wait(1)
    time.sleep(0.5)
    peer.privmsg(ZNC_USER, "second")
    time.sleep(1.0)
    assert len(endpoint.received) == 1
    peer.close()


def test_several_quick_messages_with_a_present_client_are_all_pushed(znc, endpoint):
    c = znc.login("c", "ergo1", extra_caps=(CAP,))
    c.send(f"WEBPUSH REGISTER {endpoint.url} {endpoint.keys()}")
    c.expect(lambda m: m.command == "WEBPUSH")
    peer = znc.networks["ergo1"].client("peer")
    peer.register("peer", "peer")
    for i in range(3):
        peer.privmsg(ZNC_USER, f"quick {i}")
    c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "quick 2")
    got = endpoint.wait(3, timeout=9)
    texts = sorted(endpoint.decrypt(b).decode().split(" :")[-1] for _, _, b in got)
    assert texts == ["quick 0", "quick 1", "quick 2"]
    c.close()
    peer.close()
