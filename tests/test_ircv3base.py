"""ircv3base: standard-replies gating, msgid minting, server-side batch."""
import pytest

from conftest import make_znc


@pytest.fixture
def znc_fake(workdir, fake, built_modules):
    """ZNC with one network pointing at the scripted fake server."""
    z = make_znc(workdir, {"fake": fake}, built_modules)
    fake.wait_registered()
    yield z
    z.stop()


def test_caps_requested_from_server(znc_fake, fake):
    reqs = []
    # The CAP REQ lines were already consumed during registration; look at the log.
    while not fake.received.empty():
        reqs.append(fake.received.get())
    text = fake.enabled_caps
    assert "standard-replies" in text
    assert "batch" in text
    assert "message-tags" in text


def test_standard_replies_offered_and_gated(znc_fake, fake):
    cap = znc_fake.login("capable", "fake", extra_caps=("standard-replies",))
    assert "standard-replies" in cap.caps_enabled
    plain = znc_fake.login("plain", "fake")
    assert "standard-replies" not in plain.caps_enabled
    for c in (cap, plain):
        c.drain(0.3)

    fake.send(":fake.test FAIL FOO BAR :something failed upstream")
    m = cap.expect_cmd("FAIL")
    assert m.params[:2] == ["FOO", "BAR"]
    plain.not_expected(lambda m: m.command == "FAIL")

    # Commands that define their own FAIL replies reach everyone.
    fake.send(":fake.test FAIL BOUNCER INVALID_NETID BIND 9 :no such network")
    cap.expect_cmd("FAIL")
    plain.expect_cmd("FAIL")
    cap.close()
    plain.close()


def test_msgid_minted_for_server_lines(znc_fake, fake):
    c = znc_fake.login("c", "fake")
    c.join("#test")
    c.drain(0.3)
    fake.send(":peer!~u@h PRIVMSG #test :no id on this one")
    m = c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "no id on this one")
    assert m.tags.get("msgid", "").startswith("znc-"), m.raw
    fake.send("@msgid=upstream-1 :peer!~u@h PRIVMSG #test :keeps upstream id")
    m = c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "keeps upstream id")
    assert m.tags["msgid"] == "upstream-1"
    # Playback after reattach carries the same ids.
    first_id = c.log[-2].tags["msgid"] if c.log[-2].command == "PRIVMSG" else None
    c.close()
    d = znc_fake.login("d", "fake")
    msgs = [m for m in d.drain(1.0) if m.command == "PRIVMSG" and m.params[0] == "#test"]
    ids = [m.tags.get("msgid") for m in msgs]
    assert "upstream-1" in ids
    assert any(i and i.startswith("znc-") for i in ids)
    assert len(set(ids)) == len(ids), ids
    d.close()


def test_msgid_minted_for_own_messages_but_not_sent_upstream(znc_fake, fake):
    a = znc_fake.login("a", "fake")
    b = znc_fake.login("b", "fake")
    a.join("#test")
    b.drain(0.5)
    a.privmsg("#test", "hello from a", tags={"+typing": "done"})
    # The other client gets ZNC's echo with a minted id...
    m = b.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "hello from a")
    assert m.tags.get("msgid", "").startswith("znc-"), m.raw
    assert m.tags.get("+typing") == "done"
    # ...and the upstream server never sees the ZNC id.
    up = fake.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "hello from a")
    assert "msgid" not in up.tags, up.raw
    assert up.tags.get("+typing") == "done"
    a.close()
    b.close()


def test_batch_forwarded_only_to_batch_clients(znc_fake, fake):
    withb = znc_fake.login("withb", "fake", caps=("message-tags", "server-time", "batch"))
    assert "batch" in withb.caps_enabled
    without = znc_fake.login("without", "fake", caps=("message-tags", "server-time"))
    assert "batch" not in without.caps_enabled
    withb.join("#test")
    for c in (withb, without):
        c.drain(0.3)
    fake.send(":fake.test BATCH +ns1 netsplit fake.test other.test")
    fake.send("@batch=ns1 :peer!~u@h QUIT :fake.test other.test")
    fake.send(":fake.test BATCH -ns1")
    start = withb.expect(lambda m: m.command == "BATCH" and m.params[0] == "+ns1")
    assert start.params[1] == "netsplit"
    inner = withb.collect_batch(start)
    assert [m.command for m in inner] == ["QUIT"]
    assert inner[0].tags.get("batch") == "ns1"
    q = without.expect_cmd("QUIT")
    assert "batch" not in q.tags
    without.not_expected(lambda m: m.command == "BATCH")
    withb.close()
    without.close()
