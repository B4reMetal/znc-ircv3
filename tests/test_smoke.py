"""Harness smoke tests: Ergo answers, ZNC relays, modules load."""


def test_ergo_direct(ergos):
    c = ergos["ergo1"].client()
    caps = c.register("direct", "direct")
    assert "message-tags" in caps
    assert "draft/chathistory" in c.caps_available
    assert "labeled-response" in c.caps_available
    c.close()


def test_znc_relays(znc):
    c = znc.login()
    assert "server-time" in c.caps_enabled
    # ZNC's own ISUPPORT replay from ergo1
    m = c.expect(lambda m: m.command == "005" and any(p.startswith("NETWORK=") for p in m.params), what="005 NETWORK")
    assert "NETWORK=ergo1" in m.params
    c.join("#test")
    d = ergos_client = znc.networks["ergo1"].client("peer")
    d.register("peer", "peer")
    d.join("#test")
    d.privmsg("#test", "hello alice")
    m = c.expect(lambda m: m.command == "PRIVMSG" and m.params[-1] == "hello alice", what="relayed PRIVMSG")
    assert m.nick == "peer"
    assert "time" in m.tags
    c.close()
    d.close()


def test_modules_loaded(znc):
    c = znc.login()
    c.send("PRIVMSG *status :ListMods")
    m = c.expect(lambda m: m.command == "PRIVMSG" and "ircv3base" in m.params[-1], what="ircv3base in ListMods")
    assert m.nick == "*status"
    c.close()


def test_client_joined_channel_is_saved_to_config(znc):
    """chansaver is part of the generated config: a channel joined from a
    client survives SaveConfig (stock ZNC would drop it)."""
    c = znc.login("c", "ergo1")
    c.join("#saved")
    c.send("PRIVMSG *status :SaveConfig")
    c.expect(lambda m: m.nick == "*status" and "Wrote config" in m.params[-1], what="SaveConfig")
    assert "<Chan #saved>" in znc.conf_path.read_text()
    c.close()
