#!/usr/bin/env python3
"""Fill an Ergo test server with chatter so chathistory has something to show.

usage: seed_history.py <host> <port> <bouncer-nick> [channel] [lines]

Connects two throwaway users, has them join the channel, exchange messages
mentioning each other and the bouncer's nick, and send the bouncer a few
private messages. Timestamps are spread out slightly so paging by time works.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from ircclient import IRCClient  # noqa: E402

LINES = [
    "morning everyone", "anyone tried the new release?", "yes, the scrollback finally works",
    "{nick}: can you check #znc later?", "that's the chathistory module in action",
    "brb coffee", "back", "who owns the bot in here?", "I think {nick} does",
    "lunch?", "sure, 12:30", "the websocket listener is on 8097 by the way",
    "read markers sync between my phone and laptop now", "neat", "pushing to the phone works too",
    "ok, logging off for a bit", "ttyl", "{nick}: ping", "pong", "that's enough history for now",
]


def main():
    host, port, nick = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    chan = sys.argv[4] if len(sys.argv) > 4 else "#test"
    n = int(sys.argv[5]) if len(sys.argv) > 5 else len(LINES)
    a = IRCClient(host, port, "alice_seed")
    b = IRCClient(host, port, "bob_seed")
    a.register("alice", "alice")
    b.register("bob", "bob")
    a.join(chan)
    b.join(chan)
    for i in range(n):
        text = LINES[i % len(LINES)].format(nick=nick)
        sender, other = (a, b) if i % 2 == 0 else (b, a)
        sender.privmsg(chan, text)
        other.expect(lambda m, t=text: m.command == "PRIVMSG" and m.params[-1] == t)
        time.sleep(0.15)
    b.send("TOPIC " + chan + " :seeded history, see CHATHISTORY LATEST")
    a.privmsg(nick, "hi, this is a private message with history")
    time.sleep(0.2)
    b.privmsg(nick, "and one from bob")
    time.sleep(0.5)
    a.send("PART " + chan + " :done seeding")
    time.sleep(0.3)
    a.close()
    b.close()
    print(f"seeded {n} channel lines and 2 private messages on {host}:{port} {chan}")


if __name__ == "__main__":
    main()
