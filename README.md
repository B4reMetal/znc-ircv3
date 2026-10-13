# znc-ircv3

Out-of-tree ZNC modules that add soju's bouncer protocol and the popular
IRCv3 drafts to a stock ZNC (1.10 or later). No fork, no core patches.

| Module | Capabilities / features | Load as |
|---|---|---|
| `ircv3base` | `standard-replies`, msgid minting for messages without one, server-side `batch`, `setname`, `draft/pre-away`, `no-implicit-names`, `extended-monitor` (AWAY/ACCOUNT/CHGHOST/SETNAME of monitored nicks outside shared channels forwarded to clients that enabled it) | global, load first |
| `bouncernetworks` | `soju.im/bouncer-networks`, `soju.im/bouncer-networks-notify`: `BOUNCER BIND/LISTNETWORKS/ADDNETWORK/CHANGENETWORK/DELNETWORK`, `BOUNCER_NETID` | global |
| `readmarker` | `draft/read-marker`, `soju.im/read`: `MARKREAD` / `READ` shared between clients | global |
| `chathistory` | `draft/chathistory`, `draft/event-playback`, `draft/message-redaction`: persistent per-network history store, `CHATHISTORY` queries, no auto-playback for capable clients; `soju.im/search` answered from a per-user SQLite FTS5 index of the same store (needs libsqlite3 with FTS5, SQLite >= 3.34) | global |
| `labeled` | `labeled-response`: labels ZNC's own replies, routes labeled upstream replies to the requesting client only | global |
| `multiline` | `draft/multiline` pass-through; flattened when the upstream lacks it | global |
| `webpush` | `soju.im/webpush`: Web Push (RFC 8030/8291/8292) for highlights and PMs; immediate when no client is present, otherwise after a 5 s grace period unless a read marker shows the message was read | global |
| (webpush) | `solder.chat/webpush-rules`: per-user highlight/mute/all/ignore push rules managed over IRC, see `docs/webpush-rules.md` | global |
| `websocket` | IRC over WebSocket listener for browser clients (gamja, kiwiirc, The Lounge) | global, needs `port=` |

All caps are offered at `CAP LS` and are inert for clients that do not
request them. Admins can still hide any of them with ZNC's `DisableClientCap`.

## Build

```sh
# against an installed ZNC (needs znc-buildmod / ZNCConfig.cmake)
cmake -S . -B build -DZNC_DIR=/usr/share/znc/cmake      # or the prefix you installed ZNC to
cmake --build build
cp build/*.so ~/.znc/modules/                            # or cmake --install build
```

Single modules also build with `znc-buildmod -I common modules/<name>.cpp`.

## Load

```
/znc loadmod ircv3base
/znc loadmod bouncernetworks
/znc loadmod readmarker
/znc loadmod chathistory days=90 limit=1000 searchlines=400000 searchms=2000
/znc loadmod labeled
/znc loadmod multiline
/znc loadmod webpush contact=mailto:you@example.org
/znc loadmod websocket port=8097 path=/socket origins=https://web.example
```

or `LoadModule = ...` lines at the top level of `znc.conf`. `ircv3base`
should be loaded before the others; `labeled` may go anywhere, it moves
itself ahead of the modules that answer commands. SASL logins need ZNC's
own `saslplainauth` module. ZNC's bundled `corecaps` global module must be
loaded too: since ZNC 1.9 it is what offers `away-notify`, `account-notify`,
`account-tag` and `extended-join` to clients (configs written by hand or
upgraded from old versions may lack it), and `extended-monitor` is useless
without `away-notify`. `webpush` takes `contact=` (the VAPID contact
URI push services may use to reach you; defaults to `mailto:znc@<host>`),
`ttl=` and `always`.

## How the pieces fit

- **bouncer-networks** keeps ZNC's one-connection-per-network model. `BOUNCER
  BIND` before `CAP END` picks the network; the core's attach to its own
  default choice is hidden from the client, so there is no part/rejoin
  noise and none of ZNC's "Selecting network" notices (PASS/USER are held
  until `CAP END` so the choice is known). Network ids are integers stored
  in the module's registry and survive renames and restarts. The server
  password is accepted in ADDNETWORK/CHANGENETWORK but never echoed.
- **webpush rules** (`solder.chat/webpush-rules`, spec in `docs/webpush-rules.md`):
  `WEBPUSH RULES` lists, `WEBPUSH RULE ADD|DEL <kind> <value>` and
  `WEBPUSH RULE CLEAR [<kind>]` edit the rules of the connection's scope
  (its bound network, or every network on an unbound connection). Kinds:
  `highlight` (whole-word pattern or `/regex/`), `mute` and `all` (buffer
  names), `ignore` (sender masks). The same rules are available as
  `rules` / `rule ...` commands on `*webpush`. The user's nick is matched
  as a whole word, and INVITEs to the user are pushed.
- **search** (`soju.im/search`): `SEARCH in=;from=;after=;before=;text=;limit=`
  answers from the chathistory store with a `soju.im/search` batch, oldest
  first, original msgid and time tags. `text` is a case-insensitive
  substring; `in` may be omitted to search every target of the network;
  `limit` is capped at the CHATHISTORY limit. Each query has a budget of
  400k scanned lines or two seconds. The cap is withdrawn with CAP DEL on
  an unbound bouncer-networks connection, since there is no network to
  search there.
- **echo-message, server side.** ZNC's core echoes a client's message
  itself and never asks the server for echo-message, so your own messages
  carried a ZNC msgid that nobody else knew. With the server's cap
  available, `ircv3base` forwards the client's message without the core's
  echo and feeds the server's echo back through the sending client: buffers,
  chathistory and every client get the server's msgid and time, delivery
  follows echo-message / `znc.in/self-message` as before, and the labeled
  echo keeps its label.
- **ISUPPORT** tokens from the modules (`BOUNCER_NETID`, `CHATHISTORY`,
  `MSGREFTYPES`, `VAPID`) are sent inside the registration burst, before
  the end of the MOTD, and the upstream's own copies of those tokens are
  dropped. Replayed JOINs on attach carry the time of the real join.
- **chathistory** writes every message (and, tagged, every event) to
  `<datadir>/moddata/chathistory/<user>/<network>/<target>/<day>.log` with
  tags intact. Messages that arrive without a `msgid` get one from
  `ircv3base` in the `znc-...` namespace, so msgid selectors work on every
  network. `tools/import_znc_logs.py` converts existing `log` module files
  into this store.
- **labeled** cannot label replies that ZNC's core sends through its raw
  path (`*status` output); those are ACKed when the next command arrives.
- **websocket** bridges each WebSocket into a regular `CClient` over a
  socketpair, so every other module sees a normal client.

## Search index

`chathistory` keeps `<moddata>/chathistory/<user>/.search.db`, an SQLite
database with an FTS5 trigram index over every stored PRIVMSG/NOTICE
(network, target, time, sender, msgid, byte range in the day file, text with
formatting stripped). The day files stay the source of truth. Lines are
indexed as they are stored; a background job (ZNC's thread pool) indexes day
files whose size changed on disk at load, hourly, and on `/msg *chathistory
sync`. `reindex` rebuilds everything. Pruning and redaction update the index.
While a sync is running, day files it has not covered yet are scanned
directly within the `searchlines`/`searchms` budget; whenever results may be
incomplete the client gets `NOTE SEARCH TRUNCATED` first (standard-replies).
`text=` keeps substring semantics: three characters and more go through the
trigram index, shorter patterns scan the text column. `status` shows the
index size, schema version and sync state.

Row ids are derived from the message time, so FTS returns the newest
matches first without sorting; two extra token columns (network/target,
sender) let `in=` and `from=` narrow the search inside FTS. On a 7 million
message store, common and rare words answer in about 10 ms. Expect the
index to take roughly 4 times the size of the day files (about 10 times the
size of the equivalent `log` module files, which carry no tags or msgids).

Schema changes are versioned: bump `kSchemaVersion` in `common/searchindex.h`
and append a migration, either SQL applied in a transaction or `recreate`
(the file is replaced at load and the sync job rebuilds it). Databases newer
than the module are refused and searches fall back to scanning. Running the
log importer while ZNC is up is fine: a hit whose line moved is looked up by
msgid, and a sync is started to re-read the rewritten files.

## Tests

Ergo runs in Docker (`ghcr.io/ergochat/ergo`), ZNC runs locally from
`deps/znc-install`, modules are built into `build/`.

```sh
cmake -S ~/src/znc -B ~/src/znc/build -DCMAKE_INSTALL_PREFIX=$PWD/deps/znc-install   # once
cmake --build ~/src/znc/build --target install
cmake -S . -B build -DZNC_DIR=$PWD/deps/znc-install/share/znc/cmake && cmake --build build
python -m venv .venv && .venv/bin/pip install pytest pytest-timeout pyyaml websockets cryptography
cd tests && ../.venv/bin/python -m pytest -q
```

`docker/compose.yaml` brings up two Ergo servers for manual testing with
real clients (goguma, gamja, senpai).

## Importing old logs

```sh
tools/import_znc_logs.py --logdir ~/.znc/moddata/log --store ~/.znc/moddata/chathistory --tz Europe/Berlin
```

Stop ZNC first. Re-running is safe (deduplicated by imported msgid).
