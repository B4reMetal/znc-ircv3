# Solder: Seedpool role groups in the user list (`seedpool/enhanced`)

Goal: show Seedpool's site roles (Sysop, Moderator, Uploader, ... Cesspool)
as sections or badges in the channel user list, the way the site's own chat
does. Everything below was captured from irc.seedpool.org through ZNC on
2026-10-12; the ircd defines the format, ZNC only relays it.

## Capability

- Name: `seedpool/enhanced` (vendor cap of the Seedpool ircd).
- Through ZNC the cap is server-dependent: it is NOT in the pre-login
  `CAP LS`, because ZNC does not know the network yet. After registration,
  once the connection is bound to the seedpool network, ZNC sends
  `CAP <nick> NEW :seedpool/enhanced` (needs `CAP LS 302`, which enables
  cap-notify). Request it then: `CAP REQ :seedpool/enhanced` -> `CAP ACK`.
  Do not treat NAK or absence as an error; the module may not be loaded.
- Request it as a courtesy. ZNC forwards the data to every client of the
  network whether or not that client requested the cap, so parse `SPGROUPS`
  whenever it arrives.

## The message

```
:SeedServ SPGROUPS <#channel> <json>
```

- Source is the service `SeedServ`, not the server. There are no tags
  beyond ZNC's `time`.
- `<json>` is one JSON object as the final parameter (it contains spaces
  and is sent as a trailing parameter). Schema:

```json
{"groups":[{"name":"Sysop","position":25,"users":["nick1","nick2"]}, ...]}
```

  - `groups` is ordered by `position` descending; higher position = more
    senior. Positions are not contiguous (gaps are normal).
  - `name` is the display name of the role.
  - `users` are bare nicks with no prefix characters. Every nick from the
    channel's NAMES reply appears in exactly one group, and no nick appears
    twice, so the groups partition the member list. Nicks not covered by
    any group should be treated as the lowest group (defensive only; not
    observed).
  - Observed group names, top to bottom: Bot, Sysop, Moderator, FLS,
    Editor, Internal, Uploader, SpecialPool, GodPool, MegaPool, UberPool,
    SuperPool, PowerPool, Pool, User, Cesspool. Do not hard-code them;
    only `position` ordering is reliable.
- Size: one line per channel, 1.5 KB for a small channel and about 14 KB
  for #seedpool (6,400 members). The IRC line is far over 512 bytes; the
  client's line reader must not truncate or drop long lines. (The ZNC
  module raises ZNC's socket limit to 16 MB for the same reason.)

## When it is sent

- Once after every NAMES reply for a channel: on join (after the 366
  `End of /NAMES`) and after any explicit `NAMES #channel`.
- It is NOT pushed when members join, part, quit or change role. To keep
  the list current, apply JOIN/PART/QUIT to the local member list and put
  new joiners in the lowest group until the next refresh; re-send `NAMES`
  when the channel is opened or on a timer if exact roles matter.
- Channel prefixes (`@`, `%`, `+`, with multi-prefix) still arrive in
  NAMES as usual and are independent of the groups; a user can be `+` and
  in the Moderator group. Show both if useful.

## Suggested handling

1. On `SPGROUPS`, parse the JSON; on parse failure log and ignore.
2. Store per channel: an ordered list of (name, position) and a nick ->
   group map, keyed case-insensitively using the network's CASEMAPPING.
3. Render the user list grouped by role in position order, prefix
   characters kept within each group; members without a group go last.
4. Clear the data on PART/KICK of the channel or on disconnect.

## Test environment

Load the module on a ZNC network connected to irc.seedpool.org and join
a channel there. Sending `NAMES #channel` triggers a fresh
`SPGROUPS #channel` within about 20 ms.
