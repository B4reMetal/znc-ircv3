# 11 — Push rules (bouncer-side highlight and filter rules)

Web Push leaves "which messages get pushed" to the bouncer, and the phone cannot add or
drop notifications (dropping needs Apple's filtering entitlement). So per-user filtering has
to live on the bouncer. This extension lets a client manage those rules over IRC, so Solder's
keyword list, muted buffers and ignored nicks also decide what is pushed.

Capability: **`solder.chat/webpush-rules`** (vendor-prefixed; requires `soju.im/webpush`).
A server that offers it MUST apply the rules below to Web Push decisions.

## Scope

Rules set on a connection bound to a network (`BOUNCER BIND`) apply to that network.
Rules set on an unbound connection apply to every network of the account. Effective rules
for a network are the union of both.

## Rule kinds

| Kind | Value | Effect |
|---|---|---|
| `highlight` | pattern | A channel line matching it is pushed, in addition to the user's nick |
| `mute` | buffer name (channel or nick) | Nothing from this buffer is pushed, highlights and DMs included |
| `all` | buffer name | Every PRIVMSG/NOTICE/ACTION in this buffer is pushed, highlight or not |
| `ignore` | nick!user@host mask (`*` `?` wildcards) | Nothing from a matching sender is pushed |

Patterns: plain text matches case-insensitively as a **whole word** (bounded by start/end or
a non-letter/digit/underscore). A value wrapped in slashes, `/…/`, is a regular expression
(ECMAScript syntax, case-insensitive). Buffer names compare with the network's casemapping.

The user's current nick always counts as a highlight and is matched as a whole word.

## Decision order for each PRIVMSG / NOTICE / ACTION / INVITE

1. Sender matches an `ignore` mask: drop.
2. Buffer is `mute`d: drop.
3. Private message or INVITE to the user: push.
4. Buffer is `all`: push.
5. Channel line matches the nick or any `highlight`: push.
6. Otherwise: drop.

The existing timing rule (immediate when no client is present, otherwise delayed and dropped
if read) still applies after this.

## Commands

```
WEBPUSH RULES                      → BATCH +x solder.chat/webpush-rules
                                     @batch=x WEBPUSH RULE <kind> <value>   (one per rule)
                                     BATCH -x
WEBPUSH RULE ADD <kind> <value>    → WEBPUSH RULE ADD <kind> <value>
WEBPUSH RULE DEL <kind> <value>    → WEBPUSH RULE DEL <kind> <value>
WEBPUSH RULE CLEAR [<kind>]        → WEBPUSH RULE CLEAR [<kind>]
```

The value is the final parameter, so it may contain spaces (`WEBPUSH RULE ADD highlight :build failed`).
ADD of an existing rule and DEL of a missing one succeed silently. Servers SHOULD support
`labeled-response` on all of these.

Errors: `FAIL WEBPUSH INVALID_PARAMS RULE :<reason>` (unknown kind, empty value, bad regex),
`FAIL WEBPUSH LIMIT_EXCEEDED RULE :<reason>`. Suggested limits: 100 rules per scope, values up
to 200 bytes; regexes are compiled once and rejected if they fail to compile.

## Notes for the ZNC implementation (`modules/webpush.cpp`)

- Store under NV keys like `rule:<user>:<network>:<kind>:<value>` (network empty for account-wide).
- Mirror the commands for humans on `*webpush`: `rules`, `rule add <kind> <value>`, `rule del …`, `rule clear [kind]`.
- Replace the current substring nick test (`WildCmp("*nick*")`) with the whole-word match above.
- Push INVITEs to the user.
- Precompile regexes with `std::regex::ECMAScript | std::regex::icase` and cap input length.

## Solder side

- Solder syncs every rule per network, on that network's bound connection. Account-wide scope
  (unbound connection) is in the protocol for other clients and for hand-written rules.
- Settings › Highlights keywords sync as `highlight` rules on each network.
- Each buffer has a notification level: **Default**, **All messages** (`all`), **Mute** (`mute`).
- Settings › Notifications › Ignored senders sync as `ignore` rules on each network.
- On each connection where the cap is enabled, Solder fetches `WEBPUSH RULES`, adds what is
  missing and deletes only rules it added earlier (tracked locally), so rules added by hand on
  `*webpush` are left alone.
- The same rules drive Solder's own in-app notifications, so behaviour matches with or without push.
- Servers without the cap (soju today) get none of this: keywords and mutes apply in-app only.
