# herald-broker

A small WebSocket **room relay**: accept clients, put them in rooms, fan out opaque binary frames. One `.c` file, zlib for optional permessage-deflate, pthread for concurrent connections (256 KiB stacks; recv buffers grow from 64 KiB up to `MAX_FRAME`). No accounts, no payload parsing, no history beyond one late-join catch-up buffer per room.

**Maintainer:** BDFL-style. Unsolicited PRs are not merged; see [SECURITY.md](SECURITY.md).

## What it does

- WebSocket server (RFC 6455); optional **permessage-deflate** (RFC 7692, `no_context_takeover` both ways).
- Rooms keyed by opaque `room_id` (capability join — knowing the id is enough to enter).
- Fan-out: `BROADCAST`, `DIRECT`, `PRESENCE`, join/leave. Application bytes stay opaque.
- **Non-blocking fan-out:** each connection has a dedicated writer thread and a bounded outbound FIFO. Producers (including room broadcast) only enqueue; they never block on another peer's socket. Broadcasts share one refcounted payload (PMD compressed at most once per message).
- **Slow-peer isolation:** if a peer's outbound queue exceeds the byte/message caps, or a single send hits the 15 s socket send timeout, that connection is kicked. Clients reconnect; app-layer CRDT resyncs via frontier ack (cheaper than silently dropping frames).
- In-memory only. Caps: rooms, peers/room, max frame size, outbound queue (env).

## What it does not do

- TLS (put a reverse proxy in front).
- Authentication beyond “you know the room id.”
- End-to-end encryption (app-layer if you need it).
- A directory of active rooms — there is no list/query API by design.
- Payload logging (verbose mode may log sizes, room ids, and display names to stderr only).
- Silent frame drops for a lagging peer (over-cap / send-timeout ⇒ disconnect that peer).

## Build

Needs a C99 compiler, POSIX threads, and zlib.

```bash
gcc -Wall -Wextra -std=c99 -O2 -DNDEBUG -o herald_broker herald_broker.c -lpthread -lz
```

Docker (build context = this directory):

```bash
docker build -t herald-broker .
docker run --rm -p 8787:8787 --ulimit nofile=65535:65535 \
  -e HERALD_BROKER_VERBOSE=0 herald-broker
# Process uid is 65532 (non-root).
```

### Env

| Variable | Default | Meaning |
|----------|---------|---------|
| `HERALD_BROKER_PORT` | `8787` | Listen port |
| `HERALD_BROKER_BIND` | `127.0.0.1` | Bind address (`0.0.0.0` for all interfaces) |
| `HERALD_BROKER_MAX_FRAME` | `1048576` (1 MiB) | Max WS payload (clamped at 4 MiB) |
| `HERALD_BROKER_MAX_CATCHUP` | `262144` (256 KiB) | Max `last_broadcast` stored per room; `0` = none |
| `HERALD_BROKER_MAX_CONNECTIONS` | `8192` | Live sockets before accept-shed; `0` = unlimited |
| `HERALD_BROKER_MAX_CONNS_PER_IP` | `0` (unlimited) | Max live sockets per TCP peer address; set `32` to restore the former hard cap |
| `HERALD_BROKER_MAX_QUEUE_BYTES` | `67108864` (64 MiB) | Per-connection outbound queue byte cap; `0` = unbounded bytes (message cap still applies). Floored to at least one max frame. |
| `HERALD_BROKER_MAX_QUEUE_MSGS` | `1024` | Per-connection outbound queue message cap; `0` = unbounded count (byte cap still applies) |
| `HERALD_BROKER_MAX_QUEUE_TOTAL` | `1073741824` (1 GiB) | Ceiling on bytes queued across **all** connections; when exceeded, the peer being enqueued to is kicked. `0` = no ceiling. Floored to `MAX_QUEUE_BYTES`. |
| `HERALD_BROKER_ORIGIN` | unset | If set, a present `Origin` header must match (comma-list) |
| `HERALD_BROKER_HOST` | unset | If set, `Host` header must match |
| `HERALD_BROKER_VERBOSE` | `0` | `1` = stderr metadata logs (includes kick reasons) |

Raise the process `nofile` limit to at least `MAX_CONNECTIONS` (container image tries `ulimit -n 65535`; pass `--ulimit nofile=65535:65535` when the platform hard-caps lower).

**Reverse-proxy / TLS terminator:** the broker sees every client as the proxy's source IP. The default per-IP cap is unlimited (`HERALD_BROKER_MAX_CONNS_PER_IP=0`); global `HERALD_BROKER_MAX_CONNECTIONS` still applies. To re-enable a strict per-IP limit in-process, set `HERALD_BROKER_MAX_CONNS_PER_IP=32` (or another value) — or rate-limit at the proxy.

**Queue sizing:** there is no back-pressure onto the sender — one peer's downlink never sets the room's pace — so a slow peer's queue must be able to hold whatever the app bursts at it. The 64 MiB default fits one fat CRDT baseline (a 10k-token Daggermap campaign is ~23 MiB) plus follow-up deltas, so a cold joiner on a ~1 Mbit/s link drains it over a few minutes instead of being kicked → rejoined → re-sent → kicked. Lower it on tiny hosts (`MAX_QUEUE_TOTAL` bounds the worst case regardless); raise it if fat-doc sessions kick healthy-but-briefly-buffered peers. Over-cap always disconnects that peer (never drops individual frames while leaving the socket up). Regression/load tests in the parent `C` repo:
- `python3 tools/herald_broker_slowpeer_test.py` — non-reading peer is kicked; fast peers stay at sender pace.
- `python3 tools/herald_broker_slowdrain_test.py` — slow-but-draining peer eventually gets every frame; **no kick**; fast peers unblocked.

## Wire protocol

Framing is documented at the top of `herald_broker.c` and in `wire.h`. Any client that speaks that binary schema works; this repo does not ship a full client stack. Wire schema is unchanged by the outbound-queue work — existing clients need no protocol update.

## License

MIT — see [LICENSE](LICENSE).
