# herald-broker

A small WebSocket **room relay**: accept clients, put them in rooms, fan out opaque binary frames. One `.c` file, zlib for optional permessage-deflate, pthread for concurrent connections (256 KiB stacks; recv buffers grow from 64 KiB up to `MAX_FRAME`). No accounts, no payload parsing, no history beyond one late-join catch-up buffer per room.

**Maintainer:** BDFL-style. Unsolicited PRs are not merged; see [SECURITY.md](SECURITY.md).

## What it does

- WebSocket server (RFC 6455); optional **permessage-deflate** (RFC 7692, `no_context_takeover` both ways).
- Rooms keyed by opaque `room_id` (capability join — knowing the id is enough to enter).
- Fan-out: `BROADCAST`, `DIRECT`, `PRESENCE`, join/leave. Application bytes stay opaque.
- In-memory only. Caps: rooms, peers/room, max frame size (env).

## What it does not do

- TLS (put a reverse proxy in front).
- Authentication beyond “you know the room id.”
- End-to-end encryption (app-layer if you need it).
- A directory of active rooms — there is no list/query API by design.
- Payload logging (verbose mode may log sizes, room ids, and display names to stderr only).

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
```

### Env

| Variable | Default | Meaning |
|----------|---------|---------|
| `HERALD_BROKER_PORT` | `8787` | Listen port |
| `HERALD_BROKER_MAX_FRAME` | `1048576` (1 MiB) | Max WS payload |
| `HERALD_BROKER_MAX_CONNECTIONS` | `8192` | Live sockets before accept-shed; `0` = unlimited |
| `HERALD_BROKER_VERBOSE` | `0` | `1` = stderr metadata logs |

Raise the process `nofile` limit to at least `MAX_CONNECTIONS` (container image tries `ulimit -n 65535`; pass `--ulimit nofile=65535:65535` when the platform hard-caps lower).

## Wire protocol

Framing is documented at the top of `herald_broker.c` and in `wire.h`. Any client that speaks that binary schema works; this repo does not ship a full client stack.

## License

MIT — see [LICENSE](LICENSE).
