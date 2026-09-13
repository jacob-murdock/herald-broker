# Security

## Threat model (honest)

| Layer | Who sees what |
|-------|----------------|
| Network path | TLS terminator sees the WS tunnel ciphertext; without TLS, path observers see frames. |
| This broker | Per-connection state in process memory: room ids, display names, frame sizes, opaque payloads, outbound queue depth. No on-disk room log. If the app did not E2EE, payloads are plaintext to the process (and anyone with host access). |
| Random internet peer | **Cannot** list rooms in use. There is no room directory. Join requires already knowing a `room_id`. |
| Peer who knows `room_id` | Can JOIN (by design). Treat guessable ids like public lobbies. |

**Confidentiality is not provided by this server.** Availability and correct opaque fan-out are. App-level E2EE (e.g. a shared passphrase) keeps map/document bytes opaque to the broker; it does **not** hide that a given `room_id` is active from the host operator, or from anyone who already has the id.

## Reporting

Security reports: **apellusmagnus@gmail.com**  

Prefer private email over public issues for unfixed bugs. Coordinated disclosure preferred. BDFL-maintained — no merge path that bypasses the maintainer.

## Hardening already present

- Max frame size (`HERALD_BROKER_MAX_FRAME`).
- Late-join catch-up cap (`HERALD_BROKER_MAX_CATCHUP`; default 256 KiB, independent of max frame).
- Max live connections (`HERALD_BROKER_MAX_CONNECTIONS`; default 8192; reject + close when full).
- Optional per-TCP-peer connection cap (`HERALD_BROKER_MAX_CONNS_PER_IP`; default 0 = unlimited). Older builds hard-capped at 32 per peer address; that breaks reverse-proxy deploys where every client shares the proxy's IP. Set `HERALD_BROKER_MAX_CONNS_PER_IP=32` to restore the old in-process limit on direct exposure, or enforce per-client limits at the TLS terminator / proxy instead.
- Per-connection **outbound queue** caps (`HERALD_BROKER_MAX_QUEUE_BYTES` / `HERALD_BROKER_MAX_QUEUE_MSGS`) plus a process-wide ceiling (`HERALD_BROKER_MAX_QUEUE_TOTAL`, default 1 GiB) so N colluding non-reading peers cannot pin unbounded memory. Fan-out never blocks on a slow socket; a peer that falls too far behind is disconnected (no silent per-frame drops). A send that makes no progress for the socket send timeout (`SO_SNDTIMEO`, 15 s) also kicks that peer — earlier builds retried `EAGAIN` forever there.
- Room table cap and peers-per-room cap.
- Room map tombstones: evicting a colliding room does not hide later probe-chain occupants (leave still unlinks `Conn *`).
- No disk persistence of room traffic; no room-list endpoint.
- Permessage-deflate uses one-shot inflate/deflate (`no_context_takeover`).
- Docker image runs as uid 65532 (`herald`), not root.

## Recommended ops

- Terminate TLS at a reverse proxy; do not expose plain `ws://` on the public internet.
- Prefer binding the process to localhost when a local proxy owns the public port.
- Keep `nofile` ≥ max connections (e.g. 65535) and leave `HERALD_BROKER_MAX_CONNECTIONS` set so accept floods shed before thread spawn fails.
- Rate-limit or cap connections at the reverse proxy when TLS terminates there (recommended for public exposure). The broker's global `HERALD_BROKER_MAX_CONNECTIONS` still sheds accept floods; per-IP is opt-in via `HERALD_BROKER_MAX_CONNS_PER_IP`.
- Threading: **reader + writer per connection** (plus the accept loop). Budget ~2× `MAX_CONNECTIONS` threads / stacks when sizing hosts.
- Keep `HERALD_BROKER_VERBOSE=0` in production (stderr can include room ids / display names / kick reasons).
- Prefer app-level E2EE for private sessions; use long random room ids.
- After a kick, clients are expected to reconnect; do not treat disconnect-under-load as a broker bug if the peer was the lagging one.
