# Security

## Threat model (honest)

| Layer | Who sees what |
|-------|----------------|
| Network path | TLS terminator sees the WS tunnel ciphertext; without TLS, path observers see frames. |
| This broker | Per-connection state in process memory: room ids, display names, frame sizes, opaque payloads. No on-disk room log. If the app did not E2EE, payloads are plaintext to the process (and anyone with host access). |
| Random internet peer | **Cannot** list rooms in use. There is no room directory. Join requires already knowing a `room_id`. |
| Peer who knows `room_id` | Can JOIN (by design). Treat guessable ids like public lobbies. |

**Confidentiality is not provided by this server.** Availability and correct opaque fan-out are. App-level E2EE (e.g. a shared passphrase) keeps map/document bytes opaque to the broker; it does **not** hide that a given `room_id` is active from the host operator, or from anyone who already has the id.

## Reporting

Security reports: **apellusmagnus@gmail.com**  

Prefer private email over public issues for unfixed bugs. Coordinated disclosure preferred. BDFL-maintained — no merge path that bypasses the maintainer.

## Hardening already present

- Max frame size (`HERALD_BROKER_MAX_FRAME`).
- Max live connections (`HERALD_BROKER_MAX_CONNECTIONS`; default 8192; reject + close when full).
- Room table cap and peers-per-room cap.
- No disk persistence of room traffic; no room-list endpoint.
- Permessage-deflate uses one-shot inflate/deflate (`no_context_takeover`).

## Recommended ops

- Terminate TLS at a reverse proxy; do not expose plain `ws://` on the public internet.
- Prefer binding the process to localhost when a local proxy owns the public port.
- Keep `nofile` ≥ max connections (e.g. 65535) and leave `HERALD_BROKER_MAX_CONNECTIONS` set so accept floods shed before thread spawn fails.
- Optionally also rate-limit at the proxy or host firewall (this binary is still **one OS thread per connection**).
- Keep `HERALD_BROKER_VERBOSE=0` in production (stderr can include room ids / display names).
- Prefer app-level E2EE for private sessions; use long random room ids.
