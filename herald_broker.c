/*
 * Herald Room Broker
 *
 * Out-of-tree room broker for the relay path. Data-blind: routes opaque
 * binary frames between clients in the same room; never parses egregore
 * payloads. POSIX sockets or Winsock + libpthread.
 *
 * Wire (herald_room.h v1; JOIN peer_id tail is ignored — broker assigns):
 *   JOIN_ROOM  0x01  [u16 LE room_id_len, room_id, u16 LE name_len, name, u64 LE peer_id]
 *   LEAVE_ROOM 0x02
 *   JOIN_ACK   0x03  [u64 LE assigned_peer_id]  (broker → joiner)
 *   BROADCAST  0x10  [opaque payload from client; broker fans out as
 *                     0x10 + u64 LE sender_peer_id + payload]
 *   DIRECT     0x11  [u64 LE dst_peer_id, opaque payload from client;
 *                     broker delivers 0x11 + u64 LE sender_peer_id + payload]
 *   SIGNAL     0x12  [u64 LE dst_peer_id, opaque]; same rewrite as DIRECT;
 *                     excluded from last_broadcast
 *   PRESENCE   0x20  [u8 kind (0=join, 1=leave), u64 LE peer_id, u16 LE name_len, name]
 *   ERROR      0x30  [u8 code, u16 LE msg_len, msg…]  (broker → client; reject JOIN)
 *
 * Behavior:
 *   JOIN_ROOM   — assign a unique peer id, JOIN_ACK the joiner, broadcast
 *                 PRESENCE_JOIN to others, send cached last BROADCAST
 *                 (late-join catch-up). On peer/room-table cap: ERROR then close.
 *   LEAVE_ROOM  — remove, broadcast PRESENCE_LEAVE to survivors.
 *   BROADCAST   — forward to all other peers, cache bytes for late joiners
 *                 (not HCAN / SIGNAL).
 *   DIRECT      — route to dst peer_id (must be in the same room).
 *   SIGNAL      — DIRECT-shaped; never cached.
 *   Disconnect  — same as LEAVE_ROOM.
 *
 * Env:
 *   HERALD_BROKER_PORT             (default 8787)
 *   HERALD_BROKER_BIND             (default 127.0.0.1; 0.0.0.0 for all)
 *   HERALD_BROKER_MAX_FRAME        (default 1 MiB; clamped to 4 MiB)
 *   HERALD_BROKER_MAX_CATCHUP      (default 256 KiB; 0 = no last_broadcast)
 *   HERALD_BROKER_MAX_CONNECTIONS  (default 8192; 0 = unlimited)
 *   HERALD_BROKER_ORIGIN           (optional comma-list; if set, a present
 *                                   Origin header must match one entry)
 *   HERALD_BROKER_HOST             (optional; if set, Host header must match)
 *   HERALD_BROKER_VERBOSE          (default 0; set 1 for log lines)
 *
 * WebSocket permessage-deflate (RFC 7692):
 *   Negotiated when the client offers Sec-WebSocket-Extensions:
 *   permessage-deflate. Acceptance always forces
 *   client_no_context_takeover + server_no_context_takeover (one-shot
 *   zlib, no sliding-window state). RSV1 marks compressed data messages.
 *   Application payloads in last_broadcast / fan-out stay plaintext;
 *   each egress path re-compresses only when that peer negotiated PMD.
 *   Platforms whose WS stacks never offer the extension (libcurl,
 *   WinHTTP) keep uncompressed frames and still interoperate.
 *
 * Out-of-tree, in-memory only. Wire constants: wire.h (this directory).
 * Production: terminate TLS at a reverse proxy (Caddy/nginx) and proxy
 * to this process on loopback; see README.md / SECURITY.md.
 */

/* Wire action codes only — no herald client / amphora dependency. */
#include "wire.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET BrokerSock;
#define BROKER_INVALID_SOCK INVALID_SOCKET
#define broker_close closesocket
#define BROKER_SEND_FLAGS 0
#define BROKER_EINTR WSAEINTR
#define BROKER_EAGAIN WSAEWOULDBLOCK
static int broker_sock_err(void) { return WSAGetLastError(); }
static int broker_setsockopt_int(BrokerSock fd, int level, int opt, int value) {
    return setsockopt(fd, level, opt, (const char *)&value, sizeof(value));
}
static int broker_send(BrokerSock fd, const void *data, size_t len, int flags) {
    return send(fd, (const char *)data, (int)len, flags);
}
static int broker_recv(BrokerSock fd, void *buf, size_t len, int flags) {
    return recv(fd, (char *)buf, (int)len, flags);
}
static int broker_net_init(void) {
    static int once = 0;
    static int ok = 0;
    if (!once) {
        WSADATA wsa;
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        once = 1;
    }
    return ok;
}
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int BrokerSock;
#define BROKER_INVALID_SOCK (-1)
#define broker_close close
#define BROKER_SEND_FLAGS MSG_NOSIGNAL
#define BROKER_EINTR EINTR
#define BROKER_EAGAIN EAGAIN
static int broker_sock_err(void) { return errno; }
static int broker_setsockopt_int(BrokerSock fd, int level, int opt, int value) {
    return setsockopt(fd, level, opt, &value, sizeof(value));
}
static int broker_send(BrokerSock fd, const void *data, size_t len, int flags) {
    return (int)send(fd, data, len, flags);
}
static int broker_recv(BrokerSock fd, void *buf, size_t len, int flags) {
    return (int)recv(fd, buf, len, flags);
}
static int broker_net_init(void) { return 1; }
#endif

/* -- Config ------------------------------------------------------------ */

#define HERALD_BROKER_DEFAULT_PORT 8787
#define HERALD_BROKER_DEFAULT_MAX_FRAME (1u * 1024u * 1024u)
#define HERALD_BROKER_MAX_FRAME_CEILING (4u * 1024u * 1024u)
/* Late-join catch-up is independent of max_frame so 4096 rooms cannot pin GiBs. */
#define HERALD_BROKER_DEFAULT_MAX_CATCHUP (256u * 1024u)
#define HERALD_BROKER_DEFAULT_MAX_CONNS 8192
#define HERALD_BROKER_MAX_CONNS_PER_IP 32
#define HERALD_BROKER_IP_SLOTS 1024
#define HERALD_BROKER_HANDSHAKE_TIMEOUT_MS 5000
#define HERALD_BROKER_IDLE_TIMEOUT_MS 120000
#define HERALD_BROKER_SEND_TIMEOUT_MS 15000
#define HERALD_BROKER_MAX_ROOMS 4096
#define HERALD_BROKER_MAX_PEERS_PER_ROOM 16
#define HERALD_BROKER_MAX_ROOM_ID 128
#define HERALD_BROKER_MAX_NAME 64
#define HERALD_BROKER_WS_RECV_BUF (16u * 1024u)
/* Per-conn recv buffer starts small and grows up to max_frame. */
#define HERALD_BROKER_RECV_INITIAL (64u * 1024u)
/* Thread-per-conn: little stack use (heap holds frames). */
#define HERALD_BROKER_THREAD_STACK (256u * 1024u)
/* Skip PMD when the payload is tiny or compression does not shrink it. */
#define HERALD_BROKER_PMD_MIN_BYTES 64
#define HERALD_BROKER_PMD_TRAILER_LEN 4

/* -- Tiny helpers ------------------------------------------------------ */

static int g_verbose = 0;
static int g_max_conns = HERALD_BROKER_DEFAULT_MAX_CONNS; /* 0 = unlimited */
static size_t g_max_catchup = HERALD_BROKER_DEFAULT_MAX_CATCHUP; /* 0 = disable */
static int g_live_conns = 0;
static pthread_mutex_t g_conn_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_origin_allow[512];
static char g_host_allow[256];

typedef struct {
    uint32_t addr;
    int n;
} IpCount;
static IpCount g_ip_counts[HERALD_BROKER_IP_SLOTS];

static int broker_set_sock_timeouts(BrokerSock fd, int recv_ms, int send_ms) {
#if defined(_WIN32)
    DWORD r = (DWORD)recv_ms;
    DWORD s = (DWORD)send_ms;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&r, sizeof(r)) != 0)
        return 0;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&s, sizeof(s)) != 0)
        return 0;
    return 1;
#else
    struct timeval rtv, stv;
    rtv.tv_sec = recv_ms / 1000;
    rtv.tv_usec = (recv_ms % 1000) * 1000;
    stv.tv_sec = send_ms / 1000;
    stv.tv_usec = (send_ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv)) != 0)
        return 0;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv)) != 0)
        return 0;
    return 1;
#endif
}

static int ip_try_admit(uint32_t addr) {
    pthread_mutex_lock(&g_conn_mu);
    int free_slot = -1;
    for (int i = 0; i < HERALD_BROKER_IP_SLOTS; ++i) {
        if (g_ip_counts[i].addr == addr && g_ip_counts[i].n > 0) {
            if (g_ip_counts[i].n >= HERALD_BROKER_MAX_CONNS_PER_IP) {
                pthread_mutex_unlock(&g_conn_mu);
                return 0;
            }
            g_ip_counts[i].n++;
            pthread_mutex_unlock(&g_conn_mu);
            return 1;
        }
        if (free_slot < 0 && g_ip_counts[i].n == 0)
            free_slot = i;
    }
    if (free_slot < 0) {
        pthread_mutex_unlock(&g_conn_mu);
        return 0;
    }
    g_ip_counts[free_slot].addr = addr;
    g_ip_counts[free_slot].n = 1;
    pthread_mutex_unlock(&g_conn_mu);
    return 1;
}

static void ip_release(uint32_t addr) {
    pthread_mutex_lock(&g_conn_mu);
    for (int i = 0; i < HERALD_BROKER_IP_SLOTS; ++i) {
        if (g_ip_counts[i].addr == addr && g_ip_counts[i].n > 0) {
            g_ip_counts[i].n--;
            if (g_ip_counts[i].n == 0)
                g_ip_counts[i].addr = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_conn_mu);
}

static int header_list_contains(const char *list, const char *value) {
    if (!list || !list[0] || !value || !value[0])
        return 0;
    const char *p = list;
    size_t vlen = strlen(value);
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',')
            ++p;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ',')
            ++p;
        size_t n = (size_t)(p - start);
        while (n > 0 && (start[n - 1] == ' ' || start[n - 1] == '\t'))
            --n;
        if (n == vlen && strncasecmp(start, value, n) == 0)
            return 1;
    }
    return 0;
}

/* Grow *buf to at least need bytes, capped at max_frame. */
static int ensure_recv_cap(uint8_t **buf, size_t *cap, size_t need, size_t max_frame) {
    if (need > max_frame)
        return 0;
    if (*cap >= need)
        return 1;
    size_t ncap = *cap ? *cap : HERALD_BROKER_RECV_INITIAL;
    while (ncap < need) {
        if (ncap >= max_frame / 2) {
            ncap = max_frame;
            break;
        }
        ncap *= 2;
    }
    if (ncap > max_frame)
        ncap = max_frame;
    if (ncap < need)
        return 0;
    uint8_t *p = (uint8_t *)realloc(*buf, ncap);
    if (!p)
        return 0;
    *buf = p;
    *cap = ncap;
    return 1;
}

static void conn_count_dec(void) {
    pthread_mutex_lock(&g_conn_mu);
    if (g_live_conns > 0)
        g_live_conns--;
    pthread_mutex_unlock(&g_conn_mu);
}

/* 1 if under cap (and counted); 0 if at cap — caller should close fd. */
static int conn_try_admit(void) {
    pthread_mutex_lock(&g_conn_mu);
    if (g_max_conns > 0 && g_live_conns >= g_max_conns) {
        pthread_mutex_unlock(&g_conn_mu);
        return 0;
    }
    g_live_conns++;
    pthread_mutex_unlock(&g_conn_mu);
    return 1;
}

/* glibc extension: case-insensitive substring search. The broker's
 * small surface means we don't need a tuned implementation. */
static const char *broker_strcasestr(const char *hay, const char *needle) {
    if (!hay || !needle)
        return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0)
        return hay;
    for (; *hay; ++hay) {
        size_t i = 0;
        for (; i < nlen; ++i) {
            unsigned char a = (unsigned char)hay[i];
            unsigned char b = (unsigned char)needle[i];
            if (a >= 'A' && a <= 'Z')
                a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z')
                b = (unsigned char)(b - 'A' + 'a');
            if (a != b)
                break;
        }
        if (i == nlen)
            return hay;
    }
    return NULL;
}

static void broker_log(const char *fmt, ...) {
    if (!g_verbose)
        return;
    va_list ap;
    va_start(ap, fmt);
    fputs("[broker] ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* Bounded C-string copy; always NUL-terminates when dst_cap > 0. */
static void broker_copy_cstr(char *dst, size_t dst_cap, const char *src) {
    if (!dst || dst_cap == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= dst_cap)
        n = dst_cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static uint16_t rd_u16_le(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }

static uint16_t rd_u16_be(const uint8_t *p) { return ((uint16_t)p[0] << 8) | (uint16_t)p[1]; }

static uint64_t rd_u64_le(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint64_t rd_u64_be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void wr_u16_le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wr_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr_u64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = (uint8_t)(v >> (i * 8));
}

static void wr_u64_be(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = (uint8_t)(v >> ((7 - i) * 8));
}

/* Send all bytes; return 1 on success, 0 on error/disconnect. */
static int send_all(BrokerSock fd, const uint8_t *data, size_t len) {
    while (len > 0) {
        int n = broker_send(fd, data, len, BROKER_SEND_FLAGS);
        if (n <= 0) {
            int err = broker_sock_err();
            if (n < 0 && (err == BROKER_EINTR || err == BROKER_EAGAIN))
                continue;
            return 0;
        }
        data += (size_t)n;
        len -= (size_t)n;
    }
    return 1;
}

/* -- WebSocket send (server -> client, unmasked binary) ---------------- */

/* Build a single-frame binary message. We pre-encode a header up to
 * 14 bytes (opcode + 1B or 8B length) into `hdr_out` and return the
 * header length; caller then send_all's hdr + payload.
 * rsv1=1 sets RSV1 (permessage-deflate compressed payload). */
static size_t ws_encode_binary_header(uint8_t *hdr_out, size_t payload_len, int rsv1) {
    /* FIN + optional RSV1 + binary opcode = 0x82 / 0xC2 */
    hdr_out[0] = (uint8_t)(0x82u | (rsv1 ? 0x40u : 0u));
    size_t h = 1;
    if (payload_len <= 125) {
        hdr_out[1] = (uint8_t)payload_len; /* server->client: no mask */
        h = 2;
    } else if (payload_len <= 0xFFFFu) {
        hdr_out[1] = 126;
        wr_u16_be(hdr_out + 2, (uint16_t)payload_len);
        h = 4;
    } else {
        hdr_out[1] = 127;
        wr_u64_be(hdr_out + 2, (uint64_t)payload_len);
        h = 10;
    }
    return h;
}

static int ws_send_binary_raw(BrokerSock fd, const uint8_t *payload, size_t len, int rsv1) {
    uint8_t hdr[14];
    size_t h = ws_encode_binary_header(hdr, len, rsv1);
    if (send_all(fd, hdr, h) != 1)
        return 0;
    if (len > 0 && send_all(fd, payload, len) != 1)
        return 0;
    return 1;
}

/* RFC 7692 §7.2.1: raw DEFLATE + strip trailing 0x00 0x00 0xff 0xff.
 * Returns malloc'd buffer; caller frees. NULL = skip compression. */
static uint8_t *ws_pmd_deflate(const uint8_t *plain, size_t plain_len, size_t *out_len) {
    if (!plain || !out_len || plain_len < HERALD_BROKER_PMD_MIN_BYTES)
        return NULL;
    *out_len = 0;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;

    /* Bound + a little headroom for the sync-flush trailer we strip. */
    uLong bound = deflateBound(&strm, (uLong)plain_len) + 16;
    uint8_t *comp = (uint8_t *)malloc((size_t)bound);
    if (!comp) {
        deflateEnd(&strm);
        return NULL;
    }

    strm.next_in = (Bytef *)plain;
    strm.avail_in = (uInt)plain_len;
    strm.next_out = comp;
    strm.avail_out = (uInt)bound;
    int rc = deflate(&strm, Z_SYNC_FLUSH);
    size_t n = (size_t)strm.total_out;
    deflateEnd(&strm);
    if (rc != Z_OK && rc != Z_BUF_ERROR) {
        free(comp);
        return NULL;
    }
    if (n < HERALD_BROKER_PMD_TRAILER_LEN) {
        free(comp);
        return NULL;
    }
    /* Trailer must be the empty stored block sync bytes. */
    if (comp[n - 4] != 0x00 || comp[n - 3] != 0x00 || comp[n - 2] != 0xff ||
        comp[n - 1] != 0xff) {
        free(comp);
        return NULL;
    }
    n -= HERALD_BROKER_PMD_TRAILER_LEN;
    if (n == 0 || n >= plain_len) {
        free(comp);
        return NULL;
    }
    *out_len = n;
    return comp;
}

/* RFC 7692 §7.2.2: append 0x00 0x00 0xff 0xff then raw inflate.
 * Returns malloc'd plain; caller frees. NULL on error. */
static uint8_t *ws_pmd_inflate(const uint8_t *comp, size_t comp_len, size_t max_plain,
                               size_t *out_len) {
    if (!comp || !out_len || max_plain == 0)
        return NULL;
    *out_len = 0;

    uint8_t *in = (uint8_t *)malloc(comp_len + HERALD_BROKER_PMD_TRAILER_LEN);
    if (!in)
        return NULL;
    if (comp_len > 0)
        memcpy(in, comp, comp_len);
    in[comp_len + 0] = 0x00;
    in[comp_len + 1] = 0x00;
    in[comp_len + 2] = 0xff;
    in[comp_len + 3] = 0xff;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
        free(in);
        return NULL;
    }

    uint8_t *plain = (uint8_t *)malloc(max_plain);
    if (!plain) {
        inflateEnd(&strm);
        free(in);
        return NULL;
    }

    strm.next_in = in;
    strm.avail_in = (uInt)(comp_len + HERALD_BROKER_PMD_TRAILER_LEN);
    strm.next_out = plain;
    strm.avail_out = (uInt)max_plain;
    /* Z_SYNC_FLUSH matches the empty stored-block trailer; Z_FINISH rejects
     * some compressors' sync-flush output as an incomplete stream. */
    int rc = inflate(&strm, Z_SYNC_FLUSH);
    size_t n = (size_t)strm.total_out;
    uInt left = strm.avail_in;
    inflateEnd(&strm);
    free(in);
    if ((rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) || left != 0) {
        free(plain);
        return NULL;
    }
    *out_len = n;
    return plain;
}

/* -- WebSocket recv (client -> server, masked) ------------------------- */

typedef struct {
    int fin;
    int rsv1;
    int opcode;
    int masked;
    uint64_t len;
} WsFrameHdr;

static int ws_read_exact(BrokerSock fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = broker_recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            if (n < 0 && broker_sock_err() == BROKER_EINTR)
                continue;
            return 0;
        }
        got += (size_t)n;
    }
    return 1;
}

static int ws_read_frame_header(BrokerSock fd, WsFrameHdr *out, size_t max_payload) {
    uint8_t b[2];
    if (!ws_read_exact(fd, b, 2))
        return 0;
    out->fin = (b[0] & 0x80) != 0;
    out->rsv1 = (b[0] & 0x40) != 0;
    /* RSV2/RSV3 must be 0 without other extensions. */
    if (b[0] & 0x30)
        return 0;
    out->opcode = b[0] & 0x0F;
    out->masked = (b[1] & 0x80) != 0;
    uint64_t len7 = b[1] & 0x7F;
    if (len7 == 126) {
        uint8_t ext[2];
        if (!ws_read_exact(fd, ext, 2))
            return 0;
        out->len = rd_u16_be(ext);
    } else if (len7 == 127) {
        uint8_t ext[8];
        if (!ws_read_exact(fd, ext, 8))
            return 0;
        out->len = rd_u64_be(ext);
    } else {
        out->len = len7;
    }
    if (out->len > max_payload)
        return 0;
    /* RFC 6455 §5.5: control frames MUST be ≤125 bytes and MUST NOT be fragmented. */
    if ((out->opcode == 0x08 || out->opcode == 0x09 || out->opcode == 0x0A) &&
        (!out->fin || out->len > 125))
        return 0;
    return 1;
}

static int ws_read_frame_payload(BrokerSock fd, uint64_t len, int masked, uint8_t *out_buf) {
    uint8_t mask[4] = {0};
    if (masked) {
        if (!ws_read_exact(fd, mask, 4))
            return 0;
    }
    if (len == 0)
        return 1;
    if (!ws_read_exact(fd, out_buf, (size_t)len))
        return 0;
    if (masked) {
        for (uint64_t i = 0; i < len; ++i)
            out_buf[i] ^= mask[i & 3];
    }
    return 1;
}

/* -- WebSocket handshake (RFC 6455 Sec-WebSocket-Accept) -------------- */

static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static size_t b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!in || !out || out_cap == 0)
        return 0;
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t n = (uint32_t)in[i] << 16;
        if (i + 1 < in_len)
            n |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len)
            n |= (uint32_t)in[i + 2];
        if (o + 4 >= out_cap)
            return 0;
        out[o++] = tbl[(n >> 18) & 63];
        out[o++] = tbl[(n >> 12) & 63];
        out[o++] = (i + 1 < in_len) ? tbl[(n >> 6) & 63] : '=';
        out[o++] = (i + 2 < in_len) ? tbl[n & 63] : '=';
    }
    if (o >= out_cap)
        return 0;
    out[o] = '\0';
    return o;
}

typedef struct {
    uint32_t h[5];
    uint64_t len_bits;
    uint8_t buf[64];
    size_t buf_len;
} Sha1Ctx;

static uint32_t sha1_rol(uint32_t v, int bits) { return (v << bits) | (v >> (32 - bits)); }

static void sha1_init(Sha1Ctx *c) {
    c->h[0] = 0x67452301u;
    c->h[1] = 0xEFCDAB89u;
    c->h[2] = 0x98BADCFEu;
    c->h[3] = 0x10325476u;
    c->h[4] = 0xC3D2E1F0u;
    c->len_bits = 0;
    c->buf_len = 0;
}

static void sha1_block(Sha1Ctx *c, const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    for (int i = 16; i < 80; ++i)
        w[i] = sha1_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = c->h[0], b = c->h[1], c2 = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c2) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c2 ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c2) | (b & d) | (c2 & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c2 ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t temp = sha1_rol(a, 5) + f + e + k + w[i];
        e = d;
        d = c2;
        c2 = sha1_rol(b, 30);
        b = a;
        a = temp;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += c2;
    c->h[3] += d;
    c->h[4] += e;
}

static void sha1_update(Sha1Ctx *c, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        c->buf[c->buf_len++] = data[i];
        if (c->buf_len == 64) {
            sha1_block(c, c->buf);
            c->len_bits += 512;
            c->buf_len = 0;
        }
    }
}

static void sha1_final(Sha1Ctx *c, uint8_t out[20]) {
    c->len_bits += (uint64_t)c->buf_len * 8u;
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > 56) {
        while (c->buf_len < 64)
            c->buf[c->buf_len++] = 0;
        sha1_block(c, c->buf);
        c->buf_len = 0;
    }
    while (c->buf_len < 56)
        c->buf[c->buf_len++] = 0;
    for (int i = 7; i >= 0; --i)
        c->buf[56 + (7 - i)] = (uint8_t)((c->len_bits >> (i * 8)) & 0xFFu);
    sha1_block(c, c->buf);
    for (int i = 0; i < 5; ++i) {
        out[i * 4 + 0] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

static void sha1_hash(const uint8_t *data, size_t len, uint8_t out[20]) {
    Sha1Ctx c;
    sha1_init(&c);
    sha1_update(&c, data, len);
    sha1_final(&c, out);
}

static void trim_ws_key(char *key) {
    if (!key)
        return;
    size_t n = strlen(key);
    while (n > 0 &&
           (key[n - 1] == ' ' || key[n - 1] == '\t' || key[n - 1] == '\r' || key[n - 1] == '\n')) {
        key[--n] = '\0';
    }
}

static int ws_compute_accept(const char *client_key_b64, char *out, size_t out_cap) {
    /* RFC 6455 §1.3: SHA1( ASCII(Sec-WebSocket-Key) || GUID ), then base64.
     * Do not decode the key — hash the base64 text itself. */
    if (!client_key_b64 || !client_key_b64[0])
        return 0;
    size_t key_len = strlen(client_key_b64);
    size_t guid_len = sizeof(WS_GUID) - 1;
    uint8_t *msg = (uint8_t *)malloc(key_len + guid_len);
    if (!msg)
        return 0;
    memcpy(msg, client_key_b64, key_len);
    memcpy(msg + key_len, WS_GUID, guid_len);
    uint8_t digest[20];
    sha1_hash(msg, key_len + guid_len, digest);
    free(msg);
    return b64_encode(digest, sizeof(digest), out, out_cap) > 0;
}

/* -- HTTP / WebSocket handshake ---------------------------------------- */

/* True if Sec-WebSocket-Extensions offers permessage-deflate. */
static int ws_extensions_offers_pmd(const char *ext) {
    if (!ext || !*ext)
        return 0;
    /* Tokenize on commas; each offer may have ;parameters. */
    const char *p = ext;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',')
            ++p;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ',' && *p != ';')
            ++p;
        size_t n = (size_t)(p - start);
        while (n > 0 && (start[n - 1] == ' ' || start[n - 1] == '\t'))
            --n;
        if (n == strlen("permessage-deflate") &&
            strncasecmp(start, "permessage-deflate", n) == 0)
            return 1;
        while (*p && *p != ',')
            ++p;
    }
    return 0;
}

/* Handshake result: 0 = fail, 1 = ok without PMD, 2 = ok with PMD. */
static int ws_handshake_server(BrokerSock fd) {
    char buf[2048];
    size_t total = 0;
    /* Read until \r\n\r\n (header terminator). Cap at 2 KiB. */
    while (total < sizeof(buf) - 1) {
        int n = broker_recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0)
            return 0;
        total += (size_t)n;
        buf[total] = '\0';
        if (strstr(buf, "\r\n\r\n"))
            break;
    }
    /* Token-by-token header walk. We require Upgrade: websocket and a
     * Sec-WebSocket-Key, then answer with a spec-compliant Accept. */
    int has_upgrade = 0, has_key = 0, has_version13 = 0, has_connection = 0, want_pmd = 0;
    char key[64] = {0};
    char origin[256] = {0};
    char host[256] = {0};
    char *p = buf;
    /* Skip the request line. Require GET. */
    char *eol = strstr(p, "\r\n");
    if (!eol)
        return 0;
    *eol = '\0';
    if (strncasecmp(p, "GET ", 4) != 0)
        return 0;
    p = eol + 2;
    while (p && *p && !(p[0] == '\r' && p[1] == '\n')) {
        char *next = strstr(p, "\r\n");
        if (!next)
            break;
        *next = '\0';
        char *colon = strchr(p, ':');
        if (colon) {
            *colon = '\0';
            char *v = colon + 1;
            while (*v == ' ' || *v == '\t')
                ++v;
            if (strcasecmp(p, "Upgrade") == 0 && broker_strcasestr(v, "websocket"))
                has_upgrade = 1;
            else if (strcasecmp(p, "Connection") == 0 && broker_strcasestr(v, "Upgrade"))
                has_connection = 1;
            else if (strcasecmp(p, "Sec-WebSocket-Key") == 0) {
                broker_copy_cstr(key, sizeof(key), v);
                has_key = 1;
            } else if (strcasecmp(p, "Sec-WebSocket-Version") == 0) {
                if (atoi(v) == 13)
                    has_version13 = 1;
            } else if (strcasecmp(p, "Sec-WebSocket-Extensions") == 0) {
                if (ws_extensions_offers_pmd(v))
                    want_pmd = 1;
            } else if (strcasecmp(p, "Origin") == 0) {
                broker_copy_cstr(origin, sizeof(origin), v);
            } else if (strcasecmp(p, "Host") == 0) {
                broker_copy_cstr(host, sizeof(host), v);
            }
        }
        p = next + 2;
    }
    if (!has_upgrade || !has_key || !has_version13 || !has_connection)
        return 0;
    if (g_origin_allow[0] && origin[0] && !header_list_contains(g_origin_allow, origin))
        return 0;
    if (g_host_allow[0] && (!host[0] || !header_list_contains(g_host_allow, host)))
        return 0;
    trim_ws_key(key);
    char accept[64];
    if (!ws_compute_accept(key, accept, sizeof(accept)))
        return 0;
    char resp[512];
    int n;
    if (want_pmd) {
        /* Force no_context_takeover both ways — one-shot zlib, no
         * per-connection inflate/deflate dictionary to retain. */
        n = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 101 Switching Protocols\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n"
                     "Sec-WebSocket-Extensions: permessage-deflate; "
                     "client_no_context_takeover; server_no_context_takeover\r\n"
                     "\r\n",
                     accept);
    } else {
        n = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 101 Switching Protocols\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n"
                     "\r\n",
                     accept);
    }
    if (n <= 0 || (size_t)n >= sizeof(resp))
        return 0;
    if (!send_all(fd, (const uint8_t *)resp, (size_t)n))
        return 0;
    return want_pmd ? 2 : 1;
}

/* -- Rooms map --------------------------------------------------------- */

typedef struct Conn Conn;

/* Open-addressed, linear probe. EMPTY stops a probe; TOMB does not.
 * Evicting into EMPTY punches a hole: leave/disconnect never unlinks
 * remaining Conn*, and a later JOIN/BROADCAST walks freed memory. */
#define ROOM_SLOT_EMPTY 0
#define ROOM_SLOT_LIVE 1
#define ROOM_SLOT_TOMB 2

typedef struct Room {
    char id[HERALD_BROKER_MAX_ROOM_ID];
    Conn *peers[HERALD_BROKER_MAX_PEERS_PER_ROOM];
    int peer_count;
    uint8_t *last_broadcast;
    size_t last_broadcast_len;
    uint8_t slot; /* ROOM_SLOT_EMPTY / LIVE / TOMB */
} Room;

static Room g_rooms[HERALD_BROKER_MAX_ROOMS];
static int g_room_count;
static uint64_t g_next_peer_id = 1;
static pthread_mutex_t g_rooms_mu = PTHREAD_MUTEX_INITIALIZER;

static uint32_t room_hash(const char *id) {
    /* FNV-1a 32-bit. Plenty for 4 KiB map; collisions fall through to
     * linear probe. */
    uint32_t h = 2166136261u;
    for (const uint8_t *p = (const uint8_t *)id; *p; ++p) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

static void room_assert_reusable(const Room *r) {
    if (r->peer_count == 0 && r->last_broadcast == NULL)
        return;
    fprintf(stderr, "[broker] room slot reuse with peer_count=%d last_broadcast=%p\n",
            r->peer_count, (void *)r->last_broadcast);
    abort();
}

static Room *room_occupy_slot_locked(Room *dst, const char *id) {
    room_assert_reusable(dst);
    memset(dst->peers, 0, sizeof(dst->peers));
    broker_copy_cstr(dst->id, sizeof(dst->id), id);
    dst->peer_count = 0;
    dst->last_broadcast = NULL;
    dst->last_broadcast_len = 0;
    dst->slot = ROOM_SLOT_LIVE;
    g_room_count++;
    return dst;
}

static Room *room_find_locked(const char *id) {
    uint32_t h = room_hash(id);
    for (uint32_t i = 0; i < HERALD_BROKER_MAX_ROOMS; ++i) {
        uint32_t idx = (h + i) % HERALD_BROKER_MAX_ROOMS;
        uint8_t slot = g_rooms[idx].slot;
        if (slot == ROOM_SLOT_EMPTY)
            return NULL;
        if (slot == ROOM_SLOT_TOMB)
            continue;
        if (strcmp(g_rooms[idx].id, id) == 0)
            return &g_rooms[idx];
    }
    return NULL;
}

static Room *room_get_or_create_locked(const char *id) {
    uint32_t h = room_hash(id);
    Room *tomb = NULL;
    for (uint32_t i = 0; i < HERALD_BROKER_MAX_ROOMS; ++i) {
        uint32_t idx = (h + i) % HERALD_BROKER_MAX_ROOMS;
        Room *s = &g_rooms[idx];
        if (s->slot == ROOM_SLOT_EMPTY)
            return room_occupy_slot_locked(tomb ? tomb : s, id);
        if (s->slot == ROOM_SLOT_TOMB) {
            if (!tomb)
                tomb = s;
            continue;
        }
        if (strcmp(s->id, id) == 0)
            return s;
    }
    /* No EMPTY in the table; reuse a tombstone if the probe hit one. */
    if (tomb)
        return room_occupy_slot_locked(tomb, id);
    return NULL; /* full of live rooms */
}

static void room_evict_if_empty_locked(Room *r) {
    if (r->peer_count != 0)
        return;
    if (r->last_broadcast) {
        free(r->last_broadcast);
        r->last_broadcast = NULL;
        r->last_broadcast_len = 0;
    }
    memset(r->peers, 0, sizeof(r->peers));
    r->id[0] = '\0';
    r->slot = ROOM_SLOT_TOMB;
    g_room_count--;
}

/* -- Connection -------------------------------------------------------- */

struct Conn {
    BrokerSock fd;
    pthread_t thread;
    pthread_mutex_t write_mu;
    char room_id[HERALD_BROKER_MAX_ROOM_ID];
    char name[HERALD_BROKER_MAX_NAME];
    uint64_t peer_id;
    uint32_t peer_addr;
    int refs;
    int closed;
    int pmd; /* 1 = permessage-deflate negotiated for this socket */
    size_t max_frame;
};

static void conn_ref(Conn *c) {
    if (c)
        (void)__sync_add_and_fetch(&c->refs, 1);
}

static void conn_unref(Conn *c) {
    if (!c)
        return;
    if (__sync_sub_and_fetch(&c->refs, 1) == 0) {
        pthread_mutex_destroy(&c->write_mu);
        free(c);
    }
}

/* Send an application payload; compress with RSV1 when PMD is on and
 * the deflate result is smaller. */
static int ws_send_binary(Conn *c, const uint8_t *payload, size_t len) {
    if (!c || c->closed || c->fd == BROKER_INVALID_SOCK)
        return 0;
    if (!c->pmd || !payload)
        return ws_send_binary_raw(c->fd, payload, len, 0);

    size_t comp_len = 0;
    uint8_t *comp = ws_pmd_deflate(payload, len, &comp_len);
    if (!comp)
        return ws_send_binary_raw(c->fd, payload, len, 0);
    int ok = ws_send_binary_raw(c->fd, comp, comp_len, 1);
    free(comp);
    return ok;
}

static int conn_add_peer_locked(Room *r, Conn *c) {
    if (r->peer_count >= HERALD_BROKER_MAX_PEERS_PER_ROOM)
        return 0;
    for (int i = 0; i < r->peer_count; ++i) {
        if (r->peers[i] == c)
            return 1; /* idempotent */
    }
    r->peers[r->peer_count++] = c;
    return 1;
}

static void conn_remove_peer_locked(Room *r, Conn *c) {
    for (int i = 0; i < r->peer_count; ++i) {
        if (r->peers[i] == c) {
            r->peers[i] = r->peers[--r->peer_count];
            r->peers[r->peer_count] = NULL;
            return;
        }
    }
}

static int conn_send_error(Conn *dst, uint8_t code, const char *msg) {
    if (!dst || dst->closed || dst->fd == BROKER_INVALID_SOCK)
        return 0;
    size_t msg_len = msg ? strlen(msg) : 0;
    if (msg_len > 200)
        msg_len = 200;
    uint8_t payload[1 + 1 + 2 + 200];
    size_t off = 0;
    payload[off++] = HERALD_ROOM_ACTION_ERROR;
    payload[off++] = code;
    wr_u16_le(payload + off, (uint16_t)msg_len);
    off += 2;
    if (msg_len > 0) {
        memcpy(payload + off, msg, msg_len);
        off += msg_len;
    }
    pthread_mutex_lock(&dst->write_mu);
    int ok = ws_send_binary(dst, payload, off);
    pthread_mutex_unlock(&dst->write_mu);
    return ok;
}

static int conn_send_presence_locked(Conn *dst, uint8_t kind, uint64_t peer_id, const char *name) {
    /* [PRESENCE, kind, peer_id u64, name_len u16, name] */
    size_t name_len = name ? strlen(name) : 0;
    if (name_len > 0xFFFFu)
        name_len = 0xFFFFu;
    uint8_t payload[1 + 1 + 8 + 2 + 256];
    size_t off = 0;
    payload[off++] = HERALD_ROOM_ACTION_PRESENCE;
    payload[off++] = kind;
    wr_u64_le(payload + off, peer_id);
    off += 8;
    wr_u16_le(payload + off, (uint16_t)name_len);
    off += 2;
    if (name_len > 0) {
        memcpy(payload + off, name, name_len);
        off += name_len;
    }
    pthread_mutex_lock(&dst->write_mu);
    int ok = ws_send_binary(dst, payload, off);
    pthread_mutex_unlock(&dst->write_mu);
    return ok;
}

static int conn_send_buffered_broadcast(Conn *dst, const uint8_t *bytes, size_t len) {
    if (len == 0)
        return 1;
    pthread_mutex_lock(&dst->write_mu);
    int ok = ws_send_binary(dst, bytes, len);
    pthread_mutex_unlock(&dst->write_mu);
    return ok;
}

/* Build a relay frame with the sender peer id prefix after the action
 * byte. Caller frees the returned buffer. Returns NULL on OOM. */
static uint8_t *broker_build_relay_frame(uint8_t action, uint64_t sender_id, const uint8_t *payload,
                                         size_t payload_len, size_t *out_len) {
    size_t total = 1 + 8 + payload_len;
    if (total < 1 + 8)
        return NULL;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out)
        return NULL;
    out[0] = action;
    wr_u64_le(out + 1, sender_id);
    if (payload_len > 0)
        memcpy(out + 9, payload, payload_len);
    *out_len = total;
    return out;
}

static uint64_t room_assign_peer_id_locked(Room *r) {
    for (;;) {
        uint64_t id = g_next_peer_id++;
        if (id == 0)
            continue;
        int taken = 0;
        for (int i = 0; i < r->peer_count; ++i) {
            if (r->peers[i] && r->peers[i]->peer_id == id) {
                taken = 1;
                break;
            }
        }
        if (!taken)
            return id;
    }
}

static int room_snapshot_others_locked(Room *r, Conn *src, Conn **out, int out_cap) {
    int n = 0;
    for (int i = 0; i < r->peer_count && n < out_cap; ++i) {
        Conn *c = r->peers[i];
        if (!c || c == src || c->closed)
            continue;
        conn_ref(c);
        out[n++] = c;
    }
    return n;
}

static void conn_snapshot_release(Conn **list, int n) {
    for (int i = 0; i < n; ++i)
        conn_unref(list[i]);
}

static int conn_send_join_ack(Conn *dst, uint64_t peer_id) {
    uint8_t payload[1 + 8];
    payload[0] = HERALD_ROOM_ACTION_JOIN_ACK;
    wr_u64_le(payload + 1, peer_id);
    pthread_mutex_lock(&dst->write_mu);
    int ok = ws_send_binary(dst, payload, sizeof(payload));
    pthread_mutex_unlock(&dst->write_mu);
    return ok;
}

static int payload_starts_hcan(const uint8_t *app, size_t app_len) {
    return app && app_len >= 4 && app[0] == 'H' && app[1] == 'C' && app[2] == 'A' && app[3] == 'N';
}

/* Caller holds g_rooms_mu. Copies the wire bytes, snapshots peers, then
 * drops the lock before send. Always returns with g_rooms_mu unlocked. */
static void fanout_broadcast(Room *r, Conn *src, const uint8_t *frame, size_t frame_len) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    Conn *snaps[HERALD_BROKER_MAX_PEERS_PER_ROOM];
    int n = 0;
    if (frame_len >= 1 && frame[0] == HERALD_ROOM_ACTION_BROADCAST) {
        const uint8_t *app = frame + 1;
        size_t app_len = frame_len - 1;
        size_t relay_len = 0;
        uint8_t *relay = broker_build_relay_frame(HERALD_ROOM_ACTION_BROADCAST, src->peer_id, app,
                                                  app_len, &relay_len);
        if (relay) {
            int cache = !payload_starts_hcan(app, app_len) && relay_len <= g_max_catchup;
            if (cache) {
                if (r->last_broadcast)
                    free(r->last_broadcast);
                r->last_broadcast = relay;
                r->last_broadcast_len = relay_len;
                wire = (uint8_t *)malloc(relay_len);
                if (wire) {
                    memcpy(wire, relay, relay_len);
                    wire_len = relay_len;
                }
            } else {
                wire = relay;
                wire_len = relay_len;
            }
            n = room_snapshot_others_locked(r, src, snaps, HERALD_BROKER_MAX_PEERS_PER_ROOM);
        }
    }
    pthread_mutex_unlock(&g_rooms_mu);
    for (int i = 0; i < n; ++i) {
        Conn *peer = snaps[i];
        if (wire && !peer->closed) {
            pthread_mutex_lock(&peer->write_mu);
            ws_send_binary(peer, wire, wire_len);
            pthread_mutex_unlock(&peer->write_mu);
        }
    }
    conn_snapshot_release(snaps, n);
    free(wire);
}

static void send_presence_snapshot(Conn **snaps, int n, uint8_t kind, uint64_t peer_id,
                                   const char *name) {
    for (int i = 0; i < n; ++i)
        conn_send_presence_locked(snaps[i], kind, peer_id, name);
    conn_snapshot_release(snaps, n);
}

/* Caller holds g_rooms_mu. Drops it before send. */
static int conn_route_action(Room *r, Conn *src, uint8_t action, uint64_t dst_id,
                             const uint8_t *app_payload, size_t app_payload_len) {
    size_t relay_len = 0;
    uint8_t *relay = broker_build_relay_frame(action, src->peer_id, app_payload, app_payload_len,
                                              &relay_len);
    Conn *dst = NULL;
    if (relay) {
        for (int i = 0; i < r->peer_count; ++i) {
            Conn *peer = r->peers[i];
            if (peer == src || peer->closed)
                continue;
            if (peer->peer_id == dst_id) {
                dst = peer;
                conn_ref(dst);
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_rooms_mu);
    int ok = 0;
    if (dst && relay) {
        pthread_mutex_lock(&dst->write_mu);
        ok = ws_send_binary(dst, relay, relay_len);
        pthread_mutex_unlock(&dst->write_mu);
        conn_unref(dst);
    }
    free(relay);
    return ok;
}

/* Unlink from the room. If remaining peers need PRESENCE_LEAVE, snapshot them
 * (refs held). Caller sends after dropping g_rooms_mu. */
static int conn_leave_room_locked(Conn *c, Conn **snaps, int snap_cap, uint64_t *leave_id,
                                  char *leave_name, size_t name_cap) {
    int n = 0;
    if (leave_id)
        *leave_id = c->peer_id;
    if (leave_name && name_cap)
        broker_copy_cstr(leave_name, name_cap, c->name);
    if (c->room_id[0] == '\0')
        return 0;
    Room *r = room_find_locked(c->room_id);
    if (r) {
        conn_remove_peer_locked(r, c);
        if (r->peer_count > 0 && snaps)
            n = room_snapshot_others_locked(r, c, snaps, snap_cap);
        else
            room_evict_if_empty_locked(r);
    }
    c->room_id[0] = '\0';
    c->name[0] = '\0';
    c->peer_id = 0;
    return n;
}

/* Parse and dispatch a single room-action frame. `frame` is the WS
 * payload (post-unmask). Returns 0 on protocol error or disconnect
 * (caller should close). */
static int conn_dispatch_frame(Conn *c, const uint8_t *frame, size_t len) {
    if (len < 1)
        return 0;
    uint8_t action = frame[0];
    const uint8_t *p = frame + 1;
    size_t pl = len - 1;
    switch (action) {
    case HERALD_ROOM_ACTION_JOIN_ROOM: {
        if (pl < 4)
            return 0;
        uint16_t room_len = rd_u16_le(p);
        p += 2;
        pl -= 2;
        if (room_len > pl)
            return 0;
        if (room_len == 0 || room_len >= HERALD_BROKER_MAX_ROOM_ID)
            return 0;
        if (memchr(p, 0, room_len))
            return 0;
        char room_id[HERALD_BROKER_MAX_ROOM_ID] = {0};
        memcpy(room_id, p, room_len);
        p += room_len;
        pl -= room_len;
        if (pl < 2)
            return 0;
        uint16_t name_len = rd_u16_le(p);
        p += 2;
        pl -= 2;
        if (name_len > pl)
            return 0;
        char name[HERALD_BROKER_MAX_NAME] = {0};
        if (name_len > 0) {
            size_t copy = name_len < sizeof(name) - 1 ? name_len : sizeof(name) - 1;
            memcpy(name, p, copy);
        }
        p += name_len;
        pl -= name_len;
        if (pl < 8)
            return 0;
        (void)rd_u64_le(p); /* client-chosen id is ignored */

        Conn *leave_snaps[HERALD_BROKER_MAX_PEERS_PER_ROOM];
        int nleave = 0;
        uint64_t leave_id = 0;
        char leave_name[HERALD_BROKER_MAX_NAME];
        leave_name[0] = '\0';
        Conn *join_snaps[HERALD_BROKER_MAX_PEERS_PER_ROOM];
        int njoin = 0;
        uint8_t *catchup = NULL;
        size_t catchup_len = 0;
        uint64_t assigned = 0;
        int join_peers = 0;

        pthread_mutex_lock(&g_rooms_mu);
        if (c->room_id[0])
            nleave = conn_leave_room_locked(c, leave_snaps, HERALD_BROKER_MAX_PEERS_PER_ROOM,
                                            &leave_id, leave_name, sizeof(leave_name));
        Room *r = room_get_or_create_locked(room_id);
        if (!r) {
            pthread_mutex_unlock(&g_rooms_mu);
            send_presence_snapshot(leave_snaps, nleave, 1, leave_id, leave_name);
            broker_log("room table full; rejecting join");
            (void)conn_send_error(c, HERALD_ROOM_ERR_ROOM_TABLE_FULL, "room table full");
            return 0;
        }
        if (!conn_add_peer_locked(r, c)) {
            pthread_mutex_unlock(&g_rooms_mu);
            send_presence_snapshot(leave_snaps, nleave, 1, leave_id, leave_name);
            broker_log("peer cap on room '%s' reached", room_id);
            (void)conn_send_error(c, HERALD_ROOM_ERR_ROOM_FULL, "room full");
            return 0;
        }
        assigned = room_assign_peer_id_locked(r);
        broker_copy_cstr(c->room_id, sizeof(c->room_id), room_id);
        broker_copy_cstr(c->name, sizeof(c->name), name);
        c->peer_id = assigned;
        join_peers = r->peer_count;
        if (r->last_broadcast && r->last_broadcast_len > 0) {
            catchup = (uint8_t *)malloc(r->last_broadcast_len);
            if (catchup) {
                memcpy(catchup, r->last_broadcast, r->last_broadcast_len);
                catchup_len = r->last_broadcast_len;
            }
        }
        njoin = room_snapshot_others_locked(r, c, join_snaps, HERALD_BROKER_MAX_PEERS_PER_ROOM);
        pthread_mutex_unlock(&g_rooms_mu);

        send_presence_snapshot(leave_snaps, nleave, 1, leave_id, leave_name);
        (void)conn_send_join_ack(c, assigned);
        if (catchup && catchup_len)
            conn_send_buffered_broadcast(c, catchup, catchup_len);
        free(catchup);
        for (int i = 0; i < njoin; ++i) {
            Conn *other = join_snaps[i];
            conn_send_presence_locked(c, /*HERALD_PRESENCE_JOIN*/ 0, other->peer_id, other->name);
            conn_send_presence_locked(other, /*HERALD_PRESENCE_JOIN*/ 0, assigned, name);
        }
        conn_snapshot_release(join_snaps, njoin);
        broker_log("peer %lu joined '%s' as '%s' (now %d peers)", (unsigned long)assigned, room_id,
                   name, join_peers);
        return 1;
    }
    case HERALD_ROOM_ACTION_LEAVE_ROOM: {
        Conn *snaps[HERALD_BROKER_MAX_PEERS_PER_ROOM];
        uint64_t leave_id = 0;
        char leave_name[HERALD_BROKER_MAX_NAME];
        pthread_mutex_lock(&g_rooms_mu);
        int n = conn_leave_room_locked(c, snaps, HERALD_BROKER_MAX_PEERS_PER_ROOM, &leave_id,
                                       leave_name, sizeof(leave_name));
        pthread_mutex_unlock(&g_rooms_mu);
        send_presence_snapshot(snaps, n, 1, leave_id, leave_name);
        return 1;
    }
    case HERALD_ROOM_ACTION_BROADCAST: {
        if (c->room_id[0] == '\0')
            return 1; /* ignore broadcast from un-joined peer */
        pthread_mutex_lock(&g_rooms_mu);
        Room *r = room_find_locked(c->room_id);
        if (r) {
            broker_log("broadcast %zu bytes from peer %lu in room '%s'", len,
                       (unsigned long)c->peer_id, c->room_id);
            fanout_broadcast(r, c, frame, len);
        } else {
            pthread_mutex_unlock(&g_rooms_mu);
        }
        return 1;
    }
    case HERALD_ROOM_ACTION_DIRECT:
    case HERALD_ROOM_ACTION_SIGNAL: {
        if (pl < 8 || c->room_id[0] == '\0')
            return 1;
        uint64_t dst = rd_u64_le(p);
        const uint8_t *payload = p + 8;
        size_t payload_len = pl - 8;
        pthread_mutex_lock(&g_rooms_mu);
        Room *r = room_find_locked(c->room_id);
        if (r)
            (void)conn_route_action(r, c, action, dst, payload, payload_len);
        else
            pthread_mutex_unlock(&g_rooms_mu);
        return 1;
    }
    default:
        broker_log("unknown action 0x%02x; ignoring", action);
        return 1;
    }
}

/* -- Per-connection thread -------------------------------------------- */

static void *conn_thread_main(void *arg) {
    Conn *c = (Conn *)arg;
    (void)broker_set_sock_timeouts(c->fd, HERALD_BROKER_HANDSHAKE_TIMEOUT_MS,
                                   HERALD_BROKER_SEND_TIMEOUT_MS);
    int hs = ws_handshake_server(c->fd);
    if (!hs) {
        broker_log("handshake failed; closing fd %d", (int)c->fd);
        goto done;
    }
    (void)broker_set_sock_timeouts(c->fd, HERALD_BROKER_IDLE_TIMEOUT_MS,
                                   HERALD_BROKER_SEND_TIMEOUT_MS);
    c->pmd = (hs == 2) ? 1 : 0;
    if (c->pmd)
        broker_log("fd %d negotiated permessage-deflate", (int)c->fd);
    broker_setsockopt_int(c->fd, IPPROTO_TCP, TCP_NODELAY, 1);

    size_t cap = HERALD_BROKER_RECV_INITIAL;
    if (cap > c->max_frame)
        cap = c->max_frame;
    uint8_t *payload = (uint8_t *)malloc(cap);
    if (!payload)
        goto done;

    for (;;) {
        WsFrameHdr h;
        if (!ws_read_frame_header(c->fd, &h, c->max_frame))
            break;
        if (!h.masked) {
            broker_log("unmasked client frame; closing");
            break;
        }
        /* Control frames must not set RSV1. */
        if ((h.opcode == 0x08 || h.opcode == 0x09 || h.opcode == 0x0A) && h.rsv1) {
            broker_log("RSV1 on control frame; closing");
            break;
        }
        /* PING -> reply PONG with the same payload (echo semantics). */
        if (h.opcode == 0x09) {
            if (!ensure_recv_cap(&payload, &cap, (size_t)h.len, c->max_frame))
                break;
            if (!ws_read_frame_payload(c->fd, h.len, h.masked, payload))
                break;
            /* Build a PONG header. FIN + PONG = 0x8A. */
            uint8_t dyn[14];
            size_t dh = 0;
            if (h.len <= 125) {
                dyn[0] = 0x8A;
                dyn[1] = (uint8_t)h.len;
                dh = 2;
            } else if (h.len <= 0xFFFF) {
                dyn[0] = 0x8A;
                dyn[1] = 126;
                wr_u16_be(dyn + 2, (uint16_t)h.len);
                dh = 4;
            } else {
                dyn[0] = 0x8A;
                dyn[1] = 127;
                wr_u64_be(dyn + 2, h.len);
                dh = 10;
            }
            pthread_mutex_lock(&c->write_mu);
            send_all(c->fd, dyn, dh);
            if (h.len > 0)
                send_all(c->fd, payload, (size_t)h.len);
            pthread_mutex_unlock(&c->write_mu);
            continue;
        }
        /* PONG — curl and other clients may send these (e.g. keepalive
         * responses). Ignore payload and keep reading. */
        if (h.opcode == 0x0A) {
            if (!ensure_recv_cap(&payload, &cap, (size_t)h.len, c->max_frame))
                break;
            if (!ws_read_frame_payload(c->fd, h.len, h.masked, payload))
                break;
            continue;
        }
        /* CLOSE -> reply CLOSE and exit. */
        if (h.opcode == 0x08) {
            if (h.len > 0) {
                if (!ensure_recv_cap(&payload, &cap, (size_t)h.len, c->max_frame))
                    break;
                (void)ws_read_frame_payload(c->fd, h.len, h.masked, payload);
            }
            uint8_t close_hdr[4] = {0x88, 0x02, 0x03, 0xE8}; /* 1000 normal */
            pthread_mutex_lock(&c->write_mu);
            send_all(c->fd, close_hdr, 4);
            pthread_mutex_unlock(&c->write_mu);
            break;
        }
        /* App data: reassemble BINARY fragments (FIN=0 … FIN=1). TEXT is rejected. */
        if (h.opcode != 0x02) {
            broker_log("unsupported opcode 0x%x; closing", h.opcode);
            break;
        }
        if (h.rsv1 && !c->pmd) {
            broker_log("RSV1 without permessage-deflate; closing");
            break;
        }
        int msg_compressed = h.rsv1;
        size_t acc = 0;
        for (;;) {
            if (h.len > 0) {
                if (acc + (size_t)h.len > c->max_frame) {
                    broker_log("reassembled frame exceeds max_frame; closing");
                    goto free_payload;
                }
                if (!ensure_recv_cap(&payload, &cap, acc + (size_t)h.len, c->max_frame)) {
                    broker_log("recv buffer grow failed; closing");
                    goto free_payload;
                }
                if (!ws_read_frame_payload(c->fd, h.len, h.masked, payload + acc))
                    goto free_payload;
                acc += (size_t)h.len;
            }
            if (h.fin)
                break;
            if (!ws_read_frame_header(c->fd, &h, c->max_frame - acc))
                goto free_payload;
            if (h.opcode == 0x08 || h.opcode == 0x09 || h.opcode == 0x0A) {
                broker_log("control frame mid-message (0x%x); closing", h.opcode);
                goto free_payload;
            }
            /* RSV1 is only legal on the first fragment of a message. */
            if (h.rsv1) {
                broker_log("RSV1 on continuation; closing");
                goto free_payload;
            }
            if (h.opcode != 0x00) {
                broker_log("expected continuation opcode; closing");
                goto free_payload;
            }
        }

        const uint8_t *dispatch = payload;
        size_t dispatch_len = acc;
        uint8_t *inflated = NULL;
        if (msg_compressed) {
            size_t plain_len = 0;
            inflated = ws_pmd_inflate(payload, acc, c->max_frame, &plain_len);
            if (!inflated) {
                broker_log("permessage-deflate inflate failed; closing");
                goto free_payload;
            }
            dispatch = inflated;
            dispatch_len = plain_len;
        }
        if (dispatch_len > 0) {
            broker_log("frame %zu bytes from peer %lu%s", dispatch_len,
                       (unsigned long)c->peer_id, msg_compressed ? " (pmd)" : "");
            if (!conn_dispatch_frame(c, dispatch, dispatch_len)) {
                free(inflated);
                break;
            }
        }
        free(inflated);
    }

free_payload:
    free(payload);
done:
    c->closed = 1;
    {
        Conn *snaps[HERALD_BROKER_MAX_PEERS_PER_ROOM];
        uint64_t leave_id = 0;
        char leave_name[HERALD_BROKER_MAX_NAME];
        pthread_mutex_lock(&g_rooms_mu);
        int n = conn_leave_room_locked(c, snaps, HERALD_BROKER_MAX_PEERS_PER_ROOM, &leave_id,
                                       leave_name, sizeof(leave_name));
        pthread_mutex_unlock(&g_rooms_mu);
        send_presence_snapshot(snaps, n, 1, leave_id, leave_name);
    }
    broker_close(c->fd);
    ip_release(c->peer_addr);
    conn_unref(c);
    conn_count_dec();
    return NULL;
}

/* -- Main -------------------------------------------------------------- */

int main(void) {
#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
#endif
    if (!broker_net_init()) {
        fprintf(stderr, "winsock init failed\n");
        return 1;
    }

    const char *port_env = getenv("HERALD_BROKER_PORT");
    int port = port_env ? atoi(port_env) : HERALD_BROKER_DEFAULT_PORT;
    if (port <= 0 || port > 65535)
        port = HERALD_BROKER_DEFAULT_PORT;

    const char *mf_env = getenv("HERALD_BROKER_MAX_FRAME");
    size_t max_frame = mf_env ? (size_t)strtoul(mf_env, NULL, 10) : HERALD_BROKER_DEFAULT_MAX_FRAME;
    if (max_frame == 0)
        max_frame = HERALD_BROKER_DEFAULT_MAX_FRAME;
    if (max_frame > HERALD_BROKER_MAX_FRAME_CEILING)
        max_frame = HERALD_BROKER_MAX_FRAME_CEILING;

    const char *cu_env = getenv("HERALD_BROKER_MAX_CATCHUP");
    if (cu_env && cu_env[0]) {
        /* Explicit 0 = do not store last_broadcast. */
        g_max_catchup = (size_t)strtoul(cu_env, NULL, 10);
        if (g_max_catchup > max_frame)
            g_max_catchup = max_frame;
    }

    const char *mc_env = getenv("HERALD_BROKER_MAX_CONNECTIONS");
    if (mc_env && mc_env[0]) {
        /* Explicit 0 = unlimited; missing env keeps the default. */
        g_max_conns = (int)strtol(mc_env, NULL, 10);
        if (g_max_conns < 0)
            g_max_conns = HERALD_BROKER_DEFAULT_MAX_CONNS;
    }

    const char *vb = getenv("HERALD_BROKER_VERBOSE");
    g_verbose = (vb && vb[0] != '0') ? 1 : 0;

    const char *origin_env = getenv("HERALD_BROKER_ORIGIN");
    if (origin_env)
        broker_copy_cstr(g_origin_allow, sizeof(g_origin_allow), origin_env);
    const char *host_env = getenv("HERALD_BROKER_HOST");
    if (host_env)
        broker_copy_cstr(g_host_allow, sizeof(g_host_allow), host_env);

    const char *bind_env = getenv("HERALD_BROKER_BIND");
    uint32_t bind_addr = htonl(INADDR_LOOPBACK);
    const char *bind_label = "127.0.0.1";
    if (bind_env && bind_env[0]) {
        if (strcmp(bind_env, "0.0.0.0") == 0 || strcmp(bind_env, "*") == 0) {
            bind_addr = htonl(INADDR_ANY);
            bind_label = "0.0.0.0";
        } else {
            bind_addr = inet_addr(bind_env);
            if (bind_addr == (uint32_t)INADDR_NONE) {
                bind_addr = htonl(INADDR_LOOPBACK);
                bind_label = "127.0.0.1";
            } else {
                bind_label = bind_env;
            }
        }
    }

    size_t stack_sz = HERALD_BROKER_THREAD_STACK;
#ifdef PTHREAD_STACK_MIN
    if (stack_sz < (size_t)PTHREAD_STACK_MIN)
        stack_sz = (size_t)PTHREAD_STACK_MIN;
#endif

    BrokerSock srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == BROKER_INVALID_SOCK) {
        fprintf(stderr, "socket: error %d\n", broker_sock_err());
        return 1;
    }
    broker_setsockopt_int(srv, SOL_SOCKET, SO_REUSEADDR, 1);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = bind_addr;
    addr.sin_port = htons((uint16_t)port);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind: error %d\n", broker_sock_err());
        return 1;
    }
    if (listen(srv, 512) < 0) {
        fprintf(stderr, "listen: error %d\n", broker_sock_err());
        return 1;
    }
    fprintf(stderr, "[broker] listening on %s:%d (max_frame=%zu max_catchup=%zu max_conns=%d stack=%zu)\n",
            bind_label, port, max_frame, g_max_catchup, g_max_conns, stack_sz);

    for (;;) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        BrokerSock cfd = accept(srv, (struct sockaddr *)&caddr, &clen);
        if (cfd == BROKER_INVALID_SOCK) {
            if (broker_sock_err() == BROKER_EINTR)
                continue;
            fprintf(stderr, "accept: error %d\n", broker_sock_err());
            continue;
        }
        uint32_t ip = caddr.sin_addr.s_addr;
        if (!conn_try_admit()) {
            broker_log("max connections (%d); rejecting", g_max_conns);
            broker_close(cfd);
            continue;
        }
        if (!ip_try_admit(ip)) {
            broker_log("per-ip cap (%d); rejecting", HERALD_BROKER_MAX_CONNS_PER_IP);
            broker_close(cfd);
            conn_count_dec();
            continue;
        }
        Conn *c = (Conn *)calloc(1, sizeof(Conn));
        if (!c) {
            broker_close(cfd);
            ip_release(ip);
            conn_count_dec();
            continue;
        }
        c->fd = cfd;
        c->max_frame = max_frame;
        c->peer_addr = ip;
        c->refs = 1;
        pthread_mutex_init(&c->write_mu, NULL);

        pthread_attr_t attr;
        int attr_ok = (pthread_attr_init(&attr) == 0);
        if (attr_ok && pthread_attr_setstacksize(&attr, stack_sz) != 0)
            broker_log("pthread_attr_setstacksize(%zu) failed; using default", stack_sz);

        if (pthread_create(&c->thread, attr_ok ? &attr : NULL, conn_thread_main, c) != 0) {
            if (attr_ok)
                pthread_attr_destroy(&attr);
            broker_close(cfd);
            ip_release(ip);
            conn_unref(c);
            conn_count_dec();
            continue;
        }
        if (attr_ok)
            pthread_attr_destroy(&attr);
        pthread_detach(c->thread);
    }
    return 0;
}

