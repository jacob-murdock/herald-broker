/*
 * Herald room wire constants (broker + clients).
 *
 * Keep this file free of amphora / herald client types so the broker
 * tree can ship as a standalone FOSS repo without the rest of the
 * monorepo. Clients in-tree include it via herald_room.h.
 *
 * Wire (v1, JOIN carries peer_id tail):
 *   JOIN_ROOM  0x01  [u16 LE room_id_len, room_id, u16 LE name_len, name, u64 LE peer_id]
 *   LEAVE_ROOM 0x02
 *   BROADCAST  0x10  [opaque payload from client; broker fans out as
 *                     0x10 + u64 LE sender_peer_id + payload]
 *   DIRECT     0x11  [u64 LE dst_peer_id, opaque payload from client;
 *                     broker delivers 0x11 + u64 LE sender_peer_id + payload]
 *   PRESENCE   0x20  [u8 kind (0=join, 1=leave), u64 LE peer_id, u16 LE name_len, name]
 *   ERROR      0x30  [u8 code, u16 LE msg_len, msg…]  (broker → client; reject JOIN)
 */

#pragma once

#define HERALD_ROOM_ACTION_JOIN_ROOM 0x01u
#define HERALD_ROOM_ACTION_LEAVE_ROOM 0x02u
#define HERALD_ROOM_ACTION_BROADCAST 0x10u
#define HERALD_ROOM_ACTION_DIRECT 0x11u
#define HERALD_ROOM_ACTION_PRESENCE 0x20u
/* Broker → client only. Sent before closing a rejected JOIN (room/peer caps). */
#define HERALD_ROOM_ACTION_ERROR 0x30u

#define HERALD_ROOM_ERR_ROOM_FULL 1u
#define HERALD_ROOM_ERR_ROOM_TABLE_FULL 2u
