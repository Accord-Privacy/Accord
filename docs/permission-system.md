# Accord Permission System Design

## Overview

Accord's permission system is modeled after Discord's but designed for privacy-first architecture.
Roles and permissions are **per-Node** — there are no global roles.

## Permission Bits

Permissions are stored as a 64-bit integer bitmask, same as Discord.
This allows efficient storage, comparison, and inheritance calculations.

### Core Permissions (Phase 1 — 20 bits)

| Bit | Name | Description |
|-----|------|-------------|
| 0 | CREATE_INVITE | Create invite links for the Node |
| 1 | KICK_MEMBERS | Remove members from the Node |
| 2 | BAN_MEMBERS | Ban members from the Node |
| 3 | ADMINISTRATOR | Full access, bypasses all permission checks |
| 4 | MANAGE_CHANNELS | Create, edit, delete, reorder channels and categories |
| 5 | MANAGE_NODE | Edit Node name, description, icon, settings |
| 6 | ADD_REACTIONS | Add emoji reactions to messages |
| 10 | VIEW_CHANNEL | See the channel in the channel list |
| 11 | SEND_MESSAGES | Send messages in text channels |
| 13 | MANAGE_MESSAGES | Delete others' messages, pin/unpin |
| 14 | EMBED_LINKS | Links auto-preview |
| 15 | ATTACH_FILES | Upload files |
| 16 | READ_MESSAGE_HISTORY | View messages sent before joining |
| 17 | MENTION_EVERYONE | Use @everyone and @here |
| 20 | CONNECT | Join voice channels |
| 21 | SPEAK | Transmit audio in voice channels |
| 22 | MUTE_MEMBERS | Server-mute others in voice |
| 23 | DEAFEN_MEMBERS | Server-deafen others in voice |
| 24 | MOVE_MEMBERS | Move members between voice channels |
| 28 | MANAGE_ROLES | Create, edit, delete roles below own highest role |

### Future Permissions (Phase 2+)

| Bit | Name | Notes |
|-----|------|-------|
| 7 | VIEW_AUDIT_LOG | See Node audit log |
| 8 | PRIORITY_SPEAKER | Louder in voice, reduces others' volume |
| 9 | STREAM | Share screen in voice channels |
| 25 | USE_VAD | Use voice activity detection (vs push-to-talk) |
| 26 | CHANGE_NICKNAME | Change own display name in this Node |
| 27 | MANAGE_NICKNAMES | Change others' display names |
| 29 | MANAGE_WEBHOOKS | Create/edit/delete bot webhooks |
| 33 | MANAGE_EVENTS | Create/edit scheduled events |
| 34 | MANAGE_THREADS | Archive, delete threads |

## Discord Bit Compatibility

We intentionally use the same bit positions as Discord where applicable.
This means Discord template import is a direct bitmask copy for supported bits.
Unsupported bits are masked out and logged during import.

## Role Model

```rust
pub struct Role {
    pub id: Uuid,
    pub node_id: Uuid,
    pub name: String,           // e.g., "CHAD", "Big Daddy"
    pub color: u32,             // RGB color as integer (0 = no color)
    pub permissions: u64,       // Bitmask
    pub position: i32,          // Hierarchy position (higher = more authority)
    pub hoist: bool,            // Show separately in member list
    pub mentionable: bool,      // Can be @mentioned by anyone
    pub icon_emoji: Option<String>, // Unicode emoji for role icon
    pub created_at: i64,
}
```

### Default Roles

Every Node has an `@everyone` role (position 0, cannot be deleted).
Its permissions define the baseline for all members.

### Role Hierarchy

- Roles are ordered by `position` (higher number = higher authority)
- Members inherit permissions from ALL their assigned roles (union/OR)
- A member can only modify roles with position BELOW their highest role
- Administrator permission (bit 3) bypasses ALL checks

## Channel Permission Overwrites

Channels can override the computed permissions for specific roles.

```rust
pub struct ChannelPermissionOverwrite {
    pub channel_id: Uuid,
    pub role_id: Uuid,
    pub allow: u64,     // Explicitly granted permissions
    pub deny: u64,      // Explicitly denied permissions
}
```

### Permission Resolution Order

1. Start with `@everyone` role permissions
2. OR all the member's additional role permissions
3. If ADMINISTRATOR is set, grant everything (stop here)
4. Apply channel `@everyone` overwrite: deny removes, allow adds
5. For each of the member's roles, collect all channel overwrites
6. OR all role denies → remove those
7. OR all role allows → add those

This matches Discord's resolution algorithm exactly.

## Category Inheritance

- Categories (type 4) hold permission overwrites
- Child channels inherit the category's overwrites by default
- If a channel has its own overwrite for a role, it replaces the category's
  (not merged — full replacement per role)
- "Sync with category" option resets channel overwrites to match parent

## Channel Types

| Type | Name | Description |
|------|------|-------------|
| 0 | TEXT | Standard text channel |
| 2 | VOICE | Voice + optional text chat |
| 4 | CATEGORY | Container for organizing channels |

## Database Schema

### `roles` table
```sql
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    name TEXT NOT NULL,
    color INTEGER NOT NULL DEFAULT 0,
    permissions INTEGER NOT NULL DEFAULT 0,
    position INTEGER NOT NULL DEFAULT 0,
    hoist BOOLEAN NOT NULL DEFAULT FALSE,
    mentionable BOOLEAN NOT NULL DEFAULT FALSE,
    icon_emoji TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX idx_roles_node ON roles(node_id);
```

### `member_roles` table
```sql
CREATE TABLE member_roles (
    member_id TEXT NOT NULL,  -- user_id
    role_id TEXT NOT NULL REFERENCES roles(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    assigned_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (member_id, role_id)
);
CREATE INDEX idx_member_roles_node ON member_roles(node_id);
```

### `channel_permission_overwrites` table
```sql
CREATE TABLE channel_permission_overwrites (
    channel_id TEXT NOT NULL REFERENCES channels(id),
    role_id TEXT NOT NULL REFERENCES roles(id),
    allow_bits INTEGER NOT NULL DEFAULT 0,
    deny_bits INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_id, role_id)
);
```

### Modifications to `channels` table
```sql
ALTER TABLE channels ADD COLUMN channel_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE channels ADD COLUMN parent_id TEXT REFERENCES channels(id);
ALTER TABLE channels ADD COLUMN position INTEGER NOT NULL DEFAULT 0;
ALTER TABLE channels ADD COLUMN topic TEXT;
ALTER TABLE channels ADD COLUMN nsfw BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE channels ADD COLUMN icon_emoji TEXT;
```

## Discord Template Import

### Endpoint
`POST /api/nodes/{node_id}/import-discord-template`

### Request Body
```json
{
    "template_code": "RHzsRPA9xrRW"
}
```

### Import Process
1. Fetch template from Discord API (`/guilds/templates/{code}`)
2. Create roles (map Discord role IDs to new Accord UUIDs)
3. Create categories first (type 4), then child channels
4. Apply permission overwrites (rewriting Discord role IDs to Accord role IDs)
5. Assign Node creator the highest-permission role
6. Return import summary (what was created, what was skipped)

### Permission Mapping
- Supported bits: direct copy (same bit positions)
- Unsupported bits: masked out, logged in import summary
- Discord "type" field in overwrites (0=role, 1=member): only role overwrites imported

## API Endpoints

### Roles
- `GET /api/nodes/{id}/roles` — list all roles
- `POST /api/nodes/{id}/roles` — create role
- `PATCH /api/nodes/{id}/roles/{role_id}` — edit role
- `DELETE /api/nodes/{id}/roles/{role_id}` — delete role
- `PATCH /api/nodes/{id}/roles/reorder` — reorder roles

### Member Roles
- `GET /api/nodes/{id}/members/{user_id}/roles` — get member's roles
- `PUT /api/nodes/{id}/members/{user_id}/roles/{role_id}` — assign role
- `DELETE /api/nodes/{id}/members/{user_id}/roles/{role_id}` — remove role

### Channel Overwrites
- `GET /api/channels/{id}/permissions` — list overwrites
- `PUT /api/channels/{id}/permissions/{role_id}` — set overwrite
- `DELETE /api/channels/{id}/permissions/{role_id}` — remove overwrite

### Import
- `POST /api/nodes/{id}/import-discord-template` — import from template code
