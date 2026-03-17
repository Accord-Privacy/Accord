# Accord Relay Server — REST API Reference

> **Version:** 0.1.x  
> **Base URL:** `http(s)://<host>:<port>`  
> **Authentication:** Most endpoints require `?token=<auth_token>` query parameter or `Authorization: Bearer <auth_token>` header.  
> **Content-Type:** `application/json` unless noted (file uploads use `multipart/form-data`).  
> **Zero-Knowledge Design:** The server cannot decrypt user content. Encrypted payloads are base64-encoded opaque blobs.

---

## Table of Contents

- [Authentication](#authentication)
- [Users & Profiles](#users--profiles)
- [Nodes](#nodes)
- [Channels](#channels)
- [Channel Categories](#channel-categories)
- [Messages](#messages)
- [Reactions](#reactions)
- [Message Pinning](#message-pinning)
- [Threads](#threads)
- [Search](#search)
- [Files](#files)
- [Invites](#invites)
- [Moderation](#moderation)
- [Roles & Permissions](#roles--permissions)
- [Channel Permission Overwrites](#channel-permission-overwrites)
- [Voice](#voice)
- [Custom Emojis](#custom-emojis)
- [Webhooks](#webhooks)
- [Sender Keys (Group E2EE)](#sender-keys-group-e2ee)
- [Batch API](#batch-api)
- [Friends](#friends)
- [Direct Messages](#direct-messages)
- [User Blocking](#user-blocking)
- [Key Exchange (E2EE)](#key-exchange-e2ee)
- [Push Notifications](#push-notifications)
- [Bot API v2](#bot-api-v2)
- [Federation](#federation)
- [Admin](#admin)
- [Miscellaneous](#miscellaneous)
- [WebSocket API](#websocket-api)

---

## Authentication

### `POST /register` — Register a new user

**Auth required:** No

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | string | Yes | User's public key (Ed25519, base64 or hex) |
| `password` | string | No | Password for authentication |
| `display_name` | string | No | Initial display name |

**Response (200):**
```json
{
  "user_id": "uuid",
  "message": "User registered successfully"
}
```

**Rate limit:** 3 registrations per hour per IP.

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"public_key": "base64-encoded-key", "password": "secret"}'
```

---

### `POST /auth` — Authenticate

**Auth required:** No

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | string | One of these | User's public key |
| `public_key_hash` | string | One of these | SHA-256 hex hash of public key |
| `password` | string | Yes | Password |

**Headers (optional):**
- `X-Build-Hash` — Client build hash for relay-level enforcement.

**Response (200):**
```json
{
  "token": "auth-token-string",
  "user_id": "uuid",
  "expires_at": 1700000000
}
```

**Rate limit:** 5 attempts per minute per IP.

```bash
curl -X POST http://localhost:8080/auth \
  -H "Content-Type: application/json" \
  -d '{"public_key": "base64-key", "password": "secret"}'
```

---

## Users & Profiles

### `GET /users/:id/profile` — Get user profile

**Auth required:** Yes (token)

**Response (200):**
```json
{
  "user_id": "uuid",
  "display_name": "Alice",
  "avatar_url": null,
  "bio": "Hello!",
  "status": "online",
  "custom_status": "Working",
  "updated_at": 1700000000
}
```

```bash
curl "http://localhost:8080/users/{user_id}/profile?token=AUTH_TOKEN"
```

---

### `PATCH /users/me/profile` — Update own profile

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `display_name` | string | No | New display name |
| `bio` | string | No | Bio (max 500 chars) |
| `status` | string | No | `online`, `idle`, `dnd`, or `offline` |
| `custom_status` | string | No | Custom status text |

**Response (200):**
```json
{ "status": "updated", "user_id": "uuid" }
```

```bash
curl -X PATCH "http://localhost:8080/users/me/profile?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice", "bio": "Hello world"}'
```

---

### `PUT /users/me/avatar` — Upload user avatar

**Auth required:** Yes (token or Bearer header)  
**Content-Type:** `multipart/form-data`

**Form fields:**
| Field | Type | Description |
|-------|------|-------------|
| `avatar` or `file` | file | Image file (PNG, JPEG, GIF, WebP). Max 256KB. |

**Response (200):**
```json
{ "status": "updated", "avatar_hash": "sha256hex" }
```

```bash
curl -X PUT "http://localhost:8080/users/me/avatar?token=AUTH_TOKEN" \
  -F "avatar=@photo.png"
```

---

### `GET /users/:id/avatar` — Get user avatar

**Auth required:** No

**Response:** Raw image bytes with appropriate `Content-Type` header. Returns `304` with `ETag` caching.

```bash
curl -o avatar.png "http://localhost:8080/users/{user_id}/avatar"
```

---

## Nodes

### `POST /nodes` — Create a Node

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Node name |
| `description` | string | No | Node description |

**Response (200):**
```json
{
  "id": "uuid",
  "name": "My Server",
  "owner_id": "uuid",
  "description": "A cool server",
  "created_at": 1700000000
}
```

```bash
curl -X POST "http://localhost:8080/nodes?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Server", "description": "Welcome!"}'
```

---

### `GET /nodes` — List user's Nodes

**Auth required:** Yes (token)

**Response (200):**
```json
[
  {
    "id": "uuid",
    "name": "My Server",
    "owner_id": "uuid",
    "description": "...",
    "created_at": 1700000000,
    "icon_hash": "sha256hex"
  }
]
```

```bash
curl "http://localhost:8080/nodes?token=AUTH_TOKEN"
```

---

### `GET /nodes/:id` — Get Node info

**Auth required:** No

**Response (200):** `NodeInfo` object with id, name, owner_id, description, member count, channels, created_at.

```bash
curl "http://localhost:8080/nodes/{node_id}"
```

---

### `PATCH /nodes/:id` — Update Node settings

**Auth required:** Yes (token, Admin permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | New name |
| `description` | string | No | New description |

**Response (200):**
```json
{ "status": "updated", "node_id": "uuid" }
```

```bash
curl -X PATCH "http://localhost:8080/nodes/{node_id}?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Renamed Server"}'
```

---

### `POST /nodes/:id/join` — Join a Node

**Auth required:** Yes (token)

**Headers (optional):** `X-Build-Hash` — checked against Node's build allowlist.

**Request body (optional):**
| Field | Type | Description |
|-------|------|-------------|
| `device_fingerprint_hash` | string | Device fingerprint for ban enforcement |

**Response (200):**
```json
{ "status": "joined", "node_id": "uuid" }
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/join?token=AUTH_TOKEN"
```

---

### `POST /nodes/:id/leave` — Leave a Node

**Auth required:** Yes (token)

**Response (200):**
```json
{ "status": "left", "node_id": "uuid" }
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/leave?token=AUTH_TOKEN"
```

---

### `GET /nodes/:id/members` — Get Node members with profiles

**Auth required:** Yes (token, must be member)

**Response (200):**
```json
{
  "members": [
    {
      "user_id": "uuid",
      "public_key_hash": "hex",
      "role": "admin",
      "joined_at": 1700000000,
      "profile": { "user_id": "uuid", "display_name": "...", "status": "online", ... }
    }
  ]
}
```

```bash
curl "http://localhost:8080/nodes/{node_id}/members?token=AUTH_TOKEN"
```

---

### `DELETE /nodes/:id/members/:user_id` — Kick a user

**Auth required:** Yes (token, Admin/Mod permission)

**Response (200):**
```json
{ "status": "kicked", "node_id": "uuid", "user_id": "uuid" }
```

```bash
curl -X DELETE "http://localhost:8080/nodes/{node_id}/members/{user_id}?token=AUTH_TOKEN"
```

---

### `PUT /nodes/:id/icon` — Upload Node icon

**Auth required:** Yes (token or Bearer, ManageChannels permission)  
**Content-Type:** `multipart/form-data`

**Form fields:**
| Field | Type | Description |
|-------|------|-------------|
| `icon` or `file` | file | Image (PNG/JPEG/GIF/WebP, max 256KB) |

**Response (200):**
```json
{ "status": "updated", "icon_hash": "sha256hex" }
```

```bash
curl -X PUT "http://localhost:8080/nodes/{node_id}/icon?token=AUTH_TOKEN" \
  -F "icon=@server-icon.png"
```

---

### `GET /nodes/:id/icon` — Get Node icon

**Auth required:** No

**Response:** Raw image bytes with `Content-Type` and `ETag` headers.

```bash
curl -o icon.png "http://localhost:8080/nodes/{node_id}/icon"
```

---

### `GET /api/presence/:id` — Get Node presence

**Auth required:** Yes (token, must be member)

**Response (200):**
```json
{
  "members": [
    { "user_id": "uuid", "status": "online", "custom_status": "Working", "updated_at": 1700000000 }
  ]
}
```

```bash
curl "http://localhost:8080/api/presence/{node_id}?token=AUTH_TOKEN"
```

---

### `PUT /nodes/:id/profile` — Set per-Node user profile

**Auth required:** Yes (token, must be member)

**Request body:**
| Field | Type | Description |
|-------|------|-------------|
| `encrypted_display_name` | string | Base64-encoded encrypted display name |
| `encrypted_avatar_url` | string | Base64-encoded encrypted avatar URL |

**Response (200):**
```json
{ "status": "updated", "node_id": "uuid", "user_id": "uuid" }
```

```bash
curl -X PUT "http://localhost:8080/nodes/{node_id}/profile?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"encrypted_display_name": "base64..."}'
```

---

### `GET /nodes/:id/profiles` — Get per-Node user profiles

**Auth required:** Yes (token, must be member)

**Response (200):**
```json
{
  "profiles": [
    {
      "node_id": "uuid",
      "user_id": "uuid",
      "encrypted_display_name": "base64...",
      "encrypted_avatar_url": "base64...",
      "joined_at": 1700000000
    }
  ]
}
```

```bash
curl "http://localhost:8080/nodes/{node_id}/profiles?token=AUTH_TOKEN"
```

---

### `GET /nodes/:id/audit-log` — Get Node audit log

**Auth required:** Yes (token, ViewAuditLog permission — Admin/Mod)

**Query params:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | u32 | 50 | Max entries (capped at 100) |
| `before` | uuid | — | Cursor for pagination |

**Response (200):**
```json
{
  "entries": [
    {
      "id": "uuid",
      "node_id": "uuid",
      "actor_id": "uuid",
      "actor_public_key_hash": "hex",
      "action": "member_kick",
      "target_type": "user",
      "target_id": "uuid",
      "details": "{\"kicked_user_id\": \"uuid\"}",
      "created_at": 1700000000
    }
  ],
  "has_more": false,
  "next_cursor": null
}
```

```bash
curl "http://localhost:8080/nodes/{node_id}/audit-log?token=AUTH_TOKEN&limit=25"
```

---

### `POST /nodes/:id/import-discord-template` — Import Discord template

**Auth required:** Yes (token, ManageNode/Admin permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `template_code` | string | One of these | Discord template code (fetched from Discord API) |
| `template_json` | object | One of these | Pre-fetched template JSON |

**Response (200):**
```json
{
  "roles_created": 5,
  "roles_updated": 1,
  "roles_skipped": 0,
  "categories_created": 3,
  "text_channels_created": 8,
  "voice_channels_created": 2,
  "overwrites_created": 12,
  "unsupported_permissions_stripped": ["Use Application Commands (bit 7)"]
}
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/import-discord-template?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"template_code": "RHzsRPA9xrRW"}'
```

---

## Channels

### `POST /nodes/:id/channels` — Create a channel

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Channel name (default: "general") |
| `channel_type` | string | No | `"text"` (default), `"voice"`, or `"category"` |

**Response (200):**
```json
{
  "id": "uuid",
  "name": "general",
  "node_id": "uuid",
  "created_at": 1700000000,
  "channel_type": "text"
}
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/channels?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "off-topic", "channel_type": "text"}'
```

---

### `GET /nodes/:id/channels` — List Node channels

**Auth required:** Yes (token)

**Response (200):**
```json
[
  {
    "id": "uuid",
    "name": "general",
    "node_id": "uuid",
    "created_at": 1700000000,
    "unread_count": 3,
    "channel_type": "text"
  }
]
```

```bash
curl "http://localhost:8080/nodes/{node_id}/channels?token=AUTH_TOKEN"
```

---

### `PATCH /channels/:id` — Update channel (category/position)

**Auth required:** Yes (token, ManageChannels permission)

**Request body:**
| Field | Type | Description |
|-------|------|-------------|
| `category_id` | uuid | New parent category (null to remove) |
| `position` | u32 | New sort position |

**Response (200):**
```json
{ "status": "updated", "channel_id": "uuid" }
```

```bash
curl -X PATCH "http://localhost:8080/channels/{channel_id}?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"category_id": "cat-uuid", "position": 2}'
```

---

### `DELETE /channels/:id` — Delete a channel

**Auth required:** Yes (token, Admin permission)

**Response (200):**
```json
{ "status": "deleted", "channel_id": "uuid" }
```

```bash
curl -X DELETE "http://localhost:8080/channels/{channel_id}?token=AUTH_TOKEN"
```

---

### `PUT /nodes/:id/channels/reorder` — Reorder channels

**Auth required:** Yes (token, ManageChannels permission)

**Request body:**
```json
{
  "channels": [
    { "id": "channel-uuid-1", "position": 0, "category_id": "cat-uuid" },
    { "id": "channel-uuid-2", "position": 1, "category_id": null }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `channels` | array | Yes | Array of channel reorder entries |
| `channels[].id` | uuid | Yes | Channel ID |
| `channels[].position` | i32 | Yes | New sort position |
| `channels[].category_id` | uuid | No | New parent category (null to unset) |

**Response:** `204 No Content`

```bash
curl -X PUT "http://localhost:8080/nodes/{node_id}/channels/reorder?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channels": [{"id": "uuid", "position": 0, "category_id": null}]}'
```

---

### `POST /channels/:id/read` — Mark channel as read

**Auth required:** Yes (token, channel member)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `message_id` | uuid | Yes | Last read message ID |

**Response (200):**
```json
{ "status": "ok" }
```

```bash
curl -X POST "http://localhost:8080/channels/{channel_id}/read?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message_id": "msg-uuid"}'
```

---

## Channel Categories

### `POST /nodes/:id/categories` — Create category

**Auth required:** Yes (token, ManageChannels permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Category name |

**Response (200):**
```json
{ "id": "uuid", "name": "Text Channels", "position": 0, "created_at": 1700000000 }
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/categories?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Text Channels"}'
```

---

### `PATCH /categories/:id` — Update category

**Auth required:** Yes (token, ManageChannels permission)

**Request body:**
| Field | Type | Description |
|-------|------|-------------|
| `name` | string | New name |
| `position` | u32 | New position |

**Response (200):**
```json
{ "status": "updated", "category_id": "uuid" }
```

```bash
curl -X PATCH "http://localhost:8080/categories/{cat_id}?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Voice Channels", "position": 1}'
```

---

### `DELETE /categories/:id` — Delete category

**Auth required:** Yes (token, ManageChannels permission)

**Response (200):**
```json
{ "status": "deleted", "category_id": "uuid" }
```

```bash
curl -X DELETE "http://localhost:8080/categories/{cat_id}?token=AUTH_TOKEN"
```

---

## Messages

### `GET /channels/:id/messages` — Get channel message history

**Auth required:** Yes (token, channel access)

**Query params:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | u32 | 50 | Messages per page (max 100) |
| `before` | uuid | — | Message ID cursor for pagination |

**Response (200):**
```json
{
  "messages": [
    {
      "id": "uuid",
      "channel_id": "uuid",
      "sender_id": "uuid",
      "sender_public_key_hash": "hex",
      "encrypted_display_name": "base64...",
      "display_name": "Alice",
      "encrypted_payload": "base64-encrypted-content",
      "created_at": 1700000000,
      "edited_at": null,
      "pinned_at": null,
      "pinned_by": null,
      "reply_to": null,
      "replied_message": null,
      "reply_count": 0
    }
  ],
  "has_more": true,
  "next_cursor": "uuid"
}
```

```bash
curl "http://localhost:8080/channels/{channel_id}/messages?token=AUTH_TOKEN&limit=25"
```

---

### `PATCH /messages/:id` — Edit a message

**Auth required:** Yes (token or Bearer, must be message author)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `encrypted_data` | string | Yes | Base64-encoded new encrypted content |

**Response (200):**
```json
{ "success": true }
```

```bash
curl -X PATCH "http://localhost:8080/messages/{msg_id}?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"encrypted_data": "base64..."}'
```

---

### `DELETE /messages/:id` — Delete a message

**Auth required:** Yes (token or Bearer, must be author or admin)

**Response (200):**
```json
{ "success": true }
```

```bash
curl -X DELETE "http://localhost:8080/messages/{msg_id}?token=AUTH_TOKEN"
```

---

## Reactions

### `PUT /messages/:id/reactions/:emoji` — Add reaction

**Auth required:** Yes (token, channel member)

**Response (200):**
```json
{
  "success": true,
  "reactions": [
    { "emoji": "👍", "count": 2, "users": ["uuid1", "uuid2"], "created_at": 1700000000 }
  ]
}
```

```bash
curl -X PUT "http://localhost:8080/messages/{msg_id}/reactions/👍?token=AUTH_TOKEN"
```

---

### `DELETE /messages/:id/reactions/:emoji` — Remove reaction

**Auth required:** Yes (token, channel member)

**Response (200):**
```json
{ "success": true, "reactions": [...] }
```

```bash
curl -X DELETE "http://localhost:8080/messages/{msg_id}/reactions/👍?token=AUTH_TOKEN"
```

---

### `GET /messages/:id/reactions` — Get message reactions

**Auth required:** Yes (token, channel member)

**Response (200):**
```json
{
  "reactions": [
    { "emoji": "👍", "count": 2, "users": ["uuid1", "uuid2"], "created_at": 1700000000 }
  ]
}
```

```bash
curl "http://localhost:8080/messages/{msg_id}/reactions?token=AUTH_TOKEN"
```

---

## Message Pinning

### `PUT /messages/:id/pin` — Pin a message

**Auth required:** Yes (token, Admin/Mod)

**Response (200):**
```json
{ "success": true, "message": "Message pinned successfully" }
```

```bash
curl -X PUT "http://localhost:8080/messages/{msg_id}/pin?token=AUTH_TOKEN"
```

---

### `DELETE /messages/:id/pin` — Unpin a message

**Auth required:** Yes (token, Admin/Mod)

**Response (200):**
```json
{ "success": true, "message": "Message unpinned successfully" }
```

```bash
curl -X DELETE "http://localhost:8080/messages/{msg_id}/pin?token=AUTH_TOKEN"
```

---

### `GET /channels/:id/pins` — Get pinned messages

**Auth required:** Yes (token, channel member)

**Response (200):**
```json
{
  "pinned_messages": [...]
}
```

```bash
curl "http://localhost:8080/channels/{channel_id}/pins?token=AUTH_TOKEN"
```

---

## Threads

### `GET /channels/:id/threads` — List thread starters

**Auth required:** Yes (token, channel member)

**Query params:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | u32 | 50 | Max threads to return |

**Response (200):**
```json
{ "threads": [...] }
```

```bash
curl "http://localhost:8080/channels/{channel_id}/threads?token=AUTH_TOKEN"
```

---

### `GET /messages/:id/thread` — Get thread replies

**Auth required:** Yes (token, channel member)

**Response (200):**
```json
{
  "messages": [...],
  "has_more": false,
  "next_cursor": null
}
```

```bash
curl "http://localhost:8080/messages/{msg_id}/thread?token=AUTH_TOKEN"
```

---

## Search

### `GET /nodes/:id/search` — Search messages in a Node

**Auth required:** Yes (token, must be member)

**Query params:**
| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `q` | string | Yes | Search query |
| `channel` | uuid | No | Filter by channel |
| `author` | uuid | No | Filter by author |
| `before` | i64 | No | Before timestamp (epoch) |
| `after` | i64 | No | After timestamp (epoch) |
| `limit` | u32 | No | Max results (default 25, max 200) |

> **Note:** Search operates on metadata only. Message content is E2E encrypted — full-text search must happen client-side after decryption.

**Response (200):**
```json
{
  "results": [
    {
      "message_id": "uuid",
      "channel_id": "uuid",
      "channel_name": "general",
      "sender_id": "uuid",
      "sender_public_key_hash": "hex",
      "created_at": 1700000000,
      "encrypted_payload": "base64..."
    }
  ],
  "total_count": 5,
  "search_query": "hello",
  "note": "Search results include metadata only..."
}
```

```bash
curl "http://localhost:8080/nodes/{node_id}/search?token=AUTH_TOKEN&q=hello&limit=10"
```

---

## Files

### `POST /channels/:id/files` — Upload encrypted file

**Auth required:** Yes (token or Bearer, channel member)  
**Content-Type:** `multipart/form-data`

**Form fields:**
| Field | Type | Description |
|-------|------|-------------|
| `encrypted_filename` | bytes | Encrypted original filename |
| `file` | file | Encrypted file data |

**Response (200):**
```json
{ "file_id": "uuid", "message": "File uploaded successfully" }
```

```bash
curl -X POST "http://localhost:8080/channels/{channel_id}/files?token=AUTH_TOKEN" \
  -F "encrypted_filename=@enc_name.bin" \
  -F "file=@encrypted_file.bin"
```

---

### `GET /channels/:id/files` — List channel files

**Auth required:** Yes (token or Bearer, channel member)

**Response (200):** Array of `FileMetadata` objects.

```bash
curl "http://localhost:8080/channels/{channel_id}/files?token=AUTH_TOKEN"
```

---

### `GET /files/:id` — Download file

**Auth required:** Yes (token or Bearer, channel member)

**Response:** Raw binary file data with `application/octet-stream` content type.

```bash
curl -o file.bin "http://localhost:8080/files/{file_id}?token=AUTH_TOKEN"
```

---

### `DELETE /files/:id` — Delete file

**Auth required:** Yes (token or Bearer, uploader or admin)

**Response (200):**
```json
{ "message": "File deleted successfully" }
```

```bash
curl -X DELETE "http://localhost:8080/files/{file_id}?token=AUTH_TOKEN"
```

---

## Invites

### `POST /nodes/:id/invites` — Create invite

**Auth required:** Yes (token, Admin/Mod)

**Request body (optional):**
| Field | Type | Description |
|-------|------|-------------|
| `max_uses` | u32 | Max uses (null = unlimited) |
| `expires_in_hours` | u32 | Hours until expiry (null = never) |

**Response (200):**
```json
{
  "id": "uuid",
  "invite_code": "abc123",
  "max_uses": 10,
  "expires_at": 1700003600,
  "created_at": 1700000000
}
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/invites?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_uses": 10, "expires_in_hours": 24}'
```

---

### `GET /nodes/:id/invites` — List invites

**Auth required:** Yes (token, Admin/Mod)

**Response (200):**
```json
{ "invites": [...] }
```

```bash
curl "http://localhost:8080/nodes/{node_id}/invites?token=AUTH_TOKEN"
```

---

### `DELETE /invites/:invite_id` — Revoke invite

**Auth required:** Yes (token, Admin/Mod)

**Response (200):**
```json
{ "status": "revoked", "invite_id": "uuid" }
```

```bash
curl -X DELETE "http://localhost:8080/invites/{invite_id}?token=AUTH_TOKEN"
```

---

### `POST /invites/:code/join` — Use invite to join Node

**Auth required:** Yes (token)

**Response (200):**
```json
{ "status": "joined", "node_id": "uuid", "node_name": "My Server" }
```

```bash
curl -X POST "http://localhost:8080/invites/abc123/join?token=AUTH_TOKEN"
```

---

### `GET /invites/:code/preview` — Preview invite (no auth)

**Auth required:** No

Returns basic Node info for an invite code without joining. Used by clients to show a preview before the user decides to join.

**Response (200):**
```json
{
  "node_name": "My Server",
  "node_id": "uuid",
  "member_count": 42,
  "server_build_hash": "abc123..."
}
```

**Error responses:**
- `404` — Invalid invite code
- `410` — Invite expired or max uses reached

```bash
curl "http://localhost:8080/invites/abc123/preview"
```

---

## Moderation

### `POST /nodes/:id/bans` — Ban a user

**Auth required:** Yes (token, KickMembers permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key_hash` | string | Yes | SHA-256 hex hash of banned user's public key |
| `reason_encrypted` | string | No | Base64-encoded encrypted reason |
| `expires_at` | u64 | No | Unix timestamp for ban expiry |
| `device_fingerprint_hash` | string | No | Device fingerprint to also ban |

**Response (200):**
```json
{ "status": "banned", "node_id": "uuid", "public_key_hash": "hex..." }
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/bans?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"public_key_hash": "abcdef..."}'
```

---

### `DELETE /nodes/:id/bans` — Unban a user

**Auth required:** Yes (token, KickMembers permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key_hash` | string | Yes | SHA-256 hex hash to unban |

**Response (200):**
```json
{ "status": "unbanned", "node_id": "uuid", "public_key_hash": "hex..." }
```

```bash
curl -X DELETE "http://localhost:8080/nodes/{node_id}/bans?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"public_key_hash": "abcdef..."}'
```

---

### `GET /nodes/:id/bans` — List bans

**Auth required:** Yes (token, KickMembers permission)

**Response (200):**
```json
{ "bans": [...] }
```

```bash
curl "http://localhost:8080/nodes/{node_id}/bans?token=AUTH_TOKEN"
```

---

### `GET /nodes/:id/ban-check` — Check ban status

**Auth required:** Yes (token)

**Query params:**
| Param | Type | Description |
|-------|------|-------------|
| `public_key_hash` | string | Public key hash to check |
| `device_fingerprint_hash` | string | Device fingerprint to check |

At least one param is required.

**Response (200):**
```json
{ "banned": true, "key_banned": true, "device_banned": false }
```

```bash
curl "http://localhost:8080/nodes/{node_id}/ban-check?token=AUTH_TOKEN&public_key_hash=abc..."
```

---

### `PUT /channels/:id/slow-mode` — Set slow mode

**Auth required:** Yes (token, ManageChannels permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `seconds` | u32 | Yes | Cooldown in seconds (0 to disable, max 3600) |

**Response (200):**
```json
{ "status": "updated", "channel_id": "uuid", "slow_mode_seconds": 10 }
```

```bash
curl -X PUT "http://localhost:8080/channels/{channel_id}/slow-mode?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"seconds": 10}'
```

---

### `GET /channels/:id/slow-mode` — Get slow mode

**Auth required:** Yes (token)

**Response (200):**
```json
{ "channel_id": "uuid", "slow_mode_seconds": 10 }
```

```bash
curl "http://localhost:8080/channels/{channel_id}/slow-mode?token=AUTH_TOKEN"
```

---

### `POST /nodes/:id/auto-mod/words` — Add auto-mod word

**Auth required:** Yes (token, ManageNode permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `word` | string | Yes | Word to filter (1-100 chars, lowercased) |
| `action` | string | Yes | `block` or `warn` |

**Response (200):**
```json
{ "status": "added", "word": "badword", "action": "block" }
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/auto-mod/words?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"word": "badword", "action": "block"}'
```

---

### `DELETE /nodes/:id/auto-mod/words/:word` — Remove auto-mod word

**Auth required:** Yes (token, ManageNode permission)

**Response (200):**
```json
{ "status": "removed", "word": "badword" }
```

```bash
curl -X DELETE "http://localhost:8080/nodes/{node_id}/auto-mod/words/badword?token=AUTH_TOKEN"
```

---

### `GET /nodes/:id/auto-mod/words` — List auto-mod words

**Auth required:** Yes (token, must be member)

**Response (200):**
```json
{ "words": [{ "node_id": "uuid", "word": "badword", "action": "block", "created_at": 1700000000 }] }
```

```bash
curl "http://localhost:8080/nodes/{node_id}/auto-mod/words?token=AUTH_TOKEN"
```

---

## Roles & Permissions

### `GET /nodes/:id/roles` — List roles

**Auth required:** Yes (token)

**Response (200):**
```json
{
  "roles": [
    {
      "id": "uuid", "node_id": "uuid", "name": "@everyone",
      "color": 0, "permissions": 66115, "position": 0,
      "hoist": false, "mentionable": false, "icon_emoji": null, "created_at": 1700000000
    }
  ]
}
```

```bash
curl "http://localhost:8080/nodes/{node_id}/roles?token=AUTH_TOKEN"
```

---

### `POST /nodes/:id/roles` — Create role

**Auth required:** Yes (token, MANAGE_ROLES permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Role name |
| `color` | u32 | No | RGB color integer (default 0) |
| `permissions` | u64 | No | Permission bitmask (default 0) |
| `hoist` | bool | No | Show separately in member list |
| `mentionable` | bool | No | Can be @mentioned by anyone |
| `icon_emoji` | string | No | Unicode emoji for role icon |

**Response (200):** The created `Role` object.

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/roles?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Moderator", "color": 3447003, "permissions": 6}'
```

---

### `PATCH /nodes/:id/roles/:role_id` — Update role

**Auth required:** Yes (token, MANAGE_ROLES permission)

**Request body:** Same fields as create (all optional).

**Response (200):** The updated `Role` object.

```bash
curl -X PATCH "http://localhost:8080/nodes/{node_id}/roles/{role_id}?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Senior Mod", "permissions": 14}'
```

---

### `DELETE /nodes/:id/roles/:role_id` — Delete role

**Auth required:** Yes (token, MANAGE_ROLES permission)

Cannot delete the `@everyone` role (position 0).

**Response:** `204 No Content`

```bash
curl -X DELETE "http://localhost:8080/nodes/{node_id}/roles/{role_id}?token=AUTH_TOKEN"
```

---

### `PATCH /nodes/:id/roles/reorder` — Reorder roles

**Auth required:** Yes (token, MANAGE_ROLES permission)

**Request body:**
```json
{
  "roles": [
    { "id": "role-uuid-1", "position": 1 },
    { "id": "role-uuid-2", "position": 2 }
  ]
}
```

**Response:** `204 No Content`

```bash
curl -X PATCH "http://localhost:8080/nodes/{node_id}/roles/reorder?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"roles": [{"id": "uuid", "position": 1}]}'
```

---

### `GET /nodes/:id/members/:user_id/roles` — Get member's roles

**Auth required:** Yes (token)

**Response (200):**
```json
{ "roles": [...] }
```

```bash
curl "http://localhost:8080/nodes/{node_id}/members/{user_id}/roles?token=AUTH_TOKEN"
```

---

### `PUT /nodes/:id/members/:user_id/roles/:role_id` — Assign role

**Auth required:** Yes (token, MANAGE_ROLES permission)

**Response:** `204 No Content`

```bash
curl -X PUT "http://localhost:8080/nodes/{node_id}/members/{user_id}/roles/{role_id}?token=AUTH_TOKEN"
```

---

### `DELETE /nodes/:id/members/:user_id/roles/:role_id` — Remove role

**Auth required:** Yes (token, MANAGE_ROLES permission)

**Response:** `204 No Content`

```bash
curl -X DELETE "http://localhost:8080/nodes/{node_id}/members/{user_id}/roles/{role_id}?token=AUTH_TOKEN"
```

---

## Channel Permission Overwrites

### `GET /channels/:id/permissions` — List overwrites

**Auth required:** Yes (token)

**Response (200):**
```json
{
  "overwrites": [
    { "channel_id": "uuid", "role_id": "uuid", "allow": 2048, "deny": 0 }
  ]
}
```

```bash
curl "http://localhost:8080/channels/{channel_id}/permissions?token=AUTH_TOKEN"
```

---

### `PUT /channels/:id/permissions/:role_id` — Set overwrite

**Auth required:** Yes (token, MANAGE_CHANNELS or MANAGE_ROLES or ADMINISTRATOR)

**Request body:**
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow` | u64 | 0 | Explicitly allowed permission bits |
| `deny` | u64 | 0 | Explicitly denied permission bits |

**Response:** `204 No Content`

```bash
curl -X PUT "http://localhost:8080/channels/{channel_id}/permissions/{role_id}?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"allow": 2048, "deny": 0}'
```

---

### `DELETE /channels/:id/permissions/:role_id` — Remove overwrite

**Auth required:** Yes (token, MANAGE_CHANNELS or MANAGE_ROLES or ADMINISTRATOR)

**Response:** `204 No Content`

```bash
curl -X DELETE "http://localhost:8080/channels/{channel_id}/permissions/{role_id}?token=AUTH_TOKEN"
```

---

### `GET /channels/:id/effective-permissions` — Get effective permissions

**Auth required:** Yes (token)

Returns the computed permissions for the requesting user in a channel (after applying role + overwrite cascade).

**Response (200):**
```json
{ "permissions": 66115, "channel_id": "uuid", "user_id": "uuid" }
```

```bash
curl "http://localhost:8080/channels/{channel_id}/effective-permissions?token=AUTH_TOKEN"
```

---

### Permission Bit Reference

| Bit | Value | Name |
|-----|-------|------|
| 0 | `1` | CREATE_INVITE |
| 1 | `2` | KICK_MEMBERS |
| 2 | `4` | BAN_MEMBERS |
| 3 | `8` | ADMINISTRATOR |
| 4 | `16` | MANAGE_CHANNELS |
| 5 | `32` | MANAGE_NODE |
| 6 | `64` | ADD_REACTIONS |
| 10 | `1024` | VIEW_CHANNEL |
| 11 | `2048` | SEND_MESSAGES |
| 13 | `8192` | MANAGE_MESSAGES |
| 14 | `16384` | EMBED_LINKS |
| 15 | `32768` | ATTACH_FILES |
| 16 | `65536` | READ_MESSAGE_HISTORY |
| 17 | `131072` | MENTION_EVERYONE |
| 20 | `1048576` | CONNECT |
| 21 | `2097152` | SPEAK |
| 22 | `4194304` | MUTE_MEMBERS |
| 23 | `8388608` | DEAFEN_MEMBERS |
| 24 | `16777216` | MOVE_MEMBERS |
| 28 | `268435456` | MANAGE_ROLES |

Bit positions are intentionally Discord-compatible for template import.

---

## Voice

Voice is handled entirely over WebSocket. See the [WebSocket API](#websocket-api) section for voice message types:

- `JoinVoiceChannel` / `LeaveVoiceChannel`
- `GetVoiceParticipants`
- `VoicePacket` (encrypted audio relay)
- `VoiceSpeakingState`
- `VoiceKeyExchange` (SRTP key exchange, opaque to server)
- `SrtpVoicePacket` (SRTP encrypted audio, opaque to server)
- `SetVoiceMode` / `GetVoiceMode` (switch between relay and P2P mode)
- `VoiceOffer` / `VoiceAnswer` / `VoiceIceCandidate` (WebRTC signaling for P2P mode)
- `P2PSignal` (legacy generic WebRTC signaling, opaque to server)

---

## Custom Emojis

### `GET /nodes/:id/emojis` — List custom emojis

**Auth required:** Yes (token)

**Response (200):**
```json
{
  "emojis": [
    {
      "id": "uuid",
      "node_id": "uuid",
      "name": "pepe_dance",
      "uploaded_by": "uuid",
      "content_hash": "sha256hex",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

```bash
curl "http://localhost:8080/nodes/{node_id}/emojis?token=AUTH_TOKEN"
```

---

### `POST /nodes/:id/emojis` — Upload custom emoji

**Auth required:** Yes (token, ManageEmojis permission)  
**Content-Type:** `multipart/form-data`

**Form fields:**
| Field | Type | Description |
|-------|------|-------------|
| `file` or `image` | file | Image file (PNG, GIF, WebP — no JPEG). Max 256KB. |
| `name` | string | Emoji name (2-32 chars, alphanumeric + underscores) |

**Response (200):**
```json
{
  "id": "uuid",
  "node_id": "uuid",
  "name": "pepe_dance",
  "uploaded_by": "uuid",
  "content_hash": "sha256hex",
  "created_at": "2024-01-01T00:00:00Z"
}
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/emojis?token=AUTH_TOKEN" \
  -F "name=pepe_dance" \
  -F "image=@emoji.png"
```

---

### `DELETE /nodes/:id/emojis/:emoji_id` — Delete custom emoji

**Auth required:** Yes (token, uploader or ManageEmojis permission)

**Response (200):**
```json
{ "status": "deleted", "emoji_id": "uuid" }
```

```bash
curl -X DELETE "http://localhost:8080/nodes/{node_id}/emojis/{emoji_id}?token=AUTH_TOKEN"
```

---

### `GET /api/emojis/:content_hash` — Get emoji image

**Auth required:** No

Serves the emoji image by its content hash. Returns raw image bytes with appropriate `Content-Type` header (image/png, image/gif, or image/webp). Supports `ETag` caching.

```bash
curl -o emoji.png "http://localhost:8080/api/emojis/{content_hash}"
```

---

## Webhooks

Outbound webhooks allow node admins to receive HTTP POST notifications when events occur.

**Supported events:** `message_create`, `message_delete`, `member_join`, `member_leave`, `reaction_add`

**Delivery:** Webhooks are delivered with HMAC-SHA256 signatures for verification:
- `X-Accord-Signature` — HMAC-SHA256(secret, body) hex digest
- `X-Accord-Event` — Event type string

**Retry policy:** 3 attempts with exponential backoff (2s, 4s). 10s timeout per attempt.

### `GET /nodes/:id/webhooks` — List webhooks

**Auth required:** Yes (token, ManageNode permission)

**Response (200):**
```json
{
  "webhooks": [
    {
      "id": "uuid",
      "node_id": "uuid",
      "channel_id": null,
      "url": "https://example.com/webhook",
      "events": "message_create,member_join",
      "created_by": "uuid",
      "created_at": 1700000000,
      "active": true
    }
  ]
}
```

```bash
curl "http://localhost:8080/nodes/{node_id}/webhooks?token=AUTH_TOKEN"
```

---

### `POST /nodes/:id/webhooks` — Create webhook

**Auth required:** Yes (token, ManageNode permission)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | Webhook delivery URL |
| `events` | string[] | Yes | Event types to subscribe to |
| `channel_id` | uuid | No | Filter to specific channel (null = all channels) |
| `secret` | string | No | HMAC secret (auto-generated if omitted) |

**Response (200):**
```json
{
  "id": "uuid",
  "node_id": "uuid",
  "channel_id": null,
  "url": "https://example.com/webhook",
  "secret": "hex-encoded-secret",
  "events": "message_create,member_join",
  "created_by": "uuid",
  "created_at": 1700000000,
  "active": true
}
```

```bash
curl -X POST "http://localhost:8080/nodes/{node_id}/webhooks?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/hook", "events": ["message_create"]}'
```

---

### `PATCH /webhooks/:id` — Update webhook

**Auth required:** Yes (token, ManageNode permission on webhook's node)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | No | New delivery URL |
| `events` | string[] | No | New event subscriptions |
| `channel_id` | uuid | No | New channel filter |
| `secret` | string | No | New HMAC secret |
| `active` | bool | No | Enable/disable webhook |

**Response (200):**
```json
{ "status": "updated", "id": "uuid" }
```

```bash
curl -X PATCH "http://localhost:8080/webhooks/{webhook_id}?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"active": false}'
```

---

### `DELETE /webhooks/:id` — Delete webhook

**Auth required:** Yes (token, ManageNode permission on webhook's node)

**Response (200):**
```json
{ "status": "deleted", "id": "uuid" }
```

```bash
curl -X DELETE "http://localhost:8080/webhooks/{webhook_id}?token=AUTH_TOKEN"
```

---

### `POST /webhooks/:id/test` — Send test webhook

**Auth required:** Yes (token, ManageNode permission on webhook's node)

Sends a test payload to the webhook URL to verify connectivity.

**Response (200):**
```json
{ "status": "sent", "response_status": 200 }
```

Or on failure:
```json
{ "status": "failed", "error": "Connection refused" }
```

```bash
curl -X POST "http://localhost:8080/webhooks/{webhook_id}/test?token=AUTH_TOKEN"
```

---

## Sender Keys (Group E2EE)

Sender Keys enable efficient group encryption for channels. Each sender distributes a Sender Key to all channel members via Double Ratchet-encrypted messages. The server stores and relays these opaque blobs without being able to read them.

### `POST /channels/:id/sender-keys` — Store sender key distribution

**Auth required:** Yes (token, must be node member)

Stores an encrypted Sender Key distribution for a specific recipient. The server also sends a real-time WebSocket notification to the recipient.

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to_user_id` | uuid | Yes | Recipient user ID (must be in same node) |
| `payload` | string | Yes | Base64-encoded DR-encrypted Sender Key distribution message |

**Response (200):**
```json
{ "id": "uuid", "status": "stored" }
```

```bash
curl -X POST "http://localhost:8080/channels/{channel_id}/sender-keys?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to_user_id": "uuid", "payload": "base64..."}'
```

---

### `GET /sender-keys/pending` — Get pending sender key distributions

**Auth required:** Yes (token)

Returns all pending Sender Key distributions for the authenticated user.

**Response (200):**
```json
{
  "distributions": [
    {
      "id": "uuid",
      "channel_id": "uuid",
      "from_user_id": "uuid",
      "to_user_id": "uuid",
      "encrypted_payload": "base64...",
      "created_at": 1700000000
    }
  ]
}
```

```bash
curl "http://localhost:8080/sender-keys/pending?token=AUTH_TOKEN"
```

---

### `POST /sender-keys/ack` — Acknowledge sender key distributions

**Auth required:** Yes (token)

Marks sender key distributions as received so they won't be returned by `/sender-keys/pending` again.

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ids` | uuid[] | Yes | Distribution IDs to acknowledge |

**Response (200):**
```json
{ "acknowledged": 3 }
```

```bash
curl -X POST "http://localhost:8080/sender-keys/ack?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["uuid1", "uuid2", "uuid3"]}'
```

---

## Batch API

Batch endpoints return aggregated data in single responses, eliminating N+1 query patterns. Designed for initial page loads.

### `GET /api/nodes/:node_id/members/batch` — Batch members

**Auth required:** Yes (token, must be node member)

Returns all members with their roles, profiles, and online status in a single response.

**Response (200):**
```json
{
  "members": [
    {
      "user_id": "uuid",
      "display_name": "Alice",
      "avatar_url": null,
      "roles": [
        { "id": "uuid", "name": "Moderator", "color": 3447003, "position": 1, "hoist": true }
      ],
      "online": true,
      "status": "online",
      "custom_status": "Working",
      "joined_at": 1700000000,
      "node_role": "admin"
    }
  ],
  "roles": [...]
}
```

```bash
curl "http://localhost:8080/api/nodes/{node_id}/members/batch?token=AUTH_TOKEN"
```

---

### `GET /api/nodes/:node_id/channels/batch` — Batch channels

**Auth required:** Yes (token, must be node member)

Returns all channels with their permission overrides, unread counts, and category info.

**Response (200):**
```json
{
  "channels": [
    {
      "id": "uuid",
      "name": "general",
      "node_id": "uuid",
      "category_id": "uuid",
      "category_name": "Text Channels",
      "position": 0,
      "permission_overrides": [
        { "role_id": "uuid", "allow": 2048, "deny": 0 }
      ],
      "unread_count": 3,
      "channel_type": "text"
    }
  ]
}
```

```bash
curl "http://localhost:8080/api/nodes/{node_id}/channels/batch?token=AUTH_TOKEN"
```

---

### `GET /api/nodes/:node_id/overview` — Node overview

**Auth required:** Yes (token, must be node member)

Returns node info + channels + members + roles in a single call. Designed for initial node load.

**Response (200):**
```json
{
  "node": { "id": "uuid", "name": "My Server", "owner_id": "uuid", ... },
  "channels": [
    {
      "id": "uuid", "name": "general", "node_id": "uuid",
      "category_id": null, "category_name": null,
      "position": 0, "unread_count": 3, "channel_type": "text"
    }
  ],
  "members": [
    {
      "user_id": "uuid", "display_name": "Alice", "avatar_url": null,
      "roles": [{ "id": "uuid", "name": "Admin", "color": 0, "position": 1 }],
      "online": true, "status": "online", "joined_at": 1700000000, "node_role": "admin"
    }
  ],
  "roles": [...]
}
```

```bash
curl "http://localhost:8080/api/nodes/{node_id}/overview?token=AUTH_TOKEN"
```

---

## Friends

### `POST /friends/request` — Send friend request

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to_user_id` | uuid | Yes | Target user |
| `node_id` | uuid | Yes | Shared Node (must share a Node) |
| `dm_key_bundle` | string | No | Base64-encoded DM key bundle |

**Response (200):**
```json
{ "status": "sent", "request_id": "uuid" }
```

```bash
curl -X POST "http://localhost:8080/friends/request?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to_user_id": "uuid", "node_id": "uuid"}'
```

---

### `POST /friends/accept` — Accept friend request

**Auth required:** Yes (token, must be request recipient)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | uuid | Yes | Friend request ID |
| `friendship_proof` | string | No | Base64-encoded proof |

**Response (200):**
```json
{ "status": "accepted" }
```

```bash
curl -X POST "http://localhost:8080/friends/accept?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"request_id": "uuid"}'
```

---

### `POST /friends/reject` — Reject friend request

**Auth required:** Yes (token, must be request recipient)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | uuid | Yes | Friend request ID |

**Response (200):**
```json
{ "status": "rejected" }
```

```bash
curl -X POST "http://localhost:8080/friends/reject?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"request_id": "uuid"}'
```

---

### `GET /friends` — List friends

**Auth required:** Yes (token)

**Response (200):**
```json
{ "friends": [...] }
```

```bash
curl "http://localhost:8080/friends?token=AUTH_TOKEN"
```

---

### `GET /friends/requests` — List pending friend requests

**Auth required:** Yes (token)

**Response (200):**
```json
{ "requests": [...] }
```

```bash
curl "http://localhost:8080/friends/requests?token=AUTH_TOKEN"
```

---

### `DELETE /friends/:user_id` — Remove friend

**Auth required:** Yes (token)

**Response (200):**
```json
{ "status": "removed" }
```

```bash
curl -X DELETE "http://localhost:8080/friends/{user_id}?token=AUTH_TOKEN"
```

---

## Direct Messages

### `POST /dm/:user_id` — Create/get DM channel

**Auth required:** Yes (token)

Requires friendship (unless a DM channel already exists).

**Response (200):**
```json
{ "id": "uuid", "user1_id": "uuid", "user2_id": "uuid", "created_at": 1700000000 }
```

```bash
curl -X POST "http://localhost:8080/dm/{target_user_id}?token=AUTH_TOKEN"
```

---

### `GET /dm` — List DM channels

**Auth required:** Yes (token)

**Response (200):**
```json
{
  "dm_channels": [
    {
      "id": "uuid",
      "user1_id": "uuid",
      "user2_id": "uuid",
      "other_user": { ... },
      "other_user_profile": { ... },
      "last_message": { ... },
      "unread_count": 2,
      "created_at": 1700000000
    }
  ]
}
```

```bash
curl "http://localhost:8080/dm?token=AUTH_TOKEN"
```

---

## User Blocking

### `POST /users/:id/block` — Block a user

**Auth required:** Yes (token)

**Response (200):**
```json
{ "status": "blocked", "user_id": "uuid" }
```

```bash
curl -X POST "http://localhost:8080/users/{user_id}/block?token=AUTH_TOKEN"
```

---

### `DELETE /users/:id/block` — Unblock a user

**Auth required:** Yes (token)

**Response (200):**
```json
{ "status": "unblocked", "user_id": "uuid" }
```

```bash
curl -X DELETE "http://localhost:8080/users/{user_id}/block?token=AUTH_TOKEN"
```

---

### `GET /api/blocked-users` — List blocked users

**Auth required:** Yes (token)

**Response (200):**
```json
{
  "blocked_users": [
    { "user_id": "uuid", "created_at": 1700000000 }
  ]
}
```

```bash
curl "http://localhost:8080/api/blocked-users?token=AUTH_TOKEN"
```

---

## Key Exchange (E2EE)

These endpoints support X3DH / Double Ratchet key exchange for end-to-end encryption.

### `POST /keys/bundle` — Publish prekey bundle

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity_key` | string | Yes | Base64-encoded identity key |
| `signed_prekey` | string | Yes | Base64-encoded signed prekey |
| `one_time_prekeys` | string[] | Yes | Array of base64-encoded one-time prekeys |

**Response (200):**
```json
{ "status": "published", "one_time_prekeys_stored": 10 }
```

```bash
curl -X POST "http://localhost:8080/keys/bundle?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"identity_key": "base64...", "signed_prekey": "base64...", "one_time_prekeys": ["base64..."]}'
```

---

### `GET /keys/bundle/:user_id` — Fetch user's prekey bundle

**Auth required:** Yes (token)

One one-time prekey is consumed per fetch.

**Response (200):**
```json
{
  "user_id": "uuid",
  "identity_key": "base64...",
  "signed_prekey": "base64...",
  "one_time_prekey": "base64..."
}
```

```bash
curl "http://localhost:8080/keys/bundle/{user_id}?token=AUTH_TOKEN"
```

---

### `POST /keys/prekey-message` — Store prekey message

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `recipient_id` | uuid | Yes | Recipient user ID |
| `message_data` | string | Yes | Base64-encoded encrypted message |

**Response (200):**
```json
{ "status": "stored", "message_id": "uuid" }
```

```bash
curl -X POST "http://localhost:8080/keys/prekey-message?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipient_id": "uuid", "message_data": "base64..."}'
```

---

### `GET /keys/prekey-messages` — Get pending prekey messages

**Auth required:** Yes (token)

Returns and deletes pending prekey messages for the authenticated user.

**Response (200):**
```json
{
  "messages": [
    { "id": "uuid", "sender_id": "uuid", "message_data": "base64...", "created_at": 1700000000 }
  ]
}
```

```bash
curl "http://localhost:8080/keys/prekey-messages?token=AUTH_TOKEN"
```

---

## Push Notifications

### `POST /push/register` — Register device token

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `platform` | string | Yes | `ios` or `android` |
| `token` | string | Yes | Device push token |
| `privacy_level` | string | No | `full`, `partial` (default), or `stealth` |

**Response (200):**
```json
{ "id": "uuid", "status": "registered" }
```

```bash
curl -X POST "http://localhost:8080/push/register?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"platform": "ios", "token": "device-push-token"}'
```

---

### `DELETE /push/register` — Deregister device token

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | Yes | Device push token to remove |

**Response (200):**
```json
{ "status": "deregistered" }
```

```bash
curl -X DELETE "http://localhost:8080/push/register?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"token": "device-push-token"}'
```

---

### `PUT /push/preferences` — Update push preferences

**Auth required:** Yes (token)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `privacy_level` | string | Yes | `full`, `partial`, or `stealth` |
| `token` | string | No | Update only this specific token |

**Response (200):**
```json
{ "status": "updated", "tokens_updated": 1 }
```

```bash
curl -X PUT "http://localhost:8080/push/preferences?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"privacy_level": "stealth"}'
```

---

## Bot API v2

Bot API v2 uses an **airgapped command architecture**. Bots are stateless command processors that never see messages, member lists, or encrypted data. They register command manifests and respond to invocations via webhooks. All bot ↔ Node communication supports optional E2EE via X25519 key exchange + AES-256-GCM.

### Concepts

- **Manifest:** A JSON declaration of the bot's identity and available commands
- **Install:** An admin installs a bot on a Node by providing its manifest and webhook URL
- **Invoke:** Any member can invoke a bot command; the server forwards it to the bot's webhook
- **Respond:** The bot posts a response back via its bot token; the server broadcasts to the channel
- **E2EE (optional):** If the bot provides an X25519 public key, invocations are encrypted. Key rotation happens automatically every 24h or 1000 invocations.

### `GET /api/nodes/:node_id/bots` — List installed bots

**Auth required:** Yes (token, must be node member)

**Response (200):**
```json
[
  {
    "bot_id": "weather-bot",
    "name": "Weather",
    "icon": "🌤️",
    "description": "Get weather forecasts",
    "commands": [
      {
        "name": "forecast",
        "description": "Get weather forecast",
        "params": [
          { "name": "location", "type": "string", "required": true, "description": "City name" }
        ]
      }
    ],
    "installed_at": 1700000000,
    "invocation_count": 42
  }
]
```

```bash
curl "http://localhost:8080/api/nodes/{node_id}/bots?token=AUTH_TOKEN"
```

---

### `POST /api/nodes/:node_id/bots` — Install bot on Node

**Auth required:** Yes (token, Node admin only)

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `manifest` | object | Yes | Bot manifest (see below) |
| `manifest.bot_id` | string | Yes | Unique bot identifier |
| `manifest.name` | string | Yes | Display name |
| `manifest.icon` | string | No | Emoji or icon URL |
| `manifest.description` | string | No | Bot description |
| `manifest.commands` | array | Yes | Array of command definitions |
| `webhook_url` | string | Yes | URL to receive command invocations |
| `ed25519_pubkey` | string | No | Bot's Ed25519 public key (base64) for signature verification |
| `x25519_pubkey` | string | No | Bot's X25519 public key (base64) for E2EE key exchange |
| `allowed_channels` | string[] | No | Channel IDs the bot can respond in (empty = all) |

**Command definition:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Command name |
| `description` | string | Yes | Command description |
| `params` | array | No | Array of parameter definitions |
| `params[].name` | string | Yes | Parameter name |
| `params[].type` | string | Yes | Parameter type (e.g. `"string"`, `"number"`) |
| `params[].required` | bool | No | Whether the parameter is required |
| `params[].default` | any | No | Default value |
| `params[].description` | string | No | Parameter description |

**Response (200):**
```json
{
  "bot_id": "weather-bot",
  "bot_token": "accord_botv2_...",
  "node_x25519_pubkey": "base64...",
  "message": "Bot installed successfully. Store the bot_token securely."
}
```

> **Important:** The `bot_token` is shown only once. Store it securely — it's used by the bot to authenticate responses.

```bash
curl -X POST "http://localhost:8080/api/nodes/{node_id}/bots?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "manifest": {
      "bot_id": "weather-bot",
      "name": "Weather",
      "commands": [{"name": "forecast", "description": "Get forecast", "params": [{"name": "location", "type": "string", "required": true}]}]
    },
    "webhook_url": "https://my-bot.example.com/webhook"
  }'
```

---

### `DELETE /api/nodes/:node_id/bots/:bot_id` — Uninstall bot

**Auth required:** Yes (token, Node admin only)

Removes the bot and securely zeroizes all associated cryptographic material.

**Response (200):**
```json
{ "status": "uninstalled", "bot_id": "weather-bot" }
```

```bash
curl -X DELETE "http://localhost:8080/api/nodes/{node_id}/bots/weather-bot?token=AUTH_TOKEN"
```

---

### `GET /api/nodes/:node_id/bots/:bot_id/commands` — Get bot commands

**Auth required:** Yes (token, must be node member)

**Response (200):**
```json
[
  {
    "name": "forecast",
    "description": "Get weather forecast",
    "params": [
      { "name": "location", "type": "string", "required": true }
    ]
  }
]
```

```bash
curl "http://localhost:8080/api/nodes/{node_id}/bots/weather-bot/commands?token=AUTH_TOKEN"
```

---

### `POST /api/nodes/:node_id/bots/:bot_id/invoke` — Invoke bot command

**Auth required:** Yes (token, must be node member)

Sends a command invocation to the bot's webhook. The server generates an `invocation_id` and delivers the command asynchronously. If E2EE is configured, the payload is encrypted with AES-256-GCM.

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | Yes | Command name to invoke |
| `params` | object | No | Command parameters (key-value pairs) |
| `channel_id` | string | Yes | Channel context for the response |

**Response (200):**
```json
{ "invocation_id": "uuid", "status": "sent" }
```

**Webhook payload sent to bot (plaintext mode):**
```json
{
  "type": "command_invocation",
  "command": "forecast",
  "invoker_display_name": "Alice",
  "params": { "location": "Minneapolis" },
  "invocation_id": "uuid",
  "channel_id": "uuid"
}
```

```bash
curl -X POST "http://localhost:8080/api/nodes/{node_id}/bots/weather-bot/invoke?token=AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "forecast", "params": {"location": "Minneapolis"}, "channel_id": "chan-uuid"}'
```

---

### `POST /api/bots/respond` — Bot responds to invocation

**Auth required:** Yes (`Authorization: Bearer <bot_token>`)

Called by the bot to deliver a response. The server broadcasts the response to channel members via WebSocket as a `bot_response` event.

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `invocation_id` | string | Yes | The invocation being responded to |
| `content` | object | Yes | Response content (see below) |
| `signature` | string | No | Ed25519 signature of content (base64) |

**Response content types:**

**Text:**
```json
{ "type": "text", "text": "The forecast for Minneapolis is 72°F and sunny." }
```

**Embed (rich response):**
```json
{
  "type": "embed",
  "title": "Weather Forecast",
  "sections": [
    { "type": "text", "text": "Current conditions for Minneapolis" },
    { "type": "fields", "fields": [
      { "name": "Temperature", "value": "72°F", "inline": true },
      { "name": "Humidity", "value": "45%", "inline": true }
    ]},
    { "type": "divider" },
    { "type": "grid", "columns": ["Day", "High", "Low"], "rows": [["Mon", "75", "60"], ["Tue", "70", "55"]] },
    { "type": "image", "url": "https://example.com/weather-map.png", "alt": "Weather map" },
    { "type": "code", "code": "console.log('hello')", "language": "javascript" },
    { "type": "progress", "label": "UV Index", "value": 6, "max": 11 },
    { "type": "actions", "buttons": [
      { "label": "Refresh", "command": "forecast", "params": {"location": "Minneapolis"} }
    ]},
    { "type": "input", "name": "city", "placeholder": "Enter city...", "command": "forecast" }
  ]
}
```

**Response (200):**
```json
{ "status": "delivered" }
```

```bash
curl -X POST "http://localhost:8080/api/bots/respond" \
  -H "Authorization: Bearer accord_botv2_..." \
  -H "Content-Type: application/json" \
  -d '{"invocation_id": "uuid", "content": {"type": "text", "text": "Hello!"}}'
```

---

## Federation

Federation enables relay-to-relay discovery, registration, and health monitoring. Endpoints are optionally authenticated via the `X-Mesh-Secret` header (if `mesh_secret` is configured; otherwise open federation).

### `GET /federation/relays` — List known relays

**Auth required:** No (or mesh secret if configured)

**Response (200):**
```json
{
  "relays": [
    {
      "relay_id": "relay-abc123",
      "hostname": "relay2.example.com",
      "port": 8443,
      "public_key": "base64-ed25519-pubkey",
      "last_seen": 1700000000,
      "status": "active",
      "registered_at": 1699900000
    }
  ]
}
```

```bash
curl "http://localhost:8080/federation/relays"
```

---

### `POST /federation/register` — Register relay

**Auth required:** Mesh secret (if configured)

Announces a relay to the federation network.

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `relay_id` | string | Yes | Unique relay identifier |
| `hostname` | string | Yes | Relay hostname |
| `port` | u16 | Yes | Relay port |
| `public_key` | string | Yes | Ed25519 public key (base64) |

**Response (200):**
```json
{ "ok": true, "message": "Relay registered" }
```

```bash
curl -X POST "http://localhost:8080/federation/register" \
  -H "Content-Type: application/json" \
  -H "X-Mesh-Secret: your-mesh-secret" \
  -d '{"relay_id": "relay-1", "hostname": "relay.example.com", "port": 8443, "public_key": "base64..."}'
```

---

### `POST /federation/heartbeat` — Relay heartbeat

**Auth required:** Mesh secret (if configured)

Periodic liveness ping. If a relay misses 3 heartbeats, it's marked inactive.

**Request body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `relay_id` | string | Yes | Relay ID to heartbeat |

**Response (200):**
```json
{ "ok": true, "message": "Heartbeat acknowledged" }
```

**Error (404):** Relay not registered — call `/federation/register` first.

```bash
curl -X POST "http://localhost:8080/federation/heartbeat" \
  -H "Content-Type: application/json" \
  -H "X-Mesh-Secret: your-mesh-secret" \
  -d '{"relay_id": "relay-1"}'
```

---

## Admin

Admin endpoints require the `ACCORD_ADMIN_TOKEN` environment variable to be set. Authenticate via `X-Admin-Token` header or `?admin_token=` query param.

### `GET /admin` — Admin dashboard HTML page

**Auth required:** No (page loads, data requires admin token)

---

### `GET /admin/stats` — Server statistics

**Auth required:** Yes (admin token)

**Response (200):**
```json
{
  "user_count": 42,
  "node_count": 5,
  "message_count": 10000,
  "connection_count": 12,
  "uptime_seconds": 86400,
  "version": "0.1.0",
  "memory_bytes": 52428800
}
```

```bash
curl -H "X-Admin-Token: YOUR_ADMIN_TOKEN" "http://localhost:8080/admin/stats"
```

---

### `GET /admin/users` — List all users

**Auth required:** Yes (admin token)

```bash
curl -H "X-Admin-Token: YOUR_ADMIN_TOKEN" "http://localhost:8080/admin/users"
```

---

### `GET /admin/nodes` — List all nodes

**Auth required:** Yes (admin token)

```bash
curl -H "X-Admin-Token: YOUR_ADMIN_TOKEN" "http://localhost:8080/admin/nodes"
```

---

### `GET /admin/logs` (WebSocket) — Live log streaming

**Auth required:** Yes (admin token)

Connect via WebSocket to receive real-time server log lines.

```bash
websocat "ws://localhost:8080/admin/logs?admin_token=YOUR_ADMIN_TOKEN"
```

---

### `GET /api/admin/audit-log` — Relay-level audit log

**Auth required:** Yes (admin token)

---

### `GET /api/admin/audit-log/actions` — List audit log action types

**Auth required:** Yes (admin token)

---

### Relay Build Allowlist (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/build-allowlist` | List relay-level allowed build hashes |
| `PUT` | `/api/admin/build-allowlist` | Replace entire allowlist |
| `POST` | `/api/admin/build-allowlist` | Add a build hash |
| `DELETE` | `/api/admin/build-allowlist/:hash` | Remove a build hash |

All require admin token authentication.

---

### Node Build Allowlist

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/nodes/:id/build-allowlist` | List Node's allowed build hashes |
| `PUT` | `/nodes/:id/build-allowlist` | Replace entire allowlist |
| `POST` | `/nodes/:id/build-allowlist` | Add a build hash |
| `DELETE` | `/nodes/:id/build-allowlist/:hash` | Remove a build hash |

All require token auth + ManageNode permission.

---

## Miscellaneous

### `GET /health` — Health check

**Auth required:** No

**Response (200):**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 86400,
  "build_hash": "abc123...",
  "database_ok": true,
  "websocket_connections": 12,
  "memory_usage_bytes": 52428800
}
```

```bash
curl "http://localhost:8080/health"
```

---

### `GET /api/build-info` — Server build info

**Auth required:** No

**Response (200):**
```json
{
  "commit_hash": "abc123",
  "version": "0.1.0",
  "build_hash": "sha256...",
  "build_timestamp": "2024-01-01T00:00:00Z",
  "target_triple": "x86_64-unknown-linux-gnu"
}
```

```bash
curl "http://localhost:8080/api/build-info"
```

---

### `GET /api/link-preview` — Link preview (Open Graph)

**Auth required:** Yes (token)

**Query params:**
| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | URL to fetch OG metadata from |

SSRF protection: blocks private/reserved IPs. Results cached 1 hour.

**Response (200):**
```json
{
  "title": "Example Page",
  "description": "A page description",
  "image": "https://example.com/og-image.jpg",
  "siteName": "Example",
  "url": "https://example.com"
}
```

```bash
curl "http://localhost:8080/api/link-preview?token=AUTH_TOKEN&url=https://example.com"
```

---

## WebSocket API

### Connection

Connect to `ws(s)://<host>:<port>/ws`

**Authentication (two methods):**

1. **Post-upgrade auth (recommended):** Connect without token, then send an `Authenticate` message within 5 seconds:
   ```json
   { "Authenticate": { "token": "your-auth-token" } }
   ```

2. **Legacy query param:** `ws://host:port/ws?token=AUTH_TOKEN` (deprecated)

**Optional header:** `X-Build-Hash` for build verification.

### Server → Client Events

After authentication, the server sends:

```json
{ "type": "authenticated", "user_id": "uuid" }
```

Then a welcome message:

```json
{
  "type": "hello",
  "server_version": "0.1.0",
  "server_build_hash": "abc...",
  "protocol_version": 1
}
```

### Message Envelope

All client → server messages use this envelope:

```json
{
  "message_type": { "ChannelMessage": { "channel_id": "uuid", "encrypted_data": "base64..." } },
  "message_id": "uuid",
  "timestamp": 1700000000
}
```

### Client → Server Message Types

| Type | Fields | Description |
|------|--------|-------------|
| `CreateNode` | `name`, `description?` | Create a new Node |
| `JoinNode` | `node_id` | Join a Node |
| `LeaveNode` | `node_id` | Leave a Node |
| `GetNodeInfo` | `node_id` | Request Node info |
| `JoinChannel` | `channel_id` | Subscribe to channel messages |
| `LeaveChannel` | `channel_id` | Unsubscribe from channel |
| `CreateChannel` | `node_id`, `name` | Create a channel |
| `ChannelMessage` | `channel_id`, `encrypted_data`, `reply_to?` | Send encrypted message |
| `DirectMessage` | `to_user`, `encrypted_data` | Send encrypted DM |
| `EditMessage` | `message_id`, `encrypted_data` | Edit a message |
| `DeleteMessage` | `message_id` | Delete a message |
| `AddReaction` | `message_id`, `emoji` | Add reaction |
| `RemoveReaction` | `message_id`, `emoji` | Remove reaction |
| `PinMessage` | `message_id` | Pin (admin/mod) |
| `UnpinMessage` | `message_id` | Unpin (admin/mod) |
| `TypingStart` | `channel_id` | Typing indicator |
| `JoinVoiceChannel` | `channel_id` | Join voice channel |
| `LeaveVoiceChannel` | `channel_id` | Leave voice channel |
| `GetVoiceParticipants` | `channel_id` | List voice participants |
| `VoicePacket` | `channel_id`, `encrypted_audio`, `sequence` | Send encrypted audio |
| `VoiceSpeakingState` | `channel_id`, `user_id`, `speaking` | Speaking state |
| `VoiceKeyExchange` | `channel_id`, `wrapped_key`, `target_user_id?`, `sender_ssrc`, `key_generation` | SRTP key exchange |
| `SrtpVoicePacket` | `channel_id`, `packet_data` | SRTP audio packet |
| `SetVoiceMode` | `channel_id`, `mode` | Set voice mode (`"relay"` or `"p2p"`) |
| `GetVoiceMode` | `channel_id` | Get current voice mode for channel |
| `P2PSignal` | `channel_id`, `target_user_id`, `signal_data` | Legacy generic WebRTC signaling |
| `VoiceOffer` | `channel_id`, `target_user_id`, `sdp` | WebRTC SDP offer (P2P mode only) |
| `VoiceAnswer` | `channel_id`, `target_user_id`, `sdp` | WebRTC SDP answer (P2P mode only) |
| `VoiceIceCandidate` | `channel_id`, `target_user_id`, `candidate` | WebRTC ICE candidate (P2P mode only) |
| `PublishKeyBundle` | `identity_key`, `signed_prekey`, `one_time_prekeys` | Publish E2EE keys |
| `FetchKeyBundle` | `target_user_id` | Fetch user's keys |
| `StorePrekeyMessage` | `recipient_id`, `message_data` | Store prekey message |
| `GetPrekeyMessages` | — | Get pending prekey messages |
| `StoreSenderKey` | `channel_id`, `to_user_id`, `payload` | Store Sender Key distribution (base64 DR-encrypted) |
| `GetPendingSenderKeys` | — | Get pending Sender Key distributions |
| `AckSenderKeys` | `ids` | Acknowledge received Sender Key distributions |
| `UpdateChannel` | `channel_id`, `category_id?`, `position?` | Update channel category/position |
| `BotResponse` | `bot_id`, `invocation_id`, `content` | Server→client: bot response broadcast |
| `Ping` | — | Heartbeat |

### Server → Client Event Types

| Event `type` | Description |
|--------------|-------------|
| `hello` | Welcome with server info |
| `authenticated` | Auth confirmed |
| `channel_message` | Message in channel (includes `from`, `channel_id`, `encrypted_data`, `message_id`, `timestamp`, `reply_to`, `sender_display_name`) |
| `message_edit` | Message edited (includes `message_id`, `channel_id`, `encrypted_data`, `edited_at`) |
| `message_delete` | Message deleted (includes `message_id`, `channel_id`) |
| `reaction_add` | Reaction added (includes `message_id`, `channel_id`, `user_id`, `emoji`, `reactions`) |
| `reaction_remove` | Reaction removed (same fields as reaction_add) |
| `message_pin` | Message pinned (includes `message_id`, `channel_id`, `pinned_by`) |
| `message_unpin` | Message unpinned |
| `typing_start` | User started typing (includes `channel_id`, `user_id`) |
| `read_receipt` | Channel read receipt (includes `user_id`, `channel_id`, `message_id`) |
| `voice_channel_joined` | Joined voice (includes participant list) |
| `voice_channel_left` | Left voice |
| `voice_peer_joined` | New peer in voice channel |
| `voice_peer_left` | Peer left voice channel |
| `voice_participants` | Voice participant list |
| `voice_packet` | Encrypted audio from peer |
| `voice_speaking_state` | Peer speaking state change |
| `voice_key_exchange` | SRTP key exchange relay |
| `srtp_voice_packet` | SRTP audio relay |
| `p2p_signal` | WebRTC signaling relay |
| `voice_offer` | WebRTC SDP offer relay (P2P mode) |
| `voice_answer` | WebRTC SDP answer relay (P2P mode) |
| `voice_ice_candidate` | WebRTC ICE candidate relay (P2P mode) |
| `voice_mode` | Voice mode response (`channel_id`, `mode`) |
| `sender_key_distribution` | Sender Key received notification |
| `bot_response` | Bot command response (`bot_id`, `invocation_id`, `content`) |
| `node_created` | Node created confirmation |
| `node_joined` | Joined Node confirmation |
| `node_left` | Left Node confirmation |
| `node_info` | Node info response |
| `channel_created` | Channel created confirmation |
| `key_bundle_published` | Key bundle stored |
| `key_bundle_response` | Fetched key bundle |
| `prekey_message_stored` | Prekey message stored |
| `prekey_messages` | Pending prekey messages |
| `pong` | Heartbeat response |
| `error` | Error (includes `message`, optional `code`) |
| `server_shutdown` | Server shutting down |
| `presence_update` | User presence changed |

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Human-readable error message",
  "code": 400
}
```

Common HTTP status codes:
- `400` — Bad request
- `401` — Unauthorized (missing/invalid token)
- `403` — Forbidden (insufficient permissions)
- `404` — Not found
- `409` — Conflict (duplicate)
- `429` — Rate limited
- `500` — Internal server error

---

## Rate Limiting

| Action | Limit |
|--------|-------|
| Registration | 3 per hour per IP |
| Authentication | 5 per minute per IP |
| File upload | Per-user rate limit |
| Reactions | Per-user rate limit |
| Profile updates | Per-user rate limit |
| Direct messages | Per-user rate limit |

Rate limit responses include `Retry-After` information in the error message.
