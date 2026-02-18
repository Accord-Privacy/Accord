# Metadata Modes

The Accord relay server supports two metadata storage modes, controlled by the
`--metadata-mode` CLI flag (default: `standard`).

## Quick Start

```bash
# Default — full backward compatibility
accord-server --metadata-mode standard

# Privacy-hardened — relay stores only routing-essential data
accord-server --metadata-mode minimal
```

## What's Stored in Each Mode

| Data field | Standard | Minimal | Notes |
|---|---|---|---|
| **User identity** | | | |
| `users.id` (UUID) | ✅ | ✅ | Routing key |
| `users.public_key_hash` | ✅ | ✅ | Authentication / identity |
| `users.public_key` | ✅ | ✅ | Key exchange |
| `users.created_at` | ✅ | ✅ | — |
| **Node metadata** | | | |
| `nodes.name` (plaintext) | ✅ | `[redacted]` | Use `encrypted_name` instead |
| `nodes.description` (plaintext) | ✅ | Omitted (`NULL`) | Use `encrypted_description` instead |
| `nodes.encrypted_name` | ✅ | ✅ | Opaque blob, relay can't read |
| `nodes.encrypted_description` | ✅ | ✅ | Opaque blob, relay can't read |
| `nodes.owner_id` | ✅ | ✅ | Routing / permissions |
| `nodes.created_at` | ✅ | ✅ | — |
| **Channel metadata** | | | |
| `channels.name` (plaintext) | ✅ | `[redacted]` | Use `encrypted_name` instead |
| `channels.encrypted_name` | ✅ | ✅ | Opaque blob |
| `channels.node_id` | ✅ | ✅ | Routing |
| `channels.created_at` | ✅ | ✅ | Ordering |
| **Channel categories** | | | |
| `channel_categories.name` | ✅ | `[redacted]` | Use `encrypted_name` instead |
| `channel_categories.encrypted_name` | ✅ | ✅ | Opaque blob |
| **Messages** | | | |
| `messages.encrypted_payload` | ✅ | ✅ | E2E encrypted blob — relay never reads content |
| `messages.channel_id` | ✅ | ✅ | Routing |
| `messages.sender_id` | ✅ | ✅ | Routing |
| `messages.created_at` | ✅ | ✅ | Ordering |
| `messages.edited_at` | ✅ | ✅ | — |
| **User profiles (relay-level)** | | | |
| `user_profiles.display_name` | ✅ | `[redacted]` | Plaintext stripped in minimal |
| `user_profiles.bio` | ✅ | Omitted (`NULL`) | — |
| `user_profiles.status` | ✅ | ✅ | Routing (online/offline/dnd/idle) |
| `user_profiles.custom_status` | ✅ | Omitted (`NULL`) | — |
| `user_profiles.display_name_encrypted` | ✅ | ✅ | Opaque blob |
| **Node user profiles** | | | |
| `node_user_profiles.encrypted_display_name` | ✅ | ✅ | Encrypted, opaque to relay |
| `node_user_profiles.encrypted_avatar_url` | ✅ | ✅ | Encrypted, opaque to relay |
| **Typing / presence** | In-memory | In-memory | Never persisted in either mode |
| **Voice channel state** | In-memory | In-memory | Never persisted in either mode |

## Design Principles

1. **Backward compatible** — `standard` mode behaves exactly as before.
2. **Routing data always stored** — UUIDs, channel→node mappings, membership, keys.
3. **Encrypted blobs always stored** — the relay can't read them anyway.
4. **Plaintext metadata stripped** — names, descriptions, bios replaced with `[redacted]` or `NULL`.
5. **Presence is ephemeral** — typing indicators and voice state are in-memory only in both modes (verified).

## Implementation

Metadata stripping is applied at the `AppState` layer (in `state.rs`) before data reaches the database. The `metadata` module provides `strip_*` functions that are no-ops in `standard` mode and sanitize in `minimal` mode.
