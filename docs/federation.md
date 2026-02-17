# Accord Federation Protocol v1

## Overview

Federation enables Accord servers to communicate with each other, allowing users on different servers to interact — similar to email or Matrix federation, but simpler and privacy-first.

**Key principle:** E2E encryption is preserved across federation. Federated servers are relays, not endpoints. They cannot read message content.

## Architecture

### Server Identity

Each Accord server has an **Ed25519 keypair** that serves as its cryptographic identity:

- **Private key**: Used to sign all outbound federation messages
- **Public key**: Shared with other servers for signature verification

Server identity is generated on first run and persisted. The public key is published via the well-known endpoint.

### User Identifiers

Federated user IDs follow the format: `username@server.domain`

- `alice@accord.example.com` — Alice on the `accord.example.com` server
- The `@domain` suffix is only needed for cross-server interactions
- Local users can omit the domain

### Discovery

Servers discover each other via a well-known URL:

```
GET https://<domain>/.well-known/accord-federation
```

Response:
```json
{
  "federation_endpoint": "https://accord.example.com",
  "public_key": "<base64 Ed25519 public key>",
  "protocol_version": 1
}
```

DNS SRV records (`_accord-federation._tcp.<domain>`) may be supported in future versions.

### Federation is Opt-in

- **Server level**: Federation must be explicitly enabled in server config
- **Node level**: Each Node admin decides whether their Node participates in federation
- **Allowlist/blocklist**: Server admins can restrict which remote servers are allowed

## Message Format

Every federation message is wrapped in a signed envelope:

```json
{
  "sender_domain": "server-a.com",
  "recipient_domain": "server-b.com",
  "timestamp": 1708185600,
  "nonce": "<base64 random 16 bytes>",
  "event": { ... },
  "signature": "<base64 Ed25519 signature>"
}
```

### Signature

The signature covers the canonical form:

```
sender_domain | recipient_domain | timestamp (LE u64) | nonce | event_json
```

Fields are concatenated with `|` byte separators. The timestamp is encoded as little-endian u64 bytes.

### Replay Protection

- **Nonce**: Each message has a unique random nonce. Receiving servers track recent nonces and reject duplicates.
- **Timestamp window**: Messages older than 5 minutes are rejected.
- **Future rejection**: Messages with timestamps more than 30 seconds in the future are rejected (clock skew tolerance).

## Event Types

### Message
Relay an E2E encrypted message between users on different servers.
```json
{
  "event_type": "Message",
  "payload": {
    "message_id": "<uuid>",
    "from": { "username": "alice", "server_domain": "a.com" },
    "to": { "username": "bob", "server_domain": "b.com" },
    "encrypted_payload": "<base64 E2E encrypted data>",
    "reply_to": null
  }
}
```

### TypingStart
Relay typing indicators.

### PresenceUpdate
Share user presence status across servers.

### JoinRequest / JoinResponse
Handle cross-server Node membership.

### Leave
User leaves a federated Node.

### ServerHello
Initial handshake — servers exchange identity and capabilities.

## Server Verification

Servers verify each other via **challenge-response**:

1. Server A sends a random challenge to Server B: `POST /v1/federation/challenge`
2. Server B signs the challenge with its private key and returns the signature + server info
3. Server A verifies the signature against Server B's public key
4. Server A registers Server B's public key for future message verification

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/accord-federation` | Discovery endpoint |
| POST | `/v1/federation/inbox` | Receive federation messages |
| POST | `/v1/federation/challenge` | Challenge-response verification |
| GET | `/v1/federation/info` | Server info |

## Security Considerations

1. **All federation messages are signed** — unsigned or invalid signatures are rejected
2. **E2E encryption is preserved** — federation servers cannot read content
3. **Replay protection** — nonce tracking + timestamp windows
4. **Opt-in federation** — nothing is federated by default
5. **Server allowlist/blocklist** — admins control which servers can communicate
6. **TLS required** — all federation traffic uses HTTPS
7. **No trust escalation** — a federated server cannot gain elevated permissions

## Configuration

```toml
[federation]
enabled = true
server_domain = "accord.example.com"
allowed_servers = []  # empty = open federation
blocked_servers = ["evil.com"]
federated_node_ids = ["uuid-of-federated-node"]
```

## Future Work

- DNS SRV record discovery
- Federated file transfer
- Cross-server voice channels
- Federation key rotation
- Mutual TLS as alternative to challenge-response
- Rate limiting per federated server
- Federation admin dashboard
