# Node Architecture

## Core Concepts

### Users Join Nodes, Not Servers
Users never interact with "relay servers" directly. The relay server is invisible infrastructure. Users discover, join, and communicate within **Nodes**.

### Invite Links
A Node invite encodes: `accord://<relay-address>/<node-id>/<invite-code>`
The client resolves the relay server transparently — users just click a link and join a Node.

## Admin Model

### Server Admin
- Manages the relay server instance (hardware, networking, updates)
- Sets Node creation policy: `admin_only | open | approval | invite`
- Monitors server resources and health
- **Has NO automatic access to Nodes** — cannot read content, manage members, or admin Nodes they don't own
- Think: landlord. Provides the building, can't enter apartments.

### Node Admin
- Creates and manages their Node
- Controls channels, roles, members, invites
- Sets Node-level permissions and policies
- Doesn't need to know about relay server infrastructure
- Think: tenant running a community in their space.

### Discoverability
- **Node → Server Admin:** Permission-gated. Node admins/members can discover the server admin for abuse reports, support, etc. — if the server admin allows it.
- **Server Admin → Node:** Server admin can see Node metadata (name, member count, creation date) for resource management, but CANNOT access Node content, channels, or member details beyond what's needed for routing.

## Permission Hierarchy

```
Server Admin
├── Create/delete Nodes (per creation policy)
├── Set server-wide policies (rate limits, storage quotas)
├── View Node metadata (name, size — NOT content)
├── Suspend/remove Nodes (abuse, ToS violations)
└── NO access to Node internals

Node Admin (per Node)
├── Manage channels (create, delete, configure)
├── Manage roles and permissions
├── Invite/remove members
├── Set Node-level policies (invite rules, etc.)
└── Appoint moderators and other admins
```

## Security Properties
- **E2E encryption** — relay server (and server admin) cannot read any message content
- **Admin isolation** — server admin ≠ Node admin. No automatic privilege escalation.
- **Metadata minimization** — server stores only what's needed for routing
- **Zero-knowledge Nodes** — Node content is opaque to the relay infrastructure
