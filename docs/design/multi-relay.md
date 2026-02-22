# Multi-Relay Architecture

## Overview
Move from single-relay connection to per-Node relay connections. Users create identities locally and connect to relays on-demand when joining Nodes.

## Current Architecture
- One global `accord_server_url` in localStorage
- One WebSocket connection (`ws` state in App.tsx)
- One API instance with one base URL
- One auth token for everything
- Registration happens during setup wizard

## Target Architecture

### Identity = Local Only
- Keypair + password stored locally
- No relay involved in account creation
- Setup wizard: create identity → done (no network)

### Per-Relay Connections
- Each relay gets its own: WebSocket, API client, auth token
- User may have tokens on 3 different relays simultaneously
- Lazy registration: first time joining a Node on relay X, register keypair there

### Data Model
```typescript
interface RelayState {
  url: string;              // normalized relay URL
  token: string | null;     // auth token for this relay
  userId: string | null;    // user ID on this relay
  ws: AccordWebSocket | null;
  connected: boolean;
  nodes: string[];          // Node IDs on this relay
}

// Stored in localStorage as JSON
interface StoredRelay {
  url: string;
  token: string;
  userId: string;
  nodeIds: string[];
}
```

### RelayManager (new class)
- `connect(relayUrl)` → establish WS + ensure registered
- `disconnect(relayUrl)` → close WS
- `getApi(relayUrl)` → API client for that relay
- `getWs(relayUrl)` → WebSocket for that relay
- `ensureRegistered(relayUrl, publicKey, password)` → register if needed
- `joinNode(inviteLink)` → parse invite → connect to relay → join node
- Stores relay list in `accord_relays` localStorage key

### Setup Wizard (simplified)
1. Create Identity (password + keygen + mnemonic)
2. Done. No relay connection.
3. Main UI shows empty state: "Join a Node to get started" with invite link input

### Join Flow
1. User pastes invite link anywhere (sidebar, empty state, menu)
2. `parseInviteLink()` extracts relay URL + invite code
3. RelayManager connects to relay, registers if needed
4. Joins Node via invite code
5. Node appears in sidebar, messages flow

### Migration
- On first load with old `accord_server_url`, migrate to new relay list format
- Existing token preserved

## Implementation Phases

### Phase 1: RelayManager + Storage
- New `RelayManager.ts` class
- `StoredRelay` persistence in localStorage
- Migration from `accord_server_url`
- Multi-API client support

### Phase 2: Simplify Setup Wizard  
- Identity-only creation (no relay step)
- Empty state UI with "Join a Node" prompt
- Remove `accord_server_url` dependency from auth flow

### Phase 3: Multi-WebSocket
- WebSocket per relay
- Event routing (which relay did this message come from?)
- Reconnect logic per relay
- Presence per relay

### Phase 3.5: Invite Preview
- New server endpoint: `GET /invites/:code/preview` (no auth required)
- Returns: node name, node ID hash, member count, server build hash
- Frontend shows preview card before joining: name, fingerprint, members, trust status
- User confirms "Join" or cancels

### Phase 4: Wire Everything
- App.tsx state management refactor
- Node sidebar shows Nodes from all relays
- Channel selection routes to correct relay
- Messages route to correct relay API/WS
