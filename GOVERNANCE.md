# Governance & Moderation Philosophy

Accord is deliberately **not** a moderated platform. This document states the
principles that govern who is responsible for what — and why the relay is built
to be unable to police content even if someone wanted it to. These are design
invariants: features that violate them are rejected regardless of convenience.

> The relay is a landlord — it provides the building, but it cannot enter your
> apartment, does not hold a master key, and keeps no record of who visits whom.

---

## 1. The parent model

**Parents are responsible for what their children see and do on Accord.** Because
the relay cannot read message content and Accord performs no central moderation,
there is no platform-side filter standing between a minor and a node's content.
Monitoring a child's access to and usage of nodes is the parent's job, the same
way it is for a general-purpose web browser.

Accord will never add relay-side or otherwise centralized content scanning to
compensate for this — doing so would require breaking the end-to-end encryption
that is the entire point of the project.

## 2. Moderation is the node owner's duty

**Node owners are 100% responsible for the content shared within their
community.** Moderation tools (roles, bans, slow mode, per-node word filters,
disappearing messages) exist, but they are operated by the node owner and their
delegated moderators, and they run **client-side or within the node's own trust
boundary** — never at the relay.

Accord will not moderate nodes in any capacity through any central means. There
are no platform administrators who can read, edit, or remove the contents of a
node. There is no cross-node ban list, no keyword scanning at the relay, and no
appeal process to "Accord" — because Accord-the-infrastructure cannot see inside
your node to begin with.

## 3. Accord is not a "safe space"

Accord **cannot and will not** guarantee that any node or user follows a broad
set of rules. There is no global code of conduct enforced by the network.

If you join a node and it is not what you expected, **leave it.** If you want a
space you trust, **create a node and invite only people you know.** Safety on
Accord comes from your choice of who to associate with, not from a platform
promising to police strangers on your behalf.

## 4. Blindness runs both ways

- **The relay is blind to nodes** — it routes opaque ciphertext and stores only
  what it strictly needs to deliver messages. It cannot read content, and it does
  not expose node membership, per-node governance, or user rosters to anyone.
- **Nodes are blind to the relay** — a node's members interact only with node
  content; the relay operator is not a participant in the node and has no role
  inside it.

The one metadata concession is documented and narrow (see below): the relay may
see node **names and descriptions**, and IP addresses for abuse defense only.

---

## Who is who

### Relay owner

**Whoever has localhost access to the relay is the relay owner.** There is no
relay account, no "first user becomes admin," and no login by default — the
admin dashboard binds to `127.0.0.1` only, so physical/SSH access to the machine
*is* the authority. (See [`docs/admin-guide.md`](docs/admin-guide.md).)

The relay owner's powers are deliberately narrow — a landlord's powers:

| Can | Cannot |
|-----|--------|
| See node **names and descriptions** | See node membership, channels, messages, or roles |
| **Create and delete** nodes | Read or edit any node's content |
| See **connection logs** (IP + connect/disconnect) and **ban an IP** for DoS/DDoS defense | Correlate an IP to a node, or see which nodes anyone belongs to |
| Set a relay-wide client **build-hash allowlist** | Enumerate users or view any per-node governance/audit |

**IP addresses are relay-only.** A node owner, node admin, or any other end user
must never be able to obtain another end user's IP. IPs are visible only to the
relay owner, only in the node-correlation-free connection log, and only for abuse
defense.

### Node owner

The node owner holds all authority *inside their node* and is fully responsible
for it. They delegate via roles (see
[`docs/permission-system.md`](docs/permission-system.md)). Node governance —
bans, kicks, word filters, retention — is theirs to run, and none of it is
visible to or enforceable by the relay.

### User

An identity is a keypair. Users choose which nodes to join and which people to
trust. That choice is the primary safety mechanism on Accord.

---

## What this means for contributors

Before adding anything that touches moderation, safety, or the relay, ask:

1. **Does this give the relay the ability to inspect or police node content?**
   If yes, it's rejected.
2. **Does this let anyone but the relay owner see an end user's IP, or let the
   relay owner correlate an IP to a node?** If yes, it's rejected.
3. **Does this centralize a moderation decision that belongs to node owners?**
   If yes, it's rejected.

Moderation features are welcome — as node-owner tools that run client-side or
within the node's trust boundary. Central, relay-side, or cross-node enforcement
is not.

See also: [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md) ·
[`docs/metadata-privacy.md`](docs/metadata-privacy.md)
