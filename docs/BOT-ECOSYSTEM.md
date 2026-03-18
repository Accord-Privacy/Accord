# Accord Bot Ecosystem

**Target audience:** Accord contributors and community builders  
**Status:** Planning / pre-launch  
**Last updated:** 2026-03-18

---

## Overview

Accord ships with a `accord-bot-sdk` Rust crate that exposes a WebSocket event loop, HTTP REST helpers, and typed models (`Message`, `User`, `Channel`, `Event`). The existing examples — an echo bot and a moderation bot — prove the core primitives work. This document proposes 7 bot concepts suited to Accord's first-party or community ecosystem, grounded in what Discord and Matrix communities actually use most.

### Research basis

Discord's most-used bot categories (by install count and community surveys):
1. **Moderation** — spam filter, role assignment, auto-mute
2. **Welcome / onboarding** — greeting new members, rule gates
3. **Polls and voting** — lightweight community decisions
4. **Scheduled reminders / events** — calendar, countdowns
5. **RSS / webhooks** — external content feeds
6. **Starboard / highlights** — surfacing great content
7. **Utility** — timezone, weather, math, definitions
8. **Music/media** — audio playback (heavy; often broken by platform changes)

Matrix community priorities skew more toward **privacy-preserving utility** (helpdesk bots, registration management, RSS bridges) and away from gamification. That aligns well with Accord's positioning.

### SDK capabilities confirmed

From the current crate (`bot-sdk/src/`):
- WebSocket event stream: `MessageCreate`, `MessageEdit`, `MessageDelete`, `ReactionAdd/Remove`, `TypingStart`
- Send messages, join channels
- HTTP REST for node-level actions (kick, ban via `reqwest`)
- Typed `Message` struct includes `reply_to`, `created_at`, `sender_public_key_hash`
- No built-in persistence — bots must manage their own state (SQLite, flat files, etc.)

---

## Bot Concepts

---

### 1. `accord-welcome` — Onboarding and gate bot

> Greets new members, presents rules, and optionally gates access behind a reaction or command confirmation.

**Key features:**
- Posts a configurable welcome message to a designated channel when a user joins
- "Rules gate" mode: withholds full channel access until the user reacts with ✅ or sends `!agree`
- Assigns an "onboarded" role via the REST API after confirmation
- Configurable per-node via a TOML config file
- Quiet mode: DMs the welcome message instead of broadcasting to a channel

**Privacy considerations:**  
Processes join events locally; no external calls. User IDs never leave the node. No analytics or tracking.

**Complexity:** Simple  
**Type:** Built-in (bundled with Accord server, opt-in via config)

---

### 2. `accord-guard` — Spam and raid protection

> Extends the existing moderation bot with automated threat detection: rate-limit enforcement, duplicate message detection, and new-account join floods.

**Key features:**
- Rate-limit messages per user (configurable: N messages per M seconds)
- Detect and suppress duplicate/copy-paste message floods
- Join flood detection: if X new users join within Y seconds, pause invites and alert mods
- Configurable auto-mute (role removal) vs. auto-kick thresholds
- Audit log channel: posts every automated action with reason and timestamp

**Privacy considerations:**  
All detection is local pattern-matching — no content sent to external services. Hashes (not plaintext) used for duplicate detection. Logs stay on-node and are admin-visible only.

**Complexity:** Medium  
**Type:** Built-in (natural successor to the bundled moderation example)

---

### 3. `accord-poll` — Native polling bot

> Creates timed polls with reaction-based or command-based voting, then announces results automatically.

**Key features:**
- `!poll "Question?" "Option A" "Option B" "Option C"` — creates an enumerated poll message
- Reacts with number emojis (1️⃣ 2️⃣ 3️⃣) automatically; users vote by reacting
- Optional `--duration 24h` flag; bot announces results when the poll closes
- `!poll-results <message_id>` for on-demand tally
- Anonymous mode: bot DMing participants to vote, hiding reaction counts until close

**Privacy considerations:**  
Votes stored in local SQLite (`~/.accord-poll/polls.db`). No user-to-vote correlation exported. Anonymous mode prevents even the bot operator from linking votes to users during an active poll.

**Complexity:** Medium  
**Type:** Optional addon (good candidate for a first community-contributed bot)

---

### 4. `accord-feed` — Privacy-respecting RSS/Atom aggregator

> Polls RSS/Atom feeds on a schedule and posts new entries to designated channels, keeping communities informed without requiring external integrations.

**Key features:**
- Subscribe a channel to one or more RSS/Atom URLs: `!feed add <url> [#channel]`
- Configurable polling interval (default: 15 min)
- Posts title + link + optional excerpt; strips tracking parameters from URLs
- `!feed list` and `!feed remove <id>` for management
- Deduplication: skips entries already posted (tracks by GUID/URL hash)

**Privacy considerations:**  
Feed URLs are fetched server-side by the bot — member browsers never hit the source. Tracking query params (`utm_*`, `fbclid`, etc.) stripped before posting. No webhook callbacks to external services.

**Complexity:** Simple  
**Type:** Optional addon

**Differentiator vs. Discord:** Discord's built-in webhook integrations leak server metadata to the source (IP, headers). This bot proxies feeds silently.

---

### 5. `accord-remind` — Persistent reminder and scheduler

> Lets users set personal or channel-wide reminders. Doubles as a lightweight event scheduler for small communities.

**Key features:**
- `!remind me in 2h about standup` — personal DM reminder
- `!remind #announcements on Friday 9am "Weekly sync starts now"`
- Lists and cancels pending reminders: `!remind list`, `!remind cancel <id>`
- Recurring reminders: `!remind every Monday 8am #general "Week starts!"`
- Timezone-aware: users register their timezone once with `!tz set America/Chicago`

**Privacy considerations:**  
Reminder content and scheduling stored locally (SQLite). No telemetry. Timezone stored per `sender_public_key_hash` so it persists across display name changes without tracking identity elsewhere.

**Complexity:** Medium  
**Type:** Optional addon

---

### 6. `accord-highlight` — Starboard / notable messages

> Surfaces highly-reacted messages to a dedicated highlights channel, preserving community "moments" without manual pinning.

**Key features:**
- Watches `ReactionAdd` events; when a message hits a configurable threshold (e.g., ⭐×5), reposts it to a `#highlights` channel
- Configurable reaction emoji and threshold per channel
- Posts include original author, channel reference, and timestamp
- Anti-spam: each message can only be highlighted once; editing the original updates the highlight
- Admin command `!highlight <message_id>` for manual promotion

**Privacy considerations:**  
Highlight posts quote message content — consider making this opt-out per user (`!highlight-optout`). No data leaves the node. Works entirely off the local event stream.

**Complexity:** Simple  
**Type:** Optional addon

---

### 7. `accord-bridge` — Webhook-in relay

> Receives inbound webhooks from external services (GitHub, GitLab, Gitea, Forgejo) and formats them as readable channel messages. Keeps notifications in Accord without subscribing to cloud services.

**Key features:**
- Listens on a local HTTP port for POST payloads (GitHub-format webhook JSON)
- Supports push, PR open/close, issue open/close, CI pass/fail events
- Routes events to configurable channels by repo or event type
- Configurable secret validation (HMAC-SHA256) to authenticate inbound payloads
- Extensible: custom event templates in TOML

**Privacy considerations:**  
Inbound-only — the bot never calls external APIs. Webhook secrets stay in local config. Git host sends to the bot's local IP; no relay through Accord's infrastructure. HMAC validation prevents spoofed payloads.

**Complexity:** Medium  
**Type:** Optional addon

**Differentiator vs. Discord:** Discord webhook integrations require exposing a Discord-hosted URL to the git provider, which means Discord can see all your push activity. This bot keeps that data within your self-hosted perimeter.

---

## Priority Matrix

| Bot | Usefulness | Privacy Value | SDK Effort | Suggested Phase |
|---|---|---|---|---|
| `accord-welcome` | ★★★★★ | ★★★ | Low | Launch (built-in) |
| `accord-guard` | ★★★★★ | ★★★★ | Medium | Launch (built-in) |
| `accord-poll` | ★★★★ | ★★★★ | Medium | v1.1 addon |
| `accord-feed` | ★★★ | ★★★★★ | Low | v1.1 addon |
| `accord-remind` | ★★★★ | ★★★ | Medium | v1.1 addon |
| `accord-highlight` | ★★★ | ★★★ | Low | v1.2 addon |
| `accord-bridge` | ★★★ | ★★★★★ | Medium | v1.2 addon |

---

## What NOT to build (at launch)

- **Music bots** — require audio mixing, voice channel streaming infrastructure, and third-party content licenses. High maintenance, legal exposure. Not a differentiator for privacy-focused communities.
- **AI/LLM bots** — tempting, but any cloud LLM integration breaks the privacy model. A local-inference variant (Ollama) is worth exploring post-launch once the bot API is stable.
- **Leveling/XP bots** — popular on Discord, but fundamentally surveillance features (tracking every message). Antithetical to Accord's ethos. If requested, it should be strictly opt-in with per-user consent.
- **Crypto/NFT bots** — no.

---

## SDK gaps to address before community bots land

1. **Persistent bot identity** — bots currently authenticate via token; no first-class "bot account" concept that survives node restarts. Needed before third-party bot authors ship.
2. **Member join events** — `accord-welcome` and `accord-guard` need a `MemberJoin` event type in the SDK models.
3. **Role management API** — required for gate bots that assign roles post-confirmation.
4. **Reaction write API** — the SDK can read `ReactionAdd` events but there's no `bot.add_reaction()` method yet (needed for poll bot emoji setup).
5. **Message history fetch** — bots that restart need to catch up on missed events; a REST endpoint for recent messages per channel would help.

These are tracked in the bot API roadmap (`docs/bot-api-v2.md`).
