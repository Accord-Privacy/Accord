# Accord UI Design Specification

> Reference: Discord (2024-2026 dark theme) + Fluxer open-source patterns
> Date: 2026-03-05 | Status: Research only — no code changes

---

## 1. Color Tokens

### 1.1 Discord Reference Palette (Dark Theme)

| Role | Discord Hex | Discord CSS Variable |
|------|------------|---------------------|
| Server list bg | `#1e1f22` | `--background-tertiary` |
| Channel sidebar bg | `#2b2d31` | `--background-secondary` |
| Chat area bg | `#313338` | `--background-primary` |
| Input bg | `#383a40` | `--background-textarea` |
| Elevated/floating | `#2b2d31` | `--background-floating` |
| Header bg | same as chat | — |
| Hover modifier | `rgba(79,84,92,0.16)` | `--background-modifier-hover` |
| Selected modifier | `rgba(79,84,92,0.32)` | `--background-modifier-selected` |
| Active modifier | `rgba(79,84,92,0.24)` | `--background-modifier-active` |
| Blurple (accent) | `#5865f2` | `--brand-500` |
| Blurple hover | `#4752c4` | `--brand-560` |
| Green (online) | `#23a559` | `--green-360` |
| Red (danger) | `#da373c` | `--red-400` |
| Yellow (warning) | `#f0b232` | `--yellow-300` |
| Text primary | `#f2f3f5` | `--text-normal` |
| Text secondary | `#dbdee1` | `--header-secondary` |
| Text muted | `#949ba4` | `--text-muted` |
| Text faint | `#6d6f78` | `--channels-default` |
| Link | `#00a8fc` | `--text-link` |

### 1.2 Accord Current Palette vs Discord

| Token | Accord Current | Discord Reference | Delta |
|-------|---------------|-------------------|-------|
| `--bg-deepest` | `#0e0f11` | `#1e1f22` | **Too dark** — Accord's server bar is much darker than Discord's. Discord uses a warm dark grey, not near-black. |
| `--bg-darkest` | `#1a1b1e` | `#232428` | Slightly dark — used for user panel/headers |
| `--bg-dark` | `#232428` | `#2b2d31` | **~8% too dark** — channel sidebar should be lighter |
| `--bg-content` | `#2e3035` | `#313338` | **Close but ~5% too dark** |
| `--bg-input` | `#1e1f23` | `#383a40` | **Way too dark** — Discord's input is lighter than the chat bg, not darker |
| `--bg-elevated` | `#393c42` | `#2b2d31` | Accord's elevated is brighter; Discord's floating surfaces are same as sidebar |
| `--bg-floating` | `#232428` | `#111214` | Discord floating (popouts) is actually very dark |
| `--accent` | `#5865f2` | `#5865f2` | ✅ Match |
| `--green` | `#23a559` | `#23a559` | ✅ Match |
| `--red` | `#da373c` | `#da373c` | ✅ Match |
| `--text-primary` | `#f2f3f5` | `#f2f3f5` | ✅ Match |
| `--text-secondary` | `#dbdee1` | `#dbdee1` | ✅ Match |
| `--text-muted` | `#949ba4` | `#949ba4` | ✅ Match |
| `--text-faint` | `#6d6f78` | `#6d6f78` | ✅ Match |

### 1.3 Recommended Color Changes

```css
/* Proposed updates to variables.css */
--bg-deepest: #1e1f22;     /* was #0e0f11 — match Discord server list */
--bg-darkest: #232428;     /* was #1a1b1e — slightly warmer */
--bg-dark: #2b2d31;        /* was #232428 — match Discord sidebar */
--bg-content: #313338;     /* was #2e3035 — match Discord chat */
--bg-input: #383a40;       /* was #1e1f23 — MAJOR: input should be LIGHTER than content */
--bg-elevated: #2b2d31;    /* was #393c42 — match Discord floating */
--bg-floating: #111214;    /* was #232428 — Discord popup bg */
```

> **Key insight:** Discord's depth model goes dark→medium→light from left to right (server bar → sidebar → chat → input). Accord currently inverts this for the input field, making it darker than the chat area — this breaks the visual hierarchy.

---

## 2. Typography

### 2.1 Discord Reference

- **Font family:** `gg sans`, fallback: `Noto Sans`, `Helvetica Neue`, Helvetica, Arial, sans-serif
- **Base size:** 16px (message content), 14px (UI chrome)
- **Message author:** 16px, semibold (600)
- **Message content:** 16px, normal (400), `line-height: 1.375`
- **Timestamp:** 12px, regular, muted color
- **Channel names:** 16px, medium (500)
- **Category headers:** 12px, semibold (600), uppercase, `letter-spacing: 0.02em`
- **Member names:** 16px, medium (500) — same as channel names
- **Input text:** 16px
- **Heading in settings:** 12px, semibold, uppercase

### 2.2 Accord Current Status

Accord's typography tokens are well-aligned:
- ✅ Font stack matches Discord's
- ✅ Font size scale (`--font-xs` through `--font-2xl`) covers all needs
- ✅ Category headers use 12px uppercase semibold
- ✅ Message content uses 16px

**Minor adjustments needed:**
- Channel names currently `font-size: 16px` — should be `15px` to match Discord's slightly smaller channel text
- Message author is `--font-lg` (16px) — correct
- Consider adding `--font-weight-normal: 400`, `--font-weight-medium: 500`, `--font-weight-semibold: 600`, `--font-weight-bold: 700` tokens for consistency

---

## 3. Spacing Grid

### 3.1 Discord Reference

Discord uses an **8px base grid** with 4px half-steps:

| Token | Value | Usage |
|-------|-------|-------|
| `4px` | half-step | inline gaps, tight padding |
| `8px` | 1 unit | standard gap, small padding |
| `12px` | 1.5 units | medium padding |
| `16px` | 2 units | section padding, message horizontal padding |
| `24px` | 3 units | large spacing |
| `32px` | 4 units | section dividers |
| `48px` | 6 units | header height |
| `72px` | 9 units | server bar width |
| `240px` | 30 units | sidebar width |

### 3.2 Accord Current Status

- ✅ `--space-xs: 4px` through `--space-2xl: 32px` — correct scale
- ✅ `--header-height: 48px` — matches Discord
- ✅ `--server-bar-width: 72px` — matches Discord
- ✅ `--sidebar-width: 240px` — matches Discord
- ✅ `--member-sidebar-width: 264px` — close (Discord uses 240px, but Fluxer uses ~264px)
- ✅ Message padding `2px 48px 2px 72px` — matches Discord's avatar-offset layout

**No spacing changes needed.** The grid is correct.

---

## 4. Border Radius

### 4.1 Discord Reference

| Element | Radius |
|---------|--------|
| Server icons (default) | `50%` (circle) |
| Server icons (hover/active) | `33%` → `30%` (squircle morph) |
| Buttons | `3px` |
| Modals/dialogs | `4-8px` |
| Message input | `8px` |
| Channels (hover) | `4-6px` |
| Tooltips | `4px` |
| Badges | `9999px` (pill) |
| Context menus | `4px` |

### 4.2 Accord Current Status

- ✅ Server icons: 50% → 30% morph on hover — matches Discord/Fluxer
- ✅ Radius tokens (`--radius-xs` through `--radius-pill`) cover all cases
- ⚠️ Message input wrapper uses `border-radius: 12px` — Discord uses `8px`. Consider reducing.
- ✅ Channels use `6px` — close to Discord's 4px, acceptable

---

## 5. Component-by-Component Audit

### 5.1 Server List (server-list.css)

**Current state:** Well-modeled after Fluxer's `GuildsLayout.module.css`.

| Feature | Status | Notes |
|---------|--------|-------|
| Pill indicator | ✅ | Left-side pill with height animation |
| Circle → squircle morph | ✅ | 50% → 30% on hover/active |
| Add server (dashed) | ✅ | Matches Fluxer pattern |
| Separator line | ✅ | 32px wide, 2px tall |
| Notification badge | ✅ | Bottom-right with border |
| Scrollbar hidden | ✅ | `scrollbar-width: none` |

**Changes needed:**
- Update `--bg-deepest` color (see §1.3) — currently too dark

### 5.2 Channel Sidebar (channel-sidebar.css)

**Current state:** Good structure, modeled after Fluxer.

| Feature | Status | Notes |
|---------|--------|-------|
| Header with server name | ✅ | 48px height, border-bottom |
| Channel items with hash | ✅ | # prefix, hover/active states |
| Unread pill indicator | ✅ | Left-edge white pill |
| Category headers | ✅ | 12px uppercase semibold |
| Create channel form | ✅ | Inline dark form |

**Changes needed:**
- Channel `font-size: 16px` → `15px` (Discord channels are slightly smaller than message text)
- Update `--bg-dark` color (see §1.3)

### 5.3 Messages (messages.css)

**Current state:** Closely matches Discord layout.

| Feature | Status | Notes |
|---------|--------|-------|
| Avatar positioning | ✅ | Absolute left, 40px circle |
| Grouped messages | ✅ | `margin-top: 0`, compact |
| Hover → action toolbar | ✅ | Top-right floating bar |
| Reply threading | ✅ | L-shaped connector line |
| Author + timestamp header | ✅ | Flex baseline alignment |
| Edit inline | ✅ | Replace content with input |

**Changes needed:**
- `.message-avatar` hover shows box-shadow ring — Discord doesn't do this. Remove or make subtle.
- Message hover `background: var(--bg-modifier-hover)` — ✅ correct

### 5.4 Message Input (message-input.css)

**Current state:** Good Fluxer-inspired design.

| Feature | Status | Notes |
|---------|--------|-------|
| Rounded container | ✅ | 12px radius wrapper |
| Attach/emoji buttons | ✅ | Inside wrapper, muted color |
| Reply preview bar | ✅ | Accent-colored left border |
| Placeholder text | ✅ | Muted color |

**Changes needed:**
- `border-radius: 12px` → `8px` (Discord uses less rounding)
- `--bg-input` fix (§1.3) is critical — input currently too dark
- `.message-input-wrapper:focus-within` changes to `--bg-elevated` which is brighter; Discord doesn't brighten the input on focus

### 5.5 Member Sidebar (member-sidebar.css)

**Current state:** Matches Discord/Fluxer well.

| Feature | Status | Notes |
|---------|--------|-------|
| Role section headers | ✅ | Uppercase, 12px, muted |
| Member items (32px height) | ✅ | Avatar + name + status |
| Offline opacity | ✅ | `opacity: 0.3` (Fluxer pattern) |
| Hover state | ✅ | `bg-modifier-hover` |

**Changes needed:**
- `member-name` at `font-size: 16px` — Discord uses `14px` for member names in the sidebar. Should be smaller.
- Missing: **status dots** (online/idle/dnd/offline colored dots on avatar corner). Discord shows a 10px circle with 3px border on the bottom-right of the avatar.

### 5.6 Chat Area (chat-area.css)

**Current state:** Clean grid layout matching Fluxer.

| Feature | Status | Notes |
|---------|--------|-------|
| Grid header | ✅ | `1fr auto` template |
| Channel name + hash | ✅ | Semibold, 16px |
| Topic separator | ✅ | Vertical bar + muted text |
| Header toolbar buttons | ✅ | 32px circles |
| E2EE badge | ✅ | Pill with color variants |

**Changes needed:** None significant. Color updates from §1.3 will cascade through.

---

## 6. Missing Discord Patterns

These are Discord features not yet present in Accord's CSS:

### 6.1 Status Dots on Avatars
```css
/* Needed: status indicator on member/message avatars */
.status-dot {
  position: absolute;
  bottom: -2px;
  right: -2px;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  border: 3px solid var(--bg-content); /* matches parent bg */
}
.status-dot.online { background: var(--green); }
.status-dot.idle { background: var(--yellow); }
.status-dot.dnd { background: var(--red); }
.status-dot.offline { background: var(--text-faint); }
```

### 6.2 Unread Badge on Channels
Discord shows a numeric badge on channels with unread mentions:
```css
.channel-mention-badge {
  background: var(--red);
  color: white;
  font-size: 10px;
  font-weight: 700;
  min-width: 16px;
  height: 16px;
  border-radius: 8px;
  padding: 0 4px;
  display: flex;
  align-items: center;
  justify-content: center;
}
```

### 6.3 New Messages Divider
Discord shows a red line with "NEW" label between read and unread messages:
```css
.new-messages-divider {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 16px;
  margin: 8px 0;
}
.new-messages-divider::before,
.new-messages-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--red);
}
.new-messages-divider-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--red);
  white-space: nowrap;
}
```

### 6.4 Date Separator
Discord shows centered date pills between message groups:
```css
.date-separator {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px 0;
  position: relative;
}
.date-separator::before {
  content: '';
  position: absolute;
  left: 16px;
  right: 16px;
  height: 1px;
  background: var(--border-subtle);
}
.date-separator-label {
  position: relative;
  background: var(--bg-content);
  padding: 0 8px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
}
```

---

## 7. Fluxer-Specific Patterns

Fluxer's source (React + CSS Modules) was partially inspectable. The Accord codebase already references Fluxer patterns in CSS comments. Key Fluxer-specific patterns already adopted:

- ✅ `GuildsLayout` → server list with pill indicators
- ✅ `ChannelItem` → channel with unread pill + hover states
- ✅ `MemberListItem` → 32px grid, offline opacity 0.3
- ✅ `GuildHeader` → expandable server header
- ✅ `TextareaInput` → rounded input container

**Fluxer patterns NOT yet adopted:**
- Fluxer uses CSS Modules (`.module.css`) with scoped class names — Accord uses global CSS. No change needed, but be aware of specificity when adding new styles.
- Fluxer has a `theme.css` with CSS custom properties very similar to Discord's — Accord's `variables.css` serves the same purpose.

---

## 8. Summary of Required Changes

### Priority 1 — Color Fixes (variables.css)
1. `--bg-deepest`: `#0e0f11` → `#1e1f22`
2. `--bg-darkest`: `#1a1b1e` → `#232428`
3. `--bg-dark`: `#232428` → `#2b2d31`
4. `--bg-content`: `#2e3035` → `#313338`
5. `--bg-input`: `#1e1f23` → `#383a40` (**critical** — inverted depth)
6. `--bg-elevated`: `#393c42` → `#2b2d31`
7. `--bg-floating`: `#232428` → `#111214`

### Priority 2 — Typography Tweaks
8. Channel name font-size: `16px` → `15px` (channel-sidebar.css)
9. Member name font-size: `16px` → `14px` (member-sidebar.css)
10. Add font-weight tokens to variables.css

### Priority 3 — Component Adjustments
11. Message input border-radius: `12px` → `8px` (message-input.css)
12. Remove `.message-avatar:hover` box-shadow ring (messages.css)
13. Remove `.message-input-wrapper:focus-within` background change (message-input.css)

### Priority 4 — New Components
14. Add status dots on avatars (§6.1)
15. Add channel mention badges (§6.2)
16. Add new-messages divider (§6.3)
17. Add date separator (§6.4)

---

## 9. Files to Modify

| File | Changes |
|------|---------|
| `styles/variables.css` | Color token updates (P1), font-weight tokens (P2) |
| `styles/channel-sidebar.css` | Channel font-size (P2) |
| `styles/member-sidebar.css` | Member name font-size (P2), add status dot styles (P4) |
| `styles/message-input.css` | Border-radius, remove focus bg change (P3) |
| `styles/messages.css` | Remove avatar hover ring (P3), add date separator & unread divider (P4) |
| `styles/shared.css` | Add status dot component styles (P4) |
