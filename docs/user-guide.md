# Accord User Guide

Welcome to **Accord** — a privacy-first chat platform that gives you Discord-style community features with end-to-end encryption. This guide will walk you through everything you need to know as a user.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Navigating the Interface](#navigating-the-interface)
3. [Messaging](#messaging)
4. [Threads & Replies](#threads--replies)
5. [Reactions](#reactions)
6. [Search](#search)
7. [Direct Messages](#direct-messages)
8. [Voice Channels](#voice-channels)
9. [Notifications](#notifications)
10. [Customization](#customization)
11. [Privacy & Security](#privacy--security)
12. [Keyboard Shortcuts](#keyboard-shortcuts)
13. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Downloading the App

Download the Accord desktop app for your operating system from the [GitHub releases page](https://github.com/Accord-Privacy/Accord/releases). Accord is available for **Windows**, **macOS**, and **Linux**.

### First-Run Setup

When you launch Accord for the first time, a setup wizard will guide you through three steps:

#### Step 1: Welcome
A brief introduction to Accord and what makes it different — your messages are end-to-end encrypted, and no personal information is required to sign up.

#### Step 2: Create Your Identity

You have two options:

- **Create a new identity** — Accord will generate a fresh cryptographic identity for you. You'll need to:
  1. Choose a **display name** (this is what other people will see).
  2. Set a **password** (at least 8 characters) to protect your identity on this device.
  3. **Save your recovery phrase** — Accord will show you a 12-word phrase. **Write this down and keep it safe!** This phrase is the only way to recover your account if you lose access to your device.

- **Recover an existing identity** — If you've used Accord before, enter your 12-word recovery phrase and set a new password to restore your identity.

#### Step 3: Connect to a Relay

A relay is the server that routes your encrypted messages. You can either:

- **Enter a relay address** directly (e.g., `wss://relay.example.com` or `relay.example.com`). The app will auto-detect the correct format.
- **Use an invite link** — If someone shared an Accord invite link with you, paste it here. The relay address and invite code will be extracted automatically.

Once connected, you're in! 🎉

---

## Navigating the Interface

Accord's layout will feel familiar if you've used Discord or similar apps:

### Sidebar (Left)
- **Node list** — At the top left, you'll see the Nodes (communities) you've joined. Click a Node's icon to switch to it.
- **Channel list** — Below the Node name, channels are organized into **categories** (collapsible groups). Text channels are marked with a **#** symbol, and voice channels have a **🔊** speaker icon.
- **Your profile** — At the bottom of the sidebar, you'll see your display name, status, and controls for mute/deafen (when in a voice channel).

### Main Content (Center)
- **Channel header** — Shows the current channel name and topic.
- **Message area** — Where conversations happen. Messages appear in chronological order.
- **Message input** — At the bottom, type your messages here.

### Member List (Right)
- Shows everyone in the current Node, organized by their roles.
- **Online indicators** — Green dot means online, yellow means away, red means busy, and grey means offline.
- Click a member's name to view their profile card.

---

## Messaging

### Sending Messages
Type your message in the input box at the bottom and press **Enter** to send. Press **Shift + Enter** to add a new line without sending.

### Editing Messages
To edit a message you've sent, hover over it and click the **pencil icon** (✏️), or right-click and select **Edit**. Make your changes, then press **Enter** to save or **Escape** to cancel.

### Deleting Messages
Hover over a message you've sent and click the **trash icon** (🗑️), or right-click and select **Delete**. You'll be asked to confirm before the message is removed.

### Markdown Formatting
Accord supports markdown to style your messages:

| Syntax | Result |
|---|---|
| `**bold**` | **bold** |
| `*italic*` | *italic* |
| `~~strikethrough~~` | ~~strikethrough~~ |
| `` `inline code` `` | `inline code` |
| ` ```code block``` ` | Code block (multi-line) |
| `> quote` | Block quote |
| `[link text](url)` | Clickable link |

### File Uploads
You can share files in two ways:
- **Click the attachment button** (📎) next to the message input to browse and select files.
- **Drag and drop** files directly into the chat window.

Selected files appear as previews below the message input before you send. You can remove a staged file by clicking the ✕ on its preview. A message holds up to 10 files of up to 100 MiB each (your relay may set a lower limit).

Each file is encrypted on your device with its own random key before it is uploaded, and the key, the file name and the file type are sent only inside the end-to-end-encrypted message. The relay stores a nameless, padded blob and deletes it with the message. It still sees that the message has attachments, how many, their approximate (padded) sizes, who uploaded them and when, in which channel, and who downloads them, when and from which IP address. It does not see file names, types, contents, keys or exact sizes.

**Limits.** Attachments are exactly as private and as authentic as the message that carries them. Until identity verification and key-recipient checks ship, a relay that injects its own sender key into a channel, or intercepts a direct-message session when it is set up, can read the attachments sent there and can forge attachments, with its own file, name and type, attributed to the member it impersonates. The relay's deletion and expiry signals are not authenticated: a malicious relay can make your device delete a message together with its attachment keys, and for a direct message that can be the device's only copy of a file's key, so the file can no longer be opened on that device. See [Known Limitations in SECURITY.md](../SECURITY.md#known-limitations).

What to expect:
- **Previews.** PNG, JPEG, GIF and WebP images, common audio formats and MP4 and WebM video up to 10 MiB preview automatically once they have been checked. Everything else, and larger files, shows a card with a **Download** button. File names are cleaned of invisible and direction-changing characters, and the extension is always shown.
- **Integrity.** Every downloaded file is checked against the hash in the message. If the check fails, nothing is shown or saved and you see "Attachment failed its integrity check and may have been tampered with".
- **Sending states.** A message with files shows upload progress, then "sent" once the relay has confirmed it. If it cannot be confirmed within 30 seconds it shows "not confirmed yet" with **Retry**. Some failures (for example slow mode) offer **Retry**; others (no permission, blocked, a node that only accepts approved app builds) offer only **Delete**.
- **No edits.** Messages with attachments cannot be edited, and direct messages cannot be edited in this release.
- **Relays that are not updated.** On a relay that does not support end-to-end-encrypted attachments, the attach button is disabled and explains why.
- **Larger uploads that always fail.** If every file over about 1 MiB fails to upload while smaller ones work, the relay sits behind a reverse proxy whose request body limit is too low. The relay operator must raise it (for nginx, `client_max_body_size`); see [Request body size for attachments](SELF-HOSTING.md#request-body-size-for-attachments).
- **When attachments may not appear.** A direct-message attachment sent while you were offline, and other members' channel attachments after the channel's history reloads, are not shown yet.
- **Legacy uploads.** Files uploaded before this release are not end-to-end encrypted. The Files panel lists them only after you turn on "Show legacy uploads (not end-to-end encrypted)", with a warning on each, and asks before downloading one. They disappear when the relay retires them.

### Link Previews
When you share a URL, Accord will automatically generate a preview showing the page title and description (when available).

---

## Threads & Replies

### Replying to a Message
To reply to a specific message, hover over it and click the **reply icon** (↩️). The message you're replying to will appear above your input box as context. Type your reply and press **Enter** to send.

Replies show a visual connection to the original message, making it easy to follow conversations.

### Viewing Threads
When a message has replies, you'll see a "replies" indicator below it. Click it to see the full thread of replies in context.

---

## Reactions

### Adding a Reaction
Hover over any message and click the **emoji icon** (😀) to open the emoji picker. Select an emoji to react to the message. You can also click an existing reaction to add your own.

### Removing a Reaction
Click on a reaction you've already added to remove it.

### Emoji Picker
The emoji picker (**Ctrl + E**) lets you search for emojis by name. Just start typing to filter the list.

---

## Search

### Opening Search
Press **Ctrl + K** (or **Cmd + K** on macOS) to open the search overlay.

### Basic Search
Type your search terms and results will appear as you type. Click a result to jump to that message in its channel.

### Filters
Click **Show Filters** to narrow your results:
- **Channel** — Search within a specific channel.
- **Author** — Filter by who sent the message.
- **Before / After** — Limit results to a date range.

### Keyboard Navigation
Use **↑** and **↓** arrow keys to move through search results, then press **Enter** to jump to the selected message. Press **Escape** to close the search overlay.

---

## Direct Messages

### Starting a DM
Click on any user's name in the member list to open their profile card, then select **Send Message** to start a direct message conversation.

### Presence Indicators
In DM conversations, you can see the other person's online status:
- 🟢 **Online** — Currently active
- 🟡 **Away** — Idle or stepped away
- 🔴 **Busy** — Do not disturb
- ⚫ **Offline / Invisible** — Not currently available

---

## Voice Channels

### Joining a Voice Channel
Click on any voice channel (marked with a 🔊 icon) in the sidebar to join. Your microphone will be **muted by default** when you join.

### Voice Controls
Once connected, you'll see a voice connection panel at the bottom of the sidebar:
- **Mute/Unmute** (🎤) — Toggle your microphone. Shortcut: **Ctrl + Shift + M**.
- **Deafen/Undeafen** (🎧) — Mute all incoming audio. Shortcut: **Ctrl + Shift + D**.
- **Disconnect** (📞) — Leave the voice channel.

### Speaking Indicators
When someone is talking, their name will be highlighted with a green ring so you can see who's speaking.

### Voice Settings
Open **Settings → Voice** to configure:
- **Input/Output device** — Choose your microphone and speakers.
- **Volume controls** — Adjust input and output volume.
- **Voice Activity Detection** — Set the sensitivity threshold for voice activation.
- **Echo cancellation, noise suppression, and auto gain** — Toggle these audio processing features on or off.

---

## Notifications

### Notification Modes
Open notification settings to choose when you want to be notified:
- **All** — Get notified for every message.
- **Mentions** — Only when someone mentions you.
- **DMs** — Only for direct messages.
- **None** — Silence all notifications.

### Desktop Notifications
When enabled, Accord will send system notifications for new messages. You may need to grant notification permissions in your browser or operating system when prompted.

### Sounds
Toggle notification sounds on or off. You can test both notifications and sounds from the notification settings panel using the **Test** buttons.

---

## Customization

### Themes
Accord comes with three built-in themes. Go to **Settings → Appearance** to switch:
- **Dark** — The default dark theme with deep grays and blue accents.
- **Light** — A bright theme with white backgrounds and subtle shadows.
- **Midnight** — A true-black OLED-friendly theme for the darkest experience.

### Font Size & Density
In **Settings → Appearance**, you can also adjust:
- **Font size** — Use the slider to make text larger or smaller.
- **Message density** — Choose between Compact, Comfortable, or Cozy spacing.

---

## Privacy & Security

### End-to-End Encryption
Messages in Accord are **end-to-end encrypted**. This means:
- Your messages are encrypted on your device before they leave.
- The relay server only sees encrypted data — it **cannot** read your messages.
- Only the intended recipients can decrypt and read them.

**Attachments are end-to-end encrypted, with limits.** They are exactly as private and as authentic as the message that carries them, the relay sees their metadata (how many, their padded sizes, who downloads them), and files uploaded before this release are readable by the relay until they are retired. Voice is not end-to-end encrypted, and a malicious relay can intercept encrypted sessions when they are set up. See [Known Limitations in SECURITY.md](../SECURITY.md#known-limitations) before sharing anything sensitive.

Accord uses industry-standard cryptography (the same foundations as the Signal protocol) to protect your conversations.

### Disappearing Messages
Node owners can set messages to auto-delete after a chosen time — a node-wide default or a per-channel override. Turning it on also wipes messages already older than the limit. The relay only ever sees an opaque expiry timestamp; the policy itself is encrypted and shared privately among members. When enabled, messages show a small clock badge.

### Read-Gated Messages
When composing, click the **clock button** in the message bar to attach retention to a single message:
- **Vanish after a time** — a plain timer.
- **Vanish after seen** — pick specific people and/or roles; the timer doesn't start until *they* have opened it, so the message stays for anyone who hasn't read it yet. Each reader's own copy disappears after they read it. (Deletion is honored by their app — like any disappearing message, it isn't a hard guarantee against a modified client.)

### Screenshot Protection
A node or channel can ask your operating system to exclude the Accord window from screen capture. This is reliable on **Windows and macOS**; on **Linux** it's best-effort (many Wayland compositors ignore it), and Accord tells you so rather than implying a guarantee.

### Panic Wipe
In **Settings → Privacy** (danger zone), **Panic Wipe** immediately destroys all local identity, keys, and data on this device and reloads the app to a clean state. Keep your 12-word recovery phrase somewhere safe if you ever want the account back.

### Duress Password
You can configure a **duress password** distinct from your real one. Entering the duress password at login **wipes your real identity and data** and opens an empty, offline decoy account — with no forensic trace that a second (real) account ever existed. Use it if you may be compelled to unlock the app.

### Blocking Users
To block a user, open their profile card and click **Block**. Blocked users won't be able to send you direct messages. You can manage your blocked users list in **Settings → Privacy**.

### Identity Export & Import
Your identity is tied to a **12-word recovery phrase** (shown when you first created your account). To move your identity to a new device:

1. On your new device, choose **Recover an existing identity** during setup.
2. Enter your 12-word recovery phrase.
3. Set a new password for the new device.

You can also use **QR code sync** — go to **Settings → Account** to generate a QR code that another device can scan to import your identity.

### Privacy Controls
In **Settings → Privacy**, you can control:
- **Read receipts** — Whether others can see when you've read their messages.
- **Typing indicators** — Whether others can see when you're typing.

### Choosing Who to Trust
Accord performs **no central moderation** — because the relay can't read your messages, no platform admin is filtering content or refereeing communities. Each **node owner** is responsible for their own space.

What this means for you:
- If a node isn't what you expected, **leave it.**
- For a space you trust, **create your own node and invite only people you know.**
- Report problems to the **node's** owners/moderators — there is no "Accord" to appeal to, by design.
- **Parents:** you are responsible for what your children see and do on Accord, the same as with a web browser. There is no platform-side content filter.

See [GOVERNANCE.md](../GOVERNANCE.md) for the full philosophy.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| **Enter** | Send message |
| **Shift + Enter** | New line in message |
| **Escape** | Close modal / Cancel edit / Deselect |
| **Ctrl + K** | Open search |
| **Ctrl + E** | Toggle emoji picker |
| **Ctrl + ,** | Open settings |
| **Ctrl + /** | Show keyboard shortcuts help |
| **?** | Show keyboard shortcuts help (when not typing) |
| **Alt + ↑ / ↓** | Navigate channels up / down |
| **Ctrl + Shift + M** | Toggle mute (in voice) |
| **Ctrl + Shift + D** | Toggle deafen (in voice) |

> **Tip:** On macOS, use **Cmd** instead of **Ctrl** for all shortcuts.

---

## Troubleshooting

### Connection Issues
If you're having trouble connecting to a relay:
1. **Check the relay address** — Make sure it's entered correctly in your settings. Go to **Settings → Advanced** to view or change it.
2. **Check your internet connection** — Ensure you have a stable network connection.
3. **Try reconnecting** — The app will automatically attempt to reconnect, but you can also restart Accord.
4. **Firewall or VPN** — Some networks may block WebSocket connections. Try a different network if possible.

### Voice Not Working
- Make sure your browser/OS has granted microphone permissions to Accord.
- Check **Settings → Voice** to ensure the correct input and output devices are selected.
- Try toggling mute on and off.

### Messages Not Decrypting
If you see encrypted/garbled messages:
- This can happen if your encryption keys are out of sync. Try leaving and rejoining the Node.
- Make sure you're using the same identity (recovery phrase) as when the messages were sent to you.

### Clearing Local Data
If Accord is behaving unexpectedly, clearing local data can help:
1. Go to **Settings → Advanced**.
2. Look for the option to clear local storage or reset the app.
3. **Warning:** This will log you out and remove locally stored data. Make sure you have your 12-word recovery phrase saved before doing this!

### Getting Help
If none of the above resolves your issue, visit the Accord community or check the [GitHub repository](https://github.com/Accord-Privacy/Accord) for known issues and support.

---

*This guide is for Accord desktop. Features may vary slightly between versions.*
